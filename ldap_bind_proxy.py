#! /usr/bin/env python
# Copyright 2024 please-open.it
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
from ldaptor.protocols.ldap.proxybase import ProxyBase
from ldaptor.protocols.ldap import ldapserver, ldaperrors
from twisted.internet import protocol, reactor
from twisted.internet.ssl import DefaultOpenSSLContextFactory
from twisted.python import log
from functools import partial
import sys
import requests
import os

from mock import Mock

class Configuration():
    """
    Configuration class to hold environment variable values.
    Reads configuration from environment variables on initialization.

    1. LDAP_PROXY_TLS_CERTFILE : Path to TLS certificate file for LDAPS (default None)
    2. LDAP_PROXY_TLS_KEYFILE : Path to TLS key file for LDAPS (default None)
    3. LDAP_PROXY_TLS_PORT : Port number for LDAPS listener (default 636)
    4. LDAP_PROXY_PORT : Port number for plain LDAP listener (default 389)

    5. LDAP_PROXY_TOKEN_URL : OIDC Token endpoint URL
    6. LDAP_PROXY_CLIENT_ID : OIDC Client ID
    7. LDAP_PROXY_CLIENT_SECRET : OIDC Client Secret
    """
    def __init__(self):
        self.tls_certfile = os.environ.get('LDAP_PROXY_TLS_CERTFILE')
        self.tls_keyfile = os.environ.get('LDAP_PROXY_TLS_KEYFILE')
        self.tls_port = int(os.environ.get('LDAP_PROXY_TLS_PORT', '636'))
        self.plain_port = int(os.environ.get('LDAP_PROXY_PORT', '389'))
        self.enable_plain = os.environ.get('LDAP_PROXY_ENABLE_PLAIN', 'false').lower() in ('1', 'true', 'yes')

        self.url = os.environ.get("LDAP_PROXY_TOKEN_URL")
        self.client_id = os.environ.get("LDAP_PROXY_CLIENT_ID")
        self.client_secret = os.environ.get("LDAP_PROXY_CLIENT_SECRET")


class OidcProxy(ProxyBase):
    """
    A simple example of using `ProxyBase` to log requests and responses.
    """
    def __init__(self, config):
        self.config = config


    def handleBeforeForwardRequest(self, request, controls, reply):
        """
        Log the representation of the request received.
        """
        print(repr(request))
        if isinstance(request, pureldap.LDAPBindRequest):
            # Get OIDC token throught password grant
            ## Quick and dirty username from DN assuming it is CN
            username = request.dn.split(b',')[0][3:]
            password = request.auth

            ## TODO : Nice to have Add support for OTP within password

            url = self.config.url
            client_id = self.config.client_id
            client_secret = self.config.client_secret

            payload = 'client_id={client_id}&client_secret={client_secret}&grant_type=password&username={username}&password={password}'.format(client_id=client_id, client_secret=client_secret, username=username.decode('utf-8'), password=password.decode('utf-8'))
            headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
            }
            print(url)
            oidc_response = requests.request("POST", url, headers=headers, data=payload)

            # Logging username and status code
            print(username.decode('utf-8') + " " + str(oidc_response.status_code))
            
            if oidc_response.status_code == requests.codes['ok']:
                # LDAP Bind success
                msg= pureldap.LDAPBindResponse(
                        resultCode=ldaperrors.Success.resultCode
                    )
            else:
                # Invalid credentials (see keycloak logs)
                msg= pureldap.LDAPBindResponse(
                        resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                    )
            reply(msg)
        if isinstance(request, pureldap.LDAPSearchRequest):
            # TODO: If needed, for confidential clients with service account only, search within keycloak API and reply with search result, dummy response for now.
            msg = pureldap.LDAPSearchResultDone(
                resultCode=ldaperrors.Success.resultCode
            )
            reply(msg)
        if isinstance(request, pureldap.LDAPExtendedRequest):
            msg = pureldap.LDAPExtendedResponse(
                resultCode=ldaperrors.Success.resultCode
            )
            reply(msg)
        if isinstance(request, pureldap.LDAPUnbindRequest):
            msg = pureldap.LDAPBindResponse(
                resultCode=ldaperrors.Success.resultCode
            )
            reply(msg)
        return None

    ## TODO: This is a Workaround, implement a cleaner proxy class from class ServerBase
    def connectionMade(self):
        """ Overridden method to prevent proxy from trying to connect non-existing backend server.
        Mocking client class to drop every operation made to it"""
        print("connectionMade called")
        self.client = Mock()
        ldapserver.BaseLDAPServer.connectionMade(self)
    
if __name__ == '__main__':
    """
    Demonstration LDAP OIDC proxy; listens on localhost:389 and translate to OIDC protocol
    """

    config = Configuration()

    log.startLogging(sys.stderr)
    factory = protocol.ServerFactory()
    proxiedEndpointStr = 'NoEndpointneeded'
    use_tls = False
    clientConnector = partial(
        connectToLDAPEndpoint,
        reactor,
        proxiedEndpointStr,
        LDAPClient)

    def buildProtocol():
        proto = OidcProxy(config)
        proto.clientConnector = clientConnector
        proto.use_tls = use_tls
        return proto

    factory.protocol = buildProtocol

    # Ports and TLS files are configurable through environment variables.
    # If TLS cert and key are provided, start an LDAPS listener (implicit TLS) on LDAP_PROXY_TLS_PORT (default 636).
    # Otherwise fall back to plain LDAP on LDAP_PROXY_PORT (default 389) for backwards compatibility.
    if config.tls_certfile and config.tls_keyfile:
        # Minimal, secure server-side TLS (LDAPS). For mutual TLS / CA verification more setup is required.
        try:
            contextFactory = DefaultOpenSSLContextFactory(config.tls_keyfile, config.tls_certfile)
            reactor.listenSSL(config.tls_port, factory, contextFactory)
            print('LDAPS listening on port {}'.format(config.tls_port))

            # Optionally also open plain port if explicitly requested
            if config.enable_plain :
                reactor.listenTCP(config.plain_port, factory)
                print('Plain LDAP also listening on port {}'.format(config.plain_port))
        except Exception as e:
            print('Failed to start LDAPS: {}'.format(e))
            print('Exiting. please check your TLS certificate and key file paths and {} port availability.'.format(config.tls_port))
            sys.exit(1)
    else:
        reactor.listenTCP(config.plain_port, factory)
        print('Plain LDAP listening on port {}'.format(config.plain_port))

    reactor.run()