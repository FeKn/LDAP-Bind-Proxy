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
from twisted.internet import protocol, reactor, ssl as twisted_ssl
from twisted.internet.ssl import CertificateOptions, Certificate, PrivateCertificate
from twisted.python import log
from functools import partial
import sys
import requests
import os
import ssl
from OpenSSL import SSL, crypto

from mock import Mock

class Configuration():
    """
    Configuration class to hold environment variable values.
    Reads configuration from environment variables on initialization.

    OIDC Configuration:
    1. LDAP_PROXY_TOKEN_URL : OIDC Token endpoint URL
    2. LDAP_PROXY_CLIENT_ID : OIDC Client ID
    3. LDAP_PROXY_CLIENT_SECRET : OIDC Client Secret

    TLS Configuration:
    1. LDAP_PROXY_TLS_CERTFILE : Path to TLS certificate file for LDAPS (default None)
    2. LDAP_PROXY_TLS_KEYFILE : Path to TLS key file for LDAPS (default None)
    3. LDAP_PROXY_TLS_PORT : Port number for LDAPS listener (default 636)
    4. LDAP_PROXY_PORT : Port number for plain LDAP listener (default 389)
    5. LDAP_PROXY_ENABLE_PLAIN : Enable plain LDAP when TLS is configured (default false)
    6. LDAP_PROXY_TLS_CAFILE : Path to CA bundle for client certificate verification (default None)
    7. LDAP_PROXY_REQUIRE_CLIENT_CERT : Require client certificate for mTLS (default false)


    """
    def __init__(self):
        # TLS configuration
        self.tls_certfile = os.environ.get('LDAP_PROXY_TLS_CERTFILE')
        self.tls_keyfile = os.environ.get('LDAP_PROXY_TLS_KEYFILE')
        self.tls_cafile = os.environ.get('LDAP_PROXY_TLS_CAFILE')
        self.tls_port = int(os.environ.get('LDAP_PROXY_TLS_PORT', '636'))
        self.plain_port = int(os.environ.get('LDAP_PROXY_PORT', '389'))
        self.enable_plain = os.environ.get('LDAP_PROXY_ENABLE_PLAIN', 'false').lower() in ('1', 'true', 'yes')
        self.require_client_cert = os.environ.get('LDAP_PROXY_REQUIRE_CLIENT_CERT', 'false').lower() in ('1', 'true', 'yes')

        # OIDC configuration
        self.url = os.environ.get("LDAP_PROXY_TOKEN_URL")
        self.client_id = os.environ.get("LDAP_PROXY_CLIENT_ID")
        self.client_secret = os.environ.get("LDAP_PROXY_CLIENT_SECRET")


class OidcProxy(ProxyBase):
    """
    LDAP to OIDC authentication proxy with TLS support.
    
    Supports:
    - LDAPS (implicit TLS on port 636)
    - STARTTLS (explicit TLS upgrade on port 389)
    - mTLS (mutual TLS with client certificate verification)
    """
    # STARTTLS OID as defined in RFC 4511
    STARTTLS_OID = '1.3.6.1.4.1.1466.20037'
    
    def __init__(self, config, ssl_context_factory=None):
        ProxyBase.__init__(self)  # Initialize parent class
        self.config = config
        self.ssl_context_factory = ssl_context_factory
        self.tls_started = False


    def handleBeforeForwardRequest(self, request, controls, reply):
        """
        Handle incoming LDAP requests and translate to OIDC.
        Supports STARTTLS extended operation for TLS upgrade.
        """
        print(repr(request))
        
        # Handle STARTTLS Extended Operation
        if isinstance(request, pureldap.LDAPExtendedRequest):
            if request.requestName == self.STARTTLS_OID:
                if self.tls_started:
                    # Already in TLS mode
                    msg = pureldap.LDAPExtendedResponse(
                        resultCode=ldaperrors.LDAPOperationsError.resultCode,
                        responseName=self.STARTTLS_OID,
                        errorMessage=b'TLS already established'
                    )
                    reply(msg)
                elif not self.ssl_context_factory:
                    # TLS not configured
                    msg = pureldap.LDAPExtendedResponse(
                        resultCode=ldaperrors.LDAPUnavailable.resultCode,
                        responseName=self.STARTTLS_OID,
                        errorMessage=b'STARTTLS not available'
                    )
                    reply(msg)
                else:
                    # Start TLS on the connection
                    msg = pureldap.LDAPExtendedResponse(
                        resultCode=ldaperrors.Success.resultCode,
                        responseName=self.STARTTLS_OID
                    )
                    reply(msg)
                    # Upgrade connection to TLS
                    self.transport.startTLS(self.ssl_context_factory)
                    self.tls_started = True
                    print("STARTTLS negotiation successful, connection upgraded to TLS")
                return None
            else:
                # Other extended operations - return success dummy response
                msg = pureldap.LDAPExtendedResponse(
                    resultCode=ldaperrors.Success.resultCode
                )
                reply(msg)
                return None
        
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


def create_ssl_context_factory(config):
    """
    Create an SSL context factory with support for mTLS and CA validation.
    
    Args:
        config: Configuration object with TLS settings
    
    Returns:
        CertificateOptions object for Twisted SSL
    """
    if not config.tls_certfile or not config.tls_keyfile:
        return None
    
    try:
        # Load server certificate and private key
        with open(config.tls_certfile, 'rb') as cert_file:
            cert_data = cert_file.read()
        with open(config.tls_keyfile, 'rb') as key_file:
            key_data = key_file.read()
        
        # Create certificate object
        certificate = PrivateCertificate.loadPEM(cert_data + key_data)
        
        # Configure SSL context
        extra_options = []
        
        # Disable SSL v2 and v3, use only TLS
        extra_options.append(SSL.OP_NO_SSLv2)
        extra_options.append(SSL.OP_NO_SSLv3)
        
        # Configure client certificate verification if mTLS is enabled
        if config.require_client_cert and config.tls_cafile:
            # Load CA certificate for client verification
            with open(config.tls_cafile, 'rb') as ca_file:
                ca_cert_data = ca_file.read()
            
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_data)
            
            # Create certificate options with client cert verification
            # Note: trustRoot alone enables client certificate verification in Twisted
            # requireCertificate is deprecated and mutually exclusive with trustRoot
            context_factory = CertificateOptions(
                privateKey=certificate.privateKey.original,
                certificate=certificate.original,
                trustRoot=twisted_ssl.trustRootFromCertificates([Certificate(ca_cert)]),
                extraCertChain=[],
            )
            print(f"mTLS enabled: client certificates will be verified against CA: {config.tls_cafile}")
        else:
            # Server-only TLS (no client cert verification)
            context_factory = CertificateOptions(
                privateKey=certificate.privateKey.original,
                certificate=certificate.original,
                extraCertChain=[],
            )
            if config.tls_cafile:
                print(f"Note: CA file specified but client cert verification not required (LDAP_PROXY_REQUIRE_CLIENT_CERT=false)")
        
        return context_factory
    
    except Exception as e:
        print(f"Error creating SSL context: {e}")
        raise
    
if __name__ == '__main__':
    """
    Demonstration LDAP OIDC proxy with TLS support.
    Supports LDAPS (implicit TLS), STARTTLS (explicit TLS), and mTLS.
    """

    config = Configuration()

    log.startLogging(sys.stderr)
    
    # Create SSL context factory if TLS is configured
    ssl_context_factory = create_ssl_context_factory(config)
    
    factory = protocol.ServerFactory()
    proxiedEndpointStr = 'NoEndpointneeded'
    use_tls = False
    clientConnector = partial(
        connectToLDAPEndpoint,
        reactor,
        proxiedEndpointStr,
        LDAPClient)

    def buildProtocol():
        proto = OidcProxy(config, ssl_context_factory)
        proto.clientConnector = clientConnector
        proto.use_tls = use_tls
        return proto

    factory.protocol = buildProtocol

    # Configure listeners based on TLS settings
    listeners_started = []
    
    # Start plain LDAP listener
    if config.enable_plain or not ssl_context_factory:
        try:
            reactor.listenTCP(config.plain_port, factory)
            listeners_started.append(f'Plain LDAP on port {config.plain_port}')
            print(f'Plain LDAP listening on port {config.plain_port}')
        except Exception as e:
            print(f'Warning: Failed to start plain LDAP listener: {e}')

    if config.tls_certfile and config.tls_keyfile and ssl_context_factory:
        # Start LDAPS listener (implicit TLS on port 636)
        try:
            reactor.listenSSL(config.tls_port, factory, ssl_context_factory)
            listeners_started.append(f'LDAPS on port {config.tls_port}')
            print(f'LDAPS listening on port {config.tls_port}')
        except Exception as e:
            print(f'Failed to start LDAPS: {e}')
            print(f'Exiting. Please check your TLS certificate and key file paths and port {config.tls_port} availability.')
            sys.exit(1)
    
    if not listeners_started:
        print('Error: No listeners could be started. Exiting.')
        sys.exit(1)
    
    print(f'LDAP proxy started with listeners: {", ".join(listeners_started)}')
    reactor.run()