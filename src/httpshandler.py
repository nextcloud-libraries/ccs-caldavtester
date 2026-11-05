##
# Copyright (c) 2010-2016 Apple Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##

import http.client
import socket
import ssl as sslmodule


def _sslContext(cert_file=None):
    """
    Create an SSL context suitable for a test client: negotiate the best TLS
    version available and do not verify the server certificate (test servers
    typically use self-signed certificates).

    @param cert_file: path to a client certificate (PEM, may include the key) or L{None}
    @type cert_file: L{str}
    """
    context = sslmodule.SSLContext(sslmodule.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = sslmodule.CERT_NONE
    if cert_file:
        context.load_cert_chain(cert_file)
    return context


class HTTPSVersionConnection(http.client.HTTPSConnection):
    """
    An L{http.client.HTTPSConnection} class that optionally uses a client certificate
    and does not verify the server certificate.
    """

    def __init__(self, host, port, cert_file=None):
        http.client.HTTPSConnection.__init__(self, host, port, context=_sslContext(cert_file))


class UnixSocketHTTPConnection(http.client.HTTPConnection):
    """
    An L{http.client.HTTPConnection} class that uses a unix socket rather than TCP.
    """

    def __init__(self, path, host, port):
        http.client.HTTPConnection.__init__(self, host, port)
        self.path = path

    def connect(self):
        """
        Connect using the supplied unix socket file path
        """
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path)


def SmartHTTPConnection(host, port, ssl, afunix, cert=None):
    """
    Create the appropriate L{http.client.HTTPConnection} derived class for the supplied arguments.

    @param host: TCP host name
    @type host: L{str}
    @param port: TCP port number
    @type port: L{int}
    @param ssl: indicates if SSL is to be used
    @type ssl: L{bool}
    @param afunix: unix socket to use or L{None}
    @type afunix: L{str}
    @param cert: SSL client cert path to use or L{None}
    @type cert: L{str}
    """

    if afunix:
        connect = UnixSocketHTTPConnection(afunix, host, port)
    elif ssl:
        connect = HTTPSVersionConnection(host, port, cert_file=cert)
    else:
        connect = http.client.HTTPConnection(host, port)
    connect.connect()
    return connect
