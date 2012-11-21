import socket
import re
import os.path
import logging

# http://packages.python.org/pyOpenSSL
from OpenSSL import SSL

"""
This module allows flexible SSL connections, direct and over HTTP proxy.
"""

HTTP_GET_FMT = 'GET {0} HTTP/1.1\r\nHost: {1}\r\nConnection: close\r\nAccept-Charset: UTF-8,*;q=0.5\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (Windows NT 5.1)\r\n\r\n'
HTTP_CONNECT_FMT = 'CONNECT {0}:{1} HTTP/1.0\r\nConnection: close\r\n\r\n'

class ProxyNotSet(Exception):
        """ proxy host and port not set """

class HTTPS:
        def __verify_none(self, conn, cert, errun, depth, status):
                """ This always returns OK status of validation. Used to fetch contents of invalid certificates. """
                self.__cert_status = status
                logging.debug('HTTPS validation errun={0} depth={1} status={2} name={3}'.format(errun, depth, status, cert.get_subject().commonName))
                return True

        def __verify_builtin(self, conn, cert, errun, depth, status):
                """ This returns validation status as passed from OpenSSL built-in validation. """
                # by default cert_status is True
                # if any cert in the path doesn't verify, it's reset to False
                logging.debug('HTTPS validation errun={0} depth={1} status={2} name={3}'.format(errun, depth, status, cert.get_subject().commonName))
                if status == 0:
                        self.__cert_status = False
                        self.__http_status = 'SSL validation failed'
                return True

        def __init__(self, proxy_host = None, proxy_port = None):
                """
                Optional parameters are proxy host and port. If set the HTTPS
                connection will be made over specified proxy. Examples:

                    h = HTTPS('proxy', 3128)    # over proxy
                    h = HTTPS()                 # direct

                    h.set_target('mail.google.com') # set target server

                    ok = h.init()                   # establish SSL connection

                    if ok:                          # SSL connection completed
                        print(h.get_header('Server')) # print HTTP header
                    else:
                        print(h.get_status)          # conn failed, get error
                """
                # Proxy related
                self.__proxy_host = proxy_host
                self.__proxy_port = proxy_port
                # Target related
                self.__server = None
                self.__port = None
                self.__path = None
                self.__ok = True
                self.__http_re = re.compile(r"^HTTP/1\.[01]\s([0-9]{3}\s.+)$")
                # init resetable values
                self.__reset()

        def __reset(self):
                self.__ok = True
                # SSL related
                self.__ctx = SSL.Context(SSL.SSLv23_METHOD)
                self.set_verify(False, None)
                self.__ssl = None
                self.__cert = None
                self.__cert_status = True
                # HTTP related
                self.__http_status = None
                self.__http_headers = None

        def set_verify(self, flag, ca_file):
                """
                Determines server's SSL certificate validation strategy.
                If False (default) no validation will be performed.
                """
                ctx = self.__ctx
                if flag:        # True
                        ctx.set_verify(SSL.VERIFY_PEER, self.__verify_builtin)
                        ctx.load_verify_locations(ca_file)
                else:           # False
                        ctx.set_verify(SSL.VERIFY_PEER, self.__verify_none)

        def set_target(self, host, port=443, path="/"):
                """
                Set new target for SSL connection. Will reset previous connection, if any.
                One mandatory parameter is target hostname. Optional port and
                path parameters are by default set to 443 and /.

                        h.set_target('mail.google.com')
                        h.set_target('mail.google.com', 443, "/")
                """
                self.__server = host
                self.__port = port
                self.__path = path
                if self.__ssl != None:
                        try:
                                self.__ssl.shutdown()
                                self.__ssl.close()
                        except:
                                pass
                self.__reset()
                logging.debug('HTTPS target {0}:{1}{2}'.format(host, port, path))

        def __http_parse(self, data):
                headers = []
                r = self.__http_re
                for line in data.splitlines():
                        if len(line) == 0:
                                # we reached the body
                                # XXX parse the body XXX
                                break
                        line = line.decode('utf-8')
                        m = r.match(str(line))
                        if m:           # search for HTTP/1.x
                                self.__http_status = m.group(1)
                        else:
                                headers.append(line.split(': ', 1))
                self.__http_headers = headers

        def __fetch_cert(self):
                if self.__ssl == None:
                        self.__connect()
                ss = self.__ssl
                self.__cert = ss.get_peer_certificate()

        def get_cert(self):
                """
                Return SSL certificate of the target server. The certificate is
                returned as dictionary with the following fields:

                    'expired'   is the cert expired? True or False
                    'valid'     did the cert pass SSL path validation? True or False
                    'subject'   X.500 subject string (e.g. 'C=US/CN=mail.google.com')
                    'name'      Common Name part of subject (e.g. 'mail.google.com')
                """
                if self.__cert == None:
                        self.__fetch_cert()
                cert = self.__cert
                ret = dict()
#               only works on unpublished pyOpenSSL
#               ext = dict()
#               for i in range(0, cert.get_extension_count()):
#                       e = cert.get_extension(i)
#                       ext[e.get_short_name()] = e.get_data()
#               ret['extensions'] = ext
                ret['expired'] = bool(cert.has_expired())
                ret['valid'] = bool(self.__cert_status)
                subject = cert.get_subject()
                ret['subject'] = str(subject)
                ret['name'] = subject.commonName
                return ret

        def init(self):
                """
                Establish SSL connection with the target. Returns True if
                connection was established, False if not.
                """
                assert(self.__server)
                assert(self.__port)
                assert(self.__path)

                if self.__http_status == None:
                        self.__connect()
                return self.__ok

        def __fetch_headers(self):
                if self.__ssl == None:
                        self.__connect()
                if not self.__ok:
                        return
                ss = self.__ssl
                req = HTTP_GET_FMT.format(self.__path, self.__server)
                ss.sendall(bytes(req, 'utf-8'))
                response = b''
                while True:
                        try:
                                data = ss.recv(1024)
                        except (SSL.ZeroReturnError, SSL.SysCallError):
                                break
                        if not data:
                                break
                        response += data
                self.__http_status = 'HTTP received {0} bytes'.format(len(response))
                self.__http_parse(response)

        def get_headers(self):
                """
                Return array of HTTP headers.
                """
                if not self.__http_headers:
                        self.__fetch_headers()
                return self.__http_headers

        def get_status(self):
                """
                Retrieve current connection status. Before SSL is established this can
                contain SSL errors. After SSL is established it contains HTTP errors
                or status codes.

                        >>> h.get_status()
                        200 OK
                """
                return self.__http_status

        def get_header(self, name):
                """
                Return single named HTTP header (case insensitive).

                        h.get_header('Server')
                """
                if not self.__http_headers:
                        self.__fetch_headers()
                for h in self.__http_headers:
                        if name.lower() == h[0].lower():
                                return h
                return None

        def __connect(self):
                if (self.__proxy_host or self.__proxy_port) and not (self.__proxy_host and self.__proxy_port):
                        raise ProxyNotSet
                if (self.__proxy_host and self.__proxy_port):
                        self.__connect_proxy()
                else:
                        self.__connect_direct()

        def __connect_proxy(self):
                logging.debug('Starting SSL connection through proxy')
                assert(self.__proxy_host and self.__proxy_port)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                        s.connect((self.__proxy_host, self.__proxy_port))
                except (socket.timeout, socket.error) as detail:
                        self.__ok = False
                        self.__http_status = detail
                        return
                self.__http_status = 'HTTP proxy connected'
                connect_str = HTTP_CONNECT_FMT.format(self.__server, self.__port)
                s.sendall(bytes(connect_str, 'utf-8'))
                s.recv(4096) # clean the socket                 
                ss = SSL.Connection(self.__ctx, s)
                ss.setblocking(True)
                ss.set_connect_state()
                try:
                        ss.do_handshake()
                except (SSL.SysCallError, SSL.Error) as detail:
                        self.__http_status = detail
                        self.__ok = False
                        return
                self.__http_status = 'SSL connected through HTTP proxy'
                self.__ssl = ss

        def __connect_direct(self):
                logging.debug('Starting direct SSL connection')
                ss = SSL.Connection(self.__ctx, socket.socket(socket.AF_INET))
                ss.setblocking(True)
                try:
                        ss.connect((self.__server, self.__port))
                except (socket.timeout, socket.error) as detail:
                        self.__http_status = detail
                        self.__ok = False
                        return
                self.__http_status = 'TCP port connected'
                try:
                        ss.do_handshake()
                except (SSL.SysCallError, SSL.Error) as detail:
                        self.__http_status = detail
                        self.__ok = False
                        return
                self.__http_status = 'SSL connected'
                self.__ssl = ss

PROXY_HOST = 'proxycachef.hewitt.com'
PROXY_PORT = 3128

import unittest

class TestCase(unittest.TestCase):
        
        def setUp(self):
                self.need_proxy = False
                s = socket.socket(socket.AF_INET)
                try:
                        s.connect(('www.google.com', 80))
                except socket.error:
                        self.need_proxy = True  
                if self.need_proxy:
                        self.h = HTTPS(PROXY_HOST, PROXY_PORT)
                else:
                        self.h = HTTPS()
                        
        def test_connect(self):
                self.h.set_target('mail.google.com', 443)
                self.assertEqual(self.h.init(), True, 'connection error')
                
        def test_http_parse(self):
                self.h.set_target('mail.google.com', 443)
                server = self.h.get_header('Server')
                self.assertIsNotNone(server)
                
        def test_verify_valid(self):
                self.h.set_target('mail.google.com', 443)
                self.h.set_verify(True, os.path.join(os.path.dirname(__file__), '..', 'work_dir', 'cache', 'cacert.pem'))
                ok = self.h.init()
                self.assertTrue(ok)
                if ok:
                        cert = self.h.get_cert()
                        self.assertEqual(cert['valid'], True, 'mail.google.com should validate by default')
                        self.assertEqual(cert['name'], 'mail.google.com')
                        
        def test_verify_invalid(self):
                self.h.set_target('cacert.org', 443)
                self.h.set_verify(True, os.path.join(os.path.dirname(__file__), '..', 'work_dir', 'cache', 'cacert.pem'))
                ok = self.h.init()
                self.assertTrue(ok)
                if ok:
                        cert = self.h.get_cert()
                        self.assertEqual(cert['valid'], False, 'cacert.org should NOT validate by default')
                        self.assertEqual(cert['name'], 'www.cacert.org')
