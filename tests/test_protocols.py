from __future__ import annotations

import socket
import struct
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ccdc_scorer.checkers.directory import check_ldap
from ccdc_scorer.checkers.dns import check_dns
from ccdc_scorer.checkers.http import check_http
from ccdc_scorer.checkers.mail import check_imap, check_pop3, check_smtp
from ccdc_scorer.checkers.remote import check_rdp, check_smb, check_tcp
from ccdc_scorer.checkers.transfer import check_ftp, check_ssh
from ccdc_scorer.models import ServiceConfig

from .helpers import OneShotTCPServer


def service(service_type, port, **options):
    return ServiceConfig("svc", "Blue", service_type, "127.0.0.1", port, timeout=2, options=options)


class HttpHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        body = b"<h1>EKU service ready</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ProtocolTests(unittest.TestCase):
    def test_http_checks_status_and_content(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), HttpHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            outcome = check_http(service("HTTP", server.server_port, expected_content="EKU service", fingerprint_mode="full"))
            self.assertTrue(outcome.passed, outcome.message)
            self.assertEqual(outcome.details["status"], 200)
            self.assertTrue(outcome.fingerprint.startswith("http:status=200"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_http_fails_missing_expected_content(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), HttpHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            outcome = check_http(service("HTTP", server.server_port, expected_content="not present"))
            self.assertFalse(outcome.passed)
        finally:
            server.shutdown()
            server.server_close()

    def test_dns_a_query(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        error = []

        def responder():
            try:
                request, address = server.recvfrom(4096)
                transaction_id = request[:2]
                question = request[12:]
                answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("10.20.30.40")
                response = transaction_id + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + answer
                server.sendto(response, address)
            except Exception as exc:
                error.append(exc)
            finally:
                server.close()

        thread = threading.Thread(target=responder, daemon=True)
        thread.start()
        outcome = check_dns(service("DNS", port, query_name="service.test", expected_answers=["10.20.30.40"]))
        thread.join(timeout=2)
        if error:
            raise error[0]
        self.assertTrue(outcome.passed, outcome.message)
        self.assertEqual(outcome.details["answers"], ["A:10.20.30.40"])

    def test_ssh_banner_handshake(self):
        with OneShotTCPServer(lambda connection: connection.sendall(b"SSH-2.0-OpenSSH_9.8\r\n")) as server:
            outcome = check_ssh(service("SSH", server.port))
        self.assertTrue(outcome.passed, outcome.message)
        self.assertEqual(outcome.details["banner"], "SSH-2.0-OpenSSH_9.8")

    def test_ftp_control_channel(self):
        def receive_line(connection):
            data = b""
            while not data.endswith(b"\n"):
                data += connection.recv(1)
            return data

        def handler(connection):
            connection.sendall(b"220 Test FTP ready\r\n")
            self.assertEqual(receive_line(connection), b"FEAT\r\n")
            connection.sendall(b"211-Features\r\n UTF8\r\n AUTH TLS\r\n211 End\r\n")
            self.assertEqual(receive_line(connection), b"NOOP\r\n")
            connection.sendall(b"200 OK\r\n")
            self.assertEqual(receive_line(connection), b"QUIT\r\n")
            connection.sendall(b"221 Bye\r\n")

        with OneShotTCPServer(handler) as server:
            outcome = check_ftp(service("FTP", server.port))
        self.assertTrue(outcome.passed, outcome.message)
        self.assertEqual(outcome.details["features"], ["AUTH TLS", "UTF8"])

    def test_smtp_noop(self):
        def receive_line(connection):
            data = b""
            while not data.endswith(b"\n"):
                data += connection.recv(1)
            return data

        def handler(connection):
            connection.sendall(b"220 mail.test ESMTP\r\n")
            command = receive_line(connection)
            self.assertTrue(command.upper().startswith(b"EHLO"))
            connection.sendall(b"250-mail.test\r\n250 SIZE 1000\r\n")
            self.assertEqual(receive_line(connection).upper(), b"NOOP\r\n")
            connection.sendall(b"250 OK\r\n")
            self.assertEqual(receive_line(connection).upper(), b"QUIT\r\n")
            connection.sendall(b"221 Bye\r\n")

        with OneShotTCPServer(handler) as server:
            outcome = check_smtp(service("SMTP", server.port))
        self.assertTrue(outcome.passed, outcome.message)
        self.assertEqual(outcome.details["features"], ["size"])

    def test_pop3_noop(self):
        def receive_line(connection):
            data = b""
            while not data.endswith(b"\n"):
                data += connection.recv(1)
            return data

        def handler(connection):
            connection.sendall(b"+OK POP3 ready\r\n")
            self.assertEqual(receive_line(connection).upper(), b"NOOP\r\n")
            connection.sendall(b"+OK\r\n")
            self.assertEqual(receive_line(connection).upper(), b"QUIT\r\n")
            connection.sendall(b"+OK bye\r\n")

        with OneShotTCPServer(handler) as server:
            outcome = check_pop3(service("POP3", server.port))
        self.assertTrue(outcome.passed, outcome.message)

    def test_imap_noop(self):
        def receive_line(connection):
            data = b""
            while not data.endswith(b"\n"):
                data += connection.recv(1)
            return data

        def handler(connection):
            connection.sendall(b"* OK IMAP ready\r\n")
            capability = receive_line(connection)
            tag = capability.split(None, 1)[0]
            self.assertIn(b"CAPABILITY", capability.upper())
            connection.sendall(b"* CAPABILITY IMAP4rev1\r\n" + tag + b" OK capabilities\r\n")
            noop = receive_line(connection)
            tag = noop.split(None, 1)[0]
            self.assertIn(b"NOOP", noop.upper())
            connection.sendall(tag + b" OK noop\r\n")
            logout = receive_line(connection)
            tag = logout.split(None, 1)[0]
            self.assertIn(b"LOGOUT", logout.upper())
            connection.sendall(b"* BYE closing\r\n" + tag + b" OK logout\r\n")

        with OneShotTCPServer(handler) as server:
            outcome = check_imap(service("IMAP", server.port))
        self.assertTrue(outcome.passed, outcome.message)

    def test_ldap_anonymous_bind(self):
        def handler(connection):
            connection.recv(4096)
            # LDAPMessage(sequence) -> message id 1 -> BindResponse(success, empty DN/diagnostic)
            response = bytes.fromhex("300c02010161070a010004000400")
            connection.sendall(response)

        with OneShotTCPServer(handler) as server:
            outcome = check_ldap(service("LDAP", server.port))
        self.assertTrue(outcome.passed, outcome.message)
        self.assertEqual(outcome.details["result_code"], 0)

    def test_rdp_negotiation(self):
        def handler(connection):
            request = connection.recv(64)
            self.assertEqual(request[:4], bytes.fromhex("03000013"))
            connection.sendall(bytes.fromhex("030000130ed000000000000200080001000000"))

        with OneShotTCPServer(handler) as server:
            outcome = check_rdp(service("RDP", server.port))
        self.assertTrue(outcome.passed, outcome.message)
        self.assertEqual(outcome.details["protocol"], "TLS")

    def test_smb2_negotiate(self):
        def handler(connection):
            request_header = connection.recv(4)
            request_size = int.from_bytes(request_header[1:4], "big")
            request = b""
            while len(request) < request_size:
                request += connection.recv(request_size - len(request))
            self.assertEqual(request[:4], b"\xfeSMB")
            header = bytearray(64)
            header[:4] = b"\xfeSMB"
            header[4:6] = struct.pack("<H", 64)
            header[12:14] = struct.pack("<H", 0)
            body = bytearray(65)
            body[:2] = struct.pack("<H", 65)
            body[4:6] = struct.pack("<H", 0x0302)
            payload = bytes(header + body)
            connection.sendall(b"\x00" + len(payload).to_bytes(3, "big") + payload)

        with OneShotTCPServer(handler) as server:
            outcome = check_smb(service("SMB", server.port))
        self.assertTrue(outcome.passed, outcome.message)
        self.assertEqual(outcome.details["dialect"], "3.0.2")

    def test_generic_tcp_content(self):
        def handler(connection):
            self.assertEqual(connection.recv(4), b"PING")
            connection.sendall(b"PONG ready\n")

        with OneShotTCPServer(handler) as server:
            outcome = check_tcp(service("TCP", server.port, send="PING", expected_content="PONG"))
        self.assertTrue(outcome.passed, outcome.message)


if __name__ == "__main__":
    unittest.main()
