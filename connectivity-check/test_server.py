import http.client
import json
import ssl
import threading
import unittest
from unittest.mock import Mock, patch

import server as app


class ProbeTests(unittest.TestCase):
    def test_direct_ip_http_avoids_dns_and_keeps_host_header(self):
        for target, ip, host_header in [("ru_ip", "77.88.55.88", "yandex.ru")]:
            with self.subTest(target=target):
                connection = Mock()
                connection.getresponse.return_value.status = 301
                connection.getresponse.return_value.reason = "Moved Permanently"
                raw_socket = Mock()
                raw_socket.getpeername.return_value = (ip, 80)
                with patch.object(app.http.client, "HTTPConnection", return_value=connection), \
                        patch.object(app.socket, "socket", return_value=raw_socket), \
                        patch.object(app.socket, "getaddrinfo", side_effect=AssertionError("Unexpected DNS lookup")):
                    result = app.probe(target)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["peer"], ip)
                raw_socket.connect.assert_called_once_with((ip, 80))
                connection.connect.assert_not_called()
                connection.request.assert_called_once_with("HEAD", "/", headers={
                    "User-Agent": "LocalConnectivityCheck/1.0", "Host": host_header
                })
                self.assertIn("без DNS", result["detail"])
                connection.close.assert_called_once()

    def test_google_ip_uses_tls_sni_without_dns(self):
        connection = Mock()
        connection.getresponse.return_value.status = 301
        connection.getresponse.return_value.reason = "Moved Permanently"
        raw_socket, tls_socket, context = Mock(), Mock(), Mock()
        tls_socket.getpeername.return_value = ("142.251.13.113", 443)
        context.wrap_socket.return_value = tls_socket
        with patch.object(app.http.client, "HTTPSConnection", return_value=connection), \
                patch.object(app.socket, "socket", return_value=raw_socket), \
                patch.object(app.ssl, "create_default_context", return_value=context), \
                patch.object(app.socket, "getaddrinfo", side_effect=AssertionError("Unexpected DNS lookup")):
            result = app.probe("foreign_ip")
        self.assertEqual(result["status"], "ok")
        raw_socket.connect.assert_called_once_with(("142.251.13.113", 443))
        context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="google.com")
        connection.connect.assert_not_called()
        connection.request.assert_called_once_with("HEAD", "/", headers={
            "User-Agent": "LocalConnectivityCheck/1.0", "Host": "google.com"
        })
        self.assertIn("HTTPS по IP · без DNS", result["detail"])

    def test_postgres_handshake_without_login(self):
        for response, expected in [(b"S", "ok"), (b"N", "ok"), (b"X", "warning"), (b"", "warning")]:
            with self.subTest(response=response):
                connection = Mock()
                connection.__enter__ = Mock(return_value=connection)
                connection.__exit__ = Mock(return_value=False)
                connection.getpeername.return_value = ("10.10.13.98", 5432)
                connection.recv.return_value = response
                with patch.object(app.socket, "create_connection", return_value=connection):
                    result = app.probe("postgres")
                self.assertEqual(result["status"], expected)
                self.assertTrue(result["reachable"])
                # PostgreSQL SSLRequest: length 8, request code 80877103.
                connection.sendall.assert_called_once_with(bytes.fromhex("0000000804d2162f"))

    def test_closed_port_and_timeout_are_not_success(self):
        for error in [ConnectionRefusedError(), TimeoutError(), app.socket.gaierror()]:
            with self.subTest(error=error), patch.object(app.socket, "create_connection", side_effect=error):
                result = app.probe("postgres")
                self.assertEqual(result["status"], "error")
                self.assertFalse(result["reachable"])

    def test_http_error_still_confirms_site_response(self):
        for code, expected in [(200, "ok"), (301, "ok"), (403, "error"), (503, "warning")]:
            with self.subTest(code=code):
                connection = Mock()
                connection.sock.getpeername.return_value = ("192.0.2.1", 443)
                connection.getresponse.return_value.status = code
                connection.getresponse.return_value.reason = "Test"
                with patch.object(app.http.client, "HTTPSConnection", return_value=connection):
                    result = app.probe("google")
                self.assertEqual(result["status"], expected)
                self.assertTrue(result["reachable"])
                self.assertEqual(result["http_status"], code)
                connection.close.assert_called_once()

    def test_postgres_two_second_budget_includes_connect_and_response(self):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        connection.getpeername.return_value = ("10.10.13.98", 5432)
        connection.recv.side_effect = TimeoutError()
        with patch.object(app.socket, "create_connection", return_value=connection) as connect, \
                patch.object(app.time, "monotonic", side_effect=[0, 0.5, 0.6, 2]):
            result = app.probe("postgres")
        connect.assert_called_once_with(("10.10.13.98", 5432), timeout=2)
        self.assertEqual(connection.settimeout.call_args_list[0].args, (1.5,))
        self.assertEqual(connection.settimeout.call_args_list[1].args, (1.4,))
        self.assertEqual(result["status"], "error")
        self.assertIn("2 с", result["detail"])

    def test_invalid_tls_certificate_is_rejected(self):
        connection = Mock()
        connection.connect.side_effect = ssl.SSLCertVerificationError("bad cert")
        with patch.object(app.http.client, "HTTPSConnection", return_value=connection):
            result = app.probe("yandex")
        self.assertEqual(result["status"], "error")
        self.assertIn("TLS", result["message"])
        connection.close.assert_called_once()

    def test_openai_unauthenticated_response_confirms_reachability(self):
        connection = Mock()
        connection.sock.getpeername.return_value = ("192.0.2.2", 443)
        connection.getresponse.return_value.status = 401
        connection.getresponse.return_value.reason = "Unauthorized"
        with patch.object(app.http.client, "HTTPSConnection", return_value=connection):
            result = app.probe("openai")
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["reachable"])
        self.assertEqual(result["http_status"], 401)
        connection.request.assert_called_once_with("GET", "/v1/models", headers={"User-Agent": "LocalConnectivityCheck/1.0"})
        self.assertIn("без API-ключа", result["detail"])

    def test_claude_unauthenticated_response_confirms_reachability(self):
        connection = Mock()
        connection.sock.getpeername.return_value = ("192.0.2.3", 443)
        connection.getresponse.return_value.status = 401
        connection.getresponse.return_value.reason = "Unauthorized"
        with patch.object(app.http.client, "HTTPSConnection", return_value=connection):
            result = app.probe("claude")
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["reachable"])
        connection.request.assert_called_once_with("GET", "/v1/models", headers={
            "User-Agent": "LocalConnectivityCheck/1.0", "anthropic-version": "2023-06-01"
        })


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        try:
            connection.request("GET", path, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_serves_dashboard(self):
        status, headers, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b"10.10.13.98:5432", body)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_file_origin_can_read_fixed_target(self):
        with patch.object(app, "probe", return_value={"target": "postgres", "status": "ok"}) as probe:
            status, headers, body = self.request("/api/check?target=postgres", {"Origin": "null"})
        self.assertEqual(status, 200)
        self.assertEqual(headers["Access-Control-Allow-Origin"], "null")
        self.assertEqual(json.loads(body)["status"], "ok")
        probe.assert_called_once_with("postgres")

    def test_arbitrary_targets_and_remote_origins_are_rejected(self):
        with patch.object(app, "probe") as probe:
            for path, headers, expected in [
                ("/api/check?target=http://example.com", {}, 400),
                ("/api/check?target=google&target=postgres", {}, 400),
                ("/api/check?target=google", {"Origin": "https://example.com"}, 403),
                ("/api/check?target=google", {"Host": "example.com"}, 403),
            ]:
                with self.subTest(path=path, headers=headers):
                    self.assertEqual(self.request(path, headers)[0], expected)
            probe.assert_not_called()

    def test_explicit_shared_host_is_allowed(self):
        with patch.object(self.server, "allowed_hosts", {"127.0.0.1", "check.example.com"}, create=True), \
                patch.object(app, "probe", return_value={"target": "google", "status": "ok"}):
            status, headers, body = self.request("/api/check?target=google", {
                "Host": "check.example.com", "Origin": "https://check.example.com"
            })
            self.assertEqual(status, 200)
            self.assertEqual(headers["Access-Control-Allow-Origin"], "https://check.example.com")
            self.assertEqual(json.loads(body)["status"], "ok")
            self.assertEqual(self.request("/", {"Host": "other.example.com"})[0], 403)
            self.assertEqual(self.request("/", {"Host": "check.example.com", "Origin": "https://other.example.com"})[0], 403)


if __name__ == "__main__":
    unittest.main()
