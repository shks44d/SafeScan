"""API and target-safety tests. No test connects to an external host."""

import socket
import unittest
from unittest.mock import patch

import app as application
from utils.netguard import normalize_target, public_ip


def dns_answer(address: str) -> tuple:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 0, 0, 0) if family == socket.AF_INET6 else (address, 0)
    return family, socket.SOCK_STREAM, 6, "", sockaddr


class TargetValidationTests(unittest.TestCase):
    def test_valid_targets_are_normalized(self):
        cases = {
            "Example.COM": "example.com",
            "https://Example.COM/path?q=1": "example.com",
            "8.8.8.8": "8.8.8.8",
            "https://[2001:4860:4860::8888]/dns": "2001:4860:4860::8888",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(normalize_target(value), expected)

    def test_invalid_targets_are_rejected(self):
        invalid = (
            "",
            "bad host",
            "ftp://example.com",
            "https://user:pass@example.com",
            "999.999.999.999",
            "-bad.example",
            "http://example.com:70000",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_target(value)

    def test_public_ip_guard(self):
        blocked = (
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "169.254.169.254",
            "::1",
            "100.64.0.1",
            "fc00::1",
            "::ffff:127.0.0.1",
        )
        for address in blocked:
            with self.subTest(address=address), self.assertRaises(ValueError):
                public_ip(address)
        self.assertEqual(str(public_ip("8.8.8.8")), "8.8.8.8")

    def test_resolve_rejects_any_private_dns_answer(self):
        answers = [dns_answer("8.8.8.8"), dns_answer("10.0.0.5")]
        with patch("utils.netguard.socket.getaddrinfo", return_value=answers):
            response = application.app.test_client().post(
                "/api/resolve", json={"target": "mixed.example"}
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("public", response.json["error"])


class ApiTests(unittest.TestCase):
    def setUp(self):
        application.app.testing = True
        application._rate_events.clear()
        application._port_events.clear()
        self.client = application.app.test_client()

    def test_health_and_page(self):
        self.assertEqual(self.client.get("/health").json, {"status": "ok"})
        page = self.client.get("/")
        favicon = self.client.get("/favicon.ico")
        self.assertIn(b"Scan public TCP ports", page.data)
        self.assertIn(b"All ports (1\xe2\x80\x9365,535)", page.data)
        self.assertEqual(favicon.status_code, 200)
        self.assertEqual(favicon.mimetype, "image/png")
        favicon.close()

    def test_json_only_enforcement(self):
        response = self.client.post("/api/resolve", data="target=example.com")
        self.assertEqual(response.status_code, 400)
        self.assertIn("application/json", response.json["error"])

    def test_version_and_invalid_types(self):
        self.assertEqual(self.client.get("/").headers["X-SafeScan-Version"], "2.0.0")
        for target in (None, 123, [], {}):
            self.assertEqual(
                self.client.post("/api/resolve", json={"target": target}).status_code, 400
            )
        with patch("app.scan_ports") as scan:
            for start in (True, 1.5, "1", None):
                response = self.client.post(
                    "/api/scan",
                    json={
                        "ip": "127.0.0.1",
                        "host": "localhost",
                        "start": start,
                        "end": 10,
                        "authorized": True,
                    },
                )
                self.assertEqual(response.status_code, 400)
            scan.assert_not_called()

    def test_resolve_returns_one_pinned_ip_and_all_answers(self):
        answers = [dns_answer("8.8.8.8"), dns_answer("1.1.1.1")]
        with patch("utils.netguard.socket.getaddrinfo", return_value=answers):
            response = self.client.post("/api/resolve", json={"target": "https://EXAMPLE.com/path"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json, {"host": "example.com", "ip": "8.8.8.8", "ips": ["8.8.8.8", "1.1.1.1"]}
        )

    def test_scan_chunk_validation(self):
        invalid = ((0, 10), (1, 65536), (100, 50), (1, 2001))
        with patch("app.scan_ports") as scan:
            for start, end in invalid:
                with self.subTest(start=start, end=end):
                    response = self.client.post(
                        "/api/scan",
                        json={
                            "ip": "127.0.0.1",
                            "host": "localhost",
                            "start": start,
                            "end": end,
                            "authorized": True,
                        },
                    )
                    self.assertEqual(response.status_code, 400)
            scan.assert_not_called()

    def test_scan_requires_authorization_and_rechecks_public_ip(self):
        response = self.client.post(
            "/api/scan",
            json={
                "ip": "8.8.8.8",
                "host": "example.com",
                "start": 80,
                "end": 80,
                "authorized": False,
            },
        )
        self.assertEqual(response.status_code, 400)
        application.app.testing = False
        try:
            response = self.client.post(
                "/api/scan",
                json={
                    "ip": "127.0.0.1",
                    "host": "example.com",
                    "start": 80,
                    "end": 80,
                    "authorized": True,
                },
            )
        finally:
            application.app.testing = True
        self.assertEqual(response.status_code, 400)

    def test_rate_limit_returns_429(self):
        with patch.object(application, "RATE_LIMIT_REQUESTS", 2), patch(
            "app.resolve_public_target", return_value=("8.8.8.8", ["8.8.8.8"])
        ):
            self.assertEqual(
                self.client.post("/api/resolve", json={"target": "one.example"}).status_code, 200
            )
            self.assertEqual(
                self.client.post("/api/resolve", json={"target": "two.example"}).status_code, 200
            )
            response = self.client.post("/api/resolve", json={"target": "three.example"})
        self.assertEqual(response.status_code, 429)
        self.assertIn("Too many", response.json["error"])

    def test_busy_response_is_retryable(self):
        with patch("app.scan_ports", side_effect=application.ScanCapacityError):
            response = self.client.post(
                "/api/scan",
                json={
                    "ip": "127.0.0.1",
                    "host": "localhost",
                    "start": 1,
                    "end": 250,
                    "authorized": True,
                },
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers["Retry-After"], "2")
        self.assertEqual(len(application._port_events), 0)

    def test_port_budget_allows_full_scan_and_blocks_excess_work(self):
        with patch("scanner.port_scanner.scan_port", return_value=None), patch.object(
            application, "RATE_LIMIT_PORTS", 65_535
        ):
            for start in range(1, 65_536, 250):
                response = self.client.post(
                    "/api/scan",
                    json={
                        "ip": "127.0.0.1",
                        "host": "localhost",
                        "start": start,
                        "end": min(start + 249, 65_535),
                        "authorized": True,
                    },
                )
                self.assertEqual(response.status_code, 200)
            response = self.client.post(
                "/api/scan",
                json={
                    "ip": "127.0.0.1",
                    "host": "localhost",
                    "start": 1,
                    "end": 2000,
                    "authorized": True,
                },
            )
            self.assertEqual(response.status_code, 429)

    def test_port_budget_expires_and_counts_larger_requests(self):
        with patch.object(application, "RATE_LIMIT_PORTS", 2000), patch(
            "app.time.monotonic", return_value=100
        ):
            self.assertTrue(application.within_port_budget("client", 2000))
            self.assertFalse(application.within_port_budget("client", 1))
        with patch("app.time.monotonic", return_value=161):
            self.assertTrue(application.within_port_budget("client", 1))


if __name__ == "__main__":
    unittest.main()
