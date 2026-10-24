"""
Unit and Integration Test Suite for ScamShield AI URL Scanner
Tests SSRF Defenses, URL Normalization, Heuristic Checks, Redirects, History Integration, and Error Handling.
"""

import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from main import app
from url_scanner_service import (
    normalize_and_validate_url,
    resolve_and_validate_hostname,
    is_ip_address_prohibited,
    extract_registered_domain,
    analyze_url_structure,
    probe_url_and_follow_redirects,
    scan_url,
    SsrfBlockError
)


class TestUrlScannerService(unittest.TestCase):
    """Low-level unit tests for url_scanner_service module."""

    def test_normalize_valid_urls(self):
        norm, comps = normalize_and_validate_url("https://example.com/path?a=1")
        self.assertEqual(norm, "https://example.com/path?a=1")
        self.assertEqual(comps["scheme"], "https")
        self.assertEqual(comps["host"], "example.com")

        # Auto-prepending https:// when no scheme is given
        norm2, comps2 = normalize_and_validate_url("example.org")
        self.assertEqual(norm2, "https://example.org/")
        self.assertEqual(comps2["scheme"], "https")

    def test_unsupported_schemes_rejected(self):
        for bad_url in [
            "ftp://ftp.example.com",
            "file:///etc/passwd",
            "javascript:alert(document.cookie)",
            "data:text/html,<html>malicious</html>",
            "gopher://evil.com"
        ]:
            with self.assertRaises(ValueError) as ctx:
                normalize_and_validate_url(bad_url)
            self.assertIn("Unsupported URL scheme", str(ctx.exception))

    def test_empty_and_control_chars_rejected(self):
        with self.assertRaises(ValueError):
            normalize_and_validate_url("")
        with self.assertRaises(ValueError):
            normalize_and_validate_url("   ")
        with self.assertRaises(ValueError):
            normalize_and_validate_url("https://example.com/\x00evil")

    def test_public_suffix_extraction(self):
        # Multi-part TLD
        sub, reg, tld = extract_registered_domain("banking.portal.secure.co.uk")
        self.assertEqual(sub, "banking.portal")
        self.assertEqual(reg, "secure.co.uk")
        self.assertEqual(tld, "co.uk")

        # Standard TLD
        sub2, reg2, tld2 = extract_registered_domain("login.paypal.com")
        self.assertEqual(sub2, "login")
        self.assertEqual(reg2, "paypal.com")
        self.assertEqual(tld2, "com")

        # Raw IP
        sub3, reg3, tld3 = extract_registered_domain("8.8.8.8")
        self.assertEqual(sub3, "")
        self.assertEqual(reg3, "8.8.8.8")

    def test_deceptive_userinfo_check(self):
        norm, comps = normalize_and_validate_url("https://google.com@phishing-server.com/login")
        self.assertTrue(comps["has_userinfo"])
        self.assertEqual(comps["userinfo"], "google.com")
        self.assertEqual(comps["host"], "phishing-server.com")

        res = analyze_url_structure("https://google.com@phishing-server.com/login", norm, comps)
        self.assertTrue(any(c["name"] == "Deceptive Userinfo (@) Check" and c["status"] == "fail" for c in res["checks"]))
        self.assertGreater(res["threat_points"], 20.0)

    def test_punycode_detection(self):
        norm, comps = normalize_and_validate_url("https://xn--pple-43d.com")
        self.assertTrue(comps["has_punycode"])

        res = analyze_url_structure("https://xn--pple-43d.com", norm, comps)
        self.assertTrue(any(c["name"] == "Punycode & Homoglyph Inspection" and c["status"] == "warning" for c in res["checks"]))

    def test_raw_ip_host_warning(self):
        norm, comps = normalize_and_validate_url("http://93.184.216.34/")
        res = analyze_url_structure("http://93.184.216.34/", norm, comps)
        self.assertTrue(res["domain_info"]["is_ip_host"])
        self.assertTrue(any(c["name"] == "Host Identity Format" and c["status"] == "warning" for c in res["checks"]))

    def test_brand_spoofing_detection(self):
        norm, comps = normalize_and_validate_url("http://paypal.security-update.attacker-domain.org/verify")
        res = analyze_url_structure("http://paypal.security-update.attacker-domain.org/verify", norm, comps)
        self.assertTrue(any(c["name"] == "Brand Impersonation & Typosquatting" and c["status"] == "warning" for c in res["checks"]))
        self.assertIn("paypal", "".join(res["findings"]).lower())

    def test_ssrf_prohibited_ips(self):
        # Loopback
        prohibited, reason = is_ip_address_prohibited("127.0.0.1")
        self.assertTrue(prohibited)
        self.assertIn("loopback", reason.lower())

        prohibited6, reason6 = is_ip_address_prohibited("::1")
        self.assertTrue(prohibited6)

        # Private RFC 1918
        self.assertTrue(is_ip_address_prohibited("10.0.0.5")[0])
        self.assertTrue(is_ip_address_prohibited("192.168.1.100")[0])
        self.assertTrue(is_ip_address_prohibited("172.16.50.1")[0])

        # Link-local & cloud metadata
        self.assertTrue(is_ip_address_prohibited("169.254.169.254")[0])
        self.assertTrue(is_ip_address_prohibited("100.100.100.200")[0])

        # Public IP (should NOT be prohibited)
        self.assertFalse(is_ip_address_prohibited("93.184.216.34")[0])
        self.assertFalse(is_ip_address_prohibited("8.8.8.8")[0])

    def test_ssrf_hostname_resolution_blocking(self):
        with self.assertRaises(SsrfBlockError):
            resolve_and_validate_hostname("localhost")

        with self.assertRaises(SsrfBlockError):
            resolve_and_validate_hostname("sub.localhost")

        with self.assertRaises(SsrfBlockError):
            resolve_and_validate_hostname("metadata.google.internal")

        with self.assertRaises(SsrfBlockError):
            resolve_and_validate_hostname("127.0.0.1")

        with self.assertRaises(SsrfBlockError):
            resolve_and_validate_hostname("169.254.169.254")

    @patch("url_scanner_service.resolve_and_validate_hostname")
    def test_redirect_to_private_ip_is_blocked(self, mock_dns):
        # Mock initial hop resolving to public IP, then subsequent redirect resolving to private IP
        mock_dns.side_effect = [
            ["93.184.216.34"],
            SsrfBlockError("Target IP is a private network address (RFC 1918).")
        ]

        # Test probe
        components = {
            "scheme": "http",
            "punycode_host": "public-redirector.com",
            "port": 80,
            "path": "/",
            "query": "",
            "fragment": ""
        }

        # Mock urllib to simulate HTTP 302 redirect
        with patch("urllib.request.build_opener") as mock_opener_builder:
            mock_opener = MagicMock()
            from urllib.error import HTTPError
            headers = MagicMock()
            headers.items.return_value = [("Location", "http://192.168.1.1/secret")]
            headers.__contains__.side_effect = lambda k: k == "Location"
            headers.__getitem__.side_effect = lambda k: "http://192.168.1.1/secret" if k == "Location" else None
            headers.get_content_type.return_value = "text/html"

            http_err = HTTPError("http://public-redirector.com", 302, "Found", headers, None)
            mock_opener.open.side_effect = http_err
            mock_opener_builder.return_value = mock_opener

            result = probe_url_and_follow_redirects("http://public-redirector.com", components)
            self.assertIn("SSRF Protection", result["error_note"])


class TestUrlScannerFastApiEndpoint(unittest.TestCase):
    """Integration tests for FastAPI endpoints, authentication, and history integration."""

    @classmethod
    def setUpClass(cls):
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client_context.__exit__(None, None, None)

    def test_01_static_urlscan_page_available(self):
        """Verify urlscan.html and clean /urlscan route return 200 OK."""
        res_file = self.client.get("/urlscan.html")
        self.assertEqual(res_file.status_code, 200)
        self.assertIn("URL & Website Scanner", res_file.text)

        res_clean = self.client.get("/urlscan")
        self.assertEqual(res_clean.status_code, 200)

    def test_02_url_scan_guest_request(self):
        """Verify unauthenticated guest URL scanning returns structured assessment."""
        # Use a safe public domain
        payload = {"url": "https://www.wikipedia.org"}
        res = self.client.post("/api/url-scan", json=payload)
        self.assertEqual(res.status_code, 200)

        data = res.json()
        self.assertEqual(data["url"], "https://www.wikipedia.org")
        self.assertIn("wikipedia.org", data["normalized_url"])
        self.assertIn(data["classification"], ["Low Risk", "Suspicious", "High Risk", "Unknown"])
        self.assertIsInstance(data["risk_score"], (int, float))
        self.assertGreaterEqual(len(data["checks"]), 4)
        self.assertIn("disclaimer", data)
        self.assertIsNone(data["scan_id"])  # Not persisted for guests

    def test_03_ssrf_blocking_via_api(self):
        """Verify API blocks localhost and private IPs with HTTP 400."""
        for target in ["http://localhost:8080/admin", "http://127.0.0.1/sensitive", "http://169.254.169.254/meta"]:
            res = self.client.post("/api/url-scan", json={"url": target})
            self.assertEqual(res.status_code, 400)
            self.assertIn("SSRF", res.json()["detail"])

    def test_04_invalid_url_schemes_via_api(self):
        """Verify API rejects unsupported schemes with HTTP 422."""
        for target in ["javascript:alert(1)", "file:///etc/hosts", "data:text/plain;hello"]:
            res = self.client.post("/api/url-scan", json={"url": target})
            self.assertEqual(res.status_code, 422)

    def test_05_authenticated_url_scan_history_and_isolation(self):
        """Verify authenticated URL scan is persisted, appears in history, and is isolated between users."""
        # 1. Register User Alpha
        email_alpha = "user_alpha_url@university.edu"
        self.client.post("/api/auth/register", json={
            "full_name": "Alpha Auditor",
            "email": email_alpha,
            "password": "Password123!",
            "confirm_password": "Password123!"
        })
        login_a = self.client.post("/api/auth/login", json={"email": email_alpha, "password": "Password123!"})
        token_a = login_a.json()["access_token"]
        headers_a = {"Authorization": f"Bearer {token_a}"}

        # 2. Register User Beta
        email_beta = "user_beta_url@university.edu"
        self.client.post("/api/auth/register", json={
            "full_name": "Beta Auditor",
            "email": email_beta,
            "password": "Password123!",
            "confirm_password": "Password123!"
        })
        login_b = self.client.post("/api/auth/login", json={"email": email_beta, "password": "Password123!"})
        token_b = login_b.json()["access_token"]
        headers_b = {"Authorization": f"Bearer {token_b}"}

        # 3. User Alpha performs URL scan
        target_url = "https://www.iana.org/domains/reserved"
        scan_res = self.client.post("/api/url-scan", json={"url": target_url}, headers=headers_a)
        self.assertEqual(scan_res.status_code, 200)
        scan_id = scan_res.json()["scan_id"]
        self.assertIsNotNone(scan_id)

        # 4. Check User Alpha history with record_type=url
        hist_a = self.client.get("/api/scans/history?record_type=url", headers=headers_a)
        self.assertEqual(hist_a.status_code, 200)
        items_a = hist_a.json()
        self.assertTrue(any(item["id"] == scan_id for item in items_a))
        self.assertTrue(any(item["record_type"] == "url" for item in items_a))

        # 5. Check User Alpha history with record_type=all
        hist_all_a = self.client.get("/api/scans/history?record_type=all", headers=headers_a)
        self.assertEqual(hist_all_a.status_code, 200)
        self.assertTrue(any(item["id"] == scan_id for item in hist_all_a.json()))

        # 6. Check User Beta history (DATA ISOLATION: Beta MUST NOT see Alpha's scan!)
        hist_b = self.client.get("/api/scans/history?record_type=url", headers=headers_b)
        self.assertEqual(hist_b.status_code, 200)
        self.assertFalse(any(item["id"] == scan_id for item in hist_b.json()))

        # 7. Check User Alpha stats includes URL scan
        stats_a = self.client.get("/api/scans/stats", headers=headers_a)
        self.assertEqual(stats_a.status_code, 200)
        self.assertGreaterEqual(stats_a.json()["total_scans"], 1)

        # 8. User Alpha deletes scan record
        del_res = self.client.delete(f"/api/scans/{scan_id}?record_type=url", headers=headers_a)
        self.assertEqual(del_res.status_code, 200)

        # Verify deleted
        hist_a_after = self.client.get("/api/scans/history?record_type=url", headers=headers_a)
        self.assertFalse(any(item["id"] == scan_id for item in hist_a_after.json()))


if __name__ == "__main__":
    unittest.main()
