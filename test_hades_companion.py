import tempfile
import unittest
from pathlib import Path

from hades_companion import create_app, normalize_origin


class CompanionApiTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.app = create_app({"TESTING": True, "TOKEN_PATH": str(root / "token"),
                               "DATABASE_PATH": str(root / "scans.db"),
                               "AUTH_DATABASE_PATH": str(root / "auth.db"),
                               "MODULE_DATA_ROOT": str(root)})
        self.client = self.app.test_client()
        self.headers = {"Authorization": f"Bearer {self.app.config['COMPANION_TOKEN']}"}

    def tearDown(self):
        self.tempdir.cleanup()

    def authorize(self):
        return self.client.post("/api/v1/authorizations", json={
            "target_url": "https://example.com/path", "authorized_by": "Test Owner",
            "acknowledged": True}, headers=self.headers)

    def test_normalize_origin(self):
        self.assertEqual(normalize_origin("HTTPS://Example.COM:443/a?q=1"), "https://example.com")
        self.assertEqual(normalize_origin("http://example.com:8080/a"), "http://example.com:8080")
        with self.assertRaises(ValueError):
            normalize_origin("file:///etc/passwd")

    def test_protected_endpoint_rejects_missing_token(self):
        self.assertEqual(self.client.get("/api/v1/authorizations").status_code, 401)

    def test_analysis_requires_authorization(self):
        response = self.client.post("/api/v1/analyze", json={"url": "https://example.com/"},
                                    headers=self.headers)
        self.assertEqual(response.status_code, 403)

    def test_authorized_analysis_and_report(self):
        self.assertEqual(self.authorize().status_code, 201)
        response = self.client.post("/api/v1/analyze", json={
            "url": "https://example.com/login", "title": "Login", "metaHeaders": {},
            "targetBlankWithoutNoopener": 2, "forms": []}, headers=self.headers)
        self.assertEqual(response.status_code, 201)
        scan = response.get_json()
        self.assertEqual({f["id"] for f in scan["findings"]},
                         {"csp-not-observed", "unsafe-target-blank"})
        report = self.client.get(f"/api/v1/scans/{scan['id']}/report", headers=self.headers)
        self.assertEqual(report.status_code, 200)
        self.assertIn("Hades AI Passive Security Report", report.get_data(as_text=True))

    def test_authorization_requires_acknowledgement(self):
        response = self.client.post("/api/v1/authorizations", json={
            "target_url": "https://example.com", "authorized_by": "Tester"}, headers=self.headers)
        self.assertEqual(response.status_code, 400)

    def test_modules_and_active_scope_gate(self):
        modules = self.client.get("/api/v1/modules", headers=self.headers).get_json()["modules"]
        self.assertTrue(all(module["available"] for module in modules))
        self.assertEqual(self.authorize().status_code, 201)
        passive = self.client.post("/api/v1/modules/payloads", json={
            "page": {"url": "https://example.com"}, "vulnerability_type": "xss"},
            headers=self.headers)
        self.assertEqual(passive.status_code, 403)

        active = self.client.post("/api/v1/authorizations", json={
            "target_url": "https://example.com", "authorized_by": "Test Owner",
            "scope": "active_web_assessment", "acknowledged": True}, headers=self.headers)
        self.assertEqual(active.status_code, 201)
        payloads = self.client.post("/api/v1/modules/payloads", json={
            "page": {"url": "https://example.com"}, "vulnerability_type": "xss"},
            headers=self.headers)
        self.assertEqual(payloads.status_code, 200)
        self.assertGreater(len(payloads.get_json()["payloads"]), 0)

    def test_active_test_requires_per_test_confirmation(self):
        self.client.post("/api/v1/authorizations", json={
            "target_url": "https://example.com", "authorized_by": "Test Owner",
            "scope": "active_web_assessment", "acknowledged": True}, headers=self.headers)
        payload = {"page": {"url": "https://example.com"},
                   "target_url": "https://example.com/path", "test_type": "xss", "parameter": "q"}
        response = self.client.post("/api/v1/modules/active-test", json=payload, headers=self.headers)
        self.assertEqual(response.status_code, 400)
        self.app.extensions["modules"].active_test = lambda *_: {
            "test_id": "xss_test", "payload_used": "test", "vulnerable": False, "confidence": 0.0}
        payload["confirmed"] = True
        response = self.client.post("/api/v1/modules/active-test", json=payload, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        audit = self.client.get("/api/v1/audit", headers=self.headers).get_json()["events"]
        self.assertEqual(audit[0]["test_id"], "xss_test")

    def test_authorization_rejects_unknown_scope(self):
        response = self.client.post("/api/v1/authorizations", json={
            "target_url": "https://example.com", "authorized_by": "Test Owner",
            "scope": "anything", "acknowledged": True}, headers=self.headers)
        self.assertEqual(response.status_code, 400)

    def test_payload_sender_and_port_scan_require_confirmation(self):
        self.client.post("/api/v1/authorizations", json={
            "target_url": "https://example.com", "authorized_by": "Test Owner",
            "scope": "active_web_assessment", "acknowledged": True}, headers=self.headers)
        payload_request = {"page": {"url": "https://example.com/path"},
                           "target_url": "https://example.com/path", "method": "GET",
                           "parameter": "id", "payload": "probe"}
        self.assertEqual(self.client.post("/api/v1/modules/send-payload",
                         json=payload_request, headers=self.headers).status_code, 400)
        self.app.extensions["modules"].send_payload = lambda *_: {"status_code": 200}
        payload_request["confirmed"] = True
        self.assertEqual(self.client.post("/api/v1/modules/send-payload",
                         json=payload_request, headers=self.headers).status_code, 200)

        scan_request = {"page": {"url": "https://example.com/path"},
                        "start_port": 1, "end_port": 1024, "timeout_ms": 100}
        self.assertEqual(self.client.post("/api/v1/modules/port-scans",
                         json=scan_request, headers=self.headers).status_code, 400)
        self.app.extensions["modules"].start_port_scan = lambda *_: {"id": "scan_test"}
        scan_request["confirmed"] = True
        self.assertEqual(self.client.post("/api/v1/modules/port-scans",
                         json=scan_request, headers=self.headers).status_code, 202)


if __name__ == "__main__":
    unittest.main()
