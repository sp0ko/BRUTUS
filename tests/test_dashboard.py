import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime

import utils.i18n as i18n
from detector.dashboard import create_server, is_loopback, render_html, build_summary

i18n.set_lang("en")
XSS = "<script>alert(1)</script>"


class TestDashboard(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        self.addCleanup(os.remove, self.path)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "timestamp": datetime.utcnow().isoformat() + "Z", "ip": "1.2.3.4", "count": 5,
                "attack_type": "SSH", "usernames": [XSS], "log_sources": ["auth.log"],
                "successful_login": False, "geo": None}) + "\n")
        self.status = {
            "running": True,
            "started_at": "2026-10-27T08:00:00+00:00",
            "sources": [{
                "type": "file", "name": "/var/log/auth.log", "parser": "linux_ssh",
                "status": "running", "last_event_at": None, "error": None,
            }],
        }
        self.server = create_server(self.path, "127.0.0.1", 0, status_provider=lambda: self.status)
        self.port = self.server.server_address[1]
        t = threading.Thread(target=self.server.serve_forever, daemon=True)
        t.start()
        self.addCleanup(t.join, 5)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def get(self, path):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as r:
                return r.status, r.headers, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode()

    def test_html_escapes_and_headers(self):
        status, headers, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertNotIn(XSS, body)
        self.assertIn("&lt;script&gt;", body)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_api(self):
        status, _, body = self.get("/api/summary?since=all")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["totals"]["alerts"], 1)

    def test_status_api_and_dashboard_panel(self):
        status, _, body = self.get("/api/status")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["running"])
        self.assertEqual(data["sources"][0]["status"], "running")

        status, _, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("Current BRUTUS status", body)
        self.assertIn("/var/log/auth.log", body)
        self.assertIn("no events yet", body)

    def test_bad_period_and_404(self):
        self.assertEqual(self.get("/?since=bogus")[0], 400)
        self.assertEqual(self.get("/nope")[0], 404)

    def test_missing_file_is_empty(self):
        self.assertEqual(build_summary(self.path + ".missing", "7d")["totals"]["alerts"], 0)

    def test_render_html_standalone(self):
        s = build_summary(self.path, "all")
        html = render_html(s, i18n.get_T(), links=False)
        self.assertNotIn("<script", html.replace(XSS, ""))
        self.assertNotIn("<nav>", html)

    def test_is_loopback(self):
        self.assertTrue(is_loopback("127.0.0.1"))
        self.assertTrue(is_loopback("localhost"))
        self.assertFalse(is_loopback("0.0.0.0"))


if __name__ == "__main__":
    unittest.main()
