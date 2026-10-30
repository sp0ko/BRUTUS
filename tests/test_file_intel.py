import os
import tempfile
import time
import unittest

import requests

import utils.i18n as i18n
from detector.alerts.discord_alert import DiscordAlert
from detector.alerts.slack_alert import SlackAlert
from detector.dashboard import _render_honeypot
from detector.honeypot import summarize_honeypot
from detector.stats import render_files_markdown, render_files_text
from utils.file_intel import FileIntel, describe

i18n.set_lang("en")
SHA = "a" * 64
SHA2 = "b" * 64


class FakeResponse:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def vt_payload(malicious=12, harmless=0, undetected=58, label="trojan.mirai"):
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "harmless": harmless, "undetected": undetected},
        "popular_threat_classification": {"suggested_threat_label": label},
    }}}


class FileIntelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = os.path.join(self.tmp.name, "intel.json")
        self.calls = []
        self.alerts = []

    def make(self, response, **kw):
        def get(url, headers=None, timeout=None):
            self.calls.append((url, headers))
            if isinstance(response, Exception):
                raise response
            return response
        return FileIntel("KEY", cache_path=self.cache, get=get,
                         on_malicious=lambda sha, v: self.alerts.append((sha, v)), **kw)

    def test_found_result_is_parsed_and_cached_on_disk(self):
        fi = self.make(FakeResponse(200, vt_payload()))
        fi.submit([SHA])
        fi._query(SHA)
        verdict = fi.lookup(SHA)
        self.assertEqual((verdict["status"], verdict["malicious"], verdict["total"]), ("found", 12, 70))
        self.assertEqual(verdict["label"], "trojan.mirai")
        self.assertIn(SHA, self.calls[0][0])
        self.assertEqual(self.calls[0][1], {"x-apikey": "KEY"})
        self.assertEqual(FileIntel("KEY", cache_path=self.cache).lookup(SHA)["malicious"], 12)

    def test_not_found_is_cached_as_unknown(self):
        fi = self.make(FakeResponse(404))
        fi._query(SHA)
        self.assertEqual(fi.lookup(SHA)["status"], "unknown")
        self.assertEqual(fi.submit([SHA]), 0)  # fresh entry, nothing to queue

    def test_submit_ignores_invalid_hashes_and_duplicates(self):
        fi = self.make(FakeResponse(404))
        self.assertEqual(fi.submit(["../etc/passwd", "xyz", SHA, SHA.upper()]), 1)

    def test_stale_entry_is_requeued(self):
        fi = self.make(FakeResponse(404))
        fi._cache[SHA] = {"status": "unknown", "checked": time.time() - 3 * 86400}
        self.assertEqual(fi.submit([SHA]), 1)

    def test_bad_key_disables_lookups_and_caches_nothing(self):
        fi = self.make(FakeResponse(401))
        fi._query(SHA)
        self.assertTrue(fi._disabled)
        self.assertIsNone(fi.lookup(SHA))

    def test_rate_limit_and_network_errors_back_off_without_caching(self):
        self.assertGreater(self.make(FakeResponse(429))._query(SHA), 0)
        fi = self.make(requests.ConnectionError("down"))
        self.assertGreater(fi._query(SHA), 0)
        self.assertIsNone(fi.lookup(SHA))

    def test_garbage_answer_is_not_cached(self):
        fi = self.make(FakeResponse(200, {"data": {}}))
        self.assertGreater(fi._query(SHA), 0)
        self.assertIsNone(fi.lookup(SHA))

    def test_alert_fires_once_above_threshold(self):
        fi = self.make(FakeResponse(200, vt_payload(malicious=12)), alert_min_detections=5)
        fi._query(SHA)
        fi._query(SHA)
        self.assertEqual(len(self.alerts), 1)
        self.assertEqual(self.alerts[0][0], SHA)

    def test_no_alert_below_threshold(self):
        fi = self.make(FakeResponse(200, vt_payload(malicious=2)), alert_min_detections=5)
        fi._query(SHA)
        self.assertEqual(self.alerts, [])

    def test_describe(self):
        self.assertEqual(describe(None), "")
        self.assertEqual(describe({"status": "unknown"}), "unknown")
        self.assertEqual(describe({"status": "found", "malicious": 3, "total": 70, "label": "x"}), "3/70 (x)")


class HoneypotIntegrationTest(unittest.TestCase):
    def _records(self):
        from datetime import datetime
        now = datetime.utcnow()
        base = {"src_ip": "5.6.7.8", "_ts": now}
        return [
            dict(base, eventid="cowrie.session.file_download", shasum=SHA, url="http://x/y"),
            dict(base, eventid="cowrie.session.file_upload", shasum=SHA2, filename=".16"),
        ], now

    def _summary(self, intel):
        records, now = self._records()
        return summarize_honeypot(records, None, now, file_intel=intel)

    def test_uploads_count_as_hashes(self):
        self.assertEqual({h for h, _ in self._summary(None)["hashes"]}, {SHA, SHA2})

    def test_intel_off_gives_none(self):
        self.assertIsNone(self._summary(None)["hash_intel"])

    def test_intel_on_queues_hashes_and_attaches_cached_verdicts(self):
        class Stub:
            def __init__(self):
                self.queued = []

            def submit(self, hashes):
                self.queued = list(hashes)

            def lookup(self, sha):
                return {"status": "found", "malicious": 9, "total": 70, "label": "mirai"} if sha == SHA else None

        stub = Stub()
        s = self._summary(stub)
        self.assertEqual(set(stub.queued), {SHA, SHA2})
        self.assertEqual(list(s["hash_intel"]), [SHA])

    def test_dashboard_panel_shows_verdicts_and_escapes_label(self):
        s = self._summary(None)
        s["hash_intel"] = {SHA: {"status": "found", "malicious": 9, "total": 70, "label": "<script>x</script>"},
                           SHA2: {"status": "unknown"}}
        html = _render_honeypot(s, i18n.get_T())
        self.assertIn("9/70", html)
        self.assertIn("unknown to VT", html)
        self.assertIn("virustotal.com/gui/file/" + SHA, html)
        self.assertNotIn("<script>x</script>", html)

    def test_dashboard_panel_without_intel_has_no_verdict_column(self):
        html = _render_honeypot(self._summary(None), i18n.get_T())
        self.assertNotIn("VirusTotal (detections)", html)
        self.assertNotIn("checking…", html)

    def test_pending_verdict_is_labelled(self):
        s = self._summary(None)
        s["hash_intel"] = {}
        self.assertIn("checking…", _render_honeypot(s, i18n.get_T()))

    def test_text_and_markdown_reports(self):
        s = self._summary(None)
        s["hash_intel"] = {SHA: {"status": "found", "malicious": 9, "total": 70, "label": "mirai"}}
        T = i18n.get_T()
        self.assertIn("9/70 (mirai)", render_files_text(s, T))
        md = render_files_markdown(s, T)
        self.assertIn("9/70 (mirai)", md)
        self.assertIn("checking…", md)  # SHA2 has no verdict yet


class AlertPayloadTest(unittest.TestCase):
    VERDICT = {"status": "found", "malicious": 12, "total": 70, "label": "trojan.mirai"}

    def test_discord_payload(self):
        embed = DiscordAlert("https://example.invalid/hook")._build_file_payload(SHA, self.VERDICT)["embeds"][0]
        self.assertIn("12/70", embed["description"])
        self.assertIn(SHA, embed["fields"][0]["value"])
        self.assertTrue(embed["url"].endswith(SHA))

    def test_slack_payload(self):
        att = SlackAlert("https://example.invalid/hook")._build_file_payload(SHA, self.VERDICT)["attachments"][0]
        text = " ".join(b["text"]["text"] for b in att["blocks"])
        self.assertIn("12/70", text)
        self.assertIn(SHA, text)


if __name__ == "__main__":
    unittest.main()
