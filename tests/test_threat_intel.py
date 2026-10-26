import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from utils.threat_intel import DEFAULT_SOURCES, ThreatIntel, _parse_feed


class TestFeodoTrackerSource(unittest.TestCase):

    def test_feodo_tracker_is_a_default_source(self):
        self.assertEqual(
            DEFAULT_SOURCES["feodo_tracker"],
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        )

    def test_plain_text_ip_entries_are_parsed(self):
        feed = "# Feodo Tracker IP blocklist\n1.2.3.4\n198.51.100.0/24\n"
        self.assertEqual(_parse_feed(feed), ["1.2.3.4", "198.51.100.0/24"])


def _fake_urlopen(feeds):
    """urlopen replacement: feeds maps url -> text, or an Exception to raise."""
    def opener(req, timeout=None):
        body = feeds[req.full_url]
        if isinstance(body, Exception):
            raise body
        resp = MagicMock()
        resp.read.return_value = body.encode()
        resp.__enter__.return_value = resp
        return resp
    return opener


class TestThreatIntelUpdate(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.db = os.path.join(self._dir.name, "ti.txt")

    def _update(self, feeds, **kw):
        ti = ThreatIntel(enabled=True, db_path=self.db, sources={n: u for n, u in kw.pop("sources")}, **kw)
        with patch("urllib.request.urlopen", _fake_urlopen(feeds)):
            return ti, ti.update()

    def test_update_merges_sources_and_enables_lookups(self):
        feeds = {
            "http://a/list": "# a\n203.0.113.5\n198.51.100.0/24 ; SBL1\n",
            "http://b/list": "192.0.2.9\n",
        }
        ti, total = self._update(feeds, sources=[("feed_a", "http://a/list"), ("feed_b", "http://b/list")])
        self.assertEqual(total, 3)
        self.assertEqual(ti.is_known_bad("203.0.113.5"), "feed_a")
        self.assertEqual(ti.is_known_bad("198.51.100.77"), "feed_a")
        self.assertEqual(ti.is_known_bad("192.0.2.9"), "feed_b")
        self.assertIsNone(ti.is_known_bad("8.8.8.8"))

    def test_duplicate_entry_keeps_first_source(self):
        feeds = {"http://a/l": "203.0.113.5\n", "http://b/l": "203.0.113.5\n"}
        ti, total = self._update(feeds, sources=[("first", "http://a/l"), ("second", "http://b/l")])
        self.assertEqual(total, 1)
        self.assertEqual(ti.is_known_bad("203.0.113.5"), "first")

    def test_failing_source_does_not_block_others(self):
        feeds = {"http://a/l": OSError("boom"), "http://b/l": "192.0.2.9\n"}
        ti, total = self._update(feeds, sources=[("broken", "http://a/l"), ("ok", "http://b/l")])
        self.assertEqual(total, 1)
        self.assertEqual(ti.is_known_bad("192.0.2.9"), "ok")

    def test_all_sources_failing_keeps_existing_db(self):
        with open(self.db, "w", encoding="utf-8") as fh:
            fh.write("203.0.113.5\told\n")
        ti = ThreatIntel(enabled=True, db_path=self.db, sources={"x": "http://a/l"})
        with patch("urllib.request.urlopen", _fake_urlopen({"http://a/l": OSError("down")})):
            ti.update()
        self.assertEqual(ti.is_known_bad("203.0.113.5"), "old")
        with open(self.db, encoding="utf-8") as fh:
            self.assertIn("203.0.113.5", fh.read())

    def test_db_is_reloaded_by_a_new_instance(self):
        self._update({"http://a/l": "203.0.113.5\n"}, sources=[("feed_a", "http://a/l")])
        fresh = ThreatIntel(enabled=True, db_path=self.db)
        self.assertEqual(fresh.is_known_bad("203.0.113.5"), "feed_a")

    def test_disabled_instance_never_matches(self):
        self._update({"http://a/l": "203.0.113.5\n"}, sources=[("feed_a", "http://a/l")])
        self.assertIsNone(ThreatIntel(enabled=False, db_path=self.db).is_known_bad("203.0.113.5"))


if __name__ == "__main__":
    unittest.main()
