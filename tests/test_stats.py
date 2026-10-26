import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta

import utils.i18n as i18n
from detector.stats import (load_alerts, parse_period, render_markdown,
                            render_text, summarize)

i18n.set_lang("en")
T = i18n.get_T()


def rec(ip, minutes_ago=5, **kw):
    ts = datetime.utcnow() - timedelta(minutes=minutes_ago)
    r = {"timestamp": ts.isoformat() + "Z", "ip": ip, "count": 5,
         "attack_type": "SSH", "usernames": ["root"], "log_sources": ["auth.log"],
         "successful_login": False, "geo": {"country": "Poland"}}
    r.update(kw)
    return r


class TestStats(unittest.TestCase):
    def _write(self, lines):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        self.addCleanup(os.remove, path)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        return path

    def test_parse_period(self):
        self.assertEqual(parse_period("24h"), timedelta(hours=24))
        self.assertEqual(parse_period("2w"), timedelta(weeks=2))
        self.assertIsNone(parse_period("all"))
        with self.assertRaises(ValueError):
            parse_period("xyz")

    def test_load_skips_malformed_and_old(self):
        path = self._write([json.dumps(rec("1.1.1.1")), "not json",
                            json.dumps(rec("2.2.2.2", minutes_ago=60 * 24 * 10))])
        self.assertEqual(len(load_alerts(path)), 2)
        since = datetime.utcnow() - timedelta(days=1)
        self.assertEqual([r["ip"] for r in load_alerts(path, since)], ["1.1.1.1"])

    def test_summarize(self):
        records = [rec("1.1.1.1"), rec("1.1.1.1", successful_login=True),
                   rec("2.2.2.2", attack_type="SSH, RDP", threat_intel="feodo")]
        for r, x in zip(records, load_alerts(self._write([json.dumps(r) for r in records]))):
            r["_ts"] = x["_ts"]
        s = summarize(records, datetime.utcnow() - timedelta(days=1), datetime.utcnow())
        self.assertEqual(s["totals"]["alerts"], 3)
        self.assertEqual(s["totals"]["unique_ips"], 2)
        self.assertEqual(s["totals"]["breaches"], 1)
        self.assertEqual(s["totals"]["threat_intel"], 1)
        self.assertEqual(s["top_ips"][0]["ip"], "1.1.1.1")

    def test_empty_and_renderers(self):
        now = datetime.utcnow()
        s = summarize([], None, now)
        self.assertEqual(s["totals"]["alerts"], 0)
        self.assertIn("Summary report", render_text(s, T))
        self.assertIn("Summary report", render_markdown(s, T))

    def test_markdown_escapes_pipes(self):
        path = self._write([json.dumps(rec("1.1.1.1", usernames=["a|b"]))])
        s = summarize(load_alerts(path), None, datetime.utcnow())
        self.assertNotIn("a|b", render_markdown(s, T))


if __name__ == "__main__":
    unittest.main()
