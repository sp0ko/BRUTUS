"""Tests for the offline replay of historic logs."""

import gzip
import ipaddress
import os
import tempfile
import unittest

from detector.replay import replay_file
from detector.tracker import BruteForceTracker


def _fail(sec, ip="203.0.113.7", user="root"):
    return f"Jan  5 03:12:{sec:02d} srv sshd[10]: Failed password for {user} from {ip} port 4000 ssh2"


class TestReplay(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)

    def _write(self, name, lines, gz=False):
        path = os.path.join(self._dir.name, name)
        data = "\n".join(lines) + "\n"
        if gz:
            with gzip.open(path, "wt", encoding="utf-8") as fh:
                fh.write(data)
        else:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(data)
        return path

    def _tracker(self, **kw):
        return BruteForceTracker(threshold=5, time_window=60, alert_cooldown=0, **kw)

    def test_old_log_still_triggers_alert(self):
        # Timestamps are months in the past — the window must follow event time.
        path = self._write("auth.log", [_fail(s) for s in range(10, 16)])
        res = replay_file(path, "linux_ssh", self._tracker())
        self.assertEqual(res.failed, 6)
        self.assertGreaterEqual(len(res.alerts), 1)
        self.assertEqual(res.alerts[0].ip, "203.0.113.7")

    def test_slow_attempts_outside_window_do_not_alert(self):
        lines = [
            f"Jan  5 03:{m:02d}:00 srv sshd[10]: Failed password for root from 203.0.113.7 port 4000 ssh2"
            for m in range(10, 16)
        ]
        res = replay_file(self._write("slow.log", lines), "linux_ssh", self._tracker())
        self.assertEqual(res.failed, 6)
        self.assertEqual(res.alerts, [])

    def test_success_after_failures_is_critical(self):
        lines = [_fail(s) for s in range(10, 14)]
        lines.append("Jan  5 03:12:20 srv sshd[10]: Accepted password for root from 203.0.113.7 port 4000 ssh2")
        res = replay_file(self._write("breach.log", lines), "linux_ssh", self._tracker())
        self.assertEqual(res.success, 1)
        self.assertTrue(any(a.successful_login for a in res.alerts))

    def test_counts_and_top_ips(self):
        lines = [_fail(s, ip="198.51.100.1") for s in range(10, 13)]
        lines += [_fail(s, ip="198.51.100.2") for s in range(20, 21)]
        lines.append("Jan  5 03:13:00 srv CRON[1]: unrelated")
        res = replay_file(self._write("mix.log", lines), "linux_ssh", self._tracker())
        self.assertEqual(res.lines, 5)
        self.assertEqual(res.ignored, 1)
        self.assertEqual(res.top_ips[0], ("198.51.100.1", 3))

    def test_gzip_log_is_supported(self):
        path = self._write("auth.log.1.gz", [_fail(s) for s in range(10, 16)], gz=True)
        res = replay_file(path, "linux_ssh", self._tracker())
        self.assertGreaterEqual(len(res.alerts), 1)

    def test_whitelisted_ip_is_ignored(self):
        path = self._write("wl.log", [_fail(s, ip="10.1.2.3") for s in range(10, 18)])
        res = replay_file(
            path, "linux_ssh", self._tracker(),
            whitelist_nets=[ipaddress.ip_network("10.0.0.0/8")],
        )
        self.assertEqual(res.failed, 0)
        self.assertEqual(res.alerts, [])

    def test_on_alert_callback_receives_events(self):
        got = []
        path = self._write("cb.log", [_fail(s) for s in range(10, 16)])
        res = replay_file(path, "linux_ssh", self._tracker(), on_alert=got.append)
        self.assertEqual(got, res.alerts)

    def test_missing_file_raises_oserror(self):
        with self.assertRaises(OSError):
            replay_file("/nonexistent/auth.log", "linux_ssh", self._tracker())

    def test_binary_parser_is_rejected(self):
        with self.assertRaises(ValueError):
            replay_file(self._write("x.log", ["x"]), "windows_evtx", self._tracker())


if __name__ == "__main__":
    unittest.main(verbosity=2)
