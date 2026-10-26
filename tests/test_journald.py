"""
Tests for JournaldWatcher — journalctl is replaced by a fake command.

Run:
    python -m unittest tests/test_journald.py -v
"""

import sys
import threading
import time
import unittest

from detector.log_monitor import JournaldWatcher, LogMonitor
from detector.tracker import BruteForceTracker


def _fake_journal(lines, then_sleep=0):
    """Command that prints *lines* and optionally keeps running afterwards."""
    script = (
        "import sys, time\n"
        f"for l in {lines!r}:\n"
        "    print(l, flush=True)\n"
        f"time.sleep({then_sleep})\n"
    )
    return [sys.executable, "-c", script]


def _failed(ip, user="root"):
    return f"Oct 26 13:00:00 host sshd[1]: Failed password for {user} from {ip} port 22 ssh2"


class TestJournaldCommand(unittest.TestCase):

    def test_default_command_follows_new_entries_for_each_unit(self):
        cmd = JournaldWatcher._build_command(["ssh", "sshd"])
        self.assertEqual(cmd[:2], ["journalctl", "-f"])
        self.assertIn("--no-pager", cmd)
        self.assertEqual([cmd[i + 1] for i, a in enumerate(cmd) if a == "-u"], ["ssh", "sshd"])

    def test_default_units_used_when_none_given(self):
        w = JournaldWatcher(tracker=BruteForceTracker(), on_alert=lambda e: None)
        self.assertIn("ssh", w.units)
        self.assertIn("sshd", w.units)


class TestJournaldWatcher(unittest.TestCase):

    def _run_watcher(self, lines, threshold=3, whitelist=None, wait=5.0):
        tracker = BruteForceTracker(threshold=threshold, time_window=3600, alert_cooldown=0)
        alerts = []
        got_alert = threading.Event()

        def on_alert(event):
            alerts.append(event)
            got_alert.set()

        w = JournaldWatcher(
            tracker=tracker, on_alert=on_alert, whitelist_nets=whitelist,
            command=_fake_journal(lines, then_sleep=30),
        )
        w.start()
        got_alert.wait(timeout=wait)
        w.stop()
        w.join(timeout=5)
        return w, alerts

    def test_failed_logins_trigger_alert(self):
        w, alerts = self._run_watcher([_failed("203.0.113.9")] * 3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].ip, "203.0.113.9")
        self.assertIn("journald", alerts[0].log_sources)
        self.assertFalse(w.is_alive())

    def test_unrelated_lines_are_ignored(self):
        _, alerts = self._run_watcher(
            ["Oct 26 13:00:00 host sshd[1]: Server listening on 0.0.0.0 port 22."] * 5,
            wait=1.0,
        )
        self.assertEqual(alerts, [])

    def test_whitelisted_ip_is_skipped(self):
        import ipaddress
        _, alerts = self._run_watcher(
            [_failed("10.1.2.3")] * 5,
            whitelist=[ipaddress.ip_network("10.0.0.0/8")],
            wait=1.0,
        )
        self.assertEqual(alerts, [])

    def test_stop_terminates_running_process(self):
        w = JournaldWatcher(
            tracker=BruteForceTracker(), on_alert=lambda e: None,
            command=_fake_journal([], then_sleep=60),
        )
        w.start()
        time.sleep(0.5)
        w.stop()
        w.join(timeout=5)
        self.assertFalse(w.is_alive())

    def test_missing_journalctl_ends_thread_without_crash(self):
        w = JournaldWatcher(
            tracker=BruteForceTracker(), on_alert=lambda e: None,
            command=["/nonexistent/journalctl-binary"],
        )
        w.start()
        w.join(timeout=5)
        self.assertFalse(w.is_alive())

    def test_exited_process_is_restarted(self):
        tracker = BruteForceTracker(threshold=2, time_window=3600, alert_cooldown=0)
        alerts = []
        done = threading.Event()

        def on_alert(event):
            alerts.append(event)
            done.set()

        # Each run prints one line and exits; two runs are needed to hit the threshold.
        w = JournaldWatcher(
            tracker=tracker, on_alert=on_alert,
            command=_fake_journal([_failed("198.51.100.4")]),
        )
        w.RESTART_DELAY = 0.1
        w.start()
        self.assertTrue(done.wait(timeout=10))
        w.stop()
        w.join(timeout=5)
        self.assertEqual(alerts[0].ip, "198.51.100.4")


class TestLogMonitorJournald(unittest.TestCase):

    def test_monitor_accepts_journald_source(self):
        monitor = LogMonitor(tracker=BruteForceTracker())
        monitor.add_journald_source(units=["ssh"])
        self.assertEqual(len(monitor._watchers), 1)
        self.assertIsInstance(monitor._watchers[0], JournaldWatcher)


if __name__ == "__main__":
    unittest.main(verbosity=2)
