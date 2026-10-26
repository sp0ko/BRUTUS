"""Integration tests for LogFileWatcher (tailing) and SyslogWatcher (UDP)."""

import os
import socket
import tempfile
import threading
import time
import unittest

from detector.log_monitor import LogFileWatcher, LogMonitor, SyslogWatcher
from detector.tracker import BruteForceTracker


def _failed_line(ip="203.0.113.9", user="root"):
    ts = time.strftime("%b %d %H:%M:%S", time.localtime(time.time() - 5))
    return f"{ts} host sshd[1]: Failed password for {user} from {ip} port 22 ssh2\n"


def _tracker(threshold=3):
    return BruteForceTracker(threshold=threshold, time_window=3600, alert_cooldown=0)


class _AlertCollector:
    def __init__(self):
        self.alerts = []
        self.event = threading.Event()

    def __call__(self, alert):
        self.alerts.append(alert)
        self.event.set()


class TestLogFileWatcher(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = os.path.join(self._dir.name, "auth.log")
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(_failed_line("198.51.100.99") * 10)  # old content must be ignored
        self.collector = _AlertCollector()
        self.watcher = LogFileWatcher(
            path=self.path, parser_type="linux_ssh", tracker=_tracker(),
            on_alert=self.collector, poll_interval=0.02,
        )
        self.watcher.start()
        self.addCleanup(self._stop)
        time.sleep(0.4)  # let the watcher open the file and seek to the end

    def _stop(self):
        self.watcher.stop()
        self.watcher.join(timeout=5)

    def _append(self, text):
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(text)

    def test_new_lines_trigger_alert_and_existing_ones_do_not(self):
        self._append(_failed_line() * 3)
        self.assertTrue(self.collector.event.wait(timeout=5))
        self.assertEqual({a.ip for a in self.collector.alerts}, {"203.0.113.9"})

    def test_detection_continues_after_log_rotation(self):
        os.replace(self.path, self.path + ".1")
        with open(self.path, "w", encoding="utf-8"):
            pass
        time.sleep(0.8)  # watcher notices the new inode and reopens
        self._append(_failed_line("192.0.2.77") * 3)
        self.assertTrue(self.collector.event.wait(timeout=5))
        self.assertEqual(self.collector.alerts[0].ip, "192.0.2.77")

    def test_watcher_stops_cleanly(self):
        self.watcher.stop()
        self.watcher.join(timeout=5)
        self.assertFalse(self.watcher.is_alive())


class TestLogFileWatcherMissingFile(unittest.TestCase):

    def test_file_appearing_later_is_picked_up(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "late.log")
            collector = _AlertCollector()
            w = LogFileWatcher(path=path, parser_type="linux_ssh", tracker=_tracker(),
                               on_alert=collector, poll_interval=0.02)
            w.start()
            try:
                time.sleep(0.3)
                with open(path, "w", encoding="utf-8"):
                    pass
                time.sleep(2.6)  # watcher retries every 2 s
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write(_failed_line("192.0.2.5") * 3)
                self.assertTrue(collector.event.wait(timeout=5))
            finally:
                w.stop()
                w.join(timeout=5)


class TestSyslogWatcherUDP(unittest.TestCase):

    @staticmethod
    def _free_udp_port():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def test_udp_datagram_triggers_alert_with_sender_as_source(self):
        port = self._free_udp_port()
        collector = _AlertCollector()
        w = SyslogWatcher(host="127.0.0.1", port=port, protocol="udp",
                          tracker=_tracker(), on_alert=collector)
        w.start()
        try:
            for _ in range(100):
                if w._server is not None:
                    break
                time.sleep(0.05)
            self.assertIsNotNone(w._server, "syslog server did not start")
            payload = (_failed_line("203.0.113.9") * 3).encode()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(payload, ("127.0.0.1", port))
            self.assertTrue(collector.event.wait(timeout=5))
            alert = collector.alerts[0]
            self.assertEqual(alert.ip, "203.0.113.9")
            self.assertEqual(alert.log_sources, ["syslog:127.0.0.1"])
        finally:
            w.stop()
            w.join(timeout=5)


class TestLogMonitor(unittest.TestCase):

    def test_unknown_parser_is_rejected(self):
        with self.assertRaises(ValueError):
            LogMonitor(tracker=_tracker()).add_log_file("/tmp/x.log", "nope")

    def test_start_without_sources_raises(self):
        with self.assertRaises(RuntimeError):
            LogMonitor(tracker=_tracker()).start()

    def test_monitor_dispatches_to_all_handlers(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "auth.log")
            open(path, "w").close()
            monitor = LogMonitor(tracker=_tracker())
            c1, c2 = _AlertCollector(), _AlertCollector()
            monitor.add_alert_handler(c1)
            monitor.add_alert_handler(c2)
            monitor.add_log_file(path, "linux_ssh")
            monitor._watchers[0].poll_interval = 0.02
            monitor.start()
            try:
                time.sleep(0.4)
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write(_failed_line() * 3)
                self.assertTrue(c1.event.wait(timeout=5))
                self.assertTrue(c2.event.wait(timeout=5))
            finally:
                monitor.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
