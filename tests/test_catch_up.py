"""Log offsets: processing lines written while BRUTU$ was not running."""

import io
import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock

from detector.alerts.console_alert import ConsoleAlert
from detector.log_monitor import LogFileWatcher
from detector.offsets import OffsetStore
from detector.state import load_state, save_state
from detector.tracker import AlertEvent, BruteForceTracker
from main import AlertDispatcher
from utils.geo import GeoLocator


def fail(ip="8.8.4.4", user="root", age=5):
    ts = time.strftime("%b %d %H:%M:%S", time.localtime(time.time() - age))
    return f"{ts} host sshd[1]: Failed password for {user} from {ip} port 22 ssh2\n"


def wait_until(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


class Run:
    """One 'process lifetime': a watcher plus its tracker, collecting alerts."""

    def __init__(self, path, store, tracker=None, **kw):
        self.alerts = []
        self.tracker = tracker or BruteForceTracker(threshold=3, time_window=3600, alert_cooldown=0)
        self.watcher = LogFileWatcher(
            path=path, parser_type="linux_ssh", tracker=self.tracker,
            on_alert=self.alerts.append, poll_interval=0.02, offsets=store, **kw,
        )

    def __enter__(self):
        self.watcher.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def stop(self):
        self.watcher.stop()
        self.watcher.join(timeout=5)

    def settle(self, expect_offset_of=None):
        """Wait until the watcher has consumed the whole file."""
        path = self.watcher.path
        wait_until(lambda: self.watcher.offsets.get(path) is not None
                   and self.watcher.offsets.get(path)["offset"] >= os.path.getsize(path)
                   or os.path.getsize(path) == 0)
        time.sleep(0.1)


class TestCatchUp(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = os.path.join(self._dir.name, "auth.log")
        self.store = OffsetStore()

    def write(self, text, mode="a", path=None):
        with open(path or self.path, mode, encoding="utf-8") as fh:
            fh.write(text)

    def first_run(self):
        """A first life that reads one line, so an offset gets recorded."""
        self.write(fail("1.1.1.1", age=9999) * 4, "w")  # pre-existing content: ignored on first start
        with Run(self.path, self.store) as r:
            time.sleep(0.3)
            self.write(fail("2.2.2.2", "seen"))
            r.settle()
        self.assertEqual(r.alerts, [])

    def test_first_start_ignores_existing_content(self):
        self.write(fail() * 10, "w")
        with Run(self.path, self.store) as r:
            time.sleep(0.4)
        self.assertEqual(r.alerts, [])

    def test_lines_written_while_down_are_processed(self):
        self.first_run()
        self.write(fail(user="a", age=1800) + fail(user="b", age=1700) + fail(user="c", age=1600))
        with Run(self.path, self.store) as r:
            self.assertTrue(wait_until(lambda: r.alerts))
        self.assertTrue(all(a.catch_up for a in r.alerts))
        self.assertEqual(r.alerts[0].ip, "8.8.4.4")
        self.assertEqual(r.alerts[0].count, 3)

    def test_old_events_alert_even_though_outside_wall_clock_window(self):
        self.first_run()
        self.write(fail(age=86400 * 3) * 3)  # three days old
        with Run(self.path, self.store) as r:
            self.assertTrue(wait_until(lambda: r.alerts))

    def test_nothing_reprocessed_when_nothing_new(self):
        self.first_run()
        with Run(self.path, self.store) as r:
            time.sleep(0.5)
        self.assertEqual(r.alerts, [])

    def test_live_lines_after_catch_up_are_not_flagged(self):
        self.first_run()
        self.write(fail(age=60) * 3)
        with Run(self.path, self.store) as r:
            self.assertTrue(wait_until(lambda: r.alerts))
            n = len(r.alerts)
            self.write(fail("9.9.9.9", age=0) * 3)
            self.assertTrue(wait_until(lambda: len(r.alerts) > n))
        self.assertTrue(r.alerts[0].catch_up)
        self.assertFalse(r.alerts[-1].catch_up)
        self.assertEqual(r.alerts[-1].ip, "9.9.9.9")

    def test_rotation_while_down(self):
        self.first_run()
        self.write(fail("5.5.5.5", user="x", age=300) * 2)               # tail of the old file
        os.rename(self.path, self.path + ".1")
        self.write(fail("5.5.5.5", user="y", age=200) * 2, "w")          # new file
        with Run(self.path, self.store) as r:
            self.assertTrue(wait_until(lambda: r.alerts))
            time.sleep(0.3)
        ips = {a.ip for a in r.alerts}
        self.assertEqual(ips, {"5.5.5.5"})
        self.assertEqual(r.alerts[-1].count, 4)  # 2 from the rotated tail + 2 from the new file

    def test_rotation_while_down_with_unrelated_rotated_file_is_ignored(self):
        self.first_run()
        os.rename(self.path, self.path + ".1")
        self.write(fail("6.6.6.6", age=100) * 3, "w")
        self.write(fail("7.7.7.7", age=100) * 5, path=self.path + ".2")  # different inode: not ours
        with Run(self.path, self.store) as r:
            self.assertTrue(wait_until(lambda: r.alerts))
            time.sleep(0.3)
        self.assertEqual({a.ip for a in r.alerts}, {"6.6.6.6"})

    def test_truncated_file_is_read_from_start(self):
        self.first_run()
        self.write(fail("3.3.3.3", age=50) * 3, "w")  # smaller than the saved offset
        with Run(self.path, self.store) as r:
            self.assertTrue(wait_until(lambda: r.alerts))
        self.assertEqual(r.alerts[0].ip, "3.3.3.3")

    def test_replaced_content_same_inode_is_read_from_start(self):
        self.first_run()
        pad = "".join(fail("4.4.4.4", user=f"u{i}", age=40) for i in range(12))  # longer than before
        self.write(pad, "r+")  # overwrite in place: same inode, different first bytes, bigger
        with Run(self.path, self.store) as r:
            self.assertTrue(wait_until(lambda: r.alerts))
        self.assertTrue(all(a.ip == "4.4.4.4" for a in r.alerts))

    def test_backlog_cap_skips_oldest_part(self):
        self.first_run()
        old = fail("1.2.3.4", age=900) * 200
        recent = fail("5.6.7.8", age=30) * 3
        self.write(old + recent)
        with Run(self.path, self.store, catch_up_max_bytes=len(recent) + 10) as r:
            self.assertTrue(wait_until(lambda: r.alerts))
            time.sleep(0.3)
        self.assertEqual({a.ip for a in r.alerts}, {"5.6.7.8"})

    def test_partial_line_waits_for_newline(self):
        self.first_run()
        line = fail("8.8.8.8", age=30)
        with Run(self.path, self.store) as r:
            time.sleep(0.2)
            self.write((line * 2) + line[:20])
            time.sleep(0.4)
            self.assertEqual(r.alerts, [])          # only 2 complete lines
            self.write(line[20:])
            self.assertTrue(wait_until(lambda: r.alerts))   # 3rd completes
        self.assertFalse(r.alerts[0].catch_up)

    def test_in_run_rotation_reads_new_file_from_start(self):
        self.first_run()
        with Run(self.path, self.store) as r:
            time.sleep(0.3)
            os.rename(self.path, self.path + ".1")
            self.write(fail("9.8.7.6", age=0) * 3, "w")
            self.assertTrue(wait_until(lambda: r.alerts))
        self.assertFalse(r.alerts[0].catch_up)

    def test_state_file_keeps_counters_and_offsets_consistent(self):
        state = os.path.join(self._dir.name, "state.json")
        self.write("", "w")
        t1 = BruteForceTracker(threshold=3, time_window=3600, alert_cooldown=0)
        with Run(self.path, self.store, tracker=t1) as r:
            time.sleep(0.3)
            self.write(fail("8.8.4.4", age=20) * 2)   # 2 of 3 needed
            r.settle()
        self.assertTrue(save_state(t1, state, self.store))
        self.assertEqual(r.alerts, [])

        self.write(fail("8.8.4.4", age=10))           # written while down: the 3rd
        t2 = BruteForceTracker(threshold=3, time_window=3600, alert_cooldown=0)
        store2 = OffsetStore()
        self.assertEqual(load_state(t2, state, store2), 2)
        with Run(self.path, store2, tracker=t2) as r2:
            self.assertTrue(wait_until(lambda: r2.alerts))
            time.sleep(0.3)
        self.assertEqual(len(r2.alerts), 1)           # exactly one: nothing double-counted
        self.assertEqual(r2.alerts[0].count, 3)
        self.assertTrue(r2.alerts[0].catch_up)

    def test_without_offsets_store_behaviour_is_unchanged(self):
        self.write(fail() * 10, "w")
        alerts = []
        w = LogFileWatcher(self.path, "linux_ssh",
                           BruteForceTracker(threshold=3, time_window=3600, alert_cooldown=0),
                           alerts.append, poll_interval=0.02)
        w.start()
        try:
            time.sleep(0.3)
            self.write(fail("2.2.2.2", age=0) * 3)
            self.assertTrue(wait_until(lambda: alerts))
        finally:
            w.stop()
            w.join(timeout=5)
        self.assertEqual(alerts[0].ip, "2.2.2.2")
        self.assertFalse(alerts[0].catch_up)


class TestOffsetStore(unittest.TestCase):
    def test_load_skips_malformed_entries(self):
        s = OffsetStore()
        good = {"inode": 1, "offset": 10, "head_len": 3, "head": "abc"}
        n = s.load({"/a": good, "/b": {"inode": "x"}, "/c": "junk", "/d": {**good, "head_len": 9999},
                    "/e": {**good, "offset": -1}})
        self.assertEqual(n, 1)
        self.assertEqual(s.get("/a")["offset"], 10)
        self.assertEqual(s.load("not a dict"), 0)

    def test_snapshot_roundtrip(self):
        s = OffsetStore()
        with s.lock:
            s.update("/x", 7, 42, b"hello")
            snap = s.snapshot()
        s2 = OffsetStore()
        s2.load(snap)
        self.assertEqual(s2.get("/x"), s.get("/x"))


class TestCatchUpDispatch(unittest.TestCase):
    def _event(self, catch_up):
        return AlertEvent(ip="203.0.113.50", count=6, time_window=60, attack_type="SSH",
                          usernames=["root"], log_sources=["x"], first_seen=time.time() - 5,
                          last_seen=time.time(), catch_up=catch_up)

    def _dispatcher(self, out):
        return AlertDispatcher(console=ConsoleAlert(stream=out), discord=None, slack=None,
                               report_manager=None, geo=GeoLocator(enabled=False), blocker=MagicMock())

    def test_catch_up_alert_is_sent_but_not_blocked(self):
        out = io.StringIO()
        d = self._dispatcher(out)
        d.dispatch(self._event(True))
        self.assertIn("203.0.113.50", out.getvalue())
        d.blocker.block.assert_not_called()

    def test_live_alert_is_still_blocked(self):
        d = self._dispatcher(io.StringIO())
        d.dispatch(self._event(False))
        d.blocker.block.assert_called_once()

    def test_tracker_event_time_override(self):
        t = BruteForceTracker(threshold=3, time_window=60, alert_cooldown=0)
        old = time.time() - 7200
        results = [t.record_failed("8.8.4.4", "u", timestamp=old + i, use_event_time=True) for i in range(3)]
        self.assertIsNotNone(results[-1])
        t2 = BruteForceTracker(threshold=3, time_window=60, alert_cooldown=0)
        results = [t2.record_failed("8.8.4.4", "u", timestamp=old + i) for i in range(3)]
        self.assertIsNone(results[-1])  # wall-clock window: old events are evicted


if __name__ == "__main__":
    unittest.main()
