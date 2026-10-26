import json
import os
import stat
import tempfile
import time
import unittest

from detector.state import StatePersister, load_state, save_state
from detector.tracker import BruteForceTracker


def make(**kw):
    kw.setdefault("threshold", 5)
    kw.setdefault("time_window", 60)
    kw.setdefault("alert_cooldown", 300)
    return BruteForceTracker(**kw)


class TestState(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = os.path.join(self._dir.name, "sub", "state.json")

    def test_attack_in_progress_survives_restart(self):
        t1 = make()
        for _ in range(4):
            self.assertIsNone(t1.record_failed("8.8.4.4", "root", "SSH", "auth.log"))
        self.assertTrue(save_state(t1, self.path))

        t2 = make()
        self.assertEqual(load_state(t2, self.path), 4)
        alert = t2.record_failed("8.8.4.4", "root", "SSH", "auth.log")  # 5th overall
        self.assertIsNotNone(alert)
        self.assertEqual(alert.count, 5)

    def test_cooldown_survives_restart(self):
        t1 = make()
        for _ in range(5):
            t1.record_failed("8.8.4.4", "root")
        save_state(t1, self.path)
        t2 = make(threshold=1)
        load_state(t2, self.path)
        self.assertIsNone(t2.record_failed("8.8.4.4", "root"))  # still cooling down
        self.assertEqual(t2.get_stats()["8.8.4.4"]["total_alerts_triggered"], 1)

    def test_expired_entries_dropped(self):
        t1 = make()
        old = time.time() - 3600
        t1.record_failed("1.1.1.1", "a", timestamp=old)
        t1._last_alert["1.1.1.1"] = old
        save_state(t1, self.path)
        t2 = make()
        self.assertEqual(load_state(t2, self.path), 0)
        self.assertEqual(t2.export_state()["failed"], {})
        self.assertEqual(t2.export_state()["last_alert"], {})

    def test_load_is_idempotent(self):
        t1 = make()
        for _ in range(3):
            t1.record_failed("8.8.4.4", "root")
        save_state(t1, self.path)
        t2 = make()
        load_state(t2, self.path)
        load_state(t2, self.path)
        self.assertEqual(len(t2.export_state()["failed"]["8.8.4.4"]), 3)

    def test_missing_corrupt_and_wrong_version_are_ignored(self):
        t = make()
        self.assertEqual(load_state(t, self.path), 0)
        os.makedirs(os.path.dirname(self.path))
        for content in ("{not json", "[]", json.dumps({"version": 99, "failed": {}})):
            with open(self.path, "w") as fh:
                fh.write(content)
            self.assertEqual(load_state(t, self.path), 0)

    def test_malformed_entries_skipped(self):
        os.makedirs(os.path.dirname(self.path))
        now = time.time()
        data = {"version": 1, "failed": {
            "8.8.4.4": [[now, "ok", "SSH", "s"], ["x"], "junk", [now, "u"], [None, "u", "SSH", "s"]],
            "bad": "notalist"}, "last_alert": {"1.1.1.1": "nan?"}, "total_triggered": {"1.1.1.1": "x"}}
        with open(self.path, "w") as fh:
            json.dump(data, fh)
        t = make()
        self.assertEqual(load_state(t, self.path), 1)

    def test_future_timestamps_rejected(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as fh:
            json.dump({"version": 1, "failed": {"8.8.4.4": [[time.time() + 10_000, "u", "SSH", "s"]]}}, fh)
        self.assertEqual(load_state(make(), self.path), 0)

    def test_file_permissions_and_no_leftovers(self):
        t = make()
        t.record_failed("8.8.4.4", "root")
        save_state(t, self.path)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(os.listdir(os.path.dirname(self.path)), ["state.json"])

    def test_save_failure_returns_false(self):
        blocker = os.path.join(self._dir.name, "file")
        open(blocker, "w").close()
        self.assertFalse(save_state(make(), os.path.join(blocker, "state.json")))

    def test_persister_saves_on_stop_and_skips_unchanged(self):
        t = make()
        p = StatePersister(t, self.path, interval=3600)
        t.record_failed("8.8.4.4", "root")
        p.start()
        p.stop()  # final snapshot
        self.assertEqual(load_state(make(), self.path), 1)
        mtime = os.stat(self.path).st_mtime_ns
        self.assertTrue(p.save())  # unchanged -> no rewrite
        self.assertEqual(os.stat(self.path).st_mtime_ns, mtime)

    def test_persister_periodic_save(self):
        t = make()
        t.record_failed("8.8.4.4", "root")
        p = StatePersister(t, self.path, interval=1)
        p.start()
        self.addCleanup(p.stop)
        deadline = time.time() + 5
        while time.time() < deadline and not os.path.exists(self.path):
            time.sleep(0.1)
        self.assertTrue(os.path.exists(self.path))


if __name__ == "__main__":
    unittest.main()
