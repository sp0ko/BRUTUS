"""
Unit tests for IPBlocker (dry_run=True — no real iptables calls).

Run:
    python -m pytest tests/ -v
    python -m unittest tests/test_blocker.py -v
"""

import os
import tempfile
import time
import unittest

from utils.blocker import IPBlocker, _validate_ip


class TestIPValidation(unittest.TestCase):

    def test_valid_ipv4(self):
        self.assertTrue(_validate_ip("1.2.3.4"))
        self.assertTrue(_validate_ip("192.168.0.1"))
        self.assertTrue(_validate_ip("255.255.255.255"))

    def test_invalid_ipv4_out_of_range(self):
        self.assertFalse(_validate_ip("256.0.0.1"))
        self.assertFalse(_validate_ip("1.2.3.300"))

    def test_invalid_ip_shell_injection(self):
        self.assertFalse(_validate_ip("1.2.3.4; rm -rf /"))
        self.assertFalse(_validate_ip("$(reboot)"))
        self.assertFalse(_validate_ip("1.2.3.4 && cat /etc/passwd"))

    def test_valid_ipv6(self):
        self.assertTrue(_validate_ip("::1"))
        self.assertTrue(_validate_ip("2001:db8::1"))

    def test_empty_string_invalid(self):
        self.assertFalse(_validate_ip(""))

    def test_hostname_invalid(self):
        self.assertFalse(_validate_ip("example.com"))


class TestIPBlockerDryRun(unittest.TestCase):

    def setUp(self):
        fd, self._state_file = tempfile.mkstemp(suffix=".json", prefix="test_blocker_")
        os.close(fd)
        os.unlink(self._state_file)  # let IPBlocker create it fresh

    def tearDown(self):
        if os.path.exists(self._state_file):
            os.unlink(self._state_file)

    def _make_blocker(self, auto_unblock=0):
        return IPBlocker(
            enabled=True,
            auto_unblock_after=auto_unblock,
            state_file=self._state_file,
            dry_run=True,
        )

    def test_block_valid_ip(self):
        b = self._make_blocker()
        result = b.block("1.2.3.4", attempts=10, attack_type="SSH")
        self.assertTrue(result)
        self.assertTrue(b.is_blocked("1.2.3.4"))

    def test_block_invalid_ip_rejected(self):
        b = self._make_blocker()
        result = b.block("not-an-ip", attempts=5)
        self.assertFalse(result)
        self.assertFalse(b.is_blocked("not-an-ip"))

    def test_block_same_ip_twice_returns_false(self):
        b = self._make_blocker()
        b.block("5.5.5.5", attempts=3)
        result = b.block("5.5.5.5", attempts=3)
        self.assertFalse(result, "Second block of same IP should return False")

    def test_unblock_removes_ip(self):
        b = self._make_blocker()
        b.block("6.6.6.6")
        result = b.unblock("6.6.6.6")
        self.assertTrue(result)
        self.assertFalse(b.is_blocked("6.6.6.6"))

    def test_unblock_not_blocked_ip_returns_false(self):
        b = self._make_blocker()
        result = b.unblock("9.9.9.9")
        self.assertFalse(result)

    def test_get_blocked_returns_metadata(self):
        b = self._make_blocker()
        b.block("7.7.7.7", attempts=15, attack_type="PASSWORD_SPRAY",
                usernames=["alice", "bob"])
        rows = b.get_blocked()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["ip"], "7.7.7.7")
        self.assertEqual(row["attempts"], 15)
        self.assertEqual(row["attack_type"], "PASSWORD_SPRAY")
        self.assertIn("alice", row["usernames"])

    def test_get_blocked_sorted_newest_first(self):
        b = self._make_blocker()
        b.block("1.0.0.1", attempts=1)
        time.sleep(0.01)
        b.block("1.0.0.2", attempts=2)
        rows = b.get_blocked()
        self.assertEqual(rows[0]["ip"], "1.0.0.2")

    def test_unblock_all_clears_everything(self):
        b = self._make_blocker()
        for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
            b.block(ip)
        count = b.unblock_all()
        self.assertEqual(count, 3)
        self.assertEqual(b.get_blocked(), [])

    def test_disabled_blocker_blocks_nothing(self):
        b = IPBlocker(enabled=False, dry_run=True,
                      state_file=self._state_file)
        result = b.block("8.8.8.8")
        self.assertFalse(result)
        self.assertFalse(b.is_blocked("8.8.8.8"))

    def test_remaining_seconds_set_when_auto_unblock(self):
        b = self._make_blocker(auto_unblock=3600)
        b.block("11.11.11.11")
        rows = b.get_blocked()
        self.assertIsNotNone(rows[0]["remaining_s"])
        self.assertGreater(rows[0]["remaining_s"], 3500)

    def test_remaining_seconds_none_when_permanent(self):
        b = self._make_blocker(auto_unblock=0)
        b.block("12.12.12.12")
        rows = b.get_blocked()
        self.assertIsNone(rows[0]["remaining_s"])


if __name__ == "__main__":
    unittest.main(verbosity=2)



if __name__ == "__main__":
    unittest.main(verbosity=2)
