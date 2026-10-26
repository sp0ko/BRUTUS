import os
import tempfile
import unittest
from unittest import mock

from utils.blocker import IPBlocker
from utils.ip_utils import parse_cidr_list


class Recorder(IPBlocker):
    """IPBlocker that records iptables commands instead of running them."""

    def __init__(self, *a, **kw):
        self.cmds = []
        super().__init__(*a, **kw)

    def _run(self, cmd):
        self.cmds.append(" ".join(cmd))
        return not getattr(self, "fail_next", False)


class TestBlockerScope(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.state = os.path.join(self._dir.name, "blocked.json")

    def make(self, **kw):
        kw.setdefault("auto_unblock_after", 0)
        return Recorder(enabled=True, state_file=self.state, **kw)

    def test_default_scope_blocks_everything(self):
        b = self.make()
        self.assertTrue(b.block("1.2.3.4", attack_type="FTP"))
        self.assertEqual(b.cmds, ["iptables -I INPUT 1 -s 1.2.3.4 -j DROP"])

    def test_service_scope_blocks_only_ports(self):
        b = self.make(scope="service")
        b.block("1.2.3.4", attack_type="HTTP")
        self.assertEqual(b.cmds, [
            "iptables -I INPUT 1 -s 1.2.3.4 -p tcp --dport 80 -j DROP",
            "iptables -I INPUT 1 -s 1.2.3.4 -p tcp --dport 443 -j DROP",
        ])
        b.cmds.clear()
        self.assertTrue(b.unblock("1.2.3.4"))
        self.assertEqual(b.cmds, [
            "iptables -D INPUT -s 1.2.3.4 -p tcp --dport 80 -j DROP",
            "iptables -D INPUT -s 1.2.3.4 -p tcp --dport 443 -j DROP",
        ])

    def test_ipv6_uses_ip6tables(self):
        b = self.make(scope="service")
        b.block("2001:db8::5", attack_type="SSH")
        self.assertEqual(b.cmds, ["ip6tables -I INPUT 1 -s 2001:db8::5 -p tcp --dport 22 -j DROP"])

    def test_spray_and_unknown_types_get_full_block(self):
        b = self.make(scope="service")
        b.block("1.2.3.4", attack_type="PASSWORD_SPRAY")
        self.assertEqual(b.cmds, ["iptables -I INPUT 1 -s 1.2.3.4 -j DROP"])

    def test_combined_types_union_of_ports(self):
        b = self.make(scope="service")
        self.assertEqual(b.ports_for("SSH, FTP"), [21, 22])
        self.assertIsNone(b.ports_for("SSH, SOMETHING"))

    def test_custom_ssh_port(self):
        b = self.make(scope="service", ports={"ssh": [2222]})
        self.assertEqual(b.ports_for("SSH"), [2222])

    def test_second_service_widens_block(self):
        b = self.make(scope="service")
        b.block("1.2.3.4", attack_type="SSH")
        b.cmds.clear()
        self.assertTrue(b.block("1.2.3.4", attack_type="FTP"))
        self.assertEqual(b.cmds, ["iptables -I INPUT 1 -s 1.2.3.4 -p tcp --dport 21 -j DROP"])
        self.assertFalse(b.block("1.2.3.4", attack_type="SSH"))  # already covered
        row = b.get_blocked()[0]
        self.assertEqual(row["ports"], [21, 22])
        self.assertEqual(row["attack_type"], "SSH, FTP")

    def test_widen_to_full_block_removes_port_rules(self):
        b = self.make(scope="service")
        b.block("1.2.3.4", attack_type="SSH")
        b.cmds.clear()
        self.assertTrue(b.block("1.2.3.4", attack_type="PASSWORD_SPRAY"))
        self.assertEqual(b.cmds, ["iptables -I INPUT 1 -s 1.2.3.4 -j DROP",
                                  "iptables -D INPUT -s 1.2.3.4 -p tcp --dport 22 -j DROP"])
        self.assertIsNone(b.get_blocked()[0]["ports"])
        b.cmds.clear()
        b.unblock("1.2.3.4")
        self.assertEqual(b.cmds, ["iptables -D INPUT -s 1.2.3.4 -j DROP"])

    def test_failed_rule_does_not_record_block(self):
        b = self.make(scope="service")
        b.fail_next = True
        self.assertFalse(b.block("1.2.3.4", attack_type="HTTP"))
        self.assertFalse(b.is_blocked("1.2.3.4"))

    def test_state_roundtrip_restores_port_rules(self):
        b = self.make(scope="service")
        b.block("1.2.3.4", attack_type="FTP")
        b2 = self.make(scope="service")
        self.assertEqual(b2.cmds, ["iptables -I INPUT 1 -s 1.2.3.4 -p tcp --dport 21 -j DROP"])
        self.assertEqual(b2.get_blocked()[0]["ports"], [21])

    def test_legacy_state_without_ports_is_full_block(self):
        with open(self.state, "w") as fh:
            fh.write('{"9.9.9.9": {"blocked_at": 1, "attempts": 5, "attack_type": "SSH", '
                     '"usernames": [], "geo": null, "unblock_at": null}}')
        b = self.make()
        self.assertEqual(b.cmds, ["iptables -I INPUT 1 -s 9.9.9.9 -j DROP"])

    def test_invalid_scope_rejected(self):
        with self.assertRaises(ValueError):
            self.make(scope="bogus")


class TestProtection(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.state = os.path.join(self._dir.name, "blocked.json")

    def make(self, **kw):
        return Recorder(enabled=True, auto_unblock_after=0, state_file=self.state, **kw)

    def test_loopback_linklocal_never_blocked(self):
        b = self.make()
        for ip in ("127.0.0.1", "::1", "169.254.1.1", "fe80::1"):
            self.assertFalse(b.block(ip, attack_type="SSH"), ip)
        self.assertEqual(b.cmds, [])

    def test_own_addresses_never_blocked(self):
        with mock.patch("utils.ip_utils.local_addresses", return_value={"203.0.113.50"}):
            b = self.make()
            self.assertFalse(b.block("203.0.113.50", attack_type="HTTP"))
            self.assertTrue(b.block("203.0.113.51", attack_type="HTTP"))

    def test_trusted_proxies_never_blocked(self):
        with mock.patch("utils.ip_utils.local_addresses", return_value=set()):
            b = self.make(protected_nets=parse_cidr_list(["198.51.100.0/24"]))
            self.assertFalse(b.block("198.51.100.7", attack_type="HTTP"))
            self.assertTrue(b.block("203.0.113.7", attack_type="HTTP"))

    def test_private_blocked_by_default_protected_on_request(self):
        with mock.patch("utils.ip_utils.local_addresses", return_value=set()):
            self.assertTrue(self.make().block("192.168.50.7", attack_type="SSH"))
            os.remove(self.state)
            b = self.make(protect_private=True)
            self.assertFalse(b.block("192.168.50.7", attack_type="SSH"))
            self.assertFalse(b.block("10.1.2.3", attack_type="SSH"))
            self.assertFalse(b.block("fd00::5", attack_type="SSH"))
            self.assertTrue(b.block("8.8.4.4", attack_type="SSH"))


if __name__ == "__main__":
    unittest.main()
