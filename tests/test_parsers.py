"""
Testy jednostkowe dla parserów logów.

Uruchomienie:
    python -m pytest tests/ -v
    # lub:
    python -m unittest tests/test_parsers.py -v
"""

import time
import unittest

from detector.parsers.linux_ssh import LinuxSSHParser
from detector.parsers.windows_evtx import WindowsEvtxParser


class TestLinuxSSHParser(unittest.TestCase):

    def setUp(self):
        self.parser = LinuxSSHParser()

    def _parse(self, line):
        return self.parser.parse_line(line)

    # ------------------------------------------------------------------
    # Nieudane logowania
    # ------------------------------------------------------------------

    def test_failed_password(self):
        line = "May 20 10:23:45 host sshd[1234]: Failed password for root from 203.0.113.1 port 22 ssh2"
        ev = self._parse(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.event_type, "FAILED")
        self.assertEqual(ev.ip, "203.0.113.1")
        self.assertEqual(ev.username, "root")

    def test_failed_password_invalid_user(self):
        line = "May 20 10:23:45 host sshd[1234]: Failed password for invalid user hacker from 198.51.100.5 port 22 ssh2"
        ev = self._parse(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.event_type, "FAILED")
        self.assertEqual(ev.ip, "198.51.100.5")
        self.assertEqual(ev.username, "hacker")

    def test_invalid_user(self):
        line = "May 20 10:23:46 host sshd[1234]: Invalid user testuser from 203.0.113.2 port 22"
        ev = self._parse(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.event_type, "FAILED")
        self.assertEqual(ev.ip, "203.0.113.2")
        self.assertEqual(ev.username, "testuser")

    def test_preauth_disconnect(self):
        line = "May 20 10:23:47 host sshd[1234]: Disconnected from invalid user admin 203.0.113.3 port 54321 [preauth]"
        ev = self._parse(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.event_type, "FAILED")
        self.assertEqual(ev.ip, "203.0.113.3")

    def test_pam_auth_failure(self):
        line = "May 20 10:23:48 host sshd[1234]: pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=203.0.113.4 user=nobody"
        ev = self._parse(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.event_type, "FAILED")
        self.assertEqual(ev.ip, "203.0.113.4")

    def test_xrdp_failed(self):
        line = "May 20 10:23:49 host xrdp-sesman[1234]: Authentication failed. Username: johndoe from 203.0.113.5"
        ev = self._parse(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.event_type, "FAILED")
        self.assertEqual(ev.attack_type, "RDP")
        self.assertEqual(ev.ip, "203.0.113.5")

    # ------------------------------------------------------------------
    # Udane logowania
    # ------------------------------------------------------------------

    def test_accepted_password(self):
        line = "May 20 10:24:00 host sshd[1234]: Accepted password for ubuntu from 192.168.1.10 port 22 ssh2"
        ev = self._parse(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.event_type, "SUCCESS")
        self.assertEqual(ev.ip, "192.168.1.10")
        self.assertEqual(ev.username, "ubuntu")

    def test_accepted_publickey(self):
        line = "May 20 10:24:01 host sshd[1234]: Accepted publickey for deploy from 192.168.1.20 port 22 ssh2"
        ev = self._parse(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.event_type, "SUCCESS")
        self.assertEqual(ev.username, "deploy")

    # ------------------------------------------------------------------
    # Linie do pominięcia
    # ------------------------------------------------------------------

    def test_unrelated_line_returns_none(self):
        line = "May 20 10:23:45 host cron[1234]: (root) CMD (/usr/lib/updatedb/updatedb --prunefs ...)"
        self.assertIsNone(self._parse(line))

    def test_empty_line_returns_none(self):
        self.assertIsNone(self._parse(""))
        self.assertIsNone(self._parse("   "))

    def test_system_startup_line_returns_none(self):
        line = "May 20 10:00:00 host sshd[1234]: Server listening on 0.0.0.0 port 22."
        self.assertIsNone(self._parse(line))

    # ------------------------------------------------------------------
    # IPv6
    # ------------------------------------------------------------------

    def test_ipv6_address(self):
        line = "May 20 10:23:45 host sshd[1234]: Failed password for root from ::1 port 22 ssh2"
        ev = self._parse(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.ip, "::1")

    # ------------------------------------------------------------------
    # Timestamp parsing
    # ------------------------------------------------------------------

    def test_timestamp_is_float(self):
        line = "May 20 10:23:45 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
        ev = self._parse(line)
        self.assertIsNotNone(ev)
        self.assertIsInstance(ev.timestamp, float)
        self.assertGreater(ev.timestamp, 0)

    def test_line_without_timestamp_uses_now(self):
        line = "sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
        before = time.time()
        ev = self._parse(line)
        after = time.time()
        self.assertIsNotNone(ev)
        self.assertGreaterEqual(ev.timestamp, before)
        self.assertLessEqual(ev.timestamp, after)


class TestWindowsEvtxParser(unittest.TestCase):

    def setUp(self):
        self.parser = WindowsEvtxParser()

    def _make_xml(self, event_id, ip, username="testuser", logon_type="3"):
        """Generuje minimalny XML Event Log dla testów."""
        return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="2026-05-20T10:23:45.000000Z"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">{username}</Data>
    <Data Name="IpAddress">{ip}</Data>
    <Data Name="LogonType">{logon_type}</Data>
  </EventData>
</Event>"""

    def test_failed_logon_4625(self):
        xml = self._make_xml(4625, "203.0.113.10", "Administrator", "3")
        ev = self.parser.parse_line(xml)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.event_type, "FAILED")
        self.assertEqual(ev.ip, "203.0.113.10")
        self.assertEqual(ev.username, "Administrator")

    def test_successful_logon_4624(self):
        xml = self._make_xml(4624, "203.0.113.11", "john", "10")
        ev = self.parser.parse_line(xml)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.event_type, "SUCCESS")
        self.assertEqual(ev.ip, "203.0.113.11")

    def test_rdp_logon_type_detected(self):
        xml = self._make_xml(4625, "1.2.3.4", "admin", "10")  # logon type 10 = RDP
        ev = self.parser.parse_line(xml)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.attack_type, "RDP")

    def test_network_logon_type_detected(self):
        xml = self._make_xml(4625, "1.2.3.4", "admin", "3")  # logon type 3 = Network
        ev = self.parser.parse_line(xml)
        self.assertIsNotNone(ev)
        self.assertIn("SMB", ev.attack_type)

    def test_localhost_ip_skipped(self):
        xml = self._make_xml(4625, "127.0.0.1", "system")
        ev = self.parser.parse_line(xml)
        self.assertIsNone(ev, "127.0.0.1 powinien być pomijany")

    def test_loopback_ipv6_skipped(self):
        xml = self._make_xml(4625, "::1", "system")
        ev = self.parser.parse_line(xml)
        self.assertIsNone(ev, "::1 powinien być pomijany")

    def test_ipv4_mapped_ipv6_stripped(self):
        xml = self._make_xml(4625, "::ffff:203.0.113.5", "admin")
        ev = self.parser.parse_line(xml)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.ip, "203.0.113.5", "Prefiks ::ffff: powinien być usunięty")

    def test_unrelated_event_id_returns_none(self):
        xml = self._make_xml(4688, "1.2.3.4", "admin")   # 4688 = process creation
        ev = self.parser.parse_line(xml)
        self.assertIsNone(ev)

    def test_non_xml_line_returns_none(self):
        ev = self.parser.parse_line("To nie jest XML")
        self.assertIsNone(ev)

    def test_timestamp_parsed_from_xml(self):
        xml = self._make_xml(4625, "5.5.5.5")
        ev = self.parser.parse_line(xml)
        self.assertIsNotNone(ev)
        self.assertIsInstance(ev.timestamp, float)
        self.assertGreater(ev.timestamp, 0)


class TestParserRegistry(unittest.TestCase):

    def test_get_linux_parser(self):
        from detector.parsers import get_parser
        p = get_parser("linux_ssh")
        self.assertIsInstance(p, LinuxSSHParser)

    def test_get_windows_parser(self):
        from detector.parsers import get_parser
        p = get_parser("windows_evtx")
        self.assertIsInstance(p, WindowsEvtxParser)

    def test_unknown_parser_raises(self):
        from detector.parsers import get_parser
        with self.assertRaises(ValueError):
            get_parser("coś_nieistniejącego")


if __name__ == "__main__":
    unittest.main(verbosity=2)
