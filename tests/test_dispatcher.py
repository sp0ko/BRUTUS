"""Integration tests for AlertDispatcher (blocking, threat intel, notifications)."""

import io
import ipaddress
import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock

from detector.alerts.console_alert import ConsoleAlert
from detector.tracker import AlertEvent
from main import AlertDispatcher
from utils.geo import GeoLocator
from utils.threat_intel import ThreatIntel


def _event(ip="203.0.113.50"):
    return AlertEvent(
        ip=ip, count=6, time_window=60, attack_type="SSH",
        usernames=["root"], log_sources=["/var/log/auth.log"],
        first_seen=time.time() - 5, last_seen=time.time(),
        successful_login=False,
    )


def _wait_for(mock, timeout=2.0):
    end = time.time() + timeout
    while time.time() < end:
        if mock.called:
            return True
        time.sleep(0.01)
    return False


class TestAlertDispatcher(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.out = io.StringIO()

    def _threat_intel(self, entries):
        db = os.path.join(self._dir.name, "ti.txt")
        with open(db, "w", encoding="utf-8") as fh:
            for cidr, src in entries:
                fh.write(f"{cidr}\t{src}\n")
        return ThreatIntel(enabled=True, db_path=db)

    def _dispatcher(self, **kw):
        defaults = dict(
            console=ConsoleAlert(stream=self.out), discord=None, slack=None,
            report_manager=None, geo=GeoLocator(enabled=False), blocker=MagicMock(),
        )
        defaults.update(kw)
        return AlertDispatcher(**defaults)

    def test_console_output_and_block(self):
        d = self._dispatcher()
        d.dispatch(_event())
        self.assertIn("203.0.113.50", self.out.getvalue())
        d.blocker.block.assert_called_once()
        self.assertEqual(d.blocker.block.call_args.kwargs["ip"], "203.0.113.50")

    def test_whitelisted_ip_is_never_blocked(self):
        d = self._dispatcher(whitelist_nets=[ipaddress.ip_network("203.0.113.0/24")])
        d.dispatch(_event())
        d.blocker.block.assert_not_called()
        self.assertIn("203.0.113.50", self.out.getvalue())

    def test_threat_intel_match_tags_event(self):
        ti = self._threat_intel([("203.0.113.50", "feodo_tracker")])
        d = self._dispatcher(threat_intel=ti)
        ev = _event()
        d.dispatch(ev)
        self.assertEqual(ev.threat_intel, "feodo_tracker")
        d.blocker.block.assert_called_once()

    def test_alert_only_skips_block_on_threat_intel_match(self):
        ti = self._threat_intel([("203.0.113.0/24", "spamhaus_drop")])
        d = self._dispatcher(threat_intel=ti, ti_action="alert_only")
        d.dispatch(_event())
        d.blocker.block.assert_not_called()
        self.assertIn("203.0.113.50", self.out.getvalue())

    def test_alert_only_still_blocks_unknown_ip(self):
        ti = self._threat_intel([("198.51.100.1", "cins_army")])
        d = self._dispatcher(threat_intel=ti, ti_action="alert_only")
        d.dispatch(_event())
        d.blocker.block.assert_called_once()

    def test_discord_slack_and_report_are_notified(self):
        discord, slack, report = MagicMock(), MagicMock(), MagicMock()
        d = self._dispatcher(discord=discord, slack=slack, report_manager=report, blocker=None)
        d.dispatch(_event())
        self.assertTrue(_wait_for(discord.send))
        self.assertTrue(_wait_for(slack.send))
        self.assertTrue(_wait_for(report.save))

    def test_without_blocker_dispatch_does_not_fail(self):
        d = self._dispatcher(blocker=None)
        d.dispatch(_event())
        self.assertIn("203.0.113.50", self.out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
