"""Tests for the setup wizard (--setup) and the configuration check (--check)."""

import os
import stat
import subprocess
import sys
import tempfile
import unittest

import yaml

import utils.i18n as i18n
from detector.setup_wizard import (
    FAIL, OK, WARN, build_config, check_config, run_check, run_setup, webhook_looks_valid,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DISCORD = "https://discord.com/api/webhooks/1/abc"
SLACK = "https://hooks.slack.com/services/T/B/x"

i18n.set_lang("en")
T = i18n.get_T()


def _scripted(*answers):
    it = iter(answers)

    def ask(prompt):
        try:
            return next(it)
        except StopIteration:
            raise EOFError from None
    return ask


def _keys(results, level=None):
    return [k for lvl, k, _ in results if level is None or lvl == level]


class TestWebhookFormat(unittest.TestCase):
    def test_valid_and_invalid(self):
        self.assertTrue(webhook_looks_valid("Discord", DISCORD))
        self.assertTrue(webhook_looks_valid("Slack", SLACK))
        self.assertFalse(webhook_looks_valid("Discord", "http://discord.com/api/webhooks/1/a"))
        self.assertFalse(webhook_looks_valid("Slack", DISCORD))


class TestBuildConfig(unittest.TestCase):
    def test_blocker_modes(self):
        def blocker(mode):
            return build_config([], False, 5, 60, "", "", mode, [])["blocker"]
        self.assertEqual(blocker("off"), {"enabled": False, "dry_run": False})
        self.assertEqual(blocker("dry-run"), {"enabled": True, "dry_run": True})
        self.assertEqual(blocker("on"), {"enabled": True, "dry_run": False})

    def test_whitelist_always_keeps_loopback(self):
        cfg = build_config([], False, 5, 60, "", "", "off", ["10.0.0.0/8"])
        self.assertEqual(cfg["whitelist"], ["127.0.0.1", "::1", "10.0.0.0/8"])


class TestSetupWizard(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = os.path.join(self._dir.name, "config.yaml")
        self.lines = []

    def _run(self, *answers, files=(), journald=False):
        return run_setup(self.path, T, ask=_scripted(*answers), out=self.lines.append,
                         detect=lambda: {"files": list(files), "journald": journald})

    def test_writes_working_config_with_private_permissions(self):
        log = os.path.join(self._dir.name, "auth.log")
        # use log? / threshold / window / discord / slack / blocker / whitelist
        code = self._run("y", "3", "30", DISCORD, "", "dry-run", "192.168.1.0/24", files=[log])
        self.assertEqual(code, 0)
        with open(self.path, encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertEqual(cfg["detection"], {"threshold": 3, "time_window": 30})
        self.assertEqual(cfg["log_files"][0]["path"], log)
        self.assertTrue(cfg["discord"]["enabled"])
        self.assertFalse(cfg["slack"]["enabled"])
        self.assertTrue(cfg["blocker"]["dry_run"])
        self.assertIn("192.168.1.0/24", cfg["whitelist"])
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_invalid_input_is_reprompted(self):
        code = self._run("/var/log/custom.log", "abc", "0", "5", "60",
                         "https://evil.example/hook", DISCORD, "", "maybe", "off",
                         "not-an-ip", "")
        self.assertEqual(code, 0)
        with open(self.path, encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertEqual(cfg["detection"]["threshold"], 5)
        self.assertEqual(cfg["discord"]["webhook_url"], DISCORD)
        self.assertEqual(cfg["log_files"][0]["path"], "/var/log/custom.log")
        self.assertIn(T["wz_bad_number"], self.lines)
        self.assertIn(T["wz_bad_webhook"] % "Discord", self.lines)
        self.assertIn(T["wz_bad_whitelist"], self.lines)

    def test_journald_offered_when_no_log_file(self):
        self._run("y", "5", "60", "", "", "off", "", journald=True)
        with open(self.path, encoding="utf-8") as fh:
            self.assertTrue(yaml.safe_load(fh)["journald"]["enabled"])

    def test_existing_config_is_kept_unless_confirmed(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("original: true\n")
        self.assertEqual(self._run("n"), 1)
        with open(self.path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "original: true\n")

    def test_overwrite_makes_backup(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("original: true\n")
        self.assertEqual(self._run("y", "", "", "", "", "", "", ""), 0)
        with open(self.path + ".bak", encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "original: true\n")

    def test_aborted_input_writes_nothing(self):
        self.assertEqual(self._run(), 1)  # scripted input exhausted -> EOF-like abort
        self.assertFalse(os.path.exists(self.path))


class TestCheckConfig(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.log = os.path.join(self._dir.name, "auth.log")
        open(self.log, "w").close()
        self.base = {
            "log_files": [{"path": self.log, "type": "linux_ssh", "enabled": True}],
            "reports": {"output_path": os.path.join(self._dir.name, "alerts.jsonl")},
        }

    def check(self, cfg=None, **kw):
        kw.setdefault("is_root", False)
        kw.setdefault("which", lambda name: "/usr/bin/" + name)
        return check_config(cfg or self.base, **kw)

    def test_healthy_config_has_no_failures(self):
        results = self.check()
        self.assertNotIn(FAIL, [lvl for lvl, _, _ in results])
        self.assertIn("ck_log_ok", _keys(results, OK))
        self.assertIn("ck_no_channels", _keys(results, WARN))

    def test_no_sources_fails(self):
        self.assertIn("ck_no_sources", _keys(self.check({"log_files": []}), FAIL))

    def test_missing_log_warns_and_unknown_parser_fails(self):
        cfg = {"log_files": [{"path": "/nope/auth.log", "type": "linux_ssh"},
                             {"path": self.log, "type": "bogus"}]}
        results = self.check(cfg)
        self.assertIn("ck_log_missing", _keys(results, WARN))
        self.assertIn("ck_log_parser", _keys(results, FAIL))

    def test_disabled_log_files_are_ignored(self):
        cfg = {"log_files": [{"path": "/nope", "type": "linux_ssh", "enabled": False}]}
        self.assertIn("ck_no_sources", _keys(self.check(cfg), FAIL))

    def test_blocker_requirements(self):
        cfg = dict(self.base, blocker={"enabled": True})
        self.assertIn("ck_blocker_noroot", _keys(self.check(cfg), FAIL))
        self.assertIn("ck_blocker_noipt", _keys(self.check(cfg, which=lambda n: None, is_root=True), FAIL))
        self.assertIn("ck_blocker_ok", _keys(self.check(cfg, is_root=True), OK))
        dry = dict(self.base, blocker={"enabled": True, "dry_run": True})
        self.assertIn("ck_blocker_dry", _keys(self.check(dry), OK))

    def test_webhooks_are_validated_without_network(self):
        cfg = dict(self.base, discord={"enabled": True, "webhook_url": "nope"},
                   slack={"enabled": True, "webhook_url": SLACK})
        results = self.check(cfg)
        self.assertIn("ck_hook_bad", _keys(results, FAIL))
        self.assertIn("ck_hook_ok", _keys(results, OK))

    def test_journald_requires_journalctl(self):
        cfg = dict(self.base, journald={"enabled": True})
        self.assertIn("ck_journal_missing", _keys(self.check(cfg, which=lambda n: None), FAIL))

    def test_syslog_port_in_use_fails(self):
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as busy:
            busy.bind(("127.0.0.1", 0))
            port = busy.getsockname()[1]
            cfg = dict(self.base, syslog={"enabled": True, "host": "127.0.0.1",
                                          "port": port, "protocol": "udp"})
            self.assertIn("ck_syslog_fail", _keys(self.check(cfg), FAIL))

    def test_threat_intel_without_db_warns(self):
        cfg = dict(self.base, threat_intel={"enabled": True,
                                            "db_path": os.path.join(self._dir.name, "none.txt")})
        self.assertIn("ck_ti_nodb", _keys(self.check(cfg), WARN))

    def test_run_check_exit_code_and_summary(self):
        lines = []
        self.assertEqual(run_check("c.yaml", self.base, T, out=lines.append,
                                   is_root=False, which=lambda n: "/x"), 0)
        self.assertIn(T["ck_ready"], lines)
        lines.clear()
        self.assertEqual(run_check("c.yaml", {"log_files": []}, T, out=lines.append,
                                   is_root=False, which=lambda n: "/x"), 1)
        self.assertNotIn(T["ck_ready"], lines)

    def test_every_check_message_is_translated(self):
        for lang in ("pl", "en"):
            strings = i18n.STRINGS[lang]
            for key in [k for k in i18n.STRINGS["en"] if k.startswith(("ck_", "wz_"))]:
                self.assertIn(key, strings, f"{key} missing in {lang}")


class TestCli(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "main.py"), "--lang", "en", *args],
            capture_output=True, text=True, timeout=60, cwd=ROOT)

    def test_check_command_reports_problems_with_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "config.yaml")
            with open(cfg, "w", encoding="utf-8") as fh:
                fh.write("log_files: []\nreports:\n  save_to_file: false\n")
            res = self._run("--config", cfg, "--check")
            self.assertEqual(res.returncode, 1, res.stderr)
            self.assertIn("No log source enabled", res.stdout)

    def test_missing_config_points_to_setup(self):
        res = self._run("--config", "/nonexistent/config.yaml")
        self.assertEqual(res.returncode, 1)
        self.assertIn("--setup", res.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
