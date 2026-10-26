"""Tests for the command line interface (argument parsing and end-to-end runs)."""

import os
import subprocess
import sys
import tempfile
import unittest

import main as brutus_main
import utils.i18n as i18n

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(*args, timeout=60):
    return subprocess.run(
        [sys.executable, os.path.join(ROOT, "main.py"), "--lang", "en", *args],
        capture_output=True, text=True, timeout=timeout, cwd=ROOT,
    )


class TestArgParsing(unittest.TestCase):

    def setUp(self):
        i18n.set_lang("en")
        self.parser = brutus_main.build_arg_parser(i18n.get_T())

    def test_defaults(self):
        args = self.parser.parse_args([])
        self.assertIsNone(args.threshold)
        self.assertFalse(args.test)
        self.assertIsNone(args.replay)

    def test_options_are_parsed(self):
        args = self.parser.parse_args(
            ["--threshold", "3", "--window", "30", "--replay", "a.log", "--type", "linux_ssh"]
        )
        self.assertEqual((args.threshold, args.window), (3, 30))
        self.assertEqual(args.replay, "a.log")

    def test_invalid_number_is_rejected(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["--threshold", "many"])

    def test_cli_overrides_are_merged_into_config(self):
        args = self.parser.parse_args([
            "--threshold", "2", "--cooldown", "9", "--log", "/tmp/x.log",
            "--discord-url", "https://discord.example/hook",
        ])
        cfg = brutus_main.merge_cli_overrides({"detection": {"threshold": 5}}, args)
        self.assertEqual(cfg["detection"]["threshold"], 2)
        self.assertEqual(cfg["detection"]["alert_cooldown"], 9)
        self.assertEqual(cfg["log_files"][-1]["path"], "/tmp/x.log")
        self.assertTrue(cfg["discord"]["enabled"])

    def test_config_values_survive_when_no_override_given(self):
        args = self.parser.parse_args([])
        cfg = brutus_main.merge_cli_overrides({"detection": {"threshold": 5}}, args)
        self.assertEqual(cfg["detection"]["threshold"], 5)


class TestEndToEnd(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.config = os.path.join(self._dir.name, "config.yaml")
        with open(self.config, "w", encoding="utf-8") as fh:
            fh.write("detection:\n  threshold: 5\n  time_window: 60\n  alert_cooldown: 300\n"
                     "reports:\n  save_to_file: false\n")

    def test_version(self):
        res = _run("--version")
        self.assertEqual(res.returncode, 0)
        self.assertIn(brutus_main.VERSION, res.stdout + res.stderr)

    def test_missing_config_exits_with_error(self):
        res = _run("--config", os.path.join(self._dir.name, "nope.yaml"))
        self.assertEqual(res.returncode, 1)

    def test_replay_reports_alert_and_summary(self):
        log = os.path.join(self._dir.name, "auth.log")
        with open(log, "w", encoding="utf-8") as fh:
            for s in range(10, 17):
                fh.write(f"Jan  5 03:12:{s:02d} srv sshd[1]: Failed password for root "
                         f"from 203.0.113.7 port 22 ssh2\n")
        res = _run("--config", self.config, "--replay", log)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("203.0.113.7", res.stdout)
        self.assertIn("alerts: 1", res.stdout)

    def test_replay_missing_file_fails(self):
        res = _run("--config", self.config, "--replay", os.path.join(self._dir.name, "x.log"))
        self.assertEqual(res.returncode, 1)
        self.assertIn("Cannot replay", res.stderr)

    def test_update_threat_db_without_network_keeps_running(self):
        # No sources reachable (invalid URL) → exits 0 and does not crash.
        with open(self.config, "a", encoding="utf-8") as fh:
            fh.write(f"threat_intel:\n  enabled: true\n  db_path: {self._dir.name}/ti.txt\n"
                     "  timeout: 2\n  sources:\n    - \"http://127.0.0.1:1/none.txt\"\n")
        res = _run("--config", self.config, "--update-threat-db")
        self.assertEqual(res.returncode, 0, res.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
