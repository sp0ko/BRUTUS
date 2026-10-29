#!/usr/bin/env python3
"""
BRUTU$ v1.14.2
=============
Real-time SSH/RDP brute-force attack detector.

Examples
--------
  python main.py                         # default config.yaml
  python main.py --setup                 # interactive setup wizard
  python main.py --check                 # verify config, permissions, ports
  python main.py --config custom.yaml
  python main.py --threshold 3 --window 30
  python main.py --log /var/log/auth.log --type linux_ssh
  python main.py --discord-url "https://discord.com/api/webhooks/..."
  python main.py --test                  # simulate attack
  python main.py --stats                 # show statistics and exit
  python main.py --lang pl               # force Polish language
  python main.py --lang en               # force English language
"""

import argparse
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime
from typing import Optional

import yaml

from detector.tracker import BruteForceTracker, AlertEvent
from detector.offsets import OffsetStore
from detector.state import StatePersister, load_state
from detector.log_monitor import LogMonitor
from detector.report_manager import ReportManager
from detector.alerts.console_alert import ConsoleAlert
from detector.alerts.discord_alert import DiscordAlert
from detector.alerts.slack_alert import SlackAlert
import utils.i18n as i18n
from utils.geo import GeoLocator
from utils.blocker import IPBlocker
from utils.ip_utils import local_addresses, parse_cidr_list
from utils.threat_intel import ThreatIntel

VERSION = "1.14.2"
DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), "config.yaml")

log = logging.getLogger("brute-force-detector")

BANNER = r"""
 ██████╗ ██████╗ ██╗   ██╗████████╗██╗   ██╗███████╗
 ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██║   ██║██╔════╝
 ██████╔╝██████╔╝██║   ██║   ██║   ██║   ██║███████╗
 ██╔══██╗██╔══██╗██║   ██║   ██║   ██║   ██║╚════██║
 ██████╔╝██║  ██║╚██████╔╝   ██║   ╚██████╔╝███████║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚══════╝  $  v{version}

  SSH & RDP Brute-Force Detector  •  Discord  •  Slack  •  GeoIP
""".format(version=VERSION)

# ──────────────────────────────────────────────────────────────────────────────


def _start_lang_listener(stop_event: threading.Event) -> None:
    """Start a background daemon thread that reads 'lang' from stdin to switch language."""
    if not sys.stdin.isatty():
        return

    def _listener() -> None:
        while not stop_event.is_set():
            try:
                line = sys.stdin.readline()
                if not line:          # EOF
                    break
                if line.strip().lower() == "lang":
                    new_lang = i18n.select_language()
                    i18n.set_lang(new_lang)
                    print(i18n.get_T()["lang_changed"])
            except (EOFError, OSError):
                break

    threading.Thread(target=_listener, daemon=True, name="lang-listener").start()


# ──────────────────────────────────────────────────────────────────────────────

def setup_logging(level_str: str = "INFO", log_file: Optional[str] = None) -> None:
    level = getattr(logging, level_str.upper(), logging.INFO)
    handlers: list = [logging.StreamHandler(sys.stdout)]
    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        handlers=handlers,
    )


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def merge_cli_overrides(cfg: dict, args: argparse.Namespace) -> dict:
    det = cfg.setdefault("detection", {})
    if args.threshold is not None:
        det["threshold"] = args.threshold
    if args.window is not None:
        det["time_window"] = args.window
    if args.cooldown is not None:
        det["alert_cooldown"] = args.cooldown
    if args.log:
        cfg.setdefault("log_files", []).append({
            "path": args.log,
            "type": args.type or "linux_ssh",
            "enabled": True,
        })
    if args.discord_url:
        cfg.setdefault("discord", {}).update({"webhook_url": args.discord_url, "enabled": True})
    if args.slack_url:
        cfg.setdefault("slack", {}).update({"webhook_url": args.slack_url, "enabled": True})
    if getattr(args, "geoip_db", None):
        cfg.setdefault("geo", {})["mmdb_path"] = args.geoip_db
    return cfg


# ──────────────────────────────────────────────────────────────────────────────

class AlertDispatcher:

    def __init__(
        self,
        console: ConsoleAlert,
        discord: Optional[DiscordAlert],
        slack: Optional[SlackAlert],
        report_manager: Optional[ReportManager],
        geo: GeoLocator,
        blocker: Optional[IPBlocker] = None,
        whitelist_nets: Optional[list] = None,
        threat_intel: Optional[ThreatIntel] = None,
        ti_action: str = "block",
    ) -> None:
        self.console = console
        self.discord = discord
        self.slack = slack
        self.report_manager = report_manager
        self.geo = geo
        self.blocker = blocker
        self.whitelist_nets = whitelist_nets or []
        self.threat_intel = threat_intel
        self.ti_action = ti_action  # "block" | "alert_only"

    def dispatch(self, event: AlertEvent) -> None:
        from utils.ip_utils import ip_in_list
        geo_info = self.geo.lookup(event.ip)
        event.geo_info = geo_info

        # Threat intel enrichment — check before sending alerts
        ti_matched = False
        if self.threat_intel:
            match = self.threat_intel.is_known_bad(event.ip)
            if match:
                event.threat_intel = match
                ti_matched = True
                log.warning("THREAT INTEL MATCH: %s ← %s", event.ip, match)

        self.console.send(event, geo=geo_info)

        for handler in (self.discord, self.slack):
            if handler:
                threading.Thread(target=handler.send, args=(event,), kwargs={"geo": geo_info}, daemon=True).start()

        if self.report_manager:
            threading.Thread(target=self.report_manager.save, args=(event,), kwargs={"geo": geo_info}, daemon=True).start()

        # Active defense — block attacker unless whitelisted
        # When ti_action=alert_only and IP is in threat intel, skip the block
        skip_block = ti_matched and self.ti_action == "alert_only"
        if event.catch_up:
            # The attack may be long over (the log was written while we were down)
            skip_block = True
            log.info("Catch-up alert for %s: alert sent, IP not blocked", event.ip)
        if self.blocker and not skip_block and not ip_in_list(event.ip, self.whitelist_nets):
            self.blocker.block(
                ip=event.ip,
                attempts=event.count,
                attack_type=event.attack_type,
                usernames=event.usernames,
                geo=geo_info,
            )


# ──────────────────────────────────────────────────────────────────────────────

def print_blocked(blocker: IPBlocker, T: dict) -> None:
    rows = blocker.get_blocked()
    if not rows:
        print(T["blk_none"])
        return
    hdr = T["blk_header"]
    print(hdr)
    print("-" * 90)
    for r in rows:
        ts  = datetime.fromtimestamp(r["blocked_at"]).strftime("%Y-%m-%d %H:%M:%S")
        rem = T["blk_permanent"] if r["remaining_s"] is None else T["blk_seconds"] % r["remaining_s"]
        geo = ""
        if r["geo"]:
            geo = ", ".join(str(r["geo"][k]) for k in ("country", "city") if r["geo"].get(k) and r["geo"][k] not in ("", "unknown"))
        users = ", ".join(r["usernames"][:4]) or "—"
        scope = ",".join(map(str, r["ports"])) if r.get("ports") else "all"
        print(f"{r['ip']:<20} {r['attack_type']:<18} {r['attempts']:>9}  {ts:<20}  {rem:>10}  {users}  [ports: {scope}]")
    print()


def run_test_mode(dispatcher: AlertDispatcher, tracker: BruteForceTracker, T: dict) -> None:
    print(T["test_start"])

    scenarios = [
        {"ip": "203.0.113.42",  "users": ["root", "admin", "Administrator"], "type": "SSH",  "src": "/var/log/auth.log (test)",  "count": 8},
        {"ip": "198.51.100.17", "users": ["Administrator", "admin"],          "type": "RDP",  "src": "Security.evtx (test)",      "count": 12},
        {"ip": "192.0.2.55",    "users": ["ubuntu", "deploy"],                "type": "SSH",  "src": "/var/log/auth.log (test)",  "count": 6, "success": True},
    ]

    for s in scenarios:
        users_cycle = s["users"] * ((s["count"] // len(s["users"])) + 2)
        for i in range(s["count"]):
            alert = tracker.record_failed(
                ip=s["ip"], username=users_cycle[i],
                attack_type=s["type"], log_source=s["src"],
            )
            if alert:
                dispatcher.dispatch(alert)
                break

        if s.get("success"):
            time.sleep(0.1)
            alert = tracker.record_success(
                ip=s["ip"], username=s["users"][0],
                attack_type=s["type"], log_source=s["src"],
            )
            if alert:
                dispatcher.dispatch(alert)

        time.sleep(0.5)

    print(T["test_end"])


def run_replay(path: str, cfg: dict, args: argparse.Namespace, T: dict,
               threat_intel: ThreatIntel) -> int:
    """Analyse an existing log offline: console output only, nothing is blocked or sent."""
    from detector.replay import replay_file

    det_cfg = cfg.get("detection", {})
    tracker = BruteForceTracker(
        threshold=det_cfg.get("threshold", 5),
        time_window=det_cfg.get("time_window", 60),
        alert_cooldown=det_cfg.get("alert_cooldown", 300),
        success_failure_threshold=det_cfg.get("success_failure_threshold", 3),
        spray_username_threshold=det_cfg.get("spray_username_threshold", 8),
        slow_threshold=det_cfg.get("slow_threshold", 0),
        slow_window=det_cfg.get("slow_window", 3600),
    )
    dispatcher = AlertDispatcher(
        console=ConsoleAlert(), discord=None, slack=None, report_manager=None,
        geo=GeoLocator(enabled=False), blocker=None,
        threat_intel=threat_intel,
    )
    parser_type = args.type or "linux_ssh"
    print(T["replay_start"] % (path, parser_type))
    try:
        result = replay_file(
            path, parser_type, tracker, on_alert=dispatcher.dispatch,
            whitelist_nets=parse_cidr_list(cfg.get("whitelist", [])),
        )
    except (OSError, ValueError) as exc:
        print(T["replay_err"] % (path, exc), file=sys.stderr)
        return 1

    print(T["replay_summary"] % (result.lines, result.failed, result.success, len(result.alerts)))
    if result.top_ips:
        print(T["replay_top"])
        for ip, n in result.top_ips[:10]:
            print(f"  {ip:<40} {n}")
    return 0


def print_stats(tracker: BruteForceTracker, T: dict) -> None:
    stats = tracker.get_stats()
    if not stats:
        print(T["no_activity"])
        return
    col_attempts = T["col_attempts"]
    col_type     = T["col_type"]
    col_users    = T["col_users"]
    print(f"\n{T['col_ip']:<20} {col_attempts:>8}  {col_type:<15}  {col_users}")
    print("-" * 70)
    for ip, info in sorted(stats.items(), key=lambda x: -x[1]["count"]):
        print(
            f"{ip:<20} {info['count']:>8}  "
            f"{', '.join(info['attack_types']):<15}  "
            f"{', '.join(info['usernames'][:5]) or '—'}"
        )
    print()


# ──────────────────────────────────────────────────────────────────────────────

def build_arg_parser(T: dict) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=T["description"],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--config",      default=DEFAULT_CONFIG, help=T["help_config"])
    p.add_argument("--log",         metavar="PATH",         help=T["help_log"])
    p.add_argument("--type",        metavar="TYPE",         help=T["help_type"])
    p.add_argument("--threshold",   type=int,               help=T["help_threshold"])
    p.add_argument("--window",      type=int,               help=T["help_window"])
    p.add_argument("--cooldown",    type=int,               help=T["help_cooldown"])
    p.add_argument("--discord-url", metavar="URL",          help=T["help_discord"])
    p.add_argument("--slack-url",   metavar="URL",          help=T["help_slack"])
    p.add_argument("--test",        action="store_true",    help=T["help_test"])
    p.add_argument("--stats",       action="store_true",    help=T["help_stats"])
    p.add_argument("--blocked",     action="store_true",    help=T["help_blocked"])
    p.add_argument("--update-threat-db", action="store_true", help=T["help_update_ti"])
    p.add_argument("--lang",        choices=["pl", "en"],   help=T["help_lang"])
    p.add_argument("--geoip-download", action="store_true", help=T["help_geoip_download"])
    p.add_argument("--geoip-db",    metavar="FILE",          help=T["help_geoip_db"])
    p.add_argument("--replay",      metavar="FILE",          help=T["help_replay"])
    p.add_argument("--report",      action="store_true",    help=T["help_report"])
    p.add_argument("--since",       default="7d",           help=T["help_since"])
    p.add_argument("--format",      choices=["text", "markdown", "json", "html"], default="text",
                   help=T["help_format"])
    p.add_argument("--output",      metavar="FILE",          help=T["help_output"])
    p.add_argument("--dashboard",   action="store_true",    help=T["help_dashboard"])
    p.add_argument("--dashboard-host", default="127.0.0.1",  help=T["help_dash_host"])
    p.add_argument("--dashboard-port", type=int, default=8765, help=T["help_dash_port"])
    p.add_argument("--version",     action="version",       version=f"BRUTU$ {VERSION}")
    p.add_argument("--setup",       action="store_true",    help=T["help_setup"])
    p.add_argument("--check",       action="store_true",    help=T["help_check"])
    return p


def run_report(path: str, args: argparse.Namespace, T: dict) -> int:
    import json as _json
    from detector.dashboard import build_summary, render_html
    from detector.stats import render_markdown, render_text
    try:
        summary = build_summary(path, args.since)
    except (ValueError, OSError) as exc:
        print(T["report_err"] % exc, file=sys.stderr)
        return 1
    if args.format == "json":
        out = _json.dumps(summary, ensure_ascii=False, indent=2)
    elif args.format == "markdown":
        out = render_markdown(summary, T)
    elif args.format == "html":
        out = render_html(summary, T, period=args.since, links=False)
    else:
        out = render_text(summary, T)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out + "\n")
        except OSError as exc:
            print(T["report_err"] % exc, file=sys.stderr)
            return 1
        print(T["report_saved"] % args.output)
    else:
        print(out)
    return 0


# ──────────────────────────────────────────────────────────────────────────────

def main() -> int:
    print(BANNER)

    # ── Language selection ────────────────────────────────────────────────────
    lang = i18n.detect_lang_flag()
    if lang is None:
        # No terminal (systemd, cron): do not wait for input, use English.
        lang = i18n.select_language() if sys.stdin.isatty() else "en"
    i18n.set_lang(lang)
    T = i18n.get_T()
    print()

    args = build_arg_parser(T).parse_args()

    if args.setup:
        from detector.setup_wizard import run_setup
        return run_setup(args.config, T)

    if args.geoip_download:
        from utils.geo import DEFAULT_MMDB, download_db
        print(T["geo_downloading"] % DEFAULT_MMDB)
        try:
            download_db(DEFAULT_MMDB)
        except Exception as exc:
            print(T["geo_download_fail"] % exc, file=sys.stderr)
            return 1
        print(T["geo_download_ok"] % DEFAULT_MMDB)
        return 0

    if not os.path.exists(args.config):
        print(T["err_config"] % args.config, file=sys.stderr)
        print(T["err_config_hint"], file=sys.stderr)
        return 1

    cfg = merge_cli_overrides(load_config(args.config), args)

    if args.check:
        from detector.setup_wizard import run_check
        return run_check(args.config, cfg, T)

    log_cfg = cfg.get("logging", {})
    setup_logging(log_cfg.get("level", "INFO"), log_cfg.get("file"))
    logger = logging.getLogger("brute-force-detector")

    det_cfg = cfg.get("detection", {})
    tracker = BruteForceTracker(
        threshold=det_cfg.get("threshold", 5),
        time_window=det_cfg.get("time_window", 60),
        alert_cooldown=det_cfg.get("alert_cooldown", 300),
        success_failure_threshold=det_cfg.get("success_failure_threshold", 3),
        spray_username_threshold=det_cfg.get("spray_username_threshold", 8),
        slow_threshold=det_cfg.get("slow_threshold", 0),
        slow_window=det_cfg.get("slow_window", 3600),
    )
    logger.info(T["tracker_info"],
                tracker.threshold, tracker.time_window, tracker.alert_cooldown)
    if tracker.slow_threshold:
        logger.info(T["slow_info"], tracker.slow_threshold, tracker.slow_window)

    geo_cfg = cfg.get("geo", {})
    geo = GeoLocator(
        enabled=geo_cfg.get("enabled", True),
        cache_ttl=geo_cfg.get("cache_ttl", 3600),
        timeout=geo_cfg.get("timeout", 5),
        mmdb_path=geo_cfg.get("mmdb_path"),
        online_fallback=geo_cfg.get("online_fallback", True),
    )

    console_alert = ConsoleAlert()

    discord_alert = None
    d_cfg = cfg.get("discord", {})
    if d_cfg.get("enabled") and d_cfg.get("webhook_url"):
        discord_alert = DiscordAlert(webhook_url=d_cfg["webhook_url"])
        logger.info(T["discord_on"])
    else:
        logger.info(T["discord_off"])

    slack_alert = None
    s_cfg = cfg.get("slack", {})
    if s_cfg.get("enabled") and s_cfg.get("webhook_url"):
        slack_alert = SlackAlert(webhook_url=s_cfg["webhook_url"])
        logger.info(T["slack_on"])
    else:
        logger.info(T["slack_off"])

    rep_manager = None
    r_cfg = cfg.get("reports", {})
    if r_cfg.get("save_to_file", True):
        rep_manager = ReportManager(output_path=r_cfg.get("output_path", "reports/alerts.jsonl"))
        logger.info(T["reports_info"], r_cfg.get("output_path", "reports/alerts.jsonl"))

    blk_cfg = cfg.get("blocker", {})
    try:
        blocker = IPBlocker(
            enabled=blk_cfg.get("enabled", False),
            auto_unblock_after=blk_cfg.get("auto_unblock_after", 3600),
            state_file=blk_cfg.get("state_file", "reports/blocked_ips.json"),
            dry_run=blk_cfg.get("dry_run", False),
            scope=blk_cfg.get("scope", "all"),
            ports=blk_cfg.get("ports"),
            protected_nets=parse_cidr_list(blk_cfg.get("trusted_proxies") or []),
            protect_private=blk_cfg.get("protect_private", False),
        )
    except (ValueError, TypeError) as exc:
        print(f"[ERROR] blocker config: {exc}", file=sys.stderr)
        return 1
    if blk_cfg.get("enabled"):
        if blk_cfg.get("dry_run"):
            logger.info(T["blk_dry"])
        elif blk_cfg.get("auto_unblock_after", 3600):
            logger.info(T["blk_enabled"], blk_cfg.get("auto_unblock_after", 3600))
        else:
            logger.info(T["blk_enabled_perm"])
    else:
        logger.info(T["blk_disabled"])

    whitelist = parse_cidr_list(cfg.get("whitelist", []))

    ti_cfg = cfg.get("threat_intel", {})
    # sources: config accepts either a list of URLs or a {name: url} dict
    _raw_sources = ti_cfg.get("sources")
    if isinstance(_raw_sources, list):
        _ti_sources = {f"source_{i}": url for i, url in enumerate(_raw_sources)}
    else:
        _ti_sources = _raw_sources or None
    threat_intel = ThreatIntel(
        enabled=ti_cfg.get("enabled", False),
        db_path=ti_cfg.get("db_path", "reports/threat_intel.txt"),
        sources=_ti_sources,
        auto_update=ti_cfg.get("auto_update", False),
        update_interval=ti_cfg.get("update_interval", 86400),
        timeout=ti_cfg.get("timeout", 15),
    )
    if ti_cfg.get("enabled"):
        if threat_intel.count() > 0:
            logger.info(T["ti_enabled"], threat_intel.count(), ti_cfg.get("db_path", "reports/threat_intel.txt"))
        else:
            logger.warning(T["ti_no_db"])
    else:
        logger.info(T["ti_disabled"])

    dispatcher = AlertDispatcher(
        console=console_alert, discord=discord_alert,
        slack=slack_alert, report_manager=rep_manager, geo=geo,
        blocker=blocker, whitelist_nets=whitelist,
        threat_intel=threat_intel,
        ti_action=det_cfg.get("action_on_threat_intel_match", "block"),
    )

    # ── Special modes ─────────────────────────────────────────────────────────
    if args.update_threat_db:
        print(T["ti_updating"] % len(threat_intel.sources))
        count = threat_intel.update()
        print(T["ti_updated"] % (count, ti_cfg.get("db_path", "reports/threat_intel.txt")))
        return 0

    if args.test:
        run_test_mode(dispatcher, tracker, T)
        return 0

    report_path = (cfg.get("reports") or {}).get("output_path", "reports/alerts.jsonl")
    if args.report:
        return run_report(report_path, args, T)

    if args.replay:
        return run_replay(args.replay, cfg, args, T, threat_intel)

    state_cfg = cfg.get("state") or {}
    state_path = state_cfg.get("path", "reports/tracker_state.json")
    persister: Optional[StatePersister] = None
    offsets: Optional[OffsetStore] = None
    if state_cfg.get("enabled", True):
        if state_cfg.get("catch_up", True):
            offsets = OffsetStore()
        restored = load_state(tracker, state_path, offsets)
        if restored:
            logger.info(T["state_restored"], restored, state_path)
        persister = StatePersister(tracker, state_path, state_cfg.get("save_interval", 30), offsets=offsets)

    if args.stats:
        print_stats(tracker, T)
        return 0

    if args.blocked:
        print_blocked(blocker, T)
        return 0

    # ── Log monitor ───────────────────────────────────────────────────────────
    monitor = LogMonitor(
        tracker=tracker, whitelist_nets=whitelist, offsets=offsets,
        catch_up_max_bytes=int(state_cfg.get("catch_up_max_mb", 64)) * 1024 * 1024,
    )
    monitor.add_alert_handler(dispatcher.dispatch)

    log_files = [f for f in cfg.get("log_files", []) if f.get("enabled", True)]
    sl_cfg = cfg.get("syslog", {})
    jd_cfg = cfg.get("journald", {})
    if not log_files and not sl_cfg.get("enabled") and not jd_cfg.get("enabled"):
        logger.error(T["no_log_files"])
        return 1

    for lf in log_files:
        logger.info(T["adding_file"], lf["path"], lf["type"])
        monitor.add_log_file(path=lf["path"], parser_type=lf["type"])

    if sl_cfg.get("enabled"):
        monitor.add_syslog_source(
            host=sl_cfg.get("host", "0.0.0.0"),
            port=sl_cfg.get("port", 5514),
            protocol=sl_cfg.get("protocol", "udp"),
            parser_type=sl_cfg.get("parser", "linux_ssh"),
        )
    else:
        logger.info(T["syslog_disabled"])

    if jd_cfg.get("enabled"):
        monitor.add_journald_source(
            units=jd_cfg.get("units"),
            parser_type=jd_cfg.get("parser", "linux_ssh"),
        )
    else:
        logger.info(T["journald_disabled"])

    dashboard_server = None
    dashboard_thread = None
    if args.dashboard:
        from detector.dashboard import create_server, is_loopback
        try:
            dashboard_server = create_server(
                report_path, args.dashboard_host, args.dashboard_port,
                status_provider=monitor.get_status,
                honeypot_paths=[f["path"] for f in log_files
                                if f.get("type") == "cowrie" and f.get("path")],
                honeypot_exclude=whitelist + parse_cidr_list(sorted(local_addresses())),
            )
        except OSError as exc:
            print(T["dash_err"] % exc, file=sys.stderr)
            return 1
        if not is_loopback(args.dashboard_host):
            print(T["dash_exposed"] % args.dashboard_host, file=sys.stderr)

    monitor.start()
    if persister:
        persister.start()
    if dashboard_server:
        dashboard_thread = threading.Thread(
            target=dashboard_server.serve_forever, daemon=True, name="dashboard",
        )
        dashboard_thread.start()
        logger.info(T["dash_started"] % (
            args.dashboard_host, dashboard_server.server_address[1],
        ))

    stop_event = threading.Event()

    def handle_signal(sig, _frame):
        logger.info(i18n.get_T()["signal_stop"], sig)
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    logger.info(T["started"])
    logger.info(T["lang_hint"])
    _start_lang_listener(stop_event)

    # Active-IPs summary: at most once per stats_interval and only when it changed
    # (0 = never), so an idle journal is not flooded.
    stats_interval = float(log_cfg.get("stats_interval", 300) or 0)
    last_summary, last_logged = None, 0.0

    try:
        while not stop_event.is_set():
            stop_event.wait(timeout=30)
            stats = tracker.get_stats()
            if stats and stats_interval:
                top_ip = max(stats, key=lambda x: stats[x]["count"])
                summary = (len(stats), top_ip, stats[top_ip]["count"])
                now = time.monotonic()
                if summary != last_summary and now - last_logged >= stats_interval:
                    logger.info(i18n.get_T()["active_ips"], *summary)
                    last_summary, last_logged = summary, now
    finally:
        monitor.stop()
        if dashboard_server:
            dashboard_server.shutdown()
            dashboard_server.server_close()
        if dashboard_thread:
            dashboard_thread.join(timeout=3)
        if persister:
            persister.stop()
        if blocker.enabled:
            unblocked = blocker.unblock_all()
            if unblocked:
                logger.info("Unblocked %d IP(s) on shutdown.", unblocked)
        logger.info(i18n.get_T()["stopped"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
