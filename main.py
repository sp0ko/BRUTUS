#!/usr/bin/env python3
"""
BRUTU$ v1.0.0
=============
Detektor ataków SSH/RDP w czasie rzeczywistym.

Przykłady
---------
  python main.py                         # domyślny config.yaml
  python main.py --config custom.yaml
  python main.py --threshold 3 --window 30
  python main.py --log /var/log/auth.log --type linux_ssh
  python main.py --discord-url "https://discord.com/api/webhooks/..."
  python main.py --test                  # symulacja ataku
  python main.py --stats                 # pokaż statystyki i zakończ
"""

import argparse
import logging
import os
import signal
import sys
import threading
import time
from typing import Optional

import yaml

from detector.tracker import BruteForceTracker, AlertEvent
from detector.log_monitor import LogMonitor
from detector.report_manager import ReportManager
from detector.alerts.console_alert import ConsoleAlert
from detector.alerts.discord_alert import DiscordAlert
from detector.alerts.slack_alert import SlackAlert
from utils.geo import GeoLocator
from utils.ip_utils import parse_cidr_list

VERSION = "1.0.0"
DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), "config.yaml")

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
    ) -> None:
        self.console = console
        self.discord = discord
        self.slack = slack
        self.report_manager = report_manager
        self.geo = geo

    def dispatch(self, event: AlertEvent) -> None:
        geo_info = self.geo.lookup(event.ip)
        event.geo_info = geo_info

        self.console.send(event, geo=geo_info)

        for handler in (self.discord, self.slack):
            if handler:
                threading.Thread(target=handler.send, args=(event,), kwargs={"geo": geo_info}, daemon=True).start()

        if self.report_manager:
            threading.Thread(target=self.report_manager.save, args=(event,), kwargs={"geo": geo_info}, daemon=True).start()


# ──────────────────────────────────────────────────────────────────────────────

def run_test_mode(dispatcher: AlertDispatcher, tracker: BruteForceTracker) -> None:
    print("\n[TEST] Uruchamiam symulację ataku brute-force…\n")

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

    print("\n[TEST] Symulacja zakończona. Sprawdź Discord/Slack jeśli webhooks są skonfigurowane.")


def print_stats(tracker: BruteForceTracker) -> None:
    stats = tracker.get_stats()
    if not stats:
        print("Brak aktywności w bieżącym oknie czasu.")
        return
    print(f"\n{'IP':<20} {'Próby':>6}  {'Typ ataku':<15}  Użytkownicy")
    print("-" * 70)
    for ip, info in sorted(stats.items(), key=lambda x: -x[1]["count"]):
        print(
            f"{ip:<20} {info['count']:>6}  "
            f"{', '.join(info['attack_types']):<15}  "
            f"{', '.join(info['usernames'][:5]) or '—'}"
        )
    print()


# ──────────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="BRUTU$ — detekcja ataków SSH/RDP w czasie rzeczywistym",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--config",      default=DEFAULT_CONFIG, help="Ścieżka do pliku config.yaml")
    p.add_argument("--log",         metavar="PATH",         help="Dodatkowy plik logu")
    p.add_argument("--type",        metavar="TYPE",         help="Typ parsera: linux_ssh | windows_evtx")
    p.add_argument("--threshold",   type=int,               help="Próg nieudanych logowań")
    p.add_argument("--window",      type=int,               help="Okno czasu (sekundy)")
    p.add_argument("--cooldown",    type=int,               help="Cooldown alertów (sekundy)")
    p.add_argument("--discord-url", metavar="URL",          help="Discord webhook URL")
    p.add_argument("--slack-url",   metavar="URL",          help="Slack webhook URL")
    p.add_argument("--test",        action="store_true",    help="Tryb testowy — symulacja ataku")
    p.add_argument("--stats",       action="store_true",    help="Pokaż statystyki i zakończ")
    p.add_argument("--version",     action="version",       version=f"BRUTU$ {VERSION}")
    return p


# ──────────────────────────────────────────────────────────────────────────────

def main() -> int:
    args = build_arg_parser().parse_args()

    if not os.path.exists(args.config):
        print(f"[BŁĄD] Plik konfiguracyjny nie istnieje: {args.config}", file=sys.stderr)
        return 1

    cfg = merge_cli_overrides(load_config(args.config), args)

    log_cfg = cfg.get("logging", {})
    setup_logging(log_cfg.get("level", "INFO"), log_cfg.get("file"))
    logger = logging.getLogger("brute-force-detector")

    print(BANNER)

    det_cfg = cfg.get("detection", {})
    tracker = BruteForceTracker(
        threshold=det_cfg.get("threshold", 5),
        time_window=det_cfg.get("time_window", 60),
        alert_cooldown=det_cfg.get("alert_cooldown", 300),
        success_failure_threshold=det_cfg.get("success_failure_threshold", 3),
    )
    logger.info("Tracker: próg=%d  okno=%ds  cooldown=%ds",
                tracker.threshold, tracker.time_window, tracker.alert_cooldown)

    geo_cfg = cfg.get("geo", {})
    geo = GeoLocator(
        enabled=geo_cfg.get("enabled", True),
        cache_ttl=geo_cfg.get("cache_ttl", 3600),
        timeout=geo_cfg.get("timeout", 5),
    )

    console_alert = ConsoleAlert()

    discord_alert = None
    d_cfg = cfg.get("discord", {})
    if d_cfg.get("enabled") and d_cfg.get("webhook_url"):
        discord_alert = DiscordAlert(webhook_url=d_cfg["webhook_url"])
        logger.info("Discord webhook: aktywny ✓")
    else:
        logger.info("Discord: wyłączony")

    slack_alert = None
    s_cfg = cfg.get("slack", {})
    if s_cfg.get("enabled") and s_cfg.get("webhook_url"):
        slack_alert = SlackAlert(webhook_url=s_cfg["webhook_url"])
        logger.info("Slack webhook: aktywny ✓")
    else:
        logger.info("Slack: wyłączony")

    rep_manager = None
    r_cfg = cfg.get("reports", {})
    if r_cfg.get("save_to_file", True):
        rep_manager = ReportManager(output_path=r_cfg.get("output_path", "reports/alerts.jsonl"))
        logger.info("Raporty: %s", r_cfg.get("output_path", "reports/alerts.jsonl"))

    dispatcher = AlertDispatcher(
        console=console_alert, discord=discord_alert,
        slack=slack_alert, report_manager=rep_manager, geo=geo,
    )

    # ── Tryby specjalne ───────────────────────────────────────────────────────
    if args.test:
        run_test_mode(dispatcher, tracker)
        return 0

    if args.stats:
        print_stats(tracker)
        return 0

    # ── Monitor logów ─────────────────────────────────────────────────────────
    whitelist = parse_cidr_list(cfg.get("whitelist", []))
    monitor = LogMonitor(tracker=tracker, whitelist_nets=whitelist)
    monitor.add_alert_handler(dispatcher.dispatch)

    log_files = [f for f in cfg.get("log_files", []) if f.get("enabled", True)]
    if not log_files:
        logger.error("Brak aktywnych plików logów! Dodaj wpisy w 'log_files' w config.yaml.")
        return 1

    for lf in log_files:
        logger.info("Dodaję plik: %s  (parser: %s)", lf["path"], lf["type"])
        monitor.add_log_file(path=lf["path"], parser_type=lf["type"])

    monitor.start()

    stop_event = threading.Event()

    def handle_signal(sig, _frame):
        logger.info("Sygnał %s — zatrzymuję…", sig)
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    logger.info("BRUTU$ uruchomiony — Ctrl+C aby zatrzymać.")

    try:
        while not stop_event.is_set():
            stop_event.wait(timeout=30)
            stats = tracker.get_stats()
            if stats:
                top_ip = max(stats, key=lambda x: stats[x]["count"])
                logger.info("Aktywne IP: %d  |  Najbardziej aktywne: %s (%d prób)",
                            len(stats), top_ip, stats[top_ip]["count"])
    finally:
        monitor.stop()
        logger.info("BRUTU$ zatrzymany.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
