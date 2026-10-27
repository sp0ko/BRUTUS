"""
Interactive setup wizard (--setup) and configuration check (--check).

The wizard asks a few questions and writes a minimal config file; everything
it does not set falls back to the defaults built into the program.  The check
verifies that the configuration can actually work on this machine (log
permissions, ports, iptables, webhook format, packages) without sending
anything over the network.
"""

import importlib.util
import ipaddress
import os
import shutil
import socket
import sys
from typing import Callable, List, Optional, Tuple

import yaml

from .parsers import PARSER_REGISTRY

OK, WARN, FAIL = "OK", "WARN", "FAIL"

LOG_CANDIDATES = ("/var/log/auth.log", "/var/log/secure")
BLOCKER_MODES = ("off", "dry-run", "on")
WEBHOOK_PREFIXES = {
    "Discord": ("https://discord.com/api/webhooks/", "https://discordapp.com/api/webhooks/"),
    "Slack": ("https://hooks.slack.com/",),
}
MIN_PYTHON = (3, 10)

Result = Tuple[str, str, tuple]  # (level, message key, format args)


def webhook_looks_valid(kind: str, url: str) -> bool:
    return url.startswith(WEBHOOK_PREFIXES[kind])


# ──────────────────────────────────────────────────────────────────────────────
# Setup wizard
# ──────────────────────────────────────────────────────────────────────────────

def detect_sources(exists: Callable[[str], bool] = os.path.exists,
                   which: Callable[[str], Optional[str]] = shutil.which) -> dict:
    return {
        "files": [p for p in LOG_CANDIDATES if exists(p)],
        "journald": bool(which("journalctl")),
    }


def build_config(log_files: List[str], journald: bool, threshold: int, window: int,
                 discord: str, slack: str, blocker_mode: str, whitelist: List[str]) -> dict:
    return {
        "detection": {"threshold": threshold, "time_window": window},
        "log_files": [{"path": p, "type": "linux_ssh", "enabled": True} for p in log_files],
        "journald": {"enabled": journald, "parser": "linux_ssh"},
        "discord": {"enabled": bool(discord), "webhook_url": discord},
        "slack": {"enabled": bool(slack), "webhook_url": slack},
        "blocker": {"enabled": blocker_mode != "off", "dry_run": blocker_mode == "dry-run"},
        "whitelist": ["127.0.0.1", "::1"] + whitelist,
    }


def _ask(ask: Callable[[str], str], prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    return ask(f"{prompt}{suffix}: ").strip() or default


def _yes(ask: Callable[[str], str], T: dict, prompt: str, default: bool) -> bool:
    answer = _ask(ask, f"{prompt} ({T['wz_yn']})", "y" if default else "n").lower()
    return answer in ("y", "yes", "t", "tak")


def _ask_int(ask, out, T, prompt: str, default: int) -> int:
    while True:
        raw = _ask(ask, prompt, str(default))
        if raw.isdigit() and int(raw) > 0:
            return int(raw)
        out(T["wz_bad_number"])


def _ask_webhook(ask, out, T, kind: str) -> str:
    while True:
        url = _ask(ask, T["wz_webhook"] % kind)
        if not url or webhook_looks_valid(kind, url):
            return url
        out(T["wz_bad_webhook"] % kind)


def _ask_whitelist(ask, out, T) -> List[str]:
    while True:
        items = [i.strip() for i in _ask(ask, T["wz_whitelist"]).split(",") if i.strip()]
        try:
            for item in items:
                ipaddress.ip_network(item, strict=False)
            return items
        except ValueError:
            out(T["wz_bad_whitelist"])


def run_setup(path: str, T: dict, ask: Callable[[str], str] = input,
              out: Callable[[str], None] = print,
              detect: Callable[[], dict] = detect_sources) -> int:
    try:
        return _run_setup(path, T, ask, out, detect)
    except (EOFError, KeyboardInterrupt):
        out("")
        out(T["wz_cancelled"])
        return 1


def _run_setup(path, T, ask, out, detect) -> int:
    out(T["wz_title"])
    if os.path.exists(path) and not _yes(ask, T, T["wz_overwrite"] % path, False):
        out(T["wz_cancelled"])
        return 1

    found = detect()
    log_files = []
    for candidate in found["files"]:
        if _yes(ask, T, T["wz_use_log"] % candidate, True):
            log_files.append(candidate)

    journald = False
    if not found["files"] and found["journald"]:
        journald = _yes(ask, T, T["wz_use_journald"], True)
    if not log_files and not journald:
        custom = _ask(ask, T["wz_custom_log"])
        if custom:
            log_files.append(custom)
    if not log_files and not journald:
        out(T["wz_no_source"])

    threshold = _ask_int(ask, out, T, T["wz_threshold"], 5)
    window = _ask_int(ask, out, T, T["wz_window"], 60)
    discord = _ask_webhook(ask, out, T, "Discord")
    slack = _ask_webhook(ask, out, T, "Slack")
    mode = ""
    while mode not in BLOCKER_MODES:
        mode = _ask(ask, T["wz_blocker"], "off").lower()
    whitelist = _ask_whitelist(ask, out, T)

    cfg = build_config(log_files, journald, threshold, window, discord, slack, mode, whitelist)
    if os.path.exists(path):
        shutil.copy2(path, path + ".bak")
        out(T["wz_backup"] % (path + ".bak"))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(T["wz_file_header"])
        yaml.safe_dump(cfg, fh, sort_keys=False, allow_unicode=True)
    os.chmod(path, 0o600)  # may contain webhook URLs
    out(T["wz_saved"] % path)
    out(T["wz_next"])
    return 0


# ──────────────────────────────────────────────────────────────────────────────
# Configuration check
# ──────────────────────────────────────────────────────────────────────────────

def _writable_target(path: str) -> bool:
    """True if *path*'s directory exists and is writable, or can be created."""
    directory = os.path.dirname(os.path.abspath(path))
    while not os.path.exists(directory):
        parent = os.path.dirname(directory)
        if parent == directory:
            return False
        directory = parent
    return os.access(directory, os.W_OK)


def _check_log_file(entry) -> Result:
    if not isinstance(entry, dict) or not entry.get("path") or not entry.get("type"):
        return FAIL, "ck_log_entry", (str(entry),)
    path, parser = entry["path"], entry["type"]
    if parser not in PARSER_REGISTRY:
        return FAIL, "ck_log_parser", (parser, path)
    if not os.path.exists(path):
        return WARN, "ck_log_missing", (path,)
    if not os.access(path, os.R_OK):
        return FAIL, "ck_log_denied", (path,)
    return OK, "ck_log_ok", (path,)


def _check_syslog(cfg: dict) -> Result:
    host, port = cfg.get("host", "0.0.0.0"), cfg.get("port", 5514)
    proto = str(cfg.get("protocol", "udp")).lower()
    family = socket.AF_INET6 if ":" in str(host) else socket.AF_INET
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    try:
        with socket.socket(family, kind) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
    except OSError as exc:
        return FAIL, "ck_syslog_fail", (host, port, proto.upper(), exc)
    return OK, "ck_syslog_ok", (port, proto.upper())


def check_config(cfg: dict, is_root: Optional[bool] = None,
                 which: Callable[[str], Optional[str]] = shutil.which) -> List[Result]:
    if is_root is None:
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    results: List[Result] = []
    add = results.append

    py = ".".join(map(str, sys.version_info[:3]))
    add((OK, "ck_python_ok", (py,)) if sys.version_info >= MIN_PYTHON
        else (FAIL, "ck_python_old", (py,)))

    log_files = [f for f in (cfg.get("log_files") or []) if not isinstance(f, dict) or f.get("enabled", True)]
    syslog_cfg = cfg.get("syslog") or {}
    journald_cfg = cfg.get("journald") or {}

    needed = ["requests", "yaml"]
    if any(isinstance(f, dict) and f.get("type") == "windows_evtx" for f in log_files):
        needed.append("Evtx")
    if (cfg.get("geo") or {}).get("mmdb_path"):
        needed.append("geoip2")
    missing = [m for m in needed if importlib.util.find_spec(m) is None]
    add((FAIL, "ck_dep_missing", (", ".join(missing),)) if missing else (OK, "ck_dep_ok", ()))
    if importlib.util.find_spec("colorama") is None:
        add((WARN, "ck_dep_color", ()))

    if not log_files and not syslog_cfg.get("enabled") and not journald_cfg.get("enabled"):
        add((FAIL, "ck_no_sources", ()))
    results.extend(_check_log_file(f) for f in log_files)
    if journald_cfg.get("enabled"):
        add((OK, "ck_journal_ok", ()) if which("journalctl") else (FAIL, "ck_journal_missing", ()))
    if syslog_cfg.get("enabled"):
        add(_check_syslog(syslog_cfg))

    blocker = cfg.get("blocker") or {}
    if not blocker.get("enabled"):
        add((OK, "ck_blocker_off", ()))
    elif blocker.get("dry_run"):
        add((OK, "ck_blocker_dry", ()))
    elif not which("iptables"):
        add((FAIL, "ck_blocker_noipt", ()))
    elif not is_root:
        add((FAIL, "ck_blocker_noroot", ()))
    else:
        add((OK, "ck_blocker_ok", ()))

    channels = 0
    for kind in ("Discord", "Slack"):
        section = cfg.get(kind.lower()) or {}
        if not section.get("enabled"):
            continue
        channels += 1
        url = str(section.get("webhook_url") or "")
        add((OK, "ck_hook_ok", (kind,)) if url and webhook_looks_valid(kind, url)
            else (FAIL, "ck_hook_bad", (kind,)))
    if not channels:
        add((WARN, "ck_no_channels", ()))

    ti = cfg.get("threat_intel") or {}
    if ti.get("enabled") and not os.path.exists(ti.get("db_path", "reports/threat_intel.txt")):
        add((WARN, "ck_ti_nodb", ()))
    mmdb = (cfg.get("geo") or {}).get("mmdb_path")
    if mmdb and not os.path.exists(mmdb):
        add((WARN, "ck_geo_missing", (mmdb,)))

    reports = cfg.get("reports") or {}
    if reports.get("save_to_file", True):
        target = reports.get("output_path", "reports/alerts.jsonl")
        add((OK, "ck_reports_ok", (target,)) if _writable_target(target)
            else (FAIL, "ck_reports_fail", (target,)))
    return results


def run_check(path: str, cfg: dict, T: dict, out: Callable[[str], None] = print,
              **kwargs) -> int:
    out(T["ck_header"] % path)
    results = check_config(cfg, **kwargs)
    for level, key, args in results:
        out(f"  [{level:<4}] {T[key] % args}")
    fails = sum(1 for level, _, _ in results if level == FAIL)
    warns = sum(1 for level, _, _ in results if level == WARN)
    out(T["ck_summary"] % (fails, warns))
    if not fails:
        out(T["ck_ready"])
    return 1 if fails else 0
