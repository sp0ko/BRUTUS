"""
Honeypot statistics for the dashboard, read straight from Cowrie's ``cowrie.json``.

The alerts file only knows about threshold crossings; the honeypot log also has
the passwords, shell commands and downloads attackers tried.  Everything here is
attacker-controlled text, so it is length-capped and the dashboard HTML-escapes it.
"""

import json
import re
from collections import Counter, deque
from datetime import datetime
from typing import Dict, Iterable, List, Optional

from utils.ip_utils import ip_in_list

from .stats import _parse_ts, _timeline

_MAX_TEXT = 120

# Ordered (label key, pattern); a command can match several categories.
BEHAVIOURS = (
    ("ssh_key", re.compile(r"authorized_keys|ssh-(rsa|ed25519)|ecdsa-sha2|\.ssh\b", re.I)),
    ("miner", re.compile(r"xmrig|minerd|cpuminer|stratum\+|monero|cryptonight|nanopool|moneroocean|/proc/cpuinfo.*(grep|model)", re.I)),
    ("download_exec", re.compile(r"\b(wget|curl|tftp|ftpget|scp)\b|chmod\s+[+0-7]*x|\bsh\s+\S+\.sh|nohup", re.I)),
    ("botnet", re.compile(r"busybox|mirai|/bin/\.\w+|\bgafgyt\b|\bbot\b", re.I)),
    ("persistence", re.compile(r"crontab|/etc/cron|rc\.local|systemctl\s+(enable|start)|\.bashrc|useradd|adduser", re.I)),
    ("passwd", re.compile(r"\bpasswd\b|chpasswd|usermod", re.I)),
    ("cleanup", re.compile(r"rm\s+-\w*r\w*f|history\s+-c|unset\s+HISTFILE|HISTFILE=|/dev/null\s+2>&1\s*;?\s*rm", re.I)),
    ("recon", re.compile(r"\b(uname|whoami|lscpu|nproc|uptime|hostname|ifconfig|lsb_release)\b|/proc/(cpuinfo|meminfo)|/etc/(os-release|passwd|issue)|free\s+-|\bid\b|\bw\b|\bls\b|\bps\b", re.I)),
)


def classify(command: str) -> List[str]:
    return [name for name, rx in BEHAVIOURS if rx.search(command)]
_RECENT_COMMANDS = 10
EMPTY = "(empty)"


def _clip(value) -> str:
    text = str(value if value is not None else "").replace("\n", " ").strip()
    return text if len(text) <= _MAX_TEXT else text[:_MAX_TEXT - 1] + "…"


def load_cowrie(paths: Iterable[str], since: Optional[datetime] = None,
                exclude_nets: Optional[list] = None) -> List[dict]:
    """Read Cowrie events (malformed lines skipped); missing files are ignored.
    Events from addresses in *exclude_nets* (whitelist, own host) are dropped."""
    records: List[dict] = []
    for path in paths:
        try:
            fh = open(path, "r", encoding="utf-8", errors="replace")
        except FileNotFoundError:
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(rec, dict) or not isinstance(rec.get("eventid"), str):
                    continue
                ts = _parse_ts(rec.get("timestamp"))
                if ts is None or (since is not None and ts < since):
                    continue
                if exclude_nets and ip_in_list(str(rec.get("src_ip") or ""), exclude_nets):
                    continue
                rec["_ts"] = ts
                records.append(rec)
    return records


def summarize_honeypot(records: List[dict], since: Optional[datetime], until: datetime,
                       top: int = 10) -> Dict:
    passwords: Counter = Counter()
    usernames: Counter = Counter()
    credentials: Counter = Counter()
    commands: Counter = Counter()
    downloads: Counter = Counter()
    hashes: Counter = Counter()
    behaviours: Counter = Counter()
    clients: Counter = Counter()
    ips: Counter = Counter()
    shell_ips = set()
    recent: deque = deque(maxlen=_RECENT_COMMANDS)
    sessions = attempts = logins_ok = command_count = 0
    attempt_events = []

    for r in sorted(records, key=lambda x: x["_ts"]):
        event = r["eventid"]
        ip = str(r.get("src_ip") or "")
        if event == "cowrie.session.connect":
            sessions += 1
        elif event in ("cowrie.login.failed", "cowrie.login.success"):
            attempts += 1
            attempt_events.append(r)
            ips[ip] += 1
            user = _clip(r.get("username")) or EMPTY
            pw = _clip(r.get("password")) or EMPTY
            usernames[user] += 1
            passwords[pw] += 1
            credentials[f"{user} / {pw}"] += 1
            if event == "cowrie.login.success":
                logins_ok += 1
                shell_ips.add(ip)
        elif event == "cowrie.command.input":
            command_count += 1
            cmd = _clip(r.get("input"))
            commands[cmd] += 1
            tags = classify(str(r.get("input") or ""))
            behaviours.update(tags)
            recent.append({"time": r["_ts"].strftime("%m-%d %H:%M:%S"), "ip": ip, "command": cmd, "tags": tags})
        elif event == "cowrie.session.file_download":
            sha = str(r.get("shasum") or "")
            # Files built with echo/cat have no URL; say so instead of showing a local path.
            downloads[_clip(r.get("url")) or f"(written in shell) {sha[:12]}"] += 1
            if re.fullmatch(r"[0-9a-fA-F]{64}", str(r.get("shasum") or "")):
                hashes[str(r["shasum"]).lower()] += 1
        elif event == "cowrie.client.version":
            clients[_clip(r.get("version"))] += 1

    def ranked(counter: Counter) -> List[list]:
        return [[k, v] for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:top]]

    return {
        "totals": {
            "sessions": sessions,
            "attempts": attempts,
            "unique_ips": len(ips),
            "shell_logins": logins_ok,
            "commands": command_count,
            "downloads": sum(downloads.values()),
        },
        "passwords": ranked(passwords),
        "usernames": ranked(usernames),
        "credentials": ranked(credentials),
        "commands": ranked(commands),
        "downloads": ranked(downloads),
        "hashes": ranked(hashes),
        "behaviours": ranked(behaviours),
        "clients": ranked(clients),
        "top_ips": ranked(ips),
        "shell_ips": sorted(shell_ips),
        "recent_commands": list(reversed(recent)),
        "timeline": _timeline(attempt_events, since, until),
    }
