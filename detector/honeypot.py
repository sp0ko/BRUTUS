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
    ("perm_mod", re.compile(r"\bchattr\b", re.I)),
    ("cleanup", re.compile(r"rm\s+-\w*r\w*f|history\s+-c|unset\s+HISTFILE|HISTFILE=|/dev/null\s+2>&1\s*;?\s*rm", re.I)),
    ("recon", re.compile(r"\b(uname|whoami|lscpu|nproc|uptime|hostname|ifconfig|lsb_release)\b|/proc/(cpuinfo|meminfo)|/etc/(os-release|passwd|issue)|free\s+-|\bid\b|\bw\b|\bls\b|\bps\b", re.I)),
)


# Official MITRE ATT&CK Enterprise techniques (https://attack.mitre.org/techniques/<ID>/),
# matched per command.  IDs and names were checked against attack.mitre.org.
TECHNIQUES = (
    ("T1098.004", "Account Manipulation: SSH Authorized Keys",
     re.compile(r"authorized_keys|ssh-(rsa|ed25519)|ecdsa-sha2", re.I)),
    ("T1496.001", "Resource Hijacking: Compute Hijacking",
     re.compile(r"xmrig|minerd|cpuminer|stratum\+|monero|cryptonight|nanopool", re.I)),
    ("T1105", "Ingress Tool Transfer", re.compile(r"\b(wget|curl|tftp|ftpget|scp)\b", re.I)),
    ("T1059.004", "Command and Scripting Interpreter: Unix Shell",
     re.compile(r"(^|[;&|]\s*)(\./\S+|(ba)?sh\s+\S+\.sh)|nohup", re.I)),
    ("T1222.002", "File and Directory Permissions Modification: Linux and Mac",
     re.compile(r"\b(chattr|chmod|chown)\b", re.I)),
    ("T1053.003", "Scheduled Task/Job: Cron", re.compile(r"crontab|/etc/cron", re.I)),
    ("T1546.004", "Event Triggered Execution: Unix Shell Configuration Modification",
     re.compile(r"\.bashrc|\.bash_profile|\.profile\b", re.I)),
    ("T1543.002", "Create or Modify System Process: Systemd Service",
     re.compile(r"systemctl\s+(enable|start)|/etc/systemd", re.I)),
    ("T1136.001", "Create Account: Local Account", re.compile(r"\b(useradd|adduser)\b", re.I)),
    ("T1098", "Account Manipulation", re.compile(r"\bpasswd\s+\S|chpasswd|usermod", re.I)),
    ("T1070.003", "Indicator Removal: Clear Command History",
     re.compile(r"history\s+-c|unset\s+HISTFILE|HISTFILE=", re.I)),
    ("T1070.004", "Indicator Removal: File Deletion", re.compile(r"\brm\s+-\w*[rf]", re.I)),
    ("T1082", "System Information Discovery",
     re.compile(r"\b(uname|lscpu|nproc|uptime|hostname|lsb_release)\b|/proc/(cpuinfo|meminfo|version)|/etc/(os-release|issue)|\bfree\s+-", re.I)),
    ("T1033", "System Owner/User Discovery", re.compile(r"\b(whoami|id|w|who|last)\b(?!\s*=)", re.I)),
    ("T1083", "File and Directory Discovery", re.compile(r"\b(ls|pwd|find)\b", re.I)),
    ("T1057", "Process Discovery", re.compile(r"\bps\b|\btop\b", re.I)),
    ("T1016", "System Network Configuration Discovery", re.compile(r"\bifconfig\b|\bip\s+(a|addr|route)\b", re.I)),
    ("T1087.001", "Account Discovery: Local Account", re.compile(r"/etc/passwd|getent\s+passwd", re.I)),
)
TECHNIQUE_NAMES = {tid: name for tid, name, _ in TECHNIQUES}


def techniques(command: str) -> List[str]:
    return [tid for tid, _, rx in TECHNIQUES if rx.search(command)]


_MAX_CAMPAIGNS = 8


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
    command_ips: Dict[str, set] = {}
    behaviour_ips: Dict[str, set] = {}
    technique_ips: Dict[str, set] = {}
    campaigns: Dict[str, dict] = {}
    downloads: Counter = Counter()
    hashes: Counter = Counter()
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
            raw = str(r.get("input") or "").strip()
            tags = classify(raw)
            command_ips.setdefault(cmd, set()).add(ip)
            techs = techniques(raw)
            for tag in tags:
                behaviour_ips.setdefault(tag, set()).add(ip)
            for tid in techs:
                technique_ips.setdefault(tid, set()).add(ip)
            camp = campaigns.setdefault(raw, {
                "command": cmd, "ips": set(), "runs": 0, "tags": tags, "techs": techs,
                "first": r["_ts"], "last": r["_ts"],
            })
            camp["ips"].add(ip)
            camp["runs"] += 1
            camp["last"] = r["_ts"]
            recent.append({"time": r["_ts"].strftime("%m-%d %H:%M:%S"), "ip": ip, "command": cmd, "tags": tags,
                           "techs": techs})
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

    # Rankings count distinct source IPs, so one bot looping the same command
    # cannot drown out a campaign that hits from many addresses.
    commands = Counter({k: len(v) for k, v in command_ips.items()})
    behaviours = Counter({k: len(v) for k, v in behaviour_ips.items()})
    technique_counts = Counter({k: len(v) for k, v in technique_ips.items()})
    campaign_list = sorted(
        (c for c in campaigns.values() if len(c["ips"]) >= 2 or any(t != "recon" for t in c["tags"])),
        key=lambda c: (-len(c["ips"]), -c["runs"], c["command"]),
    )[:_MAX_CAMPAIGNS]

    return {
        "campaigns": [{
            "command": c["command"], "ips": len(c["ips"]), "runs": c["runs"], "tags": c["tags"],
            "mitre": c["techs"],
            "first": c["first"].strftime("%m-%d %H:%M"), "last": c["last"].strftime("%m-%d %H:%M"),
        } for c in campaign_list],
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
        "techniques": [[tid, TECHNIQUE_NAMES[tid], n] for tid, n in sorted(
            technique_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top]],
        "clients": ranked(clients),
        "top_ips": ranked(ips),
        "shell_ips": sorted(shell_ips),
        "recent_commands": list(reversed(recent)),
        "timeline": _timeline(attempt_events, since, until),
    }
