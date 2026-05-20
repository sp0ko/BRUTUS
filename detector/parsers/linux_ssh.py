"""
Linux SSH log parser — supports /var/log/auth.log and /var/log/secure.

Detected patterns
-----------------
FAILED  — Failed password, Invalid user, PAM auth failure, xRDP failure
SUCCESS — Accepted password/publickey
"""

import re
import time
from dataclasses import dataclass
from typing import Optional


_RE_FAILED_PASSWORD = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d\.a-fA-F:]+) port \d+"
)
_RE_INVALID_USER = re.compile(r"Invalid user (\S+) from ([\d\.a-fA-F:]+)")
_RE_PREAUTH_DISCONNECT = re.compile(
    r"(?:Disconnected from|Connection closed by) (?:invalid user )?(\S+) ([\d\.a-fA-F:]+) port \d+ \[preauth\]"
)
_RE_XRDP_FAILED = re.compile(
    r"xrdp(?:-sesman)?\[\d+\].*?(?:Authentication failed|login failed)"
    r".*?(?:[Uu]ser(?:name)?:?\s*(\S+))?"
    r".*?(\b\d{1,3}(?:\.\d{1,3}){3}\b)"
)
_RE_PAM_FAILURE = re.compile(
    r"pam_unix\(sshd:auth\): authentication failure.*?rhost=([\d\.a-fA-F:]+)(?:.*?user=(\S+))?"
)
_RE_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive) for (\S+) from ([\d\.a-fA-F:]+) port \d+"
)
_RE_SYSLOG_TS = re.compile(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})")


@dataclass
class ParsedEvent:
    event_type: str          # "FAILED" | "SUCCESS"
    ip: str
    username: str
    attack_type: str = "SSH"
    raw_line: str = ""
    timestamp: float = 0.0


class LinuxSSHParser:
    name = "linux_ssh"

    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        line = line.strip()
        if not line:
            return None
        ts = self._extract_timestamp(line)

        m = _RE_FAILED_PASSWORD.search(line)
        if m:
            return ParsedEvent("FAILED", m.group(2), m.group(1), timestamp=ts, raw_line=line)

        m = _RE_INVALID_USER.search(line)
        if m:
            return ParsedEvent("FAILED", m.group(2), m.group(1), timestamp=ts, raw_line=line)

        m = _RE_PREAUTH_DISCONNECT.search(line)
        if m:
            return ParsedEvent("FAILED", m.group(2), m.group(1), timestamp=ts, raw_line=line)

        m = _RE_PAM_FAILURE.search(line)
        if m:
            return ParsedEvent("FAILED", m.group(1), m.group(2) or "", timestamp=ts, raw_line=line)

        m = _RE_XRDP_FAILED.search(line)
        if m:
            return ParsedEvent("FAILED", m.group(2), m.group(1) or "", attack_type="RDP", timestamp=ts, raw_line=line)

        m = _RE_ACCEPTED.search(line)
        if m:
            return ParsedEvent("SUCCESS", m.group(2), m.group(1), timestamp=ts, raw_line=line)

        return None

    @staticmethod
    def _extract_timestamp(line: str) -> float:
        m = _RE_SYSLOG_TS.match(line)
        if not m:
            return time.time()
        try:
            import datetime
            now = datetime.datetime.now()
            dt = datetime.datetime.strptime(m.group(1), "%b %d %H:%M:%S").replace(year=now.year)
            if dt > now:
                dt = dt.replace(year=now.year - 1)
            return dt.timestamp()
        except ValueError:
            return time.time()
