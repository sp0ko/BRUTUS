"""
FTP parser — vsftpd, ProFTPD and Pure-FTPd (own log files or syslog/journald).

Detected patterns
-----------------
FAILED  — vsftpd "FAIL LOGIN", ProFTPD "Login failed" / "no such user",
          Pure-FTPd "Authentication failed"
SUCCESS — vsftpd "OK LOGIN", ProFTPD "Login successful",
          Pure-FTPd "is now logged in"
"""

import re
import time
from datetime import datetime
from typing import Optional

from .linux_ssh import LinuxSSHParser, ParsedEvent

_IP = r"[\da-fA-F\.:]+"

_RE_VSFTPD = re.compile(rf'\[([^\]]*)\]\s+(FAIL|OK) LOGIN: Client "(?:::ffff:)?({_IP})"')
_RE_VSFTPD_TS = re.compile(r"^\w{3} (\w{3} +\d+ \d{2}:\d{2}:\d{2}) (\d{4})")
_RE_PROFTPD_FAIL = re.compile(rf"\(\S*?\[({_IP})\]\) - USER (\S+) \(Login failed\)")
_RE_PROFTPD_NOUSER = re.compile(rf"USER (\S+): no such user found from \S+ \[({_IP})\]")
_RE_PROFTPD_OK = re.compile(rf"\(\S*?\[({_IP})\]\) - USER (\S+): Login successful")
_RE_PURE_FAIL = re.compile(rf"\(\?@({_IP})\) \[WARNING\] Authentication failed for user \[([^\]]*)\]")
_RE_PURE_OK = re.compile(rf"\(([^@)]*)@({_IP})\) \[INFO\] \S+ is now logged in")


def _timestamp(line: str) -> float:
    m = _RE_VSFTPD_TS.match(line)
    if m:
        try:
            return datetime.strptime(f"{m.group(1)} {m.group(2)}", "%b %d %H:%M:%S %Y").timestamp()
        except ValueError:
            return time.time()
    return LinuxSSHParser._extract_timestamp(line)


class FtpParser:
    name = "ftp"

    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        line = line.strip()
        if not line:
            return None

        def ev(kind: str, ip: str, user: str) -> ParsedEvent:
            return ParsedEvent(kind, ip, user, attack_type="FTP", timestamp=_timestamp(line), raw_line=line)

        m = _RE_VSFTPD.search(line)
        if m:
            return ev("FAILED" if m.group(2) == "FAIL" else "SUCCESS", m.group(3), m.group(1))
        m = _RE_PROFTPD_FAIL.search(line)
        if m:
            return ev("FAILED", m.group(1), m.group(2))
        m = _RE_PROFTPD_NOUSER.search(line)
        if m:
            return ev("FAILED", m.group(2), m.group(1))
        m = _RE_PROFTPD_OK.search(line)
        if m:
            return ev("SUCCESS", m.group(1), m.group(2))
        m = _RE_PURE_FAIL.search(line)
        if m:
            return ev("FAILED", m.group(1), m.group(2))
        m = _RE_PURE_OK.search(line)
        if m:
            return ev("SUCCESS", m.group(2), m.group(1))
        return None
