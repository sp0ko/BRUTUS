"""
MySQL / MariaDB error-log parser (also works on journald / syslog output).

Detected pattern
----------------
FAILED — "Access denied for user 'bob'@'1.2.3.4'"

Notes: MariaDB logs this only with log_warnings=2; MySQL 8 with
log_error_verbosity=2 or higher.  Clients whose address resolves to a hostname
(no skip-name-resolve) are not reported — only IP literals are matched.  The
error log has no record of successful logins, so no breach detection here.
"""

import re
import time
from datetime import datetime
from typing import Optional

from .linux_ssh import LinuxSSHParser, ParsedEvent

_RE_DENIED = re.compile(
    r"Access denied for user '([^']*)'@'((?:::ffff:)?[\da-fA-F\.:]+)'"
)
_RE_ISO_TS = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")


def _timestamp(line: str) -> float:
    m = _RE_ISO_TS.match(line)
    if m:  # MySQL 8 error log: 2026-10-26T13:00:00.123456Z (UTC)
        try:
            dt = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
            if line[m.end():].split(" ", 1)[0].endswith("Z"):
                from datetime import timezone
                return dt.replace(tzinfo=timezone.utc).timestamp()
            return dt.timestamp()
        except ValueError:
            return time.time()
    return LinuxSSHParser._extract_timestamp(line)


class MySQLParser:
    name = "mysql"

    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        line = line.strip()
        if not line:
            return None
        m = _RE_DENIED.search(line)
        if not m:
            return None
        ip = m.group(2).removeprefix("::ffff:")
        return ParsedEvent("FAILED", ip, m.group(1), attack_type="MYSQL",
                           timestamp=_timestamp(line), raw_line=line)
