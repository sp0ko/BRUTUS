"""
Cowrie honeypot log parser (cowrie.json, one JSON object per line).

Detected events
---------------
FAILED — cowrie.login.failed and cowrie.login.success

Cowrie accepts some credentials on purpose, so a "successful" login to the
honeypot is still an attack attempt, never a breach: it is reported as FAILED
and no SUCCESS event is ever produced.  Everything else (commands, sessions,
downloads) is ignored here.
"""

import json
import time
from datetime import datetime, timezone
from typing import Optional

from .linux_ssh import ParsedEvent

_LOGIN_EVENTS = ("cowrie.login.failed", "cowrie.login.success")


def _timestamp(value) -> float:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
        except ValueError:
            pass
    return time.time()


class CowrieParser:
    name = "cowrie"

    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        line = line.strip()
        if not line.startswith("{"):
            return None
        try:
            data = json.loads(line)
        except ValueError:
            return None
        if not isinstance(data, dict) or data.get("eventid") not in _LOGIN_EVENTS:
            return None

        ip = str(data.get("src_ip") or "")
        if not ip:
            return None
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        return ParsedEvent(
            "FAILED", ip, str(data.get("username") or ""),
            attack_type="HONEYPOT", raw_line=line, timestamp=_timestamp(data.get("timestamp")),
        )
