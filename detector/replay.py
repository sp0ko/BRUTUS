"""
Offline replay of an existing log file through the detection pipeline.

Lets you check how BRUTU$ would have reacted to real (historic) logs without
waiting for an attack.  Supports plain files and ``.gz`` rotated logs.
"""

import gzip
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

from .parsers import get_parser
from .tracker import AlertEvent, BruteForceTracker


@dataclass
class ReplayResult:
    lines: int = 0
    failed: int = 0
    success: int = 0
    ignored: int = 0
    alerts: list = field(default_factory=list)
    failures_per_ip: Dict[str, int] = field(default_factory=dict)

    @property
    def top_ips(self):
        return sorted(self.failures_per_ip.items(), key=lambda kv: -kv[1])


def _open_text(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def replay_file(
    path: str,
    parser_type: str,
    tracker: BruteForceTracker,
    on_alert: Optional[Callable[[AlertEvent], None]] = None,
    whitelist_nets: Optional[list] = None,
) -> ReplayResult:
    """Feed every line of *path* through the parser and tracker (read-only)."""
    from utils.ip_utils import ip_in_list

    parser = get_parser(parser_type)
    if not hasattr(parser, "parse_line") or parser_type == "windows_evtx":
        raise ValueError(f"Replay supports line-based logs only, not '{parser_type}'")

    tracker.use_event_time = True
    result = ReplayResult()

    with _open_text(path) as fh:
        for line in fh:
            result.lines += 1
            try:
                event = parser.parse_line(line)
            except Exception:
                event = None
            if event is None:
                result.ignored += 1
                continue
            if whitelist_nets and ip_in_list(event.ip, whitelist_nets):
                result.ignored += 1
                continue

            if event.event_type == "FAILED":
                result.failed += 1
                result.failures_per_ip[event.ip] = result.failures_per_ip.get(event.ip, 0) + 1
                alert = tracker.record_failed(
                    ip=event.ip, username=event.username,
                    attack_type=event.attack_type, log_source=path,
                    timestamp=event.timestamp or None,
                )
            elif event.event_type == "SUCCESS":
                result.success += 1
                alert = tracker.record_success(
                    ip=event.ip, username=event.username,
                    attack_type=event.attack_type, log_source=path,
                    timestamp=event.timestamp or None,
                )
            else:
                result.ignored += 1
                continue

            if alert:
                result.alerts.append(alert)
                if on_alert:
                    on_alert(alert)

    return result
