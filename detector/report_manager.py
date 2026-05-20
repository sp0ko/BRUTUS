"""Persist alert events to a JSON-Lines file."""

import json
import os
import threading
from datetime import datetime
from typing import Optional

from .tracker import AlertEvent


class ReportManager:

    def __init__(self, output_path: str) -> None:
        self._path = output_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    def save(self, event: AlertEvent, geo: Optional[dict] = None) -> None:
        record = {
            "timestamp": datetime.utcfromtimestamp(event.last_seen).isoformat() + "Z",
            "ip": event.ip,
            "count": event.count,
            "time_window_sec": event.time_window,
            "attack_type": event.attack_type,
            "usernames": event.usernames,
            "log_sources": event.log_sources,
            "first_seen": datetime.utcfromtimestamp(event.first_seen).isoformat() + "Z",
            "last_seen": datetime.utcfromtimestamp(event.last_seen).isoformat() + "Z",
            "successful_login": event.successful_login,
            "geo": geo,
        }
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
