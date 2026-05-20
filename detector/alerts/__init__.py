import time
from datetime import datetime
from typing import Optional

from ..tracker import AlertEvent


def format_alert(event: AlertEvent, geo: Optional[dict] = None) -> str:
    ts = datetime.fromtimestamp(event.last_seen).strftime("%Y-%m-%d %H:%M:%S")
    tag = "BRUTE-FORCE+PWNED" if event.successful_login else "BRUTE-FORCE"
    return (
        f"[{ts}] [{tag}] IP={event.ip}  ataki={event.count}  "
        f"okno={event.time_window}s  typ={event.attack_type}  "
        f"użytkownicy={','.join(event.usernames)}"
    )
