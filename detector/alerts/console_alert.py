"""
Console alert handler — coloured, human-readable terminal output.
"""

import sys
from datetime import datetime
from typing import Optional

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False

from ..tracker import AlertEvent


def _c(code: str, text: str) -> str:
    if not _HAS_COLOR:
        return text
    return f"{code}{text}{Style.RESET_ALL}"


class ConsoleAlert:

    def __init__(self, stream=None) -> None:
        self._out = stream or sys.stdout

    def send(self, event: AlertEvent, geo: Optional[dict] = None) -> bool:
        print(self._format(event, geo), file=self._out)
        return True

    def _format(self, event: AlertEvent, geo: Optional[dict]) -> str:
        ts = datetime.fromtimestamp(event.last_seen).strftime("%Y-%m-%d %H:%M:%S")

        if event.successful_login:
            border = _c(Fore.RED if _HAS_COLOR else "", "=" * 70)
            title  = _c(Fore.RED if _HAS_COLOR else "", " 🚨 KRYTYCZNE! UDANE LOGOWANIE PO BRUTE-FORCE! 🚨".center(70))
        else:
            border = _c(Fore.YELLOW if _HAS_COLOR else "", "=" * 70)
            title  = _c(Fore.YELLOW if _HAS_COLOR else "", " ⚠️  UWAGA! POTENCJALNY BRUTE FORCE!  ⚠️".center(70))

        ip_str      = _c(Fore.CYAN    if _HAS_COLOR else "", event.ip)
        count_str   = _c(Fore.RED     if _HAS_COLOR else "", str(event.count))
        type_str    = _c(Fore.MAGENTA if _HAS_COLOR else "", event.attack_type)
        users_str   = _c(Fore.WHITE   if _HAS_COLOR else "", ", ".join(event.usernames) or "—")

        lines = [
            border, title, border,
            f"  🌐 Adres IP       : {ip_str}",
            f"  📊 Nieudane próby : {count_str} w ciągu {event.time_window}s",
            f"  🔌 Typ ataku      : {type_str}",
            f"  👤 Użytkownicy    : {users_str}",
            f"  📁 Źródło logów   : {', '.join(event.log_sources) or '—'}",
            f"  🕐 Czas wykrycia  : {ts}",
        ]

        if geo:
            parts = [str(geo[k]) for k in ("country", "regionName", "city") if geo.get(k) and geo[k] != "unknown"]
            if parts:
                lines.append(f"  🗺  Geolokalizacja  : {_c(Fore.GREEN if _HAS_COLOR else '', ', '.join(parts))}")
            if geo.get("isp") and geo["isp"] != "unknown":
                lines.append(f"  🏢 ISP / Org       : {geo['isp']}")

        if event.successful_login:
            lines.append(_c(Fore.RED if _HAS_COLOR else "", "  ‼ MOŻLIWE WŁAMANIE — sprawdź konto natychmiast!"))

        lines.append(border)
        return "\n".join(lines)
