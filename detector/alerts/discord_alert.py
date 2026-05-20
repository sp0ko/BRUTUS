"""
Discord webhook alert handler — rich embeds.
"""

from datetime import datetime
from typing import Optional

import requests

from ..tracker import AlertEvent


class DiscordAlert:
    _COLOR_WARNING  = 0xFFA500
    _COLOR_CRITICAL = 0xFF0000

    def __init__(self, webhook_url: str, timeout: int = 10) -> None:
        if not webhook_url:
            raise ValueError("Discord webhook URL nie może być pusty.")
        self._url = webhook_url
        self._timeout = timeout

    def send(self, event: AlertEvent, geo: Optional[dict] = None) -> bool:
        try:
            resp = requests.post(self._url, json=self._build_payload(event, geo), timeout=self._timeout)
            resp.raise_for_status()
            return True
        except requests.RequestException as exc:
            print(f"[Discord] Błąd wysyłki: {exc}")
            return False

    def _build_payload(self, event: AlertEvent, geo: Optional[dict]) -> dict:
        ts_iso = datetime.utcfromtimestamp(event.last_seen).isoformat() + "Z"
        color = self._COLOR_CRITICAL if event.successful_login else self._COLOR_WARNING

        if event.successful_login:
            title = "🚨 KRYTYCZNE! UDANE LOGOWANIE PO BRUTE-FORCE!"
            description = (
                f"Adres IP **{event.ip}** prawdopodobnie **pomyślnie przejął konto** "
                f"po {event.count} nieudanych próbach."
            )
        else:
            title = "⚠️ UWAGA! POTENCJALNY BRUTE FORCE WYKRYTY!"
            description = (
                f"Adres IP **{event.ip}** wykonał **{event.count} nieudanych prób logowania** "
                f"w ciągu **{event.time_window} sekund**."
            )

        fields = [
            {"name": "🌐 Adres IP",      "value": f"`{event.ip}`",                       "inline": True},
            {"name": "📊 Liczba prób",   "value": str(event.count),                      "inline": True},
            {"name": "⏱ Okno czasu",     "value": f"{event.time_window}s",               "inline": True},
            {"name": "🔌 Typ ataku",     "value": event.attack_type or "—",              "inline": True},
            {"name": "👤 Użytkownicy",   "value": _trunc(", ".join(event.usernames) or "—", 1024), "inline": False},
            {"name": "📁 Źródło logów", "value": _trunc(", ".join(event.log_sources) or "—", 512), "inline": False},
        ]

        if geo:
            loc = ", ".join(str(geo[k]) for k in ("country", "regionName", "city") if geo.get(k) and geo[k] != "unknown")
            if loc:
                fields.append({"name": "🗺 Geolokalizacja", "value": loc, "inline": False})
            if geo.get("isp") and geo["isp"] != "unknown":
                fields.append({"name": "🏢 ISP / Org", "value": geo["isp"], "inline": False})

        return {
            "username": "BRUTU$",
            "embeds": [{
                "title": title,
                "description": description,
                "color": color,
                "fields": fields,
                "timestamp": ts_iso,
                "footer": {"text": "BRUTU$ • SSH/RDP Brute-Force Detector"},
            }],
        }


def _trunc(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit - 3] + "..."
