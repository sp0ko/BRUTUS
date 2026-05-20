"""
Slack webhook alert handler — Block Kit formatting.
"""

from datetime import datetime
from typing import Optional

import requests

from ..tracker import AlertEvent


class SlackAlert:

    def __init__(self, webhook_url: str, timeout: int = 10) -> None:
        if not webhook_url:
            raise ValueError("Slack webhook URL nie może być pusty.")
        self._url = webhook_url
        self._timeout = timeout

    def send(self, event: AlertEvent, geo: Optional[dict] = None) -> bool:
        try:
            resp = requests.post(self._url, json=self._build_payload(event, geo), timeout=self._timeout)
            resp.raise_for_status()
            return True
        except requests.RequestException as exc:
            print(f"[Slack] Błąd wysyłki: {exc}")
            return False

    def _build_payload(self, event: AlertEvent, geo: Optional[dict]) -> dict:
        ts_str = datetime.fromtimestamp(event.last_seen).strftime("%Y-%m-%d %H:%M:%S")

        if event.successful_login:
            header = "🚨 KRYTYCZNE! UDANE LOGOWANIE PO BRUTE-FORCE!"
            color = "#FF0000"
            summary = f"IP `{event.ip}` prawdopodobnie *pomyślnie przejął konto* po {event.count} nieudanych próbach."
        else:
            header = "⚠️ UWAGA! POTENCJALNY BRUTE FORCE WYKRYTY!"
            color = "#FFA500"
            summary = f"IP `{event.ip}` wykonał *{event.count} nieudanych prób logowania* w ciągu *{event.time_window} sekund*."

        fields_md = "\n".join([
            f"*🌐 Adres IP:*\t`{event.ip}`",
            f"*📊 Próby:*\t{event.count} / {event.time_window}s",
            f"*🔌 Typ ataku:*\t{event.attack_type or '—'}",
            f"*👤 Użytkownicy:*\t{_trunc(', '.join(event.usernames) or '—', 300)}",
            f"*📁 Źródło:*\t{_trunc(', '.join(event.log_sources) or '—', 200)}",
            f"*🕐 Czas:*\t{ts_str}",
        ])

        if geo:
            loc = ", ".join(str(geo[k]) for k in ("country", "regionName", "city") if geo.get(k) and geo[k] != "unknown")
            if loc:
                fields_md += f"\n*🗺 Lokalizacja:*\t{loc}"
            if geo.get("isp") and geo["isp"] != "unknown":
                fields_md += f"\n*🏢 ISP:*\t{geo['isp']}"

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": header.replace("*", ""), "emoji": True}},
            {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": fields_md}},
        ]

        return {
            "attachments": [{
                "color": color,
                "blocks": blocks,
                "fallback": f"[BRUTE-FORCE] IP {event.ip} — {event.count} prób w {event.time_window}s",
            }]
        }


def _trunc(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit - 3] + "..."
