"""IP geolocation via ip-api.com (free, no API key required)."""

import time
import threading
from typing import Optional

import requests

_SINGLE_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query"
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "::1", "fc", "fd",
)


class GeoLocator:

    def __init__(self, enabled: bool = True, cache_ttl: int = 3600, timeout: int = 5) -> None:
        self.enabled = enabled
        self._cache_ttl = cache_ttl
        self._timeout = timeout
        self._cache: dict = {}
        self._req_times: list = []
        self._lock = threading.Lock()

    def lookup(self, ip: str) -> Optional[dict]:
        if not self.enabled:
            return None
        if self._is_private(ip):
            return {"country": "Private/LAN", "regionName": "", "city": "", "isp": "local", "org": ""}

        with self._lock:
            cached = self._cache.get(ip)
            if cached and (time.time() - cached[0]) < self._cache_ttl:
                return cached[1]

        if not self._rate_ok():
            return None

        try:
            resp = requests.get(_SINGLE_URL.format(ip=ip), timeout=self._timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return None

        if data.get("status") != "success":
            return None

        result = {k: data.get(k, "") for k in ("country", "regionName", "city", "isp", "org", "as", "query")}
        with self._lock:
            self._cache[ip] = (time.time(), result)
        return result

    @staticmethod
    def _is_private(ip: str) -> bool:
        return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)

    def _rate_ok(self) -> bool:
        now = time.time()
        with self._lock:
            self._req_times = [t for t in self._req_times if now - t < 60]
            if len(self._req_times) >= 40:
                return False
            self._req_times.append(now)
        return True
