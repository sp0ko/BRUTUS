"""
IP geolocation — GeoLite2 offline (MaxMind .mmdb) with ip-api.com online fallback.

Offline mode requires the ``geoip2`` package:
    pip install geoip2

Download a free GeoLite2-City database from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
and pass the path via --geoip-db or the ``mmdb_path`` config key.
"""

import logging
import os
import time
import threading
from typing import Optional

import requests

try:
    import geoip2.database
    import geoip2.errors
    _HAS_GEOIP2 = True
except ImportError:
    _HAS_GEOIP2 = False

log = logging.getLogger("brute-force-detector.geo")

_SINGLE_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query"
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "::1", "fc", "fd",
)


class GeoLocator:

    def __init__(
        self,
        enabled: bool = True,
        cache_ttl: int = 3600,
        timeout: int = 5,
        mmdb_path: Optional[str] = None,
    ) -> None:
        self.enabled = enabled
        self._cache_ttl = cache_ttl
        self._timeout = timeout
        self._cache: dict = {}
        self._req_times: list = []
        self._lock = threading.Lock()
        self._reader = None
        if mmdb_path:
            self._load_mmdb(mmdb_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lookup(self, ip: str) -> Optional[dict]:
        if not self.enabled:
            return None
        if self._is_private(ip):
            return {"country": "Private/LAN", "regionName": "", "city": "", "isp": "local", "org": ""}

        with self._lock:
            cached = self._cache.get(ip)
            if cached and (time.time() - cached[0]) < self._cache_ttl:
                return cached[1]

        result = self._lookup_offline(ip) if self._reader is not None else None
        if result is None:
            result = self._lookup_online(ip)

        if result:
            with self._lock:
                self._cache[ip] = (time.time(), result)
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_mmdb(self, path: str) -> None:
        if not _HAS_GEOIP2:
            log.warning(
                "geoip2 library not installed — offline GeoIP unavailable. "
                "Install with: pip install geoip2"
            )
            return
        if not os.path.isfile(path):
            log.warning("GeoIP2 database file not found: %s", path)
            return
        try:
            self._reader = geoip2.database.Reader(path)
            log.info("GeoIP2 offline database loaded: %s", path)
        except Exception as exc:
            log.error("Failed to open GeoIP2 database %s: %s", path, exc)

    def _lookup_offline(self, ip: str) -> Optional[dict]:
        try:
            resp = self._reader.city(ip)
            try:
                isp = resp.traits.autonomous_system_organization or ""
                asn = str(resp.traits.autonomous_system_number) if resp.traits.autonomous_system_number else ""
            except Exception:
                isp, asn = "", ""
            subdiv = resp.subdivisions.most_specific.name if resp.subdivisions else ""
            return {
                "country":    resp.country.name or "",
                "regionName": subdiv,
                "city":       resp.city.name or "",
                "isp":        isp,
                "org":        isp,
                "as":         asn,
                "query":      ip,
            }
        except Exception:
            # AddressNotFoundError or any other geoip2 error
            return None

    def _lookup_online(self, ip: str) -> Optional[dict]:
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
        return {k: data.get(k, "") for k in ("country", "regionName", "city", "isp", "org", "as", "query")}

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
