"""
File reputation lookup for files captured by the honeypot (VirusTotal v3).

Only the SHA256 of a file is sent, never the file itself.  Lookups run on one
background thread, rate limited to the free API quota, and are cached on disk
so the dashboard and reports only ever read the cache and never wait on the
network.

    fi = FileIntel(api_key="...", cache_path="reports/file_intel.json")
    fi.start()
    fi.submit(["<sha256>", ...])      # queue unknown hashes
    fi.lookup("<sha256>")             # cached verdict dict, or None
"""

import json
import logging
import os
import re
import tempfile
import threading
import time
from collections import deque
from typing import Callable, Dict, Iterable, Optional

import requests

log = logging.getLogger(__name__)

_VT_URL = "https://www.virustotal.com/api/v3/files/{sha}"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_FOUND_TTL = 7 * 86400      # detections change slowly
_UNKNOWN_TTL = 86400        # VirusTotal may learn a new sample soon
_BACKOFF = 120              # seconds to pause after HTTP 429 or a network error


def vt_gui_url(sha: str) -> str:
    return f"https://www.virustotal.com/gui/file/{sha}"


class FileIntel:

    def __init__(
        self,
        api_key: str,
        cache_path: str = "reports/file_intel.json",
        requests_per_minute: int = 4,
        daily_limit: int = 500,
        timeout: int = 15,
        alert_min_detections: int = 5,
        on_malicious: Optional[Callable[[str, dict], None]] = None,
        get: Callable = requests.get,
    ) -> None:
        self._key = api_key
        self._path = cache_path
        self._gap = 60.0 / max(1, requests_per_minute)
        self._daily_limit = max(1, daily_limit)
        self._timeout = timeout
        self._alert_min = max(1, alert_min_detections)
        self._on_malicious = on_malicious
        self._get = get
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._queue: deque = deque()
        self._queued: set = set()
        self._cache: Dict[str, dict] = {}
        self._day = ""
        self._used = 0
        self._disabled = False
        self._thread: Optional[threading.Thread] = None
        self._load()

    # ── cache ────────────────────────────────────────────────────────────────

    def _load(self) -> None:
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return
        if isinstance(data, dict):
            self._cache = {k: v for k, v in data.items() if _SHA256.fullmatch(k) and isinstance(v, dict)}

    def _save(self) -> None:
        directory = os.path.dirname(self._path) or "."
        try:
            os.makedirs(directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".file_intel_")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._cache, fh)
            os.replace(tmp, self._path)
        except OSError as exc:
            log.warning("File intel: cannot save cache: %s", exc)

    def _fresh(self, entry: dict) -> bool:
        ttl = _FOUND_TTL if entry.get("status") == "found" else _UNKNOWN_TTL
        return time.time() - float(entry.get("checked", 0)) < ttl

    def lookup(self, sha: str) -> Optional[dict]:
        """Cached verdict (possibly stale) or None. Never touches the network."""
        with self._lock:
            entry = self._cache.get(sha.lower())
            return dict(entry) if entry else None

    def submit(self, hashes: Iterable[str]) -> int:
        """Queue hashes that have no fresh cache entry; returns how many were queued."""
        added = 0
        with self._lock:
            for sha in hashes:
                sha = str(sha).lower()
                if not _SHA256.fullmatch(sha) or sha in self._queued:
                    continue
                entry = self._cache.get(sha)
                if entry and self._fresh(entry):
                    continue
                self._queue.append(sha)
                self._queued.add(sha)
                added += 1
        if added:
            self._wake.set()
        return added

    # ── worker ───────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="file-intel")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def _budget_left(self) -> bool:
        today = time.strftime("%Y-%m-%d", time.gmtime())
        if today != self._day:
            self._day, self._used = today, 0
        return self._used < self._daily_limit

    def _run(self) -> None:
        while not self._stop.is_set() and not self._disabled:
            with self._lock:
                sha = self._queue[0] if self._queue else None
            if sha is None:
                self._wake.wait(60)
                self._wake.clear()
                continue
            if not self._budget_left():
                self._stop.wait(3600)
                continue
            self._used += 1
            pause = self._query(sha)
            self._stop.wait(max(self._gap, pause))

    def _query(self, sha: str) -> float:
        """Look one hash up; returns extra seconds to wait before the next request."""
        try:
            resp = self._get(_VT_URL.format(sha=sha), headers={"x-apikey": self._key}, timeout=self._timeout)
        except requests.RequestException as exc:
            log.warning("File intel: request failed (%s); retrying later", type(exc).__name__)
            return _BACKOFF
        if resp.status_code in (401, 403):
            log.error("File intel: VirusTotal rejected the API key (HTTP %s); lookups disabled", resp.status_code)
            self._disabled = True
            return 0
        if resp.status_code == 429:
            log.warning("File intel: VirusTotal rate limit hit, pausing %ss", _BACKOFF)
            return _BACKOFF
        if resp.status_code == 404:
            self._finish(sha, {"status": "unknown"})
            return 0
        if resp.status_code != 200:
            log.warning("File intel: unexpected HTTP %s for %s", resp.status_code, sha[:12])
            return _BACKOFF
        try:
            attrs = resp.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats") or {}
            result = {
                "status": "found",
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "total": sum(int(v) for v in stats.values()),
                "label": str(((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")) or "")[:80],
            }
        except (ValueError, KeyError, TypeError, AttributeError):
            log.warning("File intel: unreadable VirusTotal answer for %s", sha[:12])
            return _BACKOFF
        self._finish(sha, result)
        return 0

    def _finish(self, sha: str, result: dict) -> None:
        with self._lock:
            previous = self._cache.get(sha) or {}
            result["checked"] = time.time()
            result["alerted"] = bool(previous.get("alerted"))
            notify = (
                result["status"] == "found"
                and result["malicious"] >= self._alert_min
                and not result["alerted"]
            )
            if notify:
                result["alerted"] = True
            self._cache[sha] = result
            if self._queue and self._queue[0] == sha:
                self._queue.popleft()
            self._queued.discard(sha)
            self._save()
        if notify and self._on_malicious:
            try:
                self._on_malicious(sha, dict(result))
            except Exception:  # noqa: BLE001 - an alert failure must not stop the lookups
                log.exception("File intel: alert callback failed")


def describe(result: Optional[dict]) -> str:
    """Short text for reports, e.g. ``12/70 (trojan.mirai)``; empty when there is no verdict."""
    if not result:
        return ""
    if result.get("status") == "unknown":
        return "unknown"
    text = f"{int(result.get('malicious', 0))}/{int(result.get('total', 0))}"
    return f"{text} ({result['label']})" if result.get("label") else text
