"""
Persistent tracker state: keeps sliding-window counters, alert cooldowns and
trigger counts across restarts, so a restart (or a crash/OOM kill) neither
forgets an attack in progress nor re-alerts on an IP that was just reported.

The file holds usernames and IPs, so it is written 0600 and atomically
(temp file + rename); a corrupt or unreadable file never prevents startup.
"""

import json
import logging
import os
import tempfile
import threading
from typing import Optional

from .tracker import BruteForceTracker

log = logging.getLogger("brute-force-detector.state")

FORMAT_VERSION = 1


def save_state(tracker: BruteForceTracker, path: str) -> bool:
    """Write the tracker snapshot to *path* atomically.  Returns True on success."""
    payload = {"version": FORMAT_VERSION, **tracker.export_state()}
    directory = os.path.dirname(os.path.abspath(path))
    tmp = None
    try:
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".tracker_state_", suffix=".tmp", dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:  # mkstemp creates it 0600
            json.dump(payload, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        return True
    except OSError as exc:
        log.warning("Could not save tracker state to %s: %s", path, exc)
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        return False


def load_state(tracker: BruteForceTracker, path: str) -> int:
    """Restore a snapshot into *tracker*.  Returns attempts restored (0 if none/invalid)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return 0
    except (OSError, ValueError) as exc:
        log.warning("Ignoring unreadable tracker state %s: %s", path, exc)
        return 0
    if not isinstance(data, dict) or data.get("version") != FORMAT_VERSION:
        log.warning("Ignoring tracker state %s: unsupported format", path)
        return 0
    return tracker.import_state(data)


class StatePersister:
    """Background thread saving the tracker every *interval* seconds (only when it changed)."""

    def __init__(self, tracker: BruteForceTracker, path: str, interval: float = 30.0) -> None:
        self.tracker = tracker
        self.path = path
        self.interval = max(1.0, float(interval))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last: Optional[str] = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="state-persister", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self.save()

    def save(self) -> bool:
        snapshot = json.dumps(self.tracker.export_state(), sort_keys=True)
        if snapshot == self._last:
            return True
        ok = save_state(self.tracker, self.path)
        if ok:
            self._last = snapshot
        return ok

    def stop(self) -> None:
        """Stop the thread and write a final snapshot."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.save()
