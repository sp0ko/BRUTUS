"""
Persistent tracker state: keeps sliding-window counters, alert cooldowns and
trigger counts across restarts, so a restart (or a crash/OOM kill) neither
forgets an attack in progress nor re-alerts on an IP that was just reported.

It also keeps the read position of each tailed log file (see offsets.py) so lines
written while the program was down can be processed after a restart.

The file holds usernames and IPs, so it is written 0600 and atomically
(temp file + rename); a corrupt or unreadable file never prevents startup.
"""

import json
import logging
import os
import tempfile
import threading
from typing import Optional

from .offsets import OffsetStore
from .tracker import BruteForceTracker

log = logging.getLogger("brute-force-detector.state")

FORMAT_VERSION = 1


def snapshot(tracker: BruteForceTracker, offsets: Optional[OffsetStore] = None) -> dict:
    """Tracker counters plus log offsets, taken atomically w.r.t. the watchers.

    Watchers advance an offset and update the tracker under ``offsets.lock``, so
    holding it here guarantees restored counters and offsets describe the same
    point in the logs (no line counted twice, none skipped).
    """
    if offsets is None:
        return {"version": FORMAT_VERSION, **tracker.export_state()}
    with offsets.lock:
        return {"version": FORMAT_VERSION, **tracker.export_state(), "offsets": offsets.snapshot()}


def _write(payload: dict, path: str) -> bool:
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


def save_state(tracker: BruteForceTracker, path: str, offsets: Optional[OffsetStore] = None) -> bool:
    """Write the snapshot to *path* atomically.  Returns True on success."""
    return _write(snapshot(tracker, offsets), path)


def load_state(tracker: BruteForceTracker, path: str, offsets: Optional[OffsetStore] = None) -> int:
    """Restore a snapshot into *tracker* (and *offsets*).  Returns attempts restored (0 if none/invalid)."""
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
    if offsets is not None:
        offsets.load(data.get("offsets"))
    return tracker.import_state(data)


class StatePersister:
    """Background thread saving the tracker every *interval* seconds (only when it changed)."""

    def __init__(self, tracker: BruteForceTracker, path: str, interval: float = 30.0,
                 offsets: Optional[OffsetStore] = None) -> None:
        self.tracker = tracker
        self.offsets = offsets
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
        payload = snapshot(self.tracker, self.offsets)
        key = json.dumps(payload, sort_keys=True)
        if key == self._last:
            return True
        ok = _write(payload, self.path)
        if ok:
            self._last = key
        return ok

    def stop(self) -> None:
        """Stop the thread and write a final snapshot."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.save()
