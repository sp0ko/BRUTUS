"""
Read positions of tailed log files, so lines written while BRUTU$ was not
running can be processed after a restart (see LogFileWatcher).

An entry identifies *which* file it belongs to by inode plus a hash of the
file's first bytes, so a rotated or replaced file is never mistaken for the one
we were reading.  The store lives inside the tracker state file (see
detector/state.py) and is saved in the same atomic write as the tracker
counters; ``lock`` makes "process a line + advance the offset" atomic with
respect to that snapshot, so restored counters and offsets always agree.
"""

import hashlib
import threading
from typing import Dict, Optional

HEAD_BYTES = 256


def head_hash(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


class OffsetStore:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self._entries: Dict[str, dict] = {}

    @staticmethod
    def _public(e: dict) -> dict:
        head = e["head"]
        return {
            "inode": e["inode"], "offset": e["offset"], "head_len": e["head_len"],
            "head": head if isinstance(head, str) else head_hash(head),
        }

    def get(self, path: str) -> Optional[dict]:
        with self.lock:
            e = self._entries.get(path)
            return self._public(e) if e else None

    def update(self, path: str, inode: int, offset: int, head: bytes) -> None:
        """Record progress.  Callers hold ``lock``.  *head* is the file's first bytes (hashed lazily)."""
        self._entries[path] = {"inode": inode, "offset": offset, "head_len": len(head), "head": head}

    def snapshot(self) -> Dict[str, dict]:
        """Callers hold ``lock``."""
        return {p: self._public(e) for p, e in self._entries.items()}

    def load(self, data: object) -> int:
        """Load a snapshot; malformed entries are skipped.  Returns entries loaded."""
        if not isinstance(data, dict):
            return 0
        loaded = 0
        with self.lock:
            for path, e in data.items():
                try:
                    entry = {
                        "inode": int(e["inode"]), "offset": int(e["offset"]),
                        "head_len": int(e["head_len"]), "head": str(e["head"]),
                    }
                except (TypeError, ValueError, KeyError):
                    continue
                if isinstance(path, str) and entry["offset"] >= 0 and 0 <= entry["head_len"] <= HEAD_BYTES:
                    self._entries[path] = entry
                    loaded += 1
        return loaded
