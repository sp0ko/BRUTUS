"""
Real-time log file monitor.

One LogFileWatcher thread per log file.  Tails the file,
parses new lines, feeds events to the BruteForceTracker.
"""

import contextlib
import os
import socketserver
import subprocess
import time
import threading
import logging
from typing import List, Callable, Optional

import utils.i18n as i18n
from .offsets import HEAD_BYTES, OffsetStore, head_hash
from .tracker import BruteForceTracker, AlertEvent
from .parsers import get_parser, PARSER_REGISTRY

log = logging.getLogger("brute-force-detector.monitor")


class LogFileWatcher(threading.Thread):
    """
    Tails one log file (binary-safe, position-tracked).

    With an *offsets* store, the position is remembered across restarts: on
    start the watcher first processes what was appended while it was not
    running ("catch-up", flagged on the resulting alerts), then follows the
    file.  Without a saved position it starts at the end of the file.  Rotated
    files (the saved inode now lives in ``<path>.1`` etc.) are finished before
    the new file is read from the beginning; truncated or replaced files are
    read from the beginning.
    """

    HEAD_BYTES = HEAD_BYTES
    _COMPRESSED = (".gz", ".bz2", ".xz", ".zst", ".zip")

    def __init__(
        self,
        path: str,
        parser_type: str,
        tracker: BruteForceTracker,
        on_alert: Callable[[AlertEvent], None],
        whitelist_nets: Optional[list] = None,
        poll_interval: float = 0.25,
        offsets: Optional[OffsetStore] = None,
        catch_up_max_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        super().__init__(daemon=True, name=f"watcher:{os.path.basename(path)}")
        self.path = path
        self.parser = get_parser(parser_type)
        self.tracker = tracker
        self.on_alert = on_alert
        self.whitelist_nets = whitelist_nets or []
        self.poll_interval = poll_interval
        self.offsets = offsets
        self.catch_up_max_bytes = catch_up_max_bytes
        self._stop_event = threading.Event()
        self._guard = offsets.lock if offsets else contextlib.nullcontext()
        self._opened = False                 # has the file been opened before (startup vs. re-open)
        self._mem: Optional[dict] = None     # position to resume at when re-opening the same file
        self._head = b""
        self._inode = 0
        self._pos = 0

    def run(self) -> None:
        log.info(i18n.get_T()["lm_monitoring"], self.path, self.parser.name)
        self._tail()

    def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------

    def _tail(self) -> None:
        while not self._stop_event.is_set():
            if not os.path.exists(self.path):
                log.warning(i18n.get_T()["lm_no_file"], self.path)
                time.sleep(2)
                continue
            try:
                self._tail_once()
            except OSError as exc:
                log.error(i18n.get_T()["lm_read_err"], self.path, exc)
                time.sleep(2)

    def _tail_once(self) -> None:
        rotated = False
        with open(self.path, "rb") as fh:
            st = os.fstat(fh.fileno())
            self._inode = st.st_ino
            pos, catch_up = self._start_position(fh, st)
            self._pos = pos
            self._head = self._read_head(fh, pos)
            fh.seek(pos)
            self._opened = True
            log.info(i18n.get_T()["lm_ready"], self.path)
            if catch_up:
                log.info(i18n.get_T()["lm_catch_up"], self.path, max(st.st_size - pos, 0))
            try:
                while not self._stop_event.is_set():
                    raw = fh.readline()
                    if raw and not raw.endswith(b"\n"):
                        fh.seek(-len(raw), 1)  # writer is mid-line: wait for the rest
                        raw = b""
                    if not raw:
                        if catch_up:
                            catch_up = False
                            log.info(i18n.get_T()["lm_catch_up_done"], self.path)
                        try:
                            cur = os.stat(self.path)
                            if cur.st_ino != self._inode:
                                log.info(i18n.get_T()["lm_rotated"], self.path)
                                rotated = True
                                break
                            if cur.st_size < self._pos:
                                log.info(i18n.get_T()["lm_truncated"], self.path)
                                rotated = True
                                break
                        except OSError:
                            rotated = True
                            break
                        time.sleep(self.poll_interval)
                        continue
                    self._pos += len(raw)
                    if len(self._head) < self.HEAD_BYTES:
                        self._head += raw[: self.HEAD_BYTES - len(self._head)]
                    self._consume(raw, self._pos, catch_up)
            finally:
                # Re-opening the same file (after an I/O error) resumes here;
                # after rotation/truncation the next file is read from the start.
                self._mem = None if rotated else {
                    "inode": self._inode, "offset": self._pos,
                    "head_len": len(self._head), "head": head_hash(self._head),
                }

    # -- start position / catch-up -------------------------------------

    def _start_position(self, fh, st) -> tuple:
        """Return (offset, catch_up) for a freshly opened file."""
        startup = not self._opened
        entry = self._mem
        if entry is None and startup and self.offsets is not None:
            entry = self.offsets.get(self.path)

        if entry is None:
            return (st.st_size if startup else 0), False

        if st.st_ino == entry["inode"]:
            if st.st_size < entry["offset"]:
                log.info(i18n.get_T()["lm_truncated"], self.path)
                return 0, startup
            if self._head_matches(fh, entry):
                return self._cap(fh, entry["offset"], st.st_size), startup
            log.info(i18n.get_T()["lm_replaced"], self.path)
            return 0, startup

        # Different inode: the file we were reading was rotated away.
        if startup:
            self._drain_rotated(entry)
            log.info(i18n.get_T()["lm_rotated"], self.path)
        return 0, startup

    def _cap(self, fh, offset: int, size: int) -> int:
        """Skip ahead if the backlog is larger than catch_up_max_bytes."""
        if size - offset <= self.catch_up_max_bytes:
            return offset
        start = size - self.catch_up_max_bytes
        fh.seek(start)
        fh.readline()  # drop the partial line
        pos = fh.tell()
        log.warning(i18n.get_T()["lm_catch_up_cap"], self.path, pos - offset)
        return pos

    @staticmethod
    def _head_matches(fh, entry: dict) -> bool:
        fh.seek(0)
        return head_hash(fh.read(entry["head_len"])) == entry["head"]

    def _read_head(self, fh, pos: int) -> bytes:
        fh.seek(0)
        return fh.read(min(pos, self.HEAD_BYTES))

    def _rotated_candidates(self) -> List[str]:
        directory = os.path.dirname(os.path.abspath(self.path))
        base = os.path.basename(self.path)
        found = []
        try:
            for name in os.listdir(directory):
                if name != base and name.startswith((base + ".", base + "-")) \
                        and not name.endswith(self._COMPRESSED):
                    full = os.path.join(directory, name)
                    try:
                        found.append((os.stat(full).st_mtime, full))
                    except OSError:
                        continue
        except OSError:
            return []
        return [p for _, p in sorted(found, reverse=True)[:8]]

    def _drain_rotated(self, entry: dict) -> None:
        """Process the unread tail of the file that was rotated while we were down."""
        for cand in self._rotated_candidates():
            try:
                st = os.stat(cand)
                if st.st_ino != entry["inode"] or st.st_size < entry["offset"]:
                    continue
                with open(cand, "rb") as rf:
                    if not self._head_matches(rf, entry):
                        continue
                    pos = self._cap(rf, entry["offset"], st.st_size)
                    rf.seek(pos)
                    log.info(i18n.get_T()["lm_catch_up"], cand, st.st_size - pos)
                    for raw in iter(rf.readline, b""):
                        self._consume(raw, None, True)
                return
            except OSError as exc:
                log.debug("rotated file %s unreadable: %s", cand, exc)

    # -- line handling ---------------------------------------------------

    def _consume(self, raw: bytes, new_pos: Optional[int], catch_up: bool) -> None:
        line = raw.decode("utf-8", errors="replace")
        with self._guard:
            alert = self._evaluate(line, catch_up)
            if new_pos is not None and self.offsets is not None:
                self.offsets.update(self.path, self._inode, new_pos, self._head)
        self._emit(alert, catch_up)

    def _process_line(self, line: str) -> None:
        self._emit(self._evaluate(line, False), False)

    def _evaluate(self, line: str, catch_up: bool) -> Optional[AlertEvent]:
        from utils.ip_utils import ip_in_list
        try:
            event = self.parser.parse_line(line)
        except Exception as exc:
            log.debug(i18n.get_T()["lm_parse_err"], exc)
            return None

        if event is None:
            return None

        if self.whitelist_nets and ip_in_list(event.ip, self.whitelist_nets):
            return None

        if event.event_type == "FAILED":
            kwargs = {"use_event_time": True} if catch_up else {}
            return self.tracker.record_failed(
                ip=event.ip, username=event.username,
                attack_type=event.attack_type, log_source=self.path,
                timestamp=event.timestamp or None, **kwargs,
            )
        if event.event_type == "SUCCESS":
            return self.tracker.record_success(
                ip=event.ip, username=event.username,
                attack_type=event.attack_type, log_source=self.path,
                timestamp=event.timestamp or None,
            )
        return None

    def _emit(self, alert: Optional[AlertEvent], catch_up: bool) -> None:
        if not alert:
            return
        alert.catch_up = catch_up
        try:
            self.on_alert(alert)
        except Exception as exc:
            log.error(i18n.get_T()["lm_alert_err"], exc)


# ──────────────────────────────────────────────────────────────────────────────
# Syslog server (UDP / TCP)
# ──────────────────────────────────────────────────────────────────────────────

class SyslogWatcher(threading.Thread):
    """
    Listens for syslog messages on UDP or TCP and feeds them through
    the same parser/tracker pipeline as LogFileWatcher.

    Remote machines send their auth logs here via rsyslog / syslog-ng.
    The attacker IP comes from INSIDE the syslog message body — not from
    the UDP source address — so no extra configuration is needed on the
    sending side beyond a basic syslog forwarding rule.

    rsyslog snippet (on the remote machine):
        *.auth    @brutus-server:5514          # UDP
        *.auth    @@brutus-server:5514         # TCP
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5514,
        protocol: str = "udp",
        parser_type: str = "linux_ssh",
        tracker: BruteForceTracker = None,
        on_alert: Callable[[AlertEvent], None] = None,
        whitelist_nets: Optional[list] = None,
    ) -> None:
        super().__init__(daemon=True, name=f"syslog:{protocol.upper()}:{port}")
        self.host          = host
        self.port          = port
        self.protocol      = protocol.lower()
        self.parser        = get_parser(parser_type)
        self.tracker       = tracker
        self.on_alert      = on_alert
        self.whitelist_nets = whitelist_nets or []
        self._server       = None

    def run(self) -> None:
        watcher = self

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sender_ip = self.client_address[0]
                if isinstance(self.request, tuple):
                    # UDP: one datagram = one or more log lines
                    raw = self.request[0]
                else:
                    # TCP: read until connection closed
                    chunks = []
                    while True:
                        chunk = self.request.recv(4096)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    raw = b"".join(chunks)

                for line in raw.decode("utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line:
                        watcher._process_line(line, sender_ip)

        base = (socketserver.TCPServer if self.protocol == "tcp"
                else socketserver.UDPServer)

        class _Server(socketserver.ThreadingMixIn, base):
            allow_reuse_address = True
            daemon_threads      = True

        try:
            self._server = _Server((self.host, self.port), _Handler)
            log.info(i18n.get_T()["syslog_started"], self.host, self.port,
                     self.protocol.upper())
            self._server.serve_forever()
        except OSError as exc:
            log.error(i18n.get_T()["syslog_bind_err"], self.host, self.port, exc)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()

    def _process_line(self, line: str, sender_ip: str) -> None:
        from utils.ip_utils import ip_in_list
        log_source = f"syslog:{sender_ip}"
        try:
            event = self.parser.parse_line(line)
        except Exception as exc:
            log.debug(i18n.get_T()["lm_parse_err"], exc)
            return
        if event is None:
            return
        if self.whitelist_nets and ip_in_list(event.ip, self.whitelist_nets):
            return
        if event.event_type == "FAILED":
            alert = self.tracker.record_failed(
                ip=event.ip, username=event.username,
                attack_type=event.attack_type, log_source=log_source,
                timestamp=event.timestamp or None,
            )
        elif event.event_type == "SUCCESS":
            alert = self.tracker.record_success(
                ip=event.ip, username=event.username,
                attack_type=event.attack_type, log_source=log_source,
                timestamp=event.timestamp or None,
            )
        else:
            return
        if alert:
            try:
                self.on_alert(alert)
            except Exception as exc:
                log.error(i18n.get_T()["lm_alert_err"], exc)


# ──────────────────────────────────────────────────────────────────────────────
# systemd journal
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_JOURNALD_UNITS = ["ssh", "sshd", "xrdp-sesman"]


class JournaldWatcher(threading.Thread):
    """
    Follows the systemd journal (``journalctl -f``) and feeds the lines through
    the same parser/tracker pipeline as LogFileWatcher.

    For systems that log SSH only to the journal (no /var/log/auth.log).
    ``command`` can be overridden (used by tests).
    """

    RESTART_DELAY = 2  # seconds before journalctl is restarted after exiting

    def __init__(
        self,
        units: Optional[List[str]] = None,
        parser_type: str = "linux_ssh",
        tracker: BruteForceTracker = None,
        on_alert: Callable[[AlertEvent], None] = None,
        whitelist_nets: Optional[list] = None,
        command: Optional[List[str]] = None,
    ) -> None:
        super().__init__(daemon=True, name="journald")
        self.units          = list(units) if units else list(DEFAULT_JOURNALD_UNITS)
        self.parser         = get_parser(parser_type)
        self.tracker        = tracker
        self.on_alert       = on_alert
        self.whitelist_nets = whitelist_nets or []
        self.command        = command or self._build_command(self.units)
        self._stop_event    = threading.Event()
        self._proc: Optional[subprocess.Popen] = None

    @staticmethod
    def _build_command(units: List[str]) -> List[str]:
        # -n 0: only new entries; -o short: syslog-like lines the parser understands
        cmd = ["journalctl", "-f", "-n", "0", "-o", "short", "--no-pager"]
        for unit in units:
            cmd += ["-u", unit]
        return cmd

    def run(self) -> None:
        T = i18n.get_T()
        log.info(T["journald_started"], ", ".join(self.units))
        while not self._stop_event.is_set():
            try:
                self._proc = subprocess.Popen(
                    self.command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
            except FileNotFoundError:
                log.error(i18n.get_T()["journald_missing"])
                return
            except OSError as exc:
                log.error(i18n.get_T()["journald_err"], exc)
                return

            try:
                for line in self._proc.stdout:
                    if self._stop_event.is_set():
                        break
                    self._process_line(line)
            except (OSError, ValueError) as exc:
                if not self._stop_event.is_set():
                    log.error(i18n.get_T()["journald_err"], exc)
            finally:
                self._terminate()

            if self._stop_event.is_set():
                break
            log.warning(i18n.get_T()["journald_restart"], self.RESTART_DELAY)
            self._stop_event.wait(self.RESTART_DELAY)

    def stop(self) -> None:
        self._stop_event.set()
        self._terminate()

    def _terminate(self) -> None:
        proc = self._proc
        if proc is None:
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        if proc.stdout and not proc.stdout.closed:
            proc.stdout.close()

    def _process_line(self, line: str) -> None:
        from utils.ip_utils import ip_in_list
        try:
            event = self.parser.parse_line(line)
        except Exception as exc:
            log.debug(i18n.get_T()["lm_parse_err"], exc)
            return
        if event is None:
            return
        if self.whitelist_nets and ip_in_list(event.ip, self.whitelist_nets):
            return
        if event.event_type == "FAILED":
            alert = self.tracker.record_failed(
                ip=event.ip, username=event.username,
                attack_type=event.attack_type, log_source="journald",
                timestamp=event.timestamp or None,
            )
        elif event.event_type == "SUCCESS":
            alert = self.tracker.record_success(
                ip=event.ip, username=event.username,
                attack_type=event.attack_type, log_source="journald",
                timestamp=event.timestamp or None,
            )
        else:
            return
        if alert:
            try:
                self.on_alert(alert)
            except Exception as exc:
                log.error(i18n.get_T()["lm_alert_err"], exc)


# ──────────────────────────────────────────────────────────────────────────────

class LogMonitor:

    def __init__(
        self,
        tracker: BruteForceTracker,
        whitelist_nets: Optional[list] = None,
        offsets: Optional[OffsetStore] = None,
        catch_up_max_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self.tracker = tracker
        self.whitelist_nets = whitelist_nets or []
        self.offsets = offsets
        self.catch_up_max_bytes = catch_up_max_bytes
        self._watchers: List[LogFileWatcher] = []
        self._handlers: List[Callable] = []

    def add_alert_handler(self, handler: Callable[[AlertEvent], None]) -> None:
        self._handlers.append(handler)

    def add_log_file(self, path: str, parser_type: str) -> None:
        if parser_type not in PARSER_REGISTRY:
            raise ValueError(i18n.get_T()["lm_unknown_parser"] % parser_type)
        self._watchers.append(LogFileWatcher(
            path=path, parser_type=parser_type,
            tracker=self.tracker, on_alert=self._dispatch,
            whitelist_nets=self.whitelist_nets,
            offsets=self.offsets, catch_up_max_bytes=self.catch_up_max_bytes,
        ))

    def add_syslog_source(
        self,
        host: str = "0.0.0.0",
        port: int = 5514,
        protocol: str = "udp",
        parser_type: str = "linux_ssh",
    ) -> None:
        self._watchers.append(SyslogWatcher(
            host=host, port=port, protocol=protocol,
            parser_type=parser_type,
            tracker=self.tracker, on_alert=self._dispatch,
            whitelist_nets=self.whitelist_nets,
        ))

    def add_journald_source(
        self,
        units: Optional[List[str]] = None,
        parser_type: str = "linux_ssh",
    ) -> None:
        self._watchers.append(JournaldWatcher(
            units=units, parser_type=parser_type,
            tracker=self.tracker, on_alert=self._dispatch,
            whitelist_nets=self.whitelist_nets,
        ))

    def start(self) -> None:
        if not self._watchers:
            raise RuntimeError(i18n.get_T()["lm_no_files"])
        for w in self._watchers:
            w.start()
        log.info(i18n.get_T()["lm_started"], len(self._watchers))

    def stop(self) -> None:
        for w in self._watchers:
            w.stop()
        for w in self._watchers:
            w.join(timeout=3)

    def _dispatch(self, event: AlertEvent) -> None:
        for h in self._handlers:
            try:
                h(event)
            except Exception as exc:
                log.error(i18n.get_T()["lm_dispatch_err"], exc)
