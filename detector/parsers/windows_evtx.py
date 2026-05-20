"""
Windows Event Log / EVTX parser.

Backends:
  1. python-evtx  — parse static .evtx files (cross-platform)
  2. pywin32      — live Security log monitoring (Windows only)

Event IDs handled: 4625 (failed logon), 4624 (success), 4648 (explicit creds)
RDP logon types: 3 (Network), 10 (RemoteInteractive)
"""

import re
import time
import xml.etree.ElementTree as ET
from typing import Optional, Iterator

from .linux_ssh import ParsedEvent

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
# Type 10 = RemoteInteractive (RDP), type 7 = Unlock (also RDP-related)
_RDP_LOGON_TYPES = {"7", "10"}


class WindowsEvtxParser:
    name = "windows_evtx"

    def iter_file(self, path: str) -> Iterator[ParsedEvent]:
        """Parse a static .evtx file (requires python-evtx)."""
        try:
            import Evtx.Evtx as evtx
        except ImportError:
            raise ImportError("Install python-evtx:  pip install python-evtx")

        with evtx.Evtx(path) as log:
            for record in log.records():
                try:
                    event = self._parse_xml(record.xml(), source=path)
                    if event:
                        yield event
                except Exception:
                    continue

    def iter_live(self, poll_interval: float = 1.0) -> Iterator[ParsedEvent]:
        """Subscribe to Windows Security log (requires pywin32, Windows only)."""
        try:
            import win32evtlog
            import win32evtlogutil
        except ImportError:
            raise ImportError("Install pywin32:  pip install pywin32")

        hand = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        win32evtlog.ReadEventLog(hand, flags, 0)  # skip to end

        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                time.sleep(poll_interval)
                continue
            for ev in events:
                event_id = ev.EventID & 0xFFFF
                if event_id not in (4625, 4624, 4648):
                    continue
                parsed = self._parse_win32_event(ev, event_id, source="Security")
                if parsed:
                    yield parsed

    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        """Handle XML-streamed EVTX records (from log shippers)."""
        line = line.strip()
        if line.startswith("<Event"):
            return self._parse_xml(line, source="xml-stream")
        return None

    # ------------------------------------------------------------------

    def _parse_xml(self, xml_str: str, source: str) -> Optional[ParsedEvent]:
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return None

        eid_el = root.find(".//e:EventID", _NS)
        if eid_el is None:
            eid_el = root.find(".//EventID")
        if eid_el is None:
            return None
        try:
            event_id = int(eid_el.text) & 0xFFFF
        except (ValueError, TypeError):
            return None

        if event_id not in (4625, 4624, 4648):
            return None

        data = {
            el.get("Name", ""): (el.text or "").strip()
            for el in (root.findall(".//e:Data", _NS) + root.findall(".//Data"))
            if el.get("Name")
        }

        ip = data.get("IpAddress", data.get("WorkstationName", ""))
        ip = re.sub(r"^::ffff:", "", ip.strip())
        if not ip or ip in ("-", "::1", "127.0.0.1"):
            return None

        username = data.get("TargetUserName", data.get("SubjectUserName", ""))
        logon_type = data.get("LogonType", "")
        attack_type = "RDP" if logon_type in _RDP_LOGON_TYPES else "SMB/Network"
        ts = self._xml_timestamp(root)

        return ParsedEvent(
            event_type="FAILED" if event_id == 4625 else "SUCCESS",
            ip=ip,
            username=username,
            attack_type=attack_type,
            raw_line=xml_str[:200],
            timestamp=ts,
        )

    def _parse_win32_event(self, ev, event_id: int, source: str) -> Optional[ParsedEvent]:
        strings = ev.StringInserts or []
        ip, username, logon_type = "", "", ""
        if event_id == 4625 and len(strings) >= 20:
            username, logon_type, ip = strings[5] or "", strings[10] or "", strings[19] or ""
        elif event_id == 4624 and len(strings) >= 19:
            username, logon_type, ip = strings[5] or "", strings[8] or "", strings[18] or ""

        ip = re.sub(r"^::ffff:", "", ip.strip())
        if not ip or ip in ("-", "::1", "127.0.0.1"):
            return None

        attack_type = "RDP" if logon_type in _RDP_LOGON_TYPES else "SMB/Network"
        ts = ev.TimeGenerated.timestamp() if hasattr(ev, "TimeGenerated") else time.time()

        return ParsedEvent(
            event_type="FAILED" if event_id == 4625 else "SUCCESS",
            ip=ip, username=username, attack_type=attack_type, timestamp=ts,
            raw_line=f"EventID={event_id}",
        )

    @staticmethod
    def _xml_timestamp(root: ET.Element) -> float:
        tc = root.find(".//e:TimeCreated", _NS)
        if tc is None:
            tc = root.find(".//TimeCreated")
        if tc is not None:
            st = tc.get("SystemTime", "").rstrip("Z")
            if st:
                try:
                    from datetime import datetime, timezone
                    return datetime.fromisoformat(st).replace(tzinfo=timezone.utc).timestamp()
                except ValueError:
                    pass
        return time.time()
