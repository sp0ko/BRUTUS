"""IP address utilities: whitelist/CIDR checking."""

import ipaddress
from typing import List


def parse_cidr_list(entries: List[str]) -> list:
    result = []
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        try:
            result.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            pass
    return result


def ip_in_list(ip: str, network_list: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in network_list)


def local_addresses() -> set:
    """Best-effort set of this host's own IP addresses (never worth blocking)."""
    import re
    import socket
    import subprocess

    found = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(info[4][0].split("%")[0])
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # UDP connect: selects a route, sends nothing
            found.add(s.getsockname()[0])
    except OSError:
        pass
    try:
        out = subprocess.run(["ip", "-o", "addr"], capture_output=True, text=True, timeout=3).stdout
        found.update(re.findall(r"\binet6? ([0-9a-fA-F\.:]+)/", out))
    except (OSError, subprocess.SubprocessError):
        pass
    return found
