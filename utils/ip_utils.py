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
