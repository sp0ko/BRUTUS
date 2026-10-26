"""
IPBlocker — active defense via iptables / ip6tables.

Automatically blocks attacker IPs using DROP rules and optionally
auto-unblocks them after a configurable timeout.  Requires the process
to run as root (or have CAP_NET_ADMIN) to modify iptables.

All subprocess calls use argument lists (no shell=True) to prevent
command injection.  IPs are validated before use.
"""

import ipaddress
import json
import logging
import os
import re
import subprocess
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("brute-force-detector.blocker")

# Strict validation patterns — no shell metacharacters can pass
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]{2,39}$")


def _validate_ip(ip: str) -> bool:
    """Return True only for syntactically valid IPv4 or IPv6 addresses."""
    if _IPV4_RE.match(ip):
        parts = ip.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return bool(_IPV6_RE.match(ip))


def _is_ipv6(ip: str) -> bool:
    return ":" in ip


# attack_type -> TCP ports blocked when scope == "service"
DEFAULT_PORTS: Dict[str, List[int]] = {
    "SSH": [22],
    "RDP": [3389],
    "HTTP": [80, 443],
    "FTP": [21],
    "MYSQL": [3306],
}

PortSet = Optional[List[int]]  # None = block every port


def _merge_ports(a: PortSet, b: PortSet) -> PortSet:
    if a is None or b is None:
        return None
    return sorted(set(a) | set(b))


class IPBlocker:
    """
    Manages a set of blocked IPs via iptables/ip6tables INSERT rules.

    Parameters
    ----------
    enabled : bool
        Master switch.  When False no iptables calls are made.
    auto_unblock_after : int
        Seconds until automatic unblock.  0 = permanent until program exit
        or explicit unblock.
    state_file : str
        JSON file to persist block state across restarts.
    dry_run : bool
        Log what would happen but do not execute iptables commands.
    scope : str
        "all" (default) drops all traffic from the IP.  "service" drops only
        the TCP ports of the attacked service (see *ports*); attack types
        without a known port (e.g. PASSWORD_SPRAY) still get a full block.
    ports : dict
        attack_type -> list of TCP ports, overrides/extends DEFAULT_PORTS.
    protected_nets : list
        Networks that are never blocked (e.g. trusted reverse proxies).
    protect_private : bool
        Also never block private (RFC1918/ULA) addresses.  Loopback,
        link-local, multicast and this host's own addresses are always safe.
    """

    def __init__(
        self,
        enabled: bool = True,
        auto_unblock_after: int = 3600,
        state_file: str = "reports/blocked_ips.json",
        dry_run: bool = False,
        scope: str = "all",
        ports: Optional[Dict[str, List[int]]] = None,
        protected_nets: Optional[list] = None,
        protect_private: bool = False,
    ) -> None:
        if scope not in ("all", "service"):
            raise ValueError(f"blocker scope must be 'all' or 'service', got {scope!r}")
        self.enabled = enabled
        self.auto_unblock_after = auto_unblock_after
        self.state_file = state_file
        self.dry_run = dry_run
        self.scope = scope
        self.ports = {k.upper(): sorted({int(p) for p in v}) for k, v in {**DEFAULT_PORTS, **(ports or {})}.items()}
        self.protected_nets = protected_nets or []
        self.protect_private = protect_private
        self._own_addrs: Optional[set] = None

        # ip -> {"blocked_at": float, "attempts": int, "attack_type": str,
        #         "usernames": list, "geo": dict|None, "unblock_at": float|None}
        self._blocked: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._op_lock = threading.Lock()  # serialises iptables changes

        self._check_privileges()
        self._load_state()

        if self.enabled and self.auto_unblock_after > 0:
            self._start_unblock_scheduler()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ports_for(self, attack_type: str) -> PortSet:
        """TCP ports to drop for *attack_type*; None means block everything."""
        if self.scope != "service":
            return None
        result: List[int] = []
        for name in (attack_type or "").split(","):
            mapped = self.ports.get(name.strip().upper())
            if not mapped:
                return None  # unknown / cross-service type (e.g. PASSWORD_SPRAY)
            result = sorted(set(result) | set(mapped))
        return result or None

    def is_protected(self, ip: str) -> bool:
        """True for addresses that must never be blocked (locking yourself out)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.is_loopback or addr.is_unspecified or addr.is_link_local or addr.is_multicast:
            return True
        if self.protect_private and addr.is_private:
            return True
        if any(addr in net for net in self.protected_nets):
            return True
        if self._own_addrs is None:
            from .ip_utils import local_addresses
            self._own_addrs = local_addresses()
        return ip in self._own_addrs

    def block(
        self,
        ip: str,
        attempts: int = 0,
        attack_type: str = "",
        usernames: Optional[List[str]] = None,
        geo: Optional[dict] = None,
    ) -> bool:
        """Add DROP rule(s) for *ip*.  Returns True if the rules changed."""
        if not self.enabled:
            return False
        if not _validate_ip(ip):
            log.warning("IPBlocker: invalid IP address ignored: %r", ip)
            return False
        if self.is_protected(ip):
            log.warning("IPBlocker: %s is protected (loopback / own address / trusted) — not blocked", ip)
            return False

        wanted = self.ports_for(attack_type)
        with self._op_lock:
            with self._lock:
                existing = self._blocked.get(ip)
                old = existing.get("ports") if existing else None
            if existing:
                merged = _merge_ports(old, wanted)
                if merged == old:
                    return False  # already covered
                if merged is None:
                    ok = self._insert(ip, None)  # widen to a full block ...
                    if ok:
                        self._delete(ip, old)    # ... and drop the now-redundant port rules
                else:
                    ok = self._insert(ip, [p for p in merged if p not in (old or [])])
                if not ok:
                    return False
                with self._lock:
                    existing["ports"] = merged
                    existing["attempts"] = max(existing.get("attempts", 0), attempts)
                    known = [t.strip() for t in existing.get("attack_type", "").split(",") if t.strip()]
                    for t in (x.strip() for x in attack_type.split(",")):
                        if t and t not in known:
                            known.append(t)
                    existing["attack_type"] = ", ".join(known)
                self._save_state()
                log.warning("BLOCK WIDENED %s | type=%s ports=%s", ip, attack_type, merged or "all")
                return True

            if not self._insert(ip, wanted):
                return False
            now = time.time()
            with self._lock:
                self._blocked[ip] = {
                    "blocked_at": now,
                    "attempts":   attempts,
                    "attack_type": attack_type,
                    "usernames":  usernames or [],
                    "geo":        geo,
                    "unblock_at": now + self.auto_unblock_after if self.auto_unblock_after > 0 else None,
                    "ports":      wanted,
                }
        log.warning(
            "BLOCKED %s | type=%s attempts=%d users=%s ports=%s unblock_in=%s",
            ip, attack_type, attempts,
            ",".join((usernames or [])[:5]) or "—",
            ",".join(map(str, wanted)) if wanted else "all",
            f"{self.auto_unblock_after}s" if self.auto_unblock_after else "permanent",
        )
        self._save_state()
        return True

    def unblock(self, ip: str) -> bool:
        """Remove the DROP rule(s) for *ip*.  Returns True on success."""
        if not _validate_ip(ip):
            return False
        with self._op_lock:
            with self._lock:
                meta = self._blocked.pop(ip, None)
            if meta is None:
                return False
            result = self._delete(ip, meta.get("ports"))
        self._save_state()
        if result:
            log.info("UNBLOCKED %s", ip)
        return result

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked

    def get_blocked(self) -> List[dict]:
        """Return a snapshot list of all currently blocked IPs with metadata."""
        now = time.time()
        with self._lock:
            rows = []
            for ip, meta in self._blocked.items():
                remaining = None
                if meta["unblock_at"]:
                    remaining = max(0, int(meta["unblock_at"] - now))
                rows.append({
                    "ip":          ip,
                    "blocked_at":  meta["blocked_at"],
                    "attempts":    meta["attempts"],
                    "attack_type": meta["attack_type"],
                    "usernames":   meta["usernames"],
                    "geo":         meta["geo"],
                    "remaining_s": remaining,
                    "ports":       meta.get("ports"),
                })
            return sorted(rows, key=lambda r: r["blocked_at"], reverse=True)

    def unblock_all(self) -> int:
        """Unblock all IPs (called on clean shutdown).  Returns count."""
        ips = list(self._blocked.keys())
        count = 0
        for ip in ips:
            if self.unblock(ip):
                count += 1
        return count

    # ------------------------------------------------------------------
    # iptables helpers
    # ------------------------------------------------------------------

    def _insert(self, ip: str, ports: PortSet) -> bool:
        """Insert the DROP rule(s); on partial failure roll back what was added."""
        done: List[Optional[int]] = []
        for port in (ports if ports else [None]):
            if not self._run(self._cmd(ip, "I", port)):
                for p in done:
                    self._run(self._cmd(ip, "D", p))
                return False
            done.append(port)
        return True

    def _delete(self, ip: str, ports: PortSet) -> bool:
        results = [self._run(self._cmd(ip, "D", port)) for port in (ports if ports else [None])]
        return all(results)

    def _cmd(self, ip: str, action: str, port: Optional[int] = None) -> List[str]:
        binary = "ip6tables" if _is_ipv6(ip) else "iptables"
        match = ["-p", "tcp", "--dport", str(port)] if port else []
        # INSERT: iptables -I INPUT 1 -s IP [-p tcp --dport N] -j DROP
        # DELETE: iptables -D INPUT   -s IP [-p tcp --dport N] -j DROP
        if action == "I":
            return [binary, "-I", "INPUT", "1", "-s", ip, *match, "-j", "DROP"]
        return [binary, "-D", "INPUT", "-s", ip, *match, "-j", "DROP"]

    def _run(self, cmd: List[str]) -> bool:
        if self.dry_run:
            log.info("[DRY-RUN] Would run: %s", " ".join(cmd))
            return True
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                log.error("iptables error: %s", result.stderr.strip())
                return False
            return True
        except FileNotFoundError:
            log.error("iptables not found — is it installed and in PATH?")
            return False
        except subprocess.TimeoutExpired:
            log.error("iptables command timed out")
            return False
        except OSError as exc:
            log.error("iptables OS error: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Auto-unblock scheduler
    # ------------------------------------------------------------------

    def _start_unblock_scheduler(self) -> None:
        def _loop() -> None:
            while True:
                time.sleep(10)
                now = time.time()
                to_unblock = []
                with self._lock:
                    for ip, meta in list(self._blocked.items()):
                        if meta["unblock_at"] and now >= meta["unblock_at"]:
                            to_unblock.append(ip)
                for ip in to_unblock:
                    self.unblock(ip)

        threading.Thread(target=_loop, daemon=True, name="ip-unblock-scheduler").start()

    # ------------------------------------------------------------------
    # Privilege check
    # ------------------------------------------------------------------

    def _check_privileges(self) -> None:
        if not self.enabled or self.dry_run:
            return
        if os.geteuid() != 0:
            log.warning(
                "IPBlocker enabled but not running as root — "
                "iptables calls will fail. Re-run with sudo or disable blocker."
            )

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _save_state(self) -> None:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.state_file)), exist_ok=True)
            with self._lock:
                data = dict(self._blocked)
            with open(self.state_file, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except OSError as exc:
            log.debug("Could not save blocker state: %s", exc)

    def _load_state(self) -> None:
        if not os.path.isfile(self.state_file):
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            now = time.time()
            restored = 0
            for ip, meta in data.items():
                if not _validate_ip(ip):
                    continue
                # Skip entries whose auto-unblock time has already passed
                if meta.get("unblock_at") and now >= meta["unblock_at"]:
                    continue
                with self._lock:
                    self._blocked[ip] = meta
                meta.setdefault("ports", None)
                self._insert(ip, meta["ports"])
                restored += 1
            if restored:
                log.info("IPBlocker: restored %d block rule(s) from %s", restored, self.state_file)
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            log.warning("Could not load blocker state: %s", exc)
