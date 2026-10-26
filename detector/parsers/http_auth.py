"""
HTTP parser for nginx and Apache — access logs (combined/common format) and
error logs.

Detected patterns
-----------------
FAILED  — HTTP Basic auth failure (401 with a username, error-log
          "password mismatch" / "user not found"), 401/403 on a POST to a login
          page, WordPress wp-login.php POST answered with 200 (re-rendered form)
SUCCESS — WordPress wp-login.php POST answered with a redirect

A 401 without a username is the normal browser challenge, not an attack, so it
is ignored.  Behind a reverse proxy the logged address is the proxy's — log the
real client IP (e.g. nginx realip module) or the alerts will name the proxy.
"""

import re
import time
from datetime import datetime
from typing import Optional

from .linux_ssh import ParsedEvent

_IP = r"[\da-fA-F\.:]+"

_RE_ACCESS = re.compile(
    rf'^(?P<ip>{_IP})\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})'
)
_RE_LOGIN_PATH = re.compile(
    r"^/(?:wp-login\.php|administrator(?:/index\.php)?|admin(?:/login)?|login|signin|sign-in|"
    r"user/login|users/sign_in|auth/login|api/(?:v\d+/)?(?:login|auth)|phpmyadmin/index\.php|"
    r"pma/index\.php|wp-admin)/?(?:[?#].*)?$",
    re.IGNORECASE,
)
_RE_WP_LOGIN = re.compile(r"^/wp-login\.php(?:[?#].*)?$", re.IGNORECASE)

_RE_NGINX_NOT_FOUND = re.compile(rf'user "([^"]*)" was not found in .*?client: ({_IP})')
_RE_NGINX_MISMATCH = re.compile(rf'user "([^"]*)": password mismatch.*?client: ({_IP})')
_RE_APACHE_AUTH = re.compile(
    r"\[client \[?([^\]\s]+)\]?(?::\d+)?\].*?AH0161[78]: user (\S+?)(?::| not found)"
)


def _strip_port(token: str) -> str:
    """Apache prints 'ip:port'; IPv6 without brackets is ambiguous, so validate."""
    import ipaddress
    for candidate in (token, token.rsplit(":", 1)[0]):
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return token


def _parse_access_ts(value: str) -> float:
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return time.time()


def _parse_error_ts(line: str) -> float:
    m = re.match(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
    if m:  # nginx error log (server local time)
        try:
            return datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S").timestamp()
        except ValueError:
            return time.time()
    m = re.match(r"^\[\w{3} (\w{3} +\d+ \d{2}:\d{2}:\d{2})(?:\.\d+)? (\d{4})\]", line)
    if m:  # Apache error log
        try:
            return datetime.strptime(f"{m.group(1)} {m.group(2)}", "%b %d %H:%M:%S %Y").timestamp()
        except ValueError:
            return time.time()
    return time.time()


class HttpAuthParser:
    name = "http_auth"

    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        line = line.strip()
        if not line:
            return None

        m = _RE_ACCESS.match(line)
        if m:
            return self._parse_access(m, line)
        return self._parse_error(line)

    def _parse_access(self, m: "re.Match", line: str) -> Optional[ParsedEvent]:
        status = int(m.group("status"))
        method, path = m.group("method"), m.group("path")
        user = m.group("user")
        user = "" if user == "-" else user
        ts = _parse_access_ts(m.group("ts"))

        def ev(kind: str) -> ParsedEvent:
            return ParsedEvent(kind, m.group("ip"), user, attack_type="HTTP", timestamp=ts, raw_line=line)

        if status == 401 and user:
            return ev("FAILED")
        if method != "POST":
            return None
        if _RE_WP_LOGIN.match(path):
            if status == 200:
                return ev("FAILED")
            if status in (302, 303):
                return ev("SUCCESS")
            if status in (401, 403):
                return ev("FAILED")
            return None
        if _RE_LOGIN_PATH.match(path) and status in (401, 403):
            return ev("FAILED")
        return None

    @staticmethod
    def _parse_error(line: str) -> Optional[ParsedEvent]:
        for regex in (_RE_NGINX_NOT_FOUND, _RE_NGINX_MISMATCH):
            m = regex.search(line)
            if m:
                return ParsedEvent("FAILED", m.group(2), m.group(1), attack_type="HTTP",
                                   timestamp=_parse_error_ts(line), raw_line=line)
        m = _RE_APACHE_AUTH.search(line)
        if m:
            return ParsedEvent("FAILED", _strip_port(m.group(1)), m.group(2), attack_type="HTTP",
                               timestamp=_parse_error_ts(line), raw_line=line)
        return None


class NginxParser(HttpAuthParser):
    name = "nginx"


class ApacheParser(HttpAuthParser):
    name = "apache"
