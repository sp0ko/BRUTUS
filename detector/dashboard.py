"""
Dashboard for the alerts report: a self-contained HTML page (no external
scripts, fonts or images) and a small read-only local web server.

All data comes from log lines an attacker can influence (usernames, sources),
so every value is HTML-escaped and the server sends a strict CSP.
"""

import ipaddress
import json
import logging
from datetime import datetime
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, List, Optional
from urllib.parse import parse_qs, urlparse

import utils.i18n as i18n
from utils.file_intel import vt_gui_url
from .honeypot import TECHNIQUE_NAMES, load_cowrie, summarize_honeypot
from .stats import PERIOD_CHOICES, load_alerts, parse_period, summarize

log = logging.getLogger("brute-force-detector.dashboard")

REFRESH_SECONDS = 30

_CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0f1419;color:#d7dde4}
header{padding:18px 24px;background:#161c24;border-bottom:1px solid #263040;display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between}
h1{margin:0;font-size:20px}h1 span{color:#ff5d5d}
h2{margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:#8b98a9}
.sub{color:#8b98a9;font-size:12px}
nav a{color:#8b98a9;text-decoration:none;padding:4px 10px;border:1px solid #263040;border-radius:6px;margin-left:6px}
nav a.on,nav a:hover{color:#fff;border-color:#4a90e2;background:#1b2a3f}
main{padding:20px 24px;max-width:1200px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.card{background:#161c24;border:1px solid #263040;border-radius:10px;padding:14px}
.card b{display:block;font-size:26px;color:#fff}.card.bad b{color:#ff5d5d}.card.warn b{color:#f5a623}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:16px}
.panel{background:#161c24;border:1px solid #263040;border-radius:10px;padding:14px;overflow:hidden}
.panel.wide{grid-column:1/-1}
.panel.breach{border-color:#ff5d5d;background:#2a1517;margin-bottom:14px}.panel.breach h2{color:#ff5d5d}
.row{display:grid;grid-template-columns:minmax(80px,40%) 1fr 48px;gap:8px;align-items:center;margin:4px 0}
.lbl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.track{background:#0f1419;border-radius:4px;height:10px}.fill{background:#4a90e2;height:10px;border-radius:4px;display:block}
.val{text-align:right;color:#8b98a9}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #263040}
th{color:#8b98a9;font-weight:600}td.n,th.n{text-align:right}
code{color:#9cdcfe}.tag{display:inline-block;padding:0 6px;border-radius:4px;font-size:11px;margin-left:4px}
.tag.m{background:#16304a;color:#7ab4f5;text-decoration:none}.tag.b{background:#5c1f1f;color:#ff9b9b}.tag.t{background:#4d3b12;color:#f5c26b}.tag.ok{background:#173d2a;color:#7be0a8}
.status{margin-bottom:20px}.state{display:inline-block;padding:2px 8px;border-radius:999px;background:#263040}
.state.running{color:#8be0a0;background:#173522}.state.error{color:#ff9b9b;background:#5c1f1f}
.state.waiting,.state.starting{color:#f5c26b;background:#4d3b12}.error-text{color:#ff9b9b}
svg{width:100%;height:auto;display:block}.bar{fill:#4a90e2}.bar:hover{fill:#7ab4f5}
.axis{fill:#8b98a9;font-size:10px}.empty{color:#8b98a9;font-style:italic}
h2.section{margin:28px 0 12px;font-size:16px;color:#f5a623}
"""


def _rows(rows: List[list], T: dict) -> str:
    if not rows:
        return f'<p class="empty">{escape(T["rp_none"])}</p>'
    peak = max(v for _, v in rows) or 1
    return "".join(
        f'<div class="row"><span class="lbl" title="{escape(str(k))}">{escape(str(k))}</span>'
        f'<span class="track"><span class="fill" style="width:{max(2, round(100 * v / peak))}%"></span></span>'
        f'<span class="val">{int(v)}</span></div>'
        for k, v in rows
    )


def _timeline_svg(buckets: List[list]) -> str:
    if not buckets:
        return ""
    width, height, base = 800, 150, 130
    n, peak = len(buckets), max(c for _, c in buckets) or 1
    step = width / n
    bars = []
    for i, (label, count) in enumerate(buckets):
        h = count / peak * (base - 10)
        bars.append(
            f'<rect class="bar" x="{i * step:.1f}" y="{base - h:.1f}" '
            f'width="{max(step - 2, 1):.1f}" height="{h:.1f}"><title>{escape(str(label))}: {int(count)}</title></rect>'
        )
    axis = []
    for i in sorted({0, n // 2, n - 1}):
        anchor = "start" if i == 0 else "end" if i == n - 1 else "middle"
        x = {"start": 0, "end": width}.get(anchor, width / 2)
        axis.append(f'<text class="axis" x="{x}" y="{height - 4}" text-anchor="{anchor}">{escape(str(buckets[i][0]))}</text>')
    return f'<svg viewBox="0 0 {width} {height}" role="img">{"".join(bars)}{"".join(axis)}</svg>'


def _ip_table(top_ips: List[dict], T: dict) -> str:
    if not top_ips:
        return f'<p class="empty">{escape(T["rp_none"])}</p>'
    head = (f'<tr><th>IP</th><th class="n">{escape(T["rp_col_alerts"])}</th>'
            f'<th class="n">{escape(T["rp_col_attempts"])}</th><th>{escape(T["rp_col_country"])}</th></tr>')
    body = []
    for e in top_ips:
        tags = ""
        if e["breach"]:
            tags += f'<span class="tag b">{escape(T["rp_breach_flag"])}</span>'
        if e["threat_intel"]:
            tags += f'<span class="tag t">{escape(str(e["threat_intel"]))}</span>'
        body.append(
            f'<tr><td><code>{escape(e["ip"])}</code>{tags}</td><td class="n">{int(e["alerts"])}</td>'
            f'<td class="n">{int(e["max_attempts"])}</td><td>{escape(str(e["country"]))}</td></tr>'
        )
    return f"<table>{head}{''.join(body)}</table>"


_TAG_KEYS = ("ssh_key", "miner", "download_exec", "botnet", "persistence", "passwd",
             "perm_mod", "cleanup", "recon")
_RED_TAGS = ("ssh_key", "miner", "botnet", "persistence", "passwd")


def _mitre_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def _tags(tags: List[str], T: dict, techs: Optional[List[str]] = None) -> str:
    out = "".join(
        f'<span class="tag {"b" if t in _RED_TAGS else "t"}">{escape(T.get("hp_tag_" + t, t))}</span>'
        for t in tags if t in _TAG_KEYS
    )
    # Only IDs from our fixed technique table are linked, never attacker-supplied text.
    out += "".join(
        f'<a class="tag m" href="{_mitre_url(t)}" target="_blank" rel="noopener noreferrer" '
        f'title="{escape(TECHNIQUE_NAMES[t])}">{escape(t)}</a>'
        for t in (techs or []) if t in TECHNIQUE_NAMES
    )
    return out


def _technique_table(items: List[list], T: dict) -> str:
    if not items:
        return f'<p class="empty">{escape(T["rp_none"])}</p>'
    head = f'<tr><th>ID</th><th>{escape(T["hp_col_tech"])}</th><th class="n">{escape(T["hp_col_ips"])}</th></tr>'
    body = "".join(
        f'<tr><td><a class="tag m" href="{_mitre_url(tid)}" target="_blank" rel="noopener noreferrer">'
        f'{escape(tid)}</a></td><td>{escape(name)}</td><td class="n">{int(n)}</td></tr>'
        for tid, name, n in items
    )
    return f"<table>{head}{body}</table>"


def _campaigns(items: List[dict], T: dict) -> str:
    if not items:
        return f'<p class="empty">{escape(T["rp_none"])}</p>'
    head = (f'<tr><th>{escape(T["hp_col_cmd"])}</th><th class="n">{escape(T["hp_col_ips"])}</th>'
            f'<th class="n">{escape(T["hp_col_runs"])}</th><th>{escape(T["hp_col_span"])}</th></tr>')
    body = "".join(
        f'<tr><td><code>{escape(c["command"])}</code>{_tags(c["tags"], T, c["mitre"])}</td>'
        f'<td class="n">{int(c["ips"])}</td><td class="n">{int(c["runs"])}</td>'
        f'<td>{escape(c["first"])} → {escape(c["last"])}</td></tr>'
        for c in items
    )
    return f"<table>{head}{body}</table>"


def _verdict(result: Optional[dict], T: dict) -> str:
    if result is None:
        return f'<span class="tag t">{escape(T["hp_vt_pending"])}</span>'
    if result.get("status") != "found":
        return f'<span class="tag t">{escape(T["hp_vt_unknown"])}</span>'
    bad = int(result.get("malicious", 0))
    text = f'{bad}/{int(result.get("total", 0))}'
    label = f' {escape(str(result["label"]))}' if result.get("label") else ""
    return f'<span class="tag {"b" if bad else "ok"}">{text}</span>{label}'


def _files(hp: dict, T: dict, intel_on: bool) -> str:
    if not hp["hashes"]:
        return f'<p class="empty">{escape(T["rp_none"])}</p>'
    head = f'<tr><th>SHA256</th><th class="n">{escape(T["hp_col_runs"])}</th>'
    head += f'<th>{escape(T["hp_col_vt"])}</th></tr>' if intel_on else "</tr>"
    body = ""
    for sha, n in hp["hashes"]:
        link = (f'<a class="tag m" href="{escape(vt_gui_url(sha))}" target="_blank" '
                f'rel="noopener noreferrer">VT</a>')
        verdict = f'<td>{_verdict(hp["hash_intel"].get(sha), T)}</td>' if intel_on else ""
        body += f'<tr><td><code title="{escape(sha)}">{escape(sha[:16])}…</code>{link}</td><td class="n">{int(n)}</td>{verdict}</tr>'
    return f"<table>{head}{body}</table>"


def _render_honeypot(hp: Optional[dict], T: dict) -> str:
    if hp is None:
        return ""
    intel_on = hp.get("hash_intel") is not None
    t = hp["totals"]
    cards = "".join(
        f'<div class="card {cls}"><b>{int(t[key])}</b>{escape(T[label])}</div>'
        for key, label, cls in (
            ("sessions", "hp_sessions", ""), ("attempts", "hp_attempts", ""),
            ("unique_ips", "hp_ips", ""), ("shell_logins", "hp_shell", "warn" if t["shell_logins"] else ""),
            ("commands", "hp_commands", ""), ("downloads", "hp_downloads", "bad" if t["downloads"] else ""),
        )
    )
    if hp["recent_commands"]:
        recent = (
            f'<table><tr><th>{escape(T["hp_col_time"])}</th><th>IP</th><th>{escape(T["hp_col_cmd"])}</th></tr>'
            + "".join(
                f'<tr><td>{escape(c["time"])}</td><td><code>{escape(c["ip"])}</code></td>'
                f'<td><code>{escape(c["command"])}</code>{_tags(c.get("tags", []), T, c.get("techs"))}</td></tr>'
                for c in hp["recent_commands"]
            ) + "</table>"
        )
    else:
        recent = f'<p class="empty">{escape(T["rp_none"])}</p>'
    panels = [
        ("wide", T["hp_timeline"], _timeline_svg(hp["timeline"]["buckets"])
         or f'<p class="empty">{escape(T["rp_none"])}</p>'),
        ("", T["hp_passwords"], _rows(hp["passwords"], T)),
        ("", T["hp_usernames"], _rows(hp["usernames"], T)),
        ("", T["hp_creds"], _rows(hp["credentials"], T)),
        ("", T["hp_top_ips"], _rows(hp["top_ips"], T)),
        ("wide", T["hp_campaigns"], _campaigns(hp["campaigns"], T)),
        ("wide", T["hp_techniques"], _technique_table(hp["techniques"], T)),
        ("", T["hp_behaviours"], _rows([[T.get("hp_tag_" + k, k), v] for k, v in hp["behaviours"]], T)),
        ("", T["hp_top_cmds"], _rows(hp["commands"], T)),
        ("wide" if intel_on else "", T["hp_hashes"], _files(hp, T, intel_on)),
        ("", T["hp_urls"], _rows(hp["downloads"], T)),
        ("", T["hp_clients"], _rows(hp["clients"], T)),
        ("wide", T["hp_recent"], recent),
    ]
    panel_html = "".join(
        f'<section class="panel {cls}"><h2>{escape(title)}</h2>{body}</section>' for cls, title, body in panels
    )
    return (f'<h2 class="section">{escape(T["hp_title"])}</h2>'
            f'<div class="cards">{cards}</div><div class="grid">{panel_html}</div>')


def _render_status(status: Optional[dict], T: dict) -> str:
    if status is None:
        return ""
    running = bool(status.get("running"))
    state = "running" if running else "stopped"
    overall = T["dash_status_running"] if running else T["dash_status_stopped"]
    started = status.get("started_at")
    started_text = str(started).replace("T", " ") if started else T["dash_status_unknown"]
    rows = []
    for source in status.get("sources", []):
        source_state = str(source.get("status", "unknown"))
        label = T.get(f"dash_state_{source_state}", source_state)
        last_event = source.get("last_event_at") or T["dash_status_never"]
        error = source.get("error")
        error_html = f'<div class="error-text">{escape(str(error))}</div>' if error else ""
        rows.append(
            f'<tr><td>{escape(str(source.get("type", "")))}</td>'
            f'<td><code>{escape(str(source.get("name", "")))}</code></td>'
            f'<td>{escape(str(source.get("parser", "")))}'
            f'<div class="sub">{escape(T["dash_last_event"])}: {escape(str(last_event))}</div>'
            f'{error_html}</td><td><span class="state {escape(source_state)}">{escape(label)}</span></td></tr>'
        )
    if rows:
        source_table = (
            f'<table><thead><tr><th>{escape(T["dash_source_type"])}</th>'
            f'<th>{escape(T["dash_source"])}</th><th>{escape(T["dash_parser_event"])}</th>'
            f'<th>{escape(T["dash_source_status"])}</th></tr></thead><tbody>{"".join(rows)}</tbody></table>'
        )
    else:
        source_table = f'<p class="empty">{escape(T["dash_no_sources"])}</p>'
    return (
        f'<section class="panel status"><h2>{escape(T["dash_status_title"])}</h2>'
        f'<p><span class="state {state}">{escape(overall)}</span> '
        f'<span class="sub">{escape(T["dash_started_at"])}: {escape(started_text)}</span></p>'
        f'{source_table}</section>'
    )


def render_html(summary: dict, T: dict, period: str = "7d", refresh: Optional[int] = None,
                links: bool = True, status: Optional[dict] = None,
                honeypot: Optional[dict] = None) -> str:
    t = summary["totals"]
    start = summary["since"][:16].replace("T", " ") if summary["since"] else T["rp_beginning"]
    period_txt = f"{start} → {summary['until'][:16].replace('T', ' ')} UTC"

    nav = ""
    if links:
        nav = "<nav>" + "".join(
            f'<a href="?since={p}"{" class=on" if p == period else ""}>{escape(p)}</a>' for p in PERIOD_CHOICES
        ) + "</nav>"
    meta_refresh = f'<meta http-equiv="refresh" content="{int(refresh)}">' if refresh else ""

    def card(label: str, value: int, cls: str = "") -> str:
        return f'<div class="card {cls}"><b>{int(value)}</b>{escape(label)}</div>'

    cards = (
        card(T["rp_alerts"], t["alerts"]) + card(T["rp_ips"], t["unique_ips"])
        + card(T["rp_breaches"], t["breaches"], "bad" if t["breaches"] else "")
        + card(T["rp_spray"], t["spray"], "warn" if t["spray"] else "")
        + card(T["rp_ti"], t["threat_intel"], "warn" if t["threat_intel"] else "")
    )
    gran = summary["timeline"]["granularity"]
    panels = [
        ("wide", f'{T["rp_timeline"]} ({gran})', _timeline_svg(summary["timeline"]["buckets"])
         or f'<p class="empty">{escape(T["rp_none"])}</p>'),
        ("wide", T["rp_top_ips"], _ip_table(summary["top_ips"], T)),
        ("", T["rp_types"], _rows(summary["attack_types"], T)),
        ("", T["rp_countries"], _rows(summary["countries"], T)),
        ("", T["rp_users"], _rows(summary["usernames"], T)),
        ("", T["rp_sources"], _rows(summary["sources"], T)),
    ]
    if summary["ti_sources"]:
        panels.append(("", T["rp_ti_sources"], _rows(summary["ti_sources"], T)))
    panel_html = "".join(
        f'<section class="panel {cls}"><h2>{escape(title)}</h2>{body}</section>' for cls, title, body in panels
    )

    breached = summary.get("breached_ips", [])
    breach_banner = ""
    if breached:
        ips = ", ".join(f"<code>{escape(ip)}</code>" for ip in breached)
        breach_banner = (
            f'<section class="panel breach"><h2>{escape(T["dash_breach_title"])}</h2>'
            f'<p>{escape(T["dash_breach_text"])} {ips}</p></section>'
        )

    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'{meta_refresh}<title>BRUTU$ — {escape(T["rp_title"])}</title><style>{_CSS}</style></head><body>'
        f'<header><div><h1>BRUTU<span>$</span> — {escape(T["rp_title"])}</h1>'
        f'<div class="sub">{escape(period_txt)}</div></div>{nav}</header>'
        f'<main>{breach_banner}{_render_status(status, T)}<div class="cards">{cards}</div>'
        f'<div class="grid">{panel_html}</div>{_render_honeypot(honeypot, T)}</main></body></html>'
    )


# ──────────────────────────────────────────────────────────────────────────────
# Server
# ──────────────────────────────────────────────────────────────────────────────

def build_summary(path: str, period: str, top: int = 10) -> dict:
    """Load the report file (missing file = no alerts yet) and summarise *period*."""
    delta = parse_period(period)
    until = datetime.utcnow()
    since = until - delta if delta else None
    try:
        records = load_alerts(path, since)
    except FileNotFoundError:
        records = []
    return summarize(records, since, until, top=top)


def build_honeypot_summary(paths: List[str], period: str, top: int = 10,
                           exclude_nets: Optional[list] = None, file_intel=None) -> dict:
    delta = parse_period(period)
    until = datetime.utcnow()
    since = until - delta if delta else None
    return summarize_honeypot(load_cowrie(paths, since, exclude_nets), since, until, top=top,
                              file_intel=file_intel)


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def create_server(
    path: str,
    host: str = "127.0.0.1",
    port: int = 8765,
    status_provider: Optional[Callable[[], dict]] = None,
    honeypot_paths: Optional[List[str]] = None,
    honeypot_exclude: Optional[list] = None,
    file_intel=None,
) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "BRUTUS-dashboard"

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            url = urlparse(self.path)
            period = (parse_qs(url.query).get("since") or ["7d"])[0]
            if url.path == "/api/status":
                if status_provider is None:
                    self._send(503, b"Live monitor status unavailable", "text/plain; charset=utf-8")
                    return
                try:
                    status = status_provider()
                except (OSError, RuntimeError) as exc:
                    log.error("Dashboard: cannot read monitor status: %s", exc)
                    self._send(500, b"Cannot read monitor status", "text/plain; charset=utf-8")
                    return
                self._send(200, json.dumps(status, ensure_ascii=False).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            if url.path not in ("/", "/api/summary"):
                self._send(404, b"Not found", "text/plain; charset=utf-8")
                return
            try:
                summary = build_summary(path, period)
            except ValueError as exc:
                self._send(400, str(exc).encode("utf-8"), "text/plain; charset=utf-8")
                return
            except OSError as exc:
                log.error("Dashboard: cannot read %s: %s", path, exc)
                self._send(500, b"Cannot read report file", "text/plain; charset=utf-8")
                return
            if url.path == "/api/summary":
                payload = summary
                if honeypot_paths:
                    payload = dict(summary, honeypot=build_honeypot_summary(honeypot_paths, period, exclude_nets=honeypot_exclude,
                                                  file_intel=file_intel))
                self._send(200, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                           "application/json; charset=utf-8")
            else:
                try:
                    status = status_provider() if status_provider else None
                except (OSError, RuntimeError) as exc:
                    log.error("Dashboard: cannot read monitor status: %s", exc)
                    self._send(500, b"Cannot read monitor status", "text/plain; charset=utf-8")
                    return
                try:
                    honeypot = build_honeypot_summary(honeypot_paths, period, exclude_nets=honeypot_exclude,
                                                  file_intel=file_intel) if honeypot_paths else None
                except OSError as exc:
                    log.error("Dashboard: cannot read honeypot log: %s", exc)
                    honeypot = None
                page = render_html(summary, i18n.get_T(), period=period, refresh=REFRESH_SECONDS,
                                   status=status, honeypot=honeypot)
                self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")

        def log_message(self, fmt, *args) -> None:
            log.debug("dashboard %s - %s", self.address_string(), fmt % args)

    return ThreadingHTTPServer((host, port), Handler)
