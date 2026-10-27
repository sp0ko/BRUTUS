"""
Aggregated reports built from the alerts JSONL file (``reports/alerts.jsonl``).

Pure functions — no I/O except ``load_alerts`` — so the same summary feeds the
text / Markdown / JSON / HTML outputs and the live dashboard.
"""

import json
import re
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

_PERIOD_RE = re.compile(r"^(\d+)([hdw])$")
_UNITS = {"h": "hours", "d": "days", "w": "weeks"}
_USER_MARK = re.compile(r"\s*✓.*$")  # "root ✓ (UDANE LOGOWANIE)" → "root"

PERIOD_CHOICES = ("24h", "7d", "30d", "all")


def parse_period(value: str) -> Optional[timedelta]:
    """'24h' / '7d' / '2w' → timedelta; 'all' → None. Raises ValueError otherwise."""
    value = (value or "").strip().lower()
    if value == "all":
        return None
    m = _PERIOD_RE.match(value)
    if not m or int(m.group(1)) == 0:
        raise ValueError(f"Invalid period '{value}' (use e.g. 24h, 7d, 2w or all)")
    return timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})


def _parse_ts(value) -> Optional[datetime]:
    """ISO timestamp with optional trailing Z → naive UTC datetime."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.rstrip("Z"))
    except ValueError:
        return None


def clean_username(name: str) -> str:
    return _USER_MARK.sub("", str(name)).strip()


def load_alerts(path: str, since: Optional[datetime] = None) -> List[dict]:
    """
    Read alert records, skipping malformed lines.  Each record gets a ``_ts``
    key (naive UTC datetime).  Raises OSError when the file cannot be read.
    """
    records: List[dict] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict) or not isinstance(rec.get("ip"), str):
                continue
            ts = _parse_ts(rec.get("timestamp"))
            if ts is None:
                continue
            if since is not None and ts < since:
                continue
            rec["_ts"] = ts
            records.append(rec)
    return records


# ──────────────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────────────

def _floor(dt: datetime, gran: str) -> datetime:
    if gran == "hour":
        return dt.replace(minute=0, second=0, microsecond=0)
    if gran == "day":
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)
    return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _next(dt: datetime, gran: str) -> datetime:
    if gran == "hour":
        return dt + timedelta(hours=1)
    if gran == "day":
        return dt + timedelta(days=1)
    return dt.replace(year=dt.year + 1, month=1) if dt.month == 12 else dt.replace(month=dt.month + 1)


_LABEL_FMT = {"hour": "%m-%d %H:00", "day": "%Y-%m-%d", "month": "%Y-%m"}


def _timeline(records: List[dict], start: Optional[datetime], until: datetime) -> dict:
    if start is None:
        if not records:
            return {"granularity": "day", "buckets": []}
        start = min(r["_ts"] for r in records)
    span = until - start
    gran = "hour" if span <= timedelta(days=2) else "day" if span <= timedelta(days=92) else "month"

    counts: Counter = Counter(_floor(r["_ts"], gran) for r in records)
    buckets: List[Tuple[str, int]] = []
    cur, end = _floor(start, gran), _floor(until, gran)
    while cur <= end:
        buckets.append((cur.strftime(_LABEL_FMT[gran]), counts.get(cur, 0)))
        cur = _next(cur, gran)
    return {"granularity": gran, "buckets": buckets}


def summarize(
    records: List[dict],
    since: Optional[datetime],
    until: datetime,
    top: int = 10,
) -> Dict:
    attack_types: Counter = Counter()
    countries: Counter = Counter()
    usernames: Counter = Counter()
    sources: Counter = Counter()
    ti_sources: Counter = Counter()
    ips: Dict[str, dict] = {}
    breaches = spray = ti_matches = 0

    for r in records:
        types = [t.strip() for t in str(r.get("attack_type", "")).split(",") if t.strip()]
        attack_types.update(types or ["unknown"])
        if "PASSWORD_SPRAY" in types:
            spray += 1
        breach = bool(r.get("successful_login"))
        breaches += breach

        geo = r.get("geo") if isinstance(r.get("geo"), dict) else {}
        country = geo.get("country") or "unknown"
        countries[country] += 1

        ti = r.get("threat_intel")
        if ti:
            ti_matches += 1
            ti_sources[str(ti)] += 1

        usernames.update({clean_username(u) for u in (r.get("usernames") or []) if clean_username(u)})
        sources.update({str(s) for s in (r.get("log_sources") or [])})

        entry = ips.setdefault(r["ip"], {
            "ip": r["ip"], "alerts": 0, "max_attempts": 0,
            "country": "unknown", "breach": False, "threat_intel": None,
        })
        entry["alerts"] += 1
        entry["max_attempts"] = max(entry["max_attempts"], int(r.get("count") or 0))
        entry["breach"] = entry["breach"] or breach
        if country != "unknown":
            entry["country"] = country
        entry["threat_intel"] = entry["threat_intel"] or (str(ti) if ti else None)

    top_ips = sorted(ips.values(), key=lambda e: (-e["alerts"], -e["max_attempts"], e["ip"]))[:top]

    def ranked(counter: Counter) -> List[list]:
        return [[k, v] for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:top]]

    return {
        "since": since.isoformat() + "Z" if since else None,
        "until": until.isoformat() + "Z",
        "totals": {
            "alerts": len(records),
            "unique_ips": len(ips),
            "breaches": breaches,
            "spray": spray,
            "threat_intel": ti_matches,
        },
        "attack_types": ranked(attack_types),
        "top_ips": top_ips,
        "breached_ips": sorted(e["ip"] for e in ips.values() if e["breach"]),
        "countries": ranked(countries),
        "usernames": ranked(usernames),
        "sources": ranked(sources),
        "ti_sources": ranked(ti_sources),
        "timeline": _timeline(records, since, until),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Text / Markdown rendering
# ──────────────────────────────────────────────────────────────────────────────

def _period_label(summary: dict, T: dict) -> str:
    start = summary["since"][:16].replace("T", " ") if summary["since"] else T["rp_beginning"]
    return f"{start} → {summary['until'][:16].replace('T', ' ')} UTC"


def _bar(value: int, maximum: int, width: int = 20) -> str:
    return "█" * max(1, round(width * value / maximum)) if maximum and value else ""


def _totals_line(summary: dict, T: dict) -> str:
    t = summary["totals"]
    return (f"{T['rp_alerts']}: {t['alerts']}  |  {T['rp_ips']}: {t['unique_ips']}  |  "
            f"{T['rp_breaches']}: {t['breaches']}  |  {T['rp_spray']}: {t['spray']}  |  "
            f"{T['rp_ti']}: {t['threat_intel']}")


def render_text(summary: dict, T: dict) -> str:
    out = [f"BRUTU$ — {T['rp_title']}", _period_label(summary, T), "", _totals_line(summary, T)]

    def section(title: str, rows: List[list]) -> None:
        out.append("")
        out.append(f"{title}:")
        if not rows:
            out.append(f"  {T['rp_none']}")
            return
        peak = max(v for _, v in rows)
        width = max(len(str(k)) for k, _ in rows)
        for k, v in rows:
            out.append(f"  {str(k):<{width}}  {v:>5}  {_bar(v, peak)}")

    section(T["rp_types"], summary["attack_types"])

    out += ["", f"{T['rp_top_ips']}:"]
    if summary["top_ips"]:
        out.append(f"  {'IP':<40} {T['rp_col_alerts']:>6} {T['rp_col_attempts']:>9}  {T['rp_col_country']}")
        for e in summary["top_ips"]:
            flags = (" ‼" if e["breach"] else "") + (f" ⚠ {e['threat_intel']}" if e["threat_intel"] else "")
            out.append(f"  {e['ip']:<40} {e['alerts']:>6} {e['max_attempts']:>9}  {e['country']}{flags}")
    else:
        out.append(f"  {T['rp_none']}")

    section(T["rp_countries"], summary["countries"])
    section(T["rp_users"], summary["usernames"])
    section(T["rp_sources"], summary["sources"])
    if summary["ti_sources"]:
        section(T["rp_ti_sources"], summary["ti_sources"])
    section(f"{T['rp_timeline']} ({summary['timeline']['granularity']})", summary["timeline"]["buckets"])
    return "\n".join(out) + "\n"


def _md(text) -> str:
    """Escape characters that would break a Markdown table cell."""
    return str(text).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("`", "'")


def render_markdown(summary: dict, T: dict) -> str:
    out = [f"# BRUTU$ — {T['rp_title']}", "", f"_{_period_label(summary, T)}_", "", f"**{_totals_line(summary, T)}**"]

    def table(title: str, rows: List[list], key_header: str) -> None:
        out.extend(["", f"## {title}", ""])
        if not rows:
            out.append(f"_{T['rp_none']}_")
            return
        out.extend([f"| {key_header} | {T['rp_col_alerts']} |", "|---|---:|"])
        out.extend(f"| {_md(k)} | {v} |" for k, v in rows)

    table(T["rp_types"], summary["attack_types"], T["rp_col_type"])

    out.extend(["", f"## {T['rp_top_ips']}", ""])
    if summary["top_ips"]:
        out += [f"| IP | {T['rp_col_alerts']} | {T['rp_col_attempts']} | {T['rp_col_country']} | {T['rp_col_flags']} |",
                "|---|---:|---:|---|---|"]
        for e in summary["top_ips"]:
            flags = ", ".join(f for f in (T["rp_breach_flag"] if e["breach"] else "", e["threat_intel"] or "") if f)
            out.append(f"| `{_md(e['ip'])}` | {e['alerts']} | {e['max_attempts']} | {_md(e['country'])} | {_md(flags)} |")
    else:
        out.append(f"_{T['rp_none']}_")

    table(T["rp_countries"], summary["countries"], T["rp_col_country"])
    table(T["rp_users"], summary["usernames"], T["rp_col_user"])
    table(T["rp_sources"], summary["sources"], T["rp_col_source"])
    if summary["ti_sources"]:
        table(T["rp_ti_sources"], summary["ti_sources"], T["rp_col_source"])
    table(f"{T['rp_timeline']} ({summary['timeline']['granularity']})",
          summary["timeline"]["buckets"], T["rp_col_period"])
    return "\n".join(out) + "\n"
