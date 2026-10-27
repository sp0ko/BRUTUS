# Changelog

All notable changes. The latest release is also summarised in the README.

## v1.10.0

| | |
|---|---|
| 🌍 **Offline GeoIP** | `--geoip-download`, automatic use of `data/geoip.mmdb`, `geo.online_fallback`, `--check` hint |
| 🚨 **Breach banner** | The dashboard highlights IPs that logged in successfully after failed attempts |
| 📡 **Live source status** | The dashboard shows what BRUTU$ monitors right now (running / waiting / error, last event) — also at `/api/status`; `--dashboard` runs detector and dashboard together |
| 🧙 **`--setup`** | Interactive config wizard: detects log sources, validates webhooks and whitelist, backs up the old config |
| 🩺 **`--check`** | Environment diagnostics (Python, packages, logs, ports, iptables, webhooks); exit code 1 on failure |
| 📦 **`install.sh`** | One-step install: venv, dependencies, wizard, check; `--service` installs the systemd unit |
| 🔐 **`config.example.yaml`** | Template is tracked, your `config.yaml` (with secrets) is git-ignored |

## v1.9.0

| | |
|---|---|
| ⏪ **Catch-up after restart** | Log offsets (inode + head hash) are saved with the state, so lines written while BRUTU$ was down are processed on the next start — alerts are sent, but those IPs are **not auto-blocked** (the attack is over, blocking is your call) |
| 🔄 **Rotation-aware** | Rotation while down (`auth.log` → `auth.log.1`), truncation and replaced files are detected; the unread tail of the rotated file is read first |
| 🧱 **Safer tailing** | A half-written last line is held until its newline arrives |

## v1.8.0

| | |
|---|---|
| 💾 **Persistent state** | Sliding-window counters, alert cooldowns and trigger counts survive restarts and crashes — an attack in progress isn't forgotten, an IP just reported isn't re-alerted |
| 📊 **`--stats`** | Now shows the restored state instead of an always-empty tracker |

## v1.7.0

| | |
|---|---|
| 🎯 **Per-service blocking** | `blocker.scope: service` drops only the attacked service's ports (configurable `ports`) instead of the whole IP |
| 🔒 **Self-lockout protection** | Loopback, link-local, this host's own addresses, `trusted_proxies` and (optionally) private ranges are never blocked |
| 📋 **`--blocked`** | Shows the blocked ports per IP |

## v1.6.1

| | |
|---|---|
| 🌐 **HTTP auth** | New `nginx` / `apache` parsers: Basic-auth failures (access + error logs) and brute force on login panels |
| 📂 **FTP** | New `ftp` parser: vsftpd, ProFTPD, Pure-FTPd |
| 🗄️ **MySQL / MariaDB** | New `mysql` parser: "Access denied for user" |
| 🏷️ **Attack types** | Alerts and reports now show `HTTP`, `FTP`, `MYSQL` next to `SSH` / `RDP` |

## v1.6.0

| | |
|---|---|
| 📊 **Summary report** | `--report` aggregates `alerts.jsonl` (top IPs, countries, accounts, attack types, timeline) as text, Markdown, JSON or HTML |
| 🖥️ **Dashboard** | `--dashboard` serves a self-contained web page on `127.0.0.1:8080` (no external assets, auto-refresh) |
| 🛡️ **Safe by default** | All data HTML-escaped, strict CSP, loopback bind with a warning otherwise |
| 🧩 **Reports keep `threat_intel`** | Alert records now store the matched feed |

## v1.5.0

| | |
|---|---|
| ⏪ **Replay mode** | `--replay FILE` analyses an existing log (also `.gz`) offline — read-only, no blocking or webhooks |
| 🐛 **Threat-intel fix** | A threat-intel match no longer crashes alert handling (missing logger in `main.py`) |
| 🧪 **117 tests** | New integration tests: log tailing & rotation, UDP syslog, alert dispatcher, threat-intel updates, CLI |

## v1.4.0

| | |
|---|---|
| 📜 **systemd journal source** | New `journald:` config section — follows `journalctl -f` on hosts without `/var/log/auth.log` |
| ⚙️ **systemd service** | Ready-made unit in `deploy/brutus.service` |
| ✅ **CI** | GitHub Actions runs the test suite on Python 3.10–3.13 for every push and PR |

## v1.3.1

| | |
|---|---|
| 🤖 **Feodo Tracker feed** | Added Abuse.ch Feodo Tracker (botnet C2 IPs) to the built-in threat intel sources and the default `config.yaml` list |

## v1.3.0

| | |
|---|---|
| 🎯 **Configurable TI action** | `action_on_threat_intel_match: block \| alert_only` — decide whether a threat intel match triggers a block or just an alert |
| 📋 **Custom source list** | `threat_intel.sources` now accepts a plain URL list in `config.yaml` — swap feeds without touching code |
| 🔄 **Extra feed** | Added **blocklist.de SSH** feed to the configurable source list |

---
