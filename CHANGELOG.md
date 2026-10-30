# Changelog

All notable changes. The latest release is also summarised in the README.

## v1.16.0

| | |
|---|---|
| 🦠 **File reputation (VirusTotal)** | Optional (`file_intel`, off by default): SHA256 hashes of files captured by the Cowrie honeypot are looked up on VirusTotal in the background (only the hash is sent, rate limited to the free quota, cached in `reports/file_intel.json`). Shown in the dashboard Files panel, in `--report` (html / json / markdown / text, from the cache) and as a Discord/Slack alert when enough engines flag a file as malicious. Files uploaded with scp/sftp (`cowrie.session.file_upload`) now count too |

## v1.15.1

| | |
|---|---|
| 🧭 **Official MITRE ATT&CK mapping** | Each honeypot command is matched to exact technique IDs (checked against attack.mitre.org), e.g. `uname` → T1082, `whoami` → T1033, `history -c` → T1070.003, `rm -rf` → T1070.004, authorized_keys → T1098.004, `chattr` → T1222.002. New techniques panel (ranked by distinct IPs) and clickable technique chips linking to attack.mitre.org |

## v1.15.0

| | |
|---|---|
| 🎯 **Campaigns & MITRE ATT&CK** | Honeypot "Top commands" and "Attacker behaviour" now count distinct IPs (one bot looping `uname` no longer drowns everything); new Campaigns panel groups the same command seen from many IPs; behaviour tags carry MITRE ATT&CK technique IDs (e.g. SSH key → T1098.004, recon → T1082); new `permission change` tag for `chattr` |

## v1.14.2

| | |
|---|---|
| 🧹 **Cleaner honeypot stats** | Whitelisted IPs and this host are excluded from the honeypot section (your own tests no longer skew it); empty passwords show as `(empty)`; files written with `echo` are labelled instead of showing a local path |

## v1.14.1

| | |
|---|---|
| 🕵️ **Attacker behaviour** | Honeypot commands are tagged (SSH key, crypto miner, download & run, botnet, persistence, password change, cover tracks, recon) with a summary panel and tags in recent commands; downloaded files are listed by SHA256 for VirusTotal lookup |

## v1.14.0

| | |
|---|---|
| 🍯 **Honeypot dashboard** | When a `cowrie` log is configured, the dashboard gets a Honeypot section: sessions, login attempts, shell entries, top passwords / usernames / pairs / commands / downloaded URLs / SSH clients, recent commands and a timeline (also in `/api/summary` as `honeypot`) |

## v1.13.1

| | |
|---|---|
| 🔕 **Less alert spam from low-and-slow** | A persistent scanner is reported once per window: the next slow alert for the same IP needs the failure count to double (or the attack to fade below `slow_threshold` and return). Before, the same IP re-alerted every `alert_cooldown` (17 alerts/hour from two IPs in a real deployment) |

## v1.13.0

| | |
|---|---|
| 🍯 **Cowrie honeypot parser** | New log type `cowrie` reads `cowrie.json`: `cowrie.login.failed` and `cowrie.login.success` both count as `HONEYPOT` attempts (the honeypot accepts some passwords on purpose); never a breach alert; other events ignored |

## v1.12.1

| | |
|---|---|
| 📊 **Short report periods** | Dashboard buttons `1h` and `8h`; `--report --since 8h`; any period works in the URL (`?since=12h`) |

## v1.12.0

| | |
|---|---|
| 🐌 **Low-and-slow detection** | `detection.slow_threshold` / `slow_window`: a second, long sliding window (e.g. 10 failures in 1 h) catches scanners that stay under `threshold`/`time_window`; off by default, state persisted across restarts |
| 🔇 **Quieter log** | "Active IPs" summary logged at most every `logging.stats_interval` seconds (default 300) and only when changed; `0` disables it |
| 🧑‍💻 **No prompt without a terminal** | Language prompt skipped (English) when stdin is not a TTY; startup log shows the low-and-slow settings |
| 🛠 **Unit & docs** | `ReadWritePaths` tolerates missing directories; DEPLOY.md: running without root |

## v1.11.0

| | |
|---|---|
| 🌍 **Offline GeoIP** | `--geoip-download` fetches a free database (`data/geoip.mmdb`, used automatically); `geo.online_fallback: false` forbids plain-HTTP lookups; `--check` hints when no local database exists |
| 🚨 **Breach banner** | The dashboard highlights IPs that logged in successfully after failed attempts |
| 🔌 **Dashboard port 8765** | New default (8080 is commonly taken) |
| 📘 **Deployment guide** | [docs/DEPLOY.md](docs/DEPLOY.md): VPS with SSH keys, systemd, dashboard over an SSH tunnel (Polish) |

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
