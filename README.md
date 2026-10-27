# BRUTU$ 🛡️

> Because every random Shodan crawler thinks your SSH is their personal playground.

**BRUTU$** monitors SSH and RDP logs in real time, counts failed logins per IP, and the moment some guy crosses the threshold — you get a ping on Discord/Slack before you even finish your coffee. GeoIP included, so you know exactly which country they're coming from.

```
 ██████╗ ██████╗ ██╗   ██╗████████╗██╗   ██╗███████╗
 ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██║   ██║██╔════╝
 ██████╔╝██████╔╝██║   ██║   ██║   ██║   ██║███████╗
 ██╔══██╗██╔══██╗██║   ██║   ██║   ██║   ██║╚════██║
 ██████╔╝██║  ██║╚██████╔╝   ██║   ╚██████╔╝███████║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚══════╝  $  v1.11.0
```

---

## What's new in v1.11.0

| | |
|---|---|
| 🌍 **Offline GeoIP** | `--geoip-download` fetches a free database (`data/geoip.mmdb`, used automatically); `geo.online_fallback: false` forbids plain-HTTP lookups; `--check` hints when no local database exists |
| 🚨 **Breach banner** | The dashboard highlights IPs that logged in successfully after failed attempts |
| 🔌 **Dashboard port 8765** | New default (8080 is commonly taken) |
| 📘 **Deployment guide** | [docs/DEPLOY.md](docs/DEPLOY.md): VPS with SSH keys, systemd, dashboard over an SSH tunnel (Polish) |

Older releases: see [CHANGELOG.md](CHANGELOG.md).

---

## What it does

### 🔍 Detection
| | |
|---|---|
| 🧠 **Brute force** | Sliding-window counter — no false alarms on restarts |
| 🚨 **Breach detection** | Successful login after failures → immediate CRITICAL alert |
| 🔫 **Password spray** | One IP → many different usernames (credential-stuffing) |

### 📡 Log sources
| | |
|---|---|
| 🐧 **Linux SSH** | `/var/log/auth.log`, `/var/log/secure` — regex on syslog format |
| 🪟 **Windows RDP** | `.evtx` files, Event ID 4625 / 4624, or live Windows Event Log |
| 📡 **Central syslog** | Receives auth logs from remote machines over UDP/TCP — no agent needed |
| 📜 **systemd journal** | Follows `journalctl -f` for hosts without `/var/log/auth.log` — see [systemd journal](#systemd-journal-journald) |
| 🌐 **nginx / Apache** | HTTP Basic-auth failures and login-panel brute force (WordPress, `/login`, `/admin`, phpMyAdmin…) — see [Other services](#other-services-http-ftp-mysql) |
| 📂 **FTP** | vsftpd, ProFTPD, Pure-FTPd |
| 🗄️ **MySQL / MariaDB** | "Access denied" entries from the error log |
| ⚡ **Real-time tail** | Reacts in a fraction of a second, just like `tail -f` |

### 🛡️ Active defense
| | |
|---|---|
| 🚫 **IP blocker** | Adds iptables DROP rules automatically (requires root) |
| 🕵️ **Threat intel** | Offline blocklists — Spamhaus, Firehol L1, CINS Army, Emerging Threats, Feodo Tracker |
| ✅ **IP whitelist** | Your home / VPN / CI never triggers a block or alert |
| 🔕 **Cooldown** | Same IP won't flood you with alerts — one notification per X minutes |

### 🌍 Intelligence & enrichment
| | |
|---|---|
| 📴 **GeoIP offline** | Country, city, ISP from local **GeoLite2-City.mmdb** — no internet, no API key |
| 🌐 **GeoIP** | `python3 main.py --geoip-download` fetches a free offline database (DB-IP, `data/geoip.mmdb`, used automatically). Without it BRUTU$ falls back to [ip-api.com](http://ip-api.com) over plain HTTP (set `geo.online_fallback: false` to forbid that) |

### 📢 Alerting & reporting
| | |
|---|---|
| 💬 **Discord** | Rich embeds — orange = warning, red = breach, ⚠ = known threat |
| 💬 **Slack** | Block Kit — looks professional even at 3 AM |
| 📄 **JSON reports** | Every alert saved to `.jsonl` — pipe into a SIEM or keep as history |

### ⚙️ Operations
| | |
|---|---|
| 🧪 **Test mode** | `--test` simulates an attack and fires alerts to your real webhooks |
| 🌐 **PL / EN** | Runtime language switch — `--lang pl` or `--lang en` |
| 📊 **Stats / Reports** | `--stats` active IPs, `--blocked` blocked IPs, `--update-threat-db` refresh intel |

---

## Installation

### One-liner (Linux / macOS)

```bash
git clone https://github.com/sp0ko/BRUTUS.git
cd BRUTUS
./install.sh
```

`install.sh` creates `.venv`, installs the dependencies, runs the [setup wizard](#1-configure) when no `config.yaml` exists yet, and finishes with a configuration check. Options: `--service` also installs a systemd unit for this directory (root/sudo; it is not started automatically), `--no-setup` copies `config.example.yaml` instead of asking questions, `--print-service` only prints the unit.

### Manual

```bash
git clone https://github.com/sp0ko/BRUTUS.git
cd BRUTUS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py --setup
```

> Debian/Ubuntu: if creating the virtualenv fails, install `python3-venv` first (`sudo apt install python3-venv`).

### Linux — log file permissions

```bash
# Ubuntu/Debian
sudo usermod -aG adm $USER
# RHEL/CentOS
sudo usermod -aG adm $USER

# or just run with sudo
sudo python main.py
```

`python main.py --check` tells you whether the current user can actually read your logs.

---

## Quick start

### 1. Configure

```bash
python main.py --setup
```

The wizard finds your auth log (or the systemd journal), asks for the alert threshold, Discord/Slack webhooks, whether to enable IP blocking (`off` / `dry-run` / `on`) and which of your own IPs to never alert on, then writes `config.yaml` readable only by you (an existing file is backed up as `config.yaml.bak`). Every option it does not ask about keeps a sensible default; all of them are documented in [`config.example.yaml`](config.example.yaml).

`config.yaml` holds your webhook URLs and is git-ignored — only `config.example.yaml` is tracked. You can also create it by hand:

```bash
cp config.example.yaml config.yaml
```

```yaml
detection:
  threshold: 5       # how many failures trigger an alert
  time_window: 60    # within how many seconds

log_files:
  - path: /var/log/auth.log
    type: linux_ssh
    enabled: true

discord:
  enabled: true
  webhook_url: "https://discord.com/api/webhooks/YOUR_URL"

slack:
  enabled: true
  webhook_url: "https://hooks.slack.com/services/YOUR_URL"
```

### 2. Check it

```bash
python main.py --check
```

Verifies — without sending anything — Python version and packages, that every log file exists and is readable, that the parsers are known, that the syslog port is free, that `journalctl` / `iptables` / root are available when needed, that webhook URLs look right, that the threat-intel and GeoIP databases exist and that reports can be written. Problems are listed with a fix hint; the exit code is `1` if anything is broken, so it also works in scripts.

### 3. Run it

```bash
python main.py
```

### 4. Test your webhooks before anything goes wrong

```bash
python main.py --test
```

---

## CLI reference

```
python main.py [options]

  --config PATH         Custom config file path
  --setup               Interactive setup wizard — writes the config file
  --check               Check config, permissions, ports and webhooks, then exit
  --log PATH            Additional log file to monitor
  --type TYPE           Parser: linux_ssh | windows_evtx | nginx | apache | ftp | mysql
  --threshold N         Number of attempts to trigger an alert
  --window N            Time window in seconds
  --cooldown N          Cooldown between alerts for the same IP
  --discord-url URL     Discord webhook (overrides config file)
  --slack-url URL       Slack webhook (overrides config file)
  --test                Simulate an attack — tests webhooks end-to-end
  --stats               Show active IPs and exit
  --replay FILE         Replay an existing log (also .gz) offline and exit
  --report              Print an aggregated report from alerts.jsonl and exit
  --since PERIOD        Report period: 24h, 7d, 2w, all (default 7d)
  --format FMT          Report format: text | markdown | json | html
  --output FILE         Write the report to a file
  --dashboard           Run the detector with the local web dashboard
  --dashboard-host H    Dashboard bind address (default 127.0.0.1)
  --dashboard-port N    Dashboard port (default 8765)
  --blocked             Show blocked IPs report and exit
  --update-threat-db    Download/update IP reputation DB and exit
  --geoip-download      Download the free GeoIP database to data/geoip.mmdb and exit
  --geoip-db PATH       Path to GeoLite2-City.mmdb for offline geolocation
  --version             Show version
```

### Examples

```bash
# Lower threshold, shorter window
python main.py --threshold 3 --window 30

# Pass webhook from CLI (e.g. for quick testing)
python main.py --discord-url "https://discord.com/api/webhooks/..."

# Monitor a specific file
python main.py --log /var/log/secure --type linux_ssh

# Use offline GeoLite2 database (no internet needed for geolocation)
python main.py --geoip-db /opt/GeoLite2-City.mmdb

# Show blocked IP report
python main.py --blocked

# Download/refresh IP reputation database (run once, then daily via cron)
python main.py --update-threat-db
```

---

## Password spray detection

BRUTUS tracks not only the number of failed attempts per IP, but also the **number of unique usernames** tried. When one IP tries more than `spray_username_threshold` different usernames it is classified as a **PASSWORD_SPRAY** attack.

Configure in `config.yaml`:

```yaml
detection:
  spray_username_threshold: 8   # unique usernames before spray alert
```

---

## Active IP blocking (iptables)

When `blocker.enabled: true`, BRUTUS automatically adds **iptables DROP rules** for every detected attacker. Works on Linux with `CAP_NET_ADMIN` (typically run as root or via `sudo`).

> **Warning**: This modifies live iptables rules. All rules are removed on clean shutdown via `unblock_all()`. Test with `dry_run: true` first.

```yaml
blocker:
  enabled: false          # set true to activate (requires root)
  auto_unblock_after: 3600  # seconds before automatic unblock; 0 = permanent
  state_file: reports/blocked_ips.json
  dry_run: false          # set true to log without touching iptables
  scope: all              # all | service  (see below)
  trusted_proxies: []     # never blocked: ["10.0.0.5", "172.16.0.0/12"]
  protect_private: false  # true = never block 10/8, 172.16/12, 192.168/16, fc00::/7
```

```bash
# Run with blocking enabled (requires root)
sudo python main.py

# View blocked IPs
python main.py --blocked
```

IPv6 addresses are handled via `ip6tables` automatically.

### Block only the attacked service (`scope: service`)

By default a block drops **all** traffic from the attacker. With `scope: service` only the TCP ports of the attacked service are dropped, so a false positive on a web login form or an FTP burst doesn't cut the IP off from everything else:

```yaml
blocker:
  scope: service
  ports:                       # defaults shown; override e.g. a non-standard SSH port
    SSH: [22]
    RDP: [3389]
    HTTP: [80, 443]
    FTP: [21]
    MYSQL: [3306]
```

- An IP that later attacks a second service gets those ports added (`SSH, FTP` → ports 21 and 22).
- `PASSWORD_SPRAY` and any type without a port mapping get a **full** block (the attacker is clearly hostile), replacing the port rules.
- FTP data connections (passive ports) are not covered by the port rule; the login port is.
- `python main.py --blocked` shows the blocked ports for each IP. State files from older versions are read as full blocks.

### Never lock yourself out

These addresses are never blocked (a warning is logged, the alert is still sent): loopback, link-local, multicast, **this host's own addresses**, everything in `blocker.trusted_proxies`, and — with `protect_private: true` — all private ranges. Use `trusted_proxies` for your reverse proxy / CDN: behind one, HTTP logs contain the proxy's address, and blocking it would take the whole site down. (`whitelist` is stricter: whitelisted IPs are ignored entirely — no alerts, no blocks. `trusted_proxies` only protects from blocking and still alerts.) Private ranges are *not* protected by default so LAN-based tests still work; turn `protect_private` on for production servers.

---

## Persistent state

```yaml
state:
  enabled: true                       # default
  path: reports/tracker_state.json
  save_interval: 30                   # seconds (only written when something changed; also on shutdown)
  catch_up: true                      # read lines written while BRUTU$ was down
  catch_up_max_mb: 64                 # max backlog per file; the older part is skipped
```

On start BRUTU$ restores attempts still inside the detection window and cooldowns still running; anything older is dropped. The file is written atomically with mode `0600` (it contains IPs and usernames), a corrupt or unknown-format file is ignored with a warning, and replay/test modes never touch it. After a hard crash you lose at most `save_interval` seconds of counters.

**Catch-up.** Per log file BRUTU$ stores the offset, inode and a hash of the first bytes. After a restart it resumes from there: new lines are evaluated with their own timestamps, alerts are sent (marked "found while BRUTU$ was not running", `"catch_up": true` in `alerts.jsonl`) and the IPs are **never blocked**. If the file was rotated meanwhile, the unread tail of `path.1` / `path-*` (uncompressed) is read first, then the new file; a truncated or replaced file is read from the start. On the first start (no saved offset) or with an old state file, tailing begins at the end as before. Set `catch_up: false` to disable.

Not covered: journald and UDP syslog (no replay of missed entries), and files already compressed (`.gz`) by logrotate — use `--replay` for those.

## Replay: check detection on real logs

Wondering how BRUTU$ would have reacted to what already happened on your server? Replay any existing log — no waiting for an attack:

```bash
python main.py --replay /var/log/auth.log
python main.py --replay /var/log/auth.log.2.gz --threshold 3 --window 120
```

Replay is read-only: it prints alerts and a summary (lines, failed/successful logins, alerts, most active IPs) and **never blocks IPs, sends webhooks or writes reports**. The sliding window follows the timestamps inside the log, so months-old files work. Your `whitelist` and threat-intel settings are honoured; line-based logs only (all parsers except `windows_evtx`).

## Summary report & dashboard

```bash
python main.py --report                                   # last 7 days, text
python main.py --report --since 30d --format markdown --output weekly.md
python main.py --report --since all --format html --output report.html
python main.py --dashboard                                # detector + http://127.0.0.1:8765/
```

`--dashboard` runs BRUTUS monitoring and the dashboard together. The status panel shows each configured log file, syslog listener and journald source, including its current state, parser, errors and time of the last recognized event. The page refreshes every 30 s; JSON is available at `/api/summary` and live source status at `/api/status`. The reports view offers `?since=24h|7d|30d|all`.

The dashboard is read-only and has **no authentication**: keep it on `127.0.0.1` and reach it through an SSH tunnel (`ssh -L 8765:127.0.0.1:8765 host`) or a password-protected reverse proxy. Usernames come from attacker-controlled log lines, so everything is HTML-escaped and a strict Content-Security-Policy is sent.

Cron example — weekly Markdown report: `0 8 * * 1 cd /opt/brutus && python3 main.py --report --since 7d --format markdown --output /var/reports/brutus-weekly.md`

## Other services: HTTP, FTP, MySQL

Add a `log_files` entry per service (also usable with `--log FILE --type X` and `--replay`):

```yaml
log_files:
  - {path: /var/log/nginx/access.log,    type: nginx,  enabled: true}
  - {path: /var/log/apache2/error.log,   type: apache, enabled: true}
  - {path: /var/log/vsftpd.log,          type: ftp,    enabled: true}
  - {path: /var/log/mysql/error.log,     type: mysql,  enabled: true}
```

| Parser | What counts as a failure | Success (breach detection) |
|---|---|---|
| `nginx` / `apache` | `401` **with a username** (Basic auth; a `401` without one is just the browser challenge and is ignored), error-log "password mismatch" / "user not found" (nginx, Apache `AH01617`/`AH01618`), `POST` to a login path (`/login`, `/admin`, `/administrator`, `/user/login`, phpMyAdmin…) answered `401`/`403`, `POST /wp-login.php` answered `200` | `POST /wp-login.php` → `302` |
| `ftp` | vsftpd `FAIL LOGIN`, ProFTPD `Login failed` / `no such user`, Pure-FTPd `Authentication failed` | vsftpd `OK LOGIN`, ProFTPD `Login successful`, Pure-FTPd `is now logged in` |
| `mysql` | `Access denied for user 'x'@'IP'` | — (the error log doesn't record successful logins) |

Notes:
- **Reverse proxy:** behind a proxy/CDN the logs contain the proxy's address. Configure real client IPs first (nginx `realip`, Apache `mod_remoteip`) — otherwise you would alert on (and block!) your own proxy. Use `whitelist` as a safety net.
- **MySQL logging:** MariaDB needs `log_warnings=2`; MySQL 8 needs `log_error_verbosity=2` or higher. Clients that resolve to hostnames are not reported (use `skip-name-resolve`).
- **Blocking:** the blocker drops all traffic from the IP, not just the attacked service.
- Access logs must use the common/combined format; custom `log_format`s are not recognised.
- Alerts of different services are tracked per IP, so one address attacking SSH and HTTP counts both.

## systemd journal (journald)

Many modern distributions log SSH only to the systemd journal, so `/var/log/auth.log` does not exist. Enable the journald source instead of (or next to) log files:

```yaml
journald:
  enabled: true
  units: [ssh, sshd, xrdp-sesman]   # Debian/Ubuntu use "ssh", RHEL/Fedora use "sshd"
  parser: linux_ssh
```

BRUTUS runs `journalctl -f` for these units (new entries only) and restarts it if it exits. Reading the journal requires root or membership in the `systemd-journal` group.

## Running as a systemd service

Step-by-step VPS deployment guide (Polish): [docs/DEPLOY.md](docs/DEPLOY.md).

A ready-made unit is in [`deploy/brutus.service`](deploy/brutus.service):

```bash
sudo cp -r . /opt/brutus && cd /opt/brutus
sudo python3 -m venv .venv && sudo .venv/bin/pip install -r requirements.txt
sudo cp deploy/brutus.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now brutus
journalctl -u brutus -f        # BRUTUS' own logs
```

## Development

Tests run on every push and pull request via GitHub Actions ([`tests.yml`](.github/workflows/tests.yml)). Locally:

```bash
python -m unittest discover -s tests -t . -v
```

---

## Central syslog server

BRUTUS can act as a **central syslog collector** — remote servers forward their auth logs to it over UDP or TCP. No agent, no extra software on the remote machines; just one rsyslog line.

```yaml
syslog:
  enabled: true
  host: "0.0.0.0"   # or a specific interface IP
  port: 5514         # 514 requires root / CAP_NET_BIND_SERVICE
  protocol: udp      # udp | tcp
  parser: linux_ssh
```

**On each remote machine** (rsyslog):
```
# /etc/rsyslog.d/99-brutus.conf
*.auth    @brutus-server-ip:5514      # UDP
# *.auth  @@brutus-server-ip:5514    # TCP (two @@ signs)
```

Then restart rsyslog: `sudo systemctl restart rsyslog`

> The attacker IP is read from inside the syslog message body (logged by sshd), not from the UDP source address — so geolocation, threat intel, and iptables blocking all work exactly the same as with local log files.

---

## Threat intelligence (offline IP reputation)

BRUTUS checks every detected attacker against free public blocklists stored **locally** — no API key, no account, no data leaving your server.

| Source | What it covers |
|---|---|
| **Spamhaus DROP** | Hijacked / rogue networks |
| **Spamhaus EDROP** | Extended DROP (delegated ranges) |
| **Firehol Level 1** | Aggregated from ~30 verified sources |
| **CINS Army** | Active botnets tracked by Shadowserver |
| **Emerging Threats** | IPs actively attacking infrastructure |
| **Feodo Tracker** | Botnet command-and-control server IPs |

### Setup

```bash
# Step 1 — download the DB (one-time, ~50 k entries, takes ~10 s)
python main.py --update-threat-db

# Step 2 — enable in config.yaml
#   threat_intel:
#     enabled: true
```

```yaml
threat_intel:
  enabled: true
  db_path: reports/threat_intel.txt
  auto_update: false        # true = refresh automatically every update_interval
  update_interval: 86400   # 24 hours
```

When a match is found, the alert is tagged `⚠ THREAT INTEL: <source>` in the console and the `threat_intel` field is included in the JSON report. Works alongside the iptables blocker — known bad IPs get blocked and flagged.

### Configurable sources & block action

You can override the default source list and control what happens on a match:

```yaml
detection:
  action_on_threat_intel_match: block  # block (default) | alert_only

threat_intel:
  enabled: true
  sources:
    - "https://www.spamhaus.org/drop/drop.txt"
    - "https://www.spamhaus.org/drop/edrop.txt"
    - "https://iplists.firehol.org/files/firehol_level1.netset"
    - "https://lists.blocklist.de/lists/ssh.txt"
    - "https://cinsscore.com/list/ci-badguys.txt"
    - "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    - "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
```

| `action_on_threat_intel_match` | Behaviour |
|---|---|
| `block` | IP blocked via iptables + alert sent (default) |
| `alert_only` | Alert sent, blocker skipped — useful for monitoring-only mode |

**Cron example** (daily refresh at 03:00):
```
0 3 * * * cd /opt/brutus && python main.py --update-threat-db >> logs/ti-update.log 2>&1
```

---

## Discord setup

1. Server settings → **Integrations → Webhooks → New Webhook**
2. Pick a channel, click **Copy Webhook URL**
3. Paste into `config.yaml`:
   ```yaml
   discord:
     enabled: true
     webhook_url: "https://discord.com/api/webhooks/YOUR_URL_HERE"
   ```

## Slack setup

1. Go to [api.slack.com/apps](https://api.slack.com/apps)
2. **Create New App → From Scratch**
3. **Incoming Webhooks → Activate → Add New Webhook to Workspace**
4. Pick a channel, copy the URL → paste into `config.yaml`

---

## Example alerts

**Terminal — standard brute-force:**
```
══════════════════════════════════════════════════════════════════════
          ⚠️  WARNING! POTENTIAL BRUTE FORCE DETECTED!  ⚠️
══════════════════════════════════════════════════════════════════════
  🌐 IP Address      : 203.0.113.42
  📊 Failed attempts : 8 in 60s
  🔌 Attack type     : SSH
  👤 Usernames tried : root, admin, Administrator
  📁 Log source      : /var/log/auth.log
  🕐 Detected at     : 2026-05-20 12:13:21
  🗺  Geolocation     : China, Beijing
  🏢 ISP / Org       : ChinaNet
══════════════════════════════════════════════════════════════════════
```

**Terminal — successful login after brute-force:**
```
══════════════════════════════════════════════════════════════════════
       🚨 CRITICAL! SUCCESSFUL LOGIN AFTER BRUTE-FORCE! 🚨
══════════════════════════════════════════════════════════════════════
  🌐 IP Address      : 192.0.2.55
  📊 Failed attempts : 5 in 60s
  ...
  ‼ POSSIBLE BREACH — check the account immediately!
══════════════════════════════════════════════════════════════════════
```

---

## Supported log formats

### `/var/log/auth.log` (Debian/Ubuntu) / `/var/log/secure` (RHEL)

Detected patterns:
- `Failed password for [invalid user] X from IP`
- `Invalid user X from IP`
- `Disconnected from invalid user X IP [preauth]`
- `pam_unix(sshd:auth): authentication failure`
- `xrdp-sesman: Authentication failed` (Linux RDP via xRDP)
- `Accepted password/publickey for X from IP` (successful login)

### Windows Event Log (`.evtx`)

- **4625** — failed logon
- **4624** — successful logon
- **4648** — logon using explicit credentials
- LogonType **10** = RemoteInteractive (RDP), **7** = Unlock (RDP-related)

---

## Project structure

```
BRUTU/
├── main.py                    ← entry point, CLI, alert dispatcher
├── config.yaml                ← all configuration lives here
├── requirements.txt
├── tests/
│   ├── test_tracker.py        ← sliding-window unit tests
│   └── test_parsers.py        ← log parser unit tests
├── detector/
│   ├── tracker.py             ← thread-safe sliding-window counter
│   ├── log_monitor.py         ← file-tailing threads
│   ├── report_manager.py      ← JSONL report writer
│   ├── parsers/
│   │   ├── linux_ssh.py       ← regex parser for auth.log
│   │   ├── http_auth.py       ← nginx / Apache (Basic auth, login panels)
│   │   ├── ftp.py             ← vsftpd / ProFTPD / Pure-FTPd
│   │   ├── mysql.py           ← MySQL / MariaDB error log
│   │   └── windows_evtx.py    ← EVTX parser + live win32evtlog
│   └── alerts/
│       ├── console_alert.py   ← colored terminal output
│       ├── discord_alert.py   ← Discord Rich Embeds
│       └── slack_alert.py     ← Slack Block Kit
└── utils/
    ├── geo.py                 ← GeoIP with cache and rate limiting
    └── ip_utils.py            ← CIDR whitelist parsing
```

---

## Requirements

- Python **3.8+**
- `requests`, `pyyaml`, `colorama` (all in `requirements.txt`)
- Windows EVTX static files: `pip install python-evtx`
- Windows live Event Log: `pip install pywin32` (Windows only)

---

## Security notes

- Keep your webhook URLs in `config.yaml` and **do not commit it to a public repo** — add it to `.gitignore` or use environment variables
- IP whitelist prevents false alarms from your own network
- Cooldown prevents notification spam from persistent attackers

---

## License

MIT — do whatever you want, but if something breaks it's on you 🤷
