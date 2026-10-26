"""
Centralised internationalisation (i18n) module.

Usage
-----
    import utils.i18n as i18n

    i18n.set_lang("en")      # called once at startup
    T = i18n.get_T()         # retrieve current translation dict anywhere
"""

import sys
from typing import Optional

STRINGS: dict = {
    "pl": {
        # ── main.py ──────────────────────────────────────────────────────────
        "description":   "BRUTU$ — detekcja ataków SSH/RDP w czasie rzeczywistym",
        "help_config":   "Ścieżka do pliku config.yaml",
        "help_log":      "Dodatkowy plik logu",
        "help_type":     "Typ parsera: linux_ssh | windows_evtx",
        "help_threshold":"Próg nieudanych logowań",
        "help_window":   "Okno czasu (sekundy)",
        "help_cooldown": "Cooldown alertów (sekundy)",
        "help_discord":  "Discord webhook URL",
        "help_slack":    "Slack webhook URL",
        "help_test":     "Tryb testowy — symulacja ataku",
        "help_stats":    "Pokaż statystyki i zakończ",
        "help_lang":     "Język interfejsu: pl | en (pomija interaktywny wybór)",
        "help_geoip_db": "Ścieżka do pliku GeoLite2-City.mmdb (zapytania offline zamiast ip-api.com)",
        "help_replay":   "Odtwórz istniejący plik logu (też .gz) offline — bez blokowania i webhooków",
        "replay_start":  "[REPLAY] Analizuję %s (parser: %s)…",
        "replay_err":    "[BŁĄD] Nie można odtworzyć %s: %s",
        "replay_summary": "\n[REPLAY] Linie: %d  |  nieudane: %d  |  udane: %d  |  alerty: %d",
        "replay_top":    "[REPLAY] Najaktywniejsze IP:",
        "help_report":   "Pokaż raport zbiorczy z alerts.jsonl i zakończ",
        "help_since":    "Okres raportu: 24h, 7d, 2w lub all (domyślnie 7d)",
        "help_format":   "Format raportu: text | markdown | json | html (domyślnie text)",
        "help_output":   "Zapisz raport do pliku zamiast wypisywać na ekran",
        "help_dashboard": "Uruchom lokalny dashboard WWW (domyślnie http://127.0.0.1:8080)",
        "help_dash_host": "Adres nasłuchu dashboardu (domyślnie 127.0.0.1)",
        "help_dash_port": "Port dashboardu (domyślnie 8080)",
        "report_err":    "[BŁĄD] Raport: %s",
        "report_saved":  "Raport zapisano do %s",
        "dash_started":  "Dashboard: http://%s:%d/  (Ctrl+C aby zatrzymać)",
        "dash_exposed":  "[UWAGA] Dashboard nasłuchuje na %s i NIE MA uwierzytelniania — pokazuje adresy IP i nazwy kont. Użyj 127.0.0.1 + tunel SSH / reverse proxy z hasłem.",
        "dash_err":      "[BŁĄD] Dashboard: %s",
        "rp_title":      "Raport zbiorczy",
        "rp_beginning":  "początek",
        "rp_alerts":     "Alerty",
        "rp_ips":        "Unikalne IP",
        "rp_breaches":   "Włamania",
        "rp_spray":      "Password spray",
        "rp_ti":         "Trafienia threat intel",
        "rp_types":      "Typy ataków",
        "rp_top_ips":    "Najaktywniejsze IP",
        "rp_countries":  "Kraje",
        "rp_users":      "Najczęściej atakowane konta",
        "rp_sources":    "Źródła logów",
        "rp_ti_sources": "Źródła threat intel",
        "rp_timeline":   "Oś czasu",
        "rp_none":       "brak danych",
        "rp_breach_flag": "WŁAMANIE",
        "rp_col_alerts": "Alerty",
        "rp_col_attempts": "Maks. prób",
        "rp_col_country": "Kraj",
        "rp_col_flags":  "Flagi",
        "rp_col_type":   "Typ",
        "rp_col_user":   "Konto",
        "rp_col_source": "Źródło",
        "rp_col_period": "Okres",
        "err_config":    "[BŁĄD] Plik konfiguracyjny nie istnieje: %s",
        "tracker_info":  "Tracker: próg=%d  okno=%ds  cooldown=%ds",
        "discord_on":    "Discord webhook: aktywny ✓",
        "discord_off":   "Discord: wyłączony",
        "slack_on":      "Slack webhook: aktywny ✓",
        "slack_off":     "Slack: wyłączony",
        "reports_info":  "Raporty: %s",
        "no_log_files":  "Brak aktywnych plików logów! Dodaj wpisy w 'log_files' w config.yaml.",
        "adding_file":   "Dodaję plik: %s  (parser: %s)",
        "signal_stop":   "Sygnał %s — zatrzymuję…",
        "started":       "BRUTU$ uruchomiony — Ctrl+C aby zatrzymać.",
        "lang_hint":     '[WSKAZÓWKA] Wpisz "lang" + Enter, aby zmienić język podczas działania.',
        "active_ips":    "Aktywne IP: %d  |  Najbardziej aktywne: %s (%d prób)",
        "stopped":       "BRUTU$ zatrzymany.",
        "test_start":    "\n[TEST] Uruchamiam symulację ataku brute-force…\n",
        "test_end":      "\n[TEST] Symulacja zakończona. Sprawdź Discord/Slack jeśli webhooks są skonfigurowane.",
        "no_activity":   "Brak aktywności w bieżącym oknie czasu.",
        "col_ip":        "IP",
        "col_attempts":  "Próby",
        "col_type":      "Typ ataku",
        "col_users":     "Użytkownicy",
        "lang_changed":  "Zmieniono język na: Polski.",
        # ── console_alert.py ─────────────────────────────────────────────────
        "ca_title_crit":    " 🚨 KRYTYCZNE! UDANE LOGOWANIE PO BRUTE-FORCE! 🚨",
        "ca_title_warn":    " ⚠️  UWAGA! POTENCJALNY BRUTE FORCE!  ⚠️",
        "ca_line_ip":       "  🌐 Adres IP       : {ip}",
        "ca_line_attempts": "  📊 Nieudane próby : {count} w ciągu {window}s",
        "ca_line_type":     "  🔌 Typ ataku      : {type}",
        "ca_line_users":    "  👤 Użytkownicy    : {users}",
        "ca_line_source":   "  📁 Źródło logów   : {source}",
        "ca_line_time":     "  🕐 Czas wykrycia  : {ts}",
        "ca_line_geo":      "  🗺  Geolokalizacja  : {geo}",
        "ca_line_isp":      "  🏢 ISP / Org       : {isp}",
        "ca_breach":        "  ‼ MOŻLIWE WŁAMANIE — sprawdź konto natychmiast!",
        # ── discord_alert.py ─────────────────────────────────────────────────
        "dc_title_crit": "🚨 KRYTYCZNE! UDANE LOGOWANIE PO BRUTE-FORCE!",
        "dc_title_warn": "⚠️ UWAGA! POTENCJALNY BRUTE FORCE WYKRYTY!",
        "dc_desc_crit":  "Adres IP **{ip}** prawdopodobnie **pomyślnie przejął konto** po {count} nieudanych próbach.",
        "dc_desc_warn":  "Adres IP **{ip}** wykonał **{count} nieudanych prób logowania** w ciągu **{window} sekund**.",
        "dc_f_ip":       "🌐 Adres IP",
        "dc_f_attempts": "📊 Liczba prób",
        "dc_f_window":   "⏱ Okno czasu",
        "dc_f_type":     "🔌 Typ ataku",
        "dc_f_users":    "👤 Użytkownicy",
        "dc_f_source":   "📁 Źródło logów",
        "dc_f_geo":      "🗺 Geolokalizacja",
        "dc_f_isp":      "🏢 ISP / Org",
        # ── slack_alert.py ───────────────────────────────────────────────────
        "sl_title_crit": "🚨 KRYTYCZNE! UDANE LOGOWANIE PO BRUTE-FORCE!",
        "sl_title_warn": "⚠️ UWAGA! POTENCJALNY BRUTE FORCE WYKRYTY!",
        "sl_summ_crit":  "IP `{ip}` prawdopodobnie *pomyślnie przejął konto* po {count} nieudanych próbach.",
        "sl_summ_warn":  "IP `{ip}` wykonał *{count} nieudanych prób logowania* w ciągu *{window} sekund*.",
        "sl_f_ip":       "*🌐 Adres IP:*",
        "sl_f_attempts": "*📊 Próby:*",
        "sl_f_type":     "*🔌 Typ ataku:*",
        "sl_f_users":    "*👤 Użytkownicy:*",
        "sl_f_source":   "*📁 Źródło:*",
        "sl_f_time":     "*🕐 Czas:*",
        "sl_f_geo":      "*🗺 Lokalizacja:*",
        "sl_f_isp":      "*🏢 ISP:*",
        "sl_fallback":   "[BRUTE-FORCE] IP {ip} — {count} prób w {window}s",
        # ── log_monitor.py ───────────────────────────────────────────────────
        "lm_monitoring":    "Monitorowanie: %s  (parser: %s)",
        "lm_no_file":       "Plik nie istnieje: %s — czekam…",
        "lm_ready":         "Gotowy do czytania: %s",
        "lm_rotated":       "Rotacja logu: %s",
        "lm_truncated":     "Plik skrócony: %s",
        "lm_read_err":      "Błąd odczytu %s: %s",
        "lm_parse_err":     "Błąd parsowania: %s",
        "lm_alert_err":     "Błąd callbacku alertu: %s",
        "lm_unknown_parser":"Nieznany parser: %s",
        "lm_no_files":      "Brak plików logów do monitorowania.",
        "lm_started":       "Monitor uruchomiony — %d plik(ów).",
        "lm_dispatch_err":  "Błąd handlera: %s",
        # ── alerts/__init__.py ───────────────────────────────────────────────
        "fmt_attacks":  "ataki",
        "fmt_window":   "okno",
        "fmt_type":     "typ",
        "fmt_users":    "użytkownicy",
        # ── blocker ──────────────────────────────────────────────────────────
        "blk_blocked":       "ZABLOKOWANO %s | typ=%s próby=%d",
        "blk_unblocked":     "ODBLOKOWANO %s",
        "blk_dry_run":       "[DRY-RUN] Blokada pominięta — tryb testowy",
        "blk_no_root":       "Bloker włączony, ale brak uprawnień root — iptables nie zadziała.",
        "blk_disabled":      "Aktywna blokada: wyłączona",
        "blk_enabled":       "Aktywna blokada: iptables ✓  (auto-odblokowanie po %ds)",
        "blk_enabled_perm":  "Aktywna blokada: iptables ✓  (blokada permanentna)",
        "blk_dry":           "Aktywna blokada: DRY-RUN (bez rzeczywistych reguł)",
        "blk_header":        "\n{'IP':<20} {'Typ ataku':<18} {'Próby':>7}  {'Zablokowano o':<20}  {'Odblok. za':>10}  Użytkownicy",
        "blk_permanent":     "permanentna",
        "blk_seconds":       "%ds",
        "blk_none":          "Brak aktualnie zablokowanych adresów IP.",
        "blk_spray_hint":    "[PASSWORD SPRAY] Wiele unikalnych kont z jednego IP.",
        "help_blocked":      "Pokaż listę zablokowanych IP i zakończ",
        # ── threat intel ─────────────────────────────────────────────────────
        "ti_enabled":         "Threat intel załadowany: %d wpisów z %s",
        "ti_disabled":        "Threat intel: wyłączony",
        "ti_no_db":           "Threat intel: brak bazy danych — uruchom --update-threat-db",
        "ti_updating":        "Pobieranie bazy reputacji IP (%d źródeł)...",
        "ti_updated":         "Threat intel zaktualizowany: %d wpisów → %s",
        "ti_match":           "THREAT INTEL: %s",
        "help_update_ti":     "Pobierz/zaktualizuj bazę reputacji IP i zakończ",
        # ── syslog server ─────────────────────────────────────────────────
        "syslog_started":     "Serwer syslog: nasłuchuje na %s:%d/%s",
        "syslog_disabled":    "Serwer syslog: wyłączony",
        "syslog_bind_err":    "Serwer syslog: błąd bind %s:%d — %s",
        "journald_started":   "Journald: monitoruję jednostki: %s",
        "journald_disabled":  "Journald: wyłączony",
        "journald_missing":   "Journald: nie znaleziono 'journalctl' — źródło wyłączone",
        "journald_err":       "Journald: błąd odczytu — %s",
        "journald_restart":   "Journald: proces zakończył się, ponowne uruchomienie za %ds",
    },
    "en": {
        # ── main.py ──────────────────────────────────────────────────────────
        "description":   "BRUTU$ — real-time SSH/RDP brute-force attack detector",
        "help_config":   "Path to config.yaml file",
        "help_log":      "Additional log file path",
        "help_type":     "Parser type: linux_ssh | windows_evtx",
        "help_threshold":"Failed login threshold",
        "help_window":   "Time window (seconds)",
        "help_cooldown": "Alert cooldown (seconds)",
        "help_discord":  "Discord webhook URL",
        "help_slack":    "Slack webhook URL",
        "help_test":     "Test mode — simulate attack",
        "help_stats":    "Show statistics and exit",
        "help_lang":     "Interface language: pl | en (skips interactive prompt)",
        "help_geoip_db": "Path to GeoLite2-City.mmdb file (offline lookups instead of ip-api.com)",
        "help_replay":   "Replay an existing log file (also .gz) offline — no blocking, no webhooks",
        "replay_start":  "[REPLAY] Analysing %s (parser: %s)…",
        "replay_err":    "[ERROR] Cannot replay %s: %s",
        "replay_summary": "\n[REPLAY] Lines: %d  |  failed: %d  |  successful: %d  |  alerts: %d",
        "replay_top":    "[REPLAY] Most active IPs:",
        "help_report":   "Print an aggregated report from alerts.jsonl and exit",
        "help_since":    "Report period: 24h, 7d, 2w or all (default 7d)",
        "help_format":   "Report format: text | markdown | json | html (default text)",
        "help_output":   "Write the report to a file instead of printing it",
        "help_dashboard": "Start a local web dashboard (default http://127.0.0.1:8080)",
        "help_dash_host": "Dashboard bind address (default 127.0.0.1)",
        "help_dash_port": "Dashboard port (default 8080)",
        "report_err":    "[ERROR] Report: %s",
        "report_saved":  "Report saved to %s",
        "dash_started":  "Dashboard: http://%s:%d/  (Ctrl+C to stop)",
        "dash_exposed":  "[WARNING] Dashboard listens on %s and has NO authentication — it shows IP addresses and account names. Use 127.0.0.1 + SSH tunnel / a password-protected reverse proxy.",
        "dash_err":      "[ERROR] Dashboard: %s",
        "rp_title":      "Summary report",
        "rp_beginning":  "beginning",
        "rp_alerts":     "Alerts",
        "rp_ips":        "Unique IPs",
        "rp_breaches":   "Breaches",
        "rp_spray":      "Password spray",
        "rp_ti":         "Threat intel matches",
        "rp_types":      "Attack types",
        "rp_top_ips":    "Top attacking IPs",
        "rp_countries":  "Countries",
        "rp_users":      "Most targeted accounts",
        "rp_sources":    "Log sources",
        "rp_ti_sources": "Threat intel sources",
        "rp_timeline":   "Timeline",
        "rp_none":       "no data",
        "rp_breach_flag": "BREACH",
        "rp_col_alerts": "Alerts",
        "rp_col_attempts": "Max attempts",
        "rp_col_country": "Country",
        "rp_col_flags":  "Flags",
        "rp_col_type":   "Type",
        "rp_col_user":   "Account",
        "rp_col_source": "Source",
        "rp_col_period": "Period",
        "err_config":    "[ERROR] Config file not found: %s",
        "tracker_info":  "Tracker: threshold=%d  window=%ds  cooldown=%ds",
        "discord_on":    "Discord webhook: active ✓",
        "discord_off":   "Discord: disabled",
        "slack_on":      "Slack webhook: active ✓",
        "slack_off":     "Slack: disabled",
        "reports_info":  "Reports: %s",
        "no_log_files":  "No active log files! Add entries under 'log_files' in config.yaml.",
        "adding_file":   "Adding file: %s  (parser: %s)",
        "signal_stop":   "Signal %s — stopping…",
        "started":       "BRUTU$ running — press Ctrl+C to stop.",
        "lang_hint":     '[HINT] Type "lang" + Enter to change language at any time.',
        "active_ips":    "Active IPs: %d  |  Most active: %s (%d attempts)",
        "stopped":       "BRUTU$ stopped.",
        "test_start":    "\n[TEST] Starting brute-force attack simulation…\n",
        "test_end":      "\n[TEST] Simulation complete. Check Discord/Slack if webhooks are configured.",
        "no_activity":   "No activity in the current time window.",
        "col_ip":        "IP",
        "col_attempts":  "Attempts",
        "col_type":      "Attack type",
        "col_users":     "Usernames",
        "lang_changed":  "Language changed to: English.",
        # ── console_alert.py ─────────────────────────────────────────────────
        "ca_title_crit":    " 🚨 CRITICAL! SUCCESSFUL LOGIN AFTER BRUTE-FORCE! 🚨",
        "ca_title_warn":    " ⚠️  WARNING! POTENTIAL BRUTE FORCE ATTACK!  ⚠️",
        "ca_line_ip":       "  🌐 IP Address      : {ip}",
        "ca_line_attempts": "  📊 Failed attempts : {count} in {window}s",
        "ca_line_type":     "  🔌 Attack type     : {type}",
        "ca_line_users":    "  👤 Usernames       : {users}",
        "ca_line_source":   "  📁 Log source      : {source}",
        "ca_line_time":     "  🕐 Detected at     : {ts}",
        "ca_line_geo":      "  🗺  Geolocation     : {geo}",
        "ca_line_isp":      "  🏢 ISP / Org       : {isp}",
        "ca_breach":        "  ‼ POSSIBLE BREACH — check account immediately!",
        # ── discord_alert.py ─────────────────────────────────────────────────
        "dc_title_crit": "🚨 CRITICAL! SUCCESSFUL LOGIN AFTER BRUTE-FORCE!",
        "dc_title_warn": "⚠️ WARNING! POTENTIAL BRUTE FORCE DETECTED!",
        "dc_desc_crit":  "IP address **{ip}** likely **successfully took over an account** after {count} failed attempts.",
        "dc_desc_warn":  "IP address **{ip}** made **{count} failed login attempts** in **{window} seconds**.",
        "dc_f_ip":       "🌐 IP Address",
        "dc_f_attempts": "📊 Attempt count",
        "dc_f_window":   "⏱ Time window",
        "dc_f_type":     "🔌 Attack type",
        "dc_f_users":    "👤 Usernames",
        "dc_f_source":   "📁 Log source",
        "dc_f_geo":      "🗺 Geolocation",
        "dc_f_isp":      "🏢 ISP / Org",
        # ── slack_alert.py ───────────────────────────────────────────────────
        "sl_title_crit": "🚨 CRITICAL! SUCCESSFUL LOGIN AFTER BRUTE-FORCE!",
        "sl_title_warn": "⚠️ WARNING! POTENTIAL BRUTE FORCE DETECTED!",
        "sl_summ_crit":  "IP `{ip}` likely *successfully took over an account* after {count} failed attempts.",
        "sl_summ_warn":  "IP `{ip}` made *{count} failed login attempts* in *{window} seconds*.",
        "sl_f_ip":       "*🌐 IP Address:*",
        "sl_f_attempts": "*📊 Attempts:*",
        "sl_f_type":     "*🔌 Attack type:*",
        "sl_f_users":    "*👤 Usernames:*",
        "sl_f_source":   "*📁 Log source:*",
        "sl_f_time":     "*🕐 Time:*",
        "sl_f_geo":      "*🗺 Location:*",
        "sl_f_isp":      "*🏢 ISP:*",
        "sl_fallback":   "[BRUTE-FORCE] IP {ip} — {count} attempts in {window}s",
        # ── log_monitor.py ───────────────────────────────────────────────────
        "lm_monitoring":    "Monitoring: %s  (parser: %s)",
        "lm_no_file":       "File not found: %s — waiting…",
        "lm_ready":         "Ready to read: %s",
        "lm_rotated":       "Log rotated: %s",
        "lm_truncated":     "File truncated: %s",
        "lm_read_err":      "Read error %s: %s",
        "lm_parse_err":     "Parse error: %s",
        "lm_alert_err":     "Alert callback error: %s",
        "lm_unknown_parser":"Unknown parser: %s",
        "lm_no_files":      "No log files to monitor.",
        "lm_started":       "Monitor started — %d file(s).",
        "lm_dispatch_err":  "Handler error: %s",
        # ── alerts/__init__.py ───────────────────────────────────────────────
        "fmt_attacks":  "attempts",
        "fmt_window":   "window",
        "fmt_type":     "type",
        "fmt_users":    "usernames",
        # ── blocker ──────────────────────────────────────────────────────────
        "blk_blocked":       "BLOCKED %s | type=%s attempts=%d",
        "blk_unblocked":     "UNBLOCKED %s",
        "blk_dry_run":       "[DRY-RUN] Block skipped — dry-run mode",
        "blk_no_root":       "Blocker enabled but not running as root — iptables will fail.",
        "blk_disabled":      "Active blocking: disabled",
        "blk_enabled":       "Active blocking: iptables ✓  (auto-unblock after %ds)",
        "blk_enabled_perm":  "Active blocking: iptables ✓  (permanent)",
        "blk_dry":           "Active blocking: DRY-RUN (no real rules applied)",
        "blk_header":        "\n{'IP':<20} {'Attack type':<18} {'Attempts':>9}  {'Blocked at':<20}  {'Unblock in':>10}  Usernames",
        "blk_permanent":     "permanent",
        "blk_seconds":       "%ds",
        "blk_none":          "No IPs are currently blocked.",
        "blk_spray_hint":    "[PASSWORD SPRAY] Many unique accounts targeted from one IP.",
        "help_blocked":      "Show blocked IP list and exit",
        # ── threat intel ─────────────────────────────────────────────────────
        "ti_enabled":         "Threat intel loaded: %d entries from %s",
        "ti_disabled":        "Threat intel: disabled",
        "ti_no_db":           "Threat intel: no DB found — run --update-threat-db to download",
        "ti_updating":        "Downloading IP reputation DB (%d sources)...",
        "ti_updated":         "Threat intel updated: %d entries → %s",
        "ti_match":           "THREAT INTEL: %s",
        "help_update_ti":     "Download/update IP reputation DB and exit",
        # ── syslog server ─────────────────────────────────────────────────
        "syslog_started":     "Syslog server: listening on %s:%d/%s",
        "syslog_disabled":    "Syslog server: disabled",
        "syslog_bind_err":    "Syslog server: bind error %s:%d — %s",
        "journald_started":   "Journald: watching units: %s",
        "journald_disabled":  "Journald: disabled",
        "journald_missing":   "Journald: 'journalctl' not found — source disabled",
        "journald_err":       "Journald: read error — %s",
        "journald_restart":   "Journald: process exited, restarting in %ds",
    },
}

_state: dict = {"lang": "en"}


def get_T() -> dict:
    """Return the current active translation dictionary."""
    return STRINGS[_state["lang"]]


def set_lang(lang: str) -> None:
    """Switch the active language. All subsequent get_T() calls reflect the change."""
    if lang not in STRINGS:
        raise ValueError(f"Unsupported language: {lang!r}. Choose from: {list(STRINGS)}")
    _state["lang"] = lang


def detect_lang_flag() -> Optional[str]:
    """Scan sys.argv for --lang without running the full argparser."""
    argv = sys.argv[1:]
    for i, arg in enumerate(argv):
        if arg.startswith("--lang="):
            val = arg.split("=", 1)[1]
            if val in STRINGS:
                return val
        elif arg == "--lang" and i + 1 < len(argv):
            val = argv[i + 1]
            if val in STRINGS:
                return val
    return None


def select_language() -> str:
    """Prompt the user to choose a language interactively and return 'pl' or 'en'."""
    prompt = "  Wybierz język / Choose language:\n  [1] Polski  [2] English  (default: 2)\n  > "
    while True:
        try:
            choice = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return "en"
        if choice == "1":
            return "pl"
        if choice in ("2", ""):
            return "en"
