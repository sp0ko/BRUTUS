# BRUTU$ 🛡️

> Bo każdy random z Shodan myśli, że twój SSH to jego prywatny plac zabaw.

**BRUTU$** śledzi logi SSH i RDP w czasie rzeczywistym, liczy nieudane logowania per IP i jak jakiś gość przekroczy próg — dostajesz ping na Discord/Slack zanim zdążysz wypić kawę. Plus geolokalizacja, żebyś wiedział z jakiego kraju przyszedł gość.

```
 ██████╗ ██████╗ ██╗   ██╗████████╗██╗   ██╗███████╗
 ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██║   ██║██╔════╝
 ██████╔╝██████╔╝██║   ██║   ██║   ██║   ██║███████╗
 ██╔══██╗██╔══██╗██║   ██║   ██║   ██║   ██║╚════██║
 ██████╔╝██║  ██║╚██████╔╝   ██║   ╚██████╔╝███████║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚══════╝  $  v1.0.0
```

---

## Co robi

| Funkcja | Opis |
|---|---|
| 🔍 **Real-time monitoring** | Tail-uje plik logu tak jak `tail -f` — reaguje w ułamku sekundy |
| 🐧 **Linux SSH** | Parsuje `/var/log/auth.log` i `/var/log/secure` (regex na syslog) |
| 🪟 **Windows RDP** | Czyta pliki `.evtx` (Event ID 4625 / 4624) lub live Windows Event Log |
| 🧠 **Sliding window** | Liczy próby w ruchomym oknie czasu — brak fałszywych alarmów przy restarcie |
| 🚨 **Brute + włamanie** | Jeśli udane logowanie pojawia się PO serii nieudanych, dostaniesz KRYTYCZNY alert |
| 🌍 **GeoIP** | Kraj, miasto, ISP — bez klucza API, przez [ip-api.com](http://ip-api.com) |
| 💬 **Discord** | Rich embeds, pomarańczowe = ostrzeżenie, czerwone = włamanie |
| 💬 **Slack** | Block Kit, wygląda profesjonalnie nawet o 3 w nocy |
| 📄 **Raporty JSON** | Każdy alert ląduje w `.jsonl` — gotujesz do SIEMa albo po prostu masz historię |
| ✅ **Biała lista** | Twoja sieć domowa / VPN / CI nie będzie Cię triggerować |
| 🔕 **Cooldown** | Ten sam IP nie zasypie Cię 500 powiadomieniami — jeden alert na X minut |
| 🧪 **Tryb testowy** | `--test` generuje symulowany atak i wysyła alerty na prawdziwe webhooks |

---

## Instalacja

```bash
git clone https://github.com/sp0ko/BRUTU.git
cd BRUTU
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Linux — uprawnienia do logów

```bash
# Ubuntu/Debian
sudo usermod -aG adm $USER
# RHEL/CentOS
sudo usermod -aG adm $USER

# albo po prostu odpal z sudo
sudo python main.py
```

---

## Szybki start

### 1. Skonfiguruj `config.yaml`

```yaml
detection:
  threshold: 5       # ile nieudanych == alert
  time_window: 60    # w ciągu ilu sekund

log_files:
  - path: /var/log/auth.log
    type: linux_ssh
    enabled: true

discord:
  enabled: true
  webhook_url: "https://discord.com/api/webhooks/TWÓJ_URL"

slack:
  enabled: true
  webhook_url: "https://hooks.slack.com/services/TWÓJ_URL"
```

### 2. Odpal

```bash
python main.py
```

### 3. Przetestuj webhooks zanim cokolwiek wybuchnie

```bash
python main.py --test
```

---

## CLI

```
python main.py [opcje]

  --config PATH         Własny plik konfiguracyjny
  --log PATH            Dodatkowy plik logu do śledzenia
  --type TYPE           Parser: linux_ssh | windows_evtx
  --threshold N         Ile prób wyzwala alert
  --window N            Okno czasowe w sekundach
  --cooldown N          Przerwa między alertami dla tego samego IP
  --discord-url URL     Discord webhook (bez konfiguracji w pliku)
  --slack-url URL       Slack webhook (bez konfiguracji w pliku)
  --test                Symulacja ataku — testuje webhooks
  --stats               Pokaż aktywne IP i zakończ
  --version             Wersja
```

### Przykłady

```bash
# Niższy próg, krótsze okno
python main.py --threshold 3 --window 30

# Podaj webhook z CLI (np. do testów)
python main.py --discord-url "https://discord.com/api/webhooks/..."

# Monitoruj konkretny plik
python main.py --log /var/log/secure --type linux_ssh
```

---

## Jak podłączyć Discord

1. Ustawienia serwera → **Integrations → Webhooks → New Webhook**
2. Wybierz kanał, kliknij **Copy Webhook URL**
3. Wklej URL do `config.yaml`:
   ```yaml
   discord:
     enabled: true
     webhook_url: "https://discord.com/api/webhooks/TUTAJ"
   ```

## Jak podłączyć Slack

1. Wejdź na [api.slack.com/apps](https://api.slack.com/apps)
2. **Create New App → From Scratch**
3. **Incoming Webhooks → Activate → Add New Webhook to Workspace**
4. Wybierz kanał, skopiuj URL → wklej do `config.yaml`

---

## Przykładowe alerty

**Terminal (normalny atak):**
```
══════════════════════════════════════════════════════════════════════
          ⚠️  UWAGA! POTENCJALNY BRUTE FORCE!  ⚠️
══════════════════════════════════════════════════════════════════════
  🌐 Adres IP       : 203.0.113.42
  📊 Nieudane próby : 8 w ciągu 60s
  🔌 Typ ataku      : SSH
  👤 Użytkownicy    : root, admin, Administrator
  📁 Źródło logów   : /var/log/auth.log
  🕐 Czas wykrycia  : 2026-05-20 12:13:21
  🗺  Geolokalizacja  : China, Beijing
  🏢 ISP / Org       : ChinaNet
══════════════════════════════════════════════════════════════════════
```

**Terminal (udane włamanie po ataku):**
```
══════════════════════════════════════════════════════════════════════
       🚨 KRYTYCZNE! UDANE LOGOWANIE PO BRUTE-FORCE! 🚨
══════════════════════════════════════════════════════════════════════
  🌐 Adres IP       : 192.0.2.55
  📊 Nieudane próby : 5 w ciągu 60s
  ...
  ‼ MOŻLIWE WŁAMANIE — sprawdź konto natychmiast!
══════════════════════════════════════════════════════════════════════
```

---

## Jakie logi obsługuje

### `/var/log/auth.log` (Debian/Ubuntu) / `/var/log/secure` (RHEL)

Wykrywane wzorce:
- `Failed password for [invalid user] X from IP`
- `Invalid user X from IP`
- `Disconnected from invalid user X IP [preauth]`
- `pam_unix(sshd:auth): authentication failure`
- `xrdp-sesman: Authentication failed` (Linux RDP via xRDP)
- `Accepted password/publickey for X from IP` (udane logowanie)

### Windows Event Log (`.evtx`)

- **4625** — nieudane logowanie
- **4624** — udane logowanie
- **4648** — logowanie przez explicit credentials
- LogonType **10** = RDP, **3** = Network/SMB

---

## Struktura projektu

```
BRUTU/
├── main.py                    ← tu się zaczyna zabawa
├── config.yaml                ← cała konfiguracja
├── requirements.txt
├── tests/
│   ├── test_tracker.py        ← testy sliding-window
│   └── test_parsers.py        ← testy parserów logów
├── detector/
│   ├── tracker.py             ← sliding-window licznik (thread-safe)
│   ├── log_monitor.py         ← wątki tail-ujące pliki
│   ├── report_manager.py      ← zapis do JSONL
│   ├── parsers/
│   │   ├── linux_ssh.py       ← regex na auth.log
│   │   └── windows_evtx.py    ← parser EVTX + live win32
│   └── alerts/
│       ├── console_alert.py   ← kolorowy output w terminalu
│       ├── discord_alert.py   ← Discord Rich Embeds
│       └── slack_alert.py     ← Slack Block Kit
└── utils/
    ├── geo.py                 ← GeoIP z cache i rate-limitem
    └── ip_utils.py            ← parsowanie list CIDR
```

---

## Wymagania

- Python **3.8+**
- `requests`, `pyyaml`, `colorama` (wszystko w `requirements.txt`)
- Windows EVTX (pliki statyczne): `pip install python-evtx`
- Windows live Event Log: `pip install pywin32` (tylko Windows)

---

## Bezpieczeństwo

- Webhook URL trzymaj w `config.yaml` i **nie commituj go do publicznego repo** — dodaj do `.gitignore` lub użyj zmiennych środowiskowych
- Biała lista IP chroni przed fałszywymi alarmami z własnej sieci
- Cooldown chroni przed flood-em powiadomień

---

## Licencja

MIT — rób co chcesz, ale jak coś wybuchnie to nie moja wina 🤷
