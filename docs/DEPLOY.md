# Wdrożenie BRUTU$ na VPS (OVH, Ubuntu 24.04)

Cel: serwer z publicznym IPv4 i otwartym portem 22, na którym BRUTU$ rejestruje prawdziwe ataki
(kraje, loginy, godziny). Całość kosztuje kilka euro miesięcznie.

> Zasada nadrzędna: ty logujesz się **kluczem SSH**, a boty mogą próbować haseł do woli.
> Dzięki temu widzisz ataki, a nie dajesz się włamać.

## 1. Zamówienie serwera

- System: **Ubuntu 24.04 LTS**.
- Dodaj **swój klucz publiczny SSH** w panelu OVH przy zamawianiu (jeśli nie masz klucza:
  `ssh-keygen -t ed25519` na swoim laptopie, wysyłasz zawartość pliku `~/.ssh/id_ed25519.pub`).
- Po instalacji OVH poda adres IP i nazwę użytkownika (zwykle `ubuntu`, sprawdź w mailu / panelu).

## 2. Pierwsze logowanie i aktualizacja

```bash
ssh uzytkownik@IP_SERWERA
sudo apt update && sudo apt upgrade -y
```

## 3. Zabezpiecz własny dostęp (zanim zaczniesz zbierać ataki)

Otwórz **drugie okno terminala** i sprawdź, że logowanie kluczem działa. Dopiero potem:

```bash
sudo nano /etc/ssh/sshd_config
```

Ustaw (lub odkomentuj):

```
PasswordAuthentication no
PermitRootLogin no
```

Na Ubuntu 24.04 sprawdź też pliki w `/etc/ssh/sshd_config.d/` (`ls /etc/ssh/sshd_config.d/`).
Mogą nadpisywać te ustawienia, np. `50-cloud-init.conf` z `PasswordAuthentication yes`.
Potem:

```bash
sudo sshd -t && sudo systemctl restart ssh
```

Sprawdź w **trzecim oknie**, że nadal możesz się zalogować kluczem. Stare okno zostaw otwarte do końca testu.

## 4. Instalacja BRUTU$

```bash
sudo apt install -y git python3-venv
git clone https://github.com/sp0ko/BRUTUS.git
cd BRUTUS
./install.sh
.venv/bin/python main.py --geoip-download
```

Instalator tworzy `.venv`, instaluje zależności (w tym `geoip2`) i uruchamia kreator konfiguracji.
W kreatorze:

- źródło logów: `/var/log/auth.log`, jeśli istnieje (patrz niżej),
- bloker: **wyłączony albo `dry-run`** (na początek nie blokuj nic naprawdę),
- webhook Discord/Slack: opcjonalnie, dostaniesz alerty na telefon.

> Baza GeoIP (`--geoip-download`) daje kraj, region i miasto bez wysyłania adresów IP
> do zewnętrznych usług.

### Brak `/var/log/auth.log`

Obrazy Ubuntu 24.04 w chmurze często nie mają `rsyslog`, a więc i pliku `auth.log`.
Sprawdź: `ls /var/log/auth.log`. Jeśli go nie ma, masz dwie drogi:

- **Dziennik systemd:** w `config.yaml` ustaw `journald.enabled: true` (jednostki `ssh`, `sshd`).
- **Plik logu:** `sudo apt install -y rsyslog`, a potem uruchom kreator ponownie.

## 5. Sprawdzenie i test

```bash
.venv/bin/python main.py --check     # diagnostyka; kod wyjścia 1 = jest błąd
.venv/bin/python main.py --test      # symulowany atak (trafia do webhooków)
```

Wpisy z `--test` trafiają też do `reports/alerts.jsonl`. Po teście usuń je: `rm reports/alerts.jsonl`.

## 6. Uruchomienie jako usługa

```bash
./install.sh --service
sudo systemctl enable --now brutus
journalctl -u brutus -f
```

Usługa startuje po restarcie serwera i restartuje się po awarii.

Domyślnie usługa **nie** włącza dashboardu. Żeby go dodać:

```bash
sudo systemctl edit brutus
```

Wklej (ścieżkę `/home/uzytkownik/BRUTUS` zamień na swoją, sprawdzisz ją przez `pwd`):

```
[Service]
ExecStart=
ExecStart=/home/uzytkownik/BRUTUS/.venv/bin/python main.py --lang en --dashboard
```

Zapisz, a potem `sudo systemctl restart brutus`.

## 7. Dashboard z laptopa

Dashboard nie ma logowania i słucha tylko na `127.0.0.1` serwera. **Nie zmieniaj tego.**
Dostęp daje tunel SSH, uruchomiony na twoim laptopie:

```bash
ssh -L 8765:127.0.0.1:8765 uzytkownik@IP_SERWERA
```

Wejdź na `http://127.0.0.1:8765`. Panel statusu pokazuje, że źródło logów działa,
a czerwony baner ostrzega o udanym logowaniu po serii nieudanych prób.

## 8. Co oglądać i jak się uczyć

- **Kraje i adresy:** skąd przychodzą ataki, ile jest powtórzeń z jednej sieci.
- **Loginy:** `root`, `admin`, `ubnt`, `pi`, `test` to klasyka słowników botów.
- **Raport z historii:** `.venv/bin/python main.py --report --since 7d --format markdown`
- **Powtórka na surowych logach:** `.venv/bin/python main.py --replay /var/log/auth.log` pokazuje,
  co BRUTU$ wykryłby w istniejącym pliku, bez blokowania i bez webhooków.

Dobre ćwiczenie do portfolio: po tygodniu opisz jedną serię ataków. Skąd przyszła, na jakie loginy,
jak BRUTU$ ją wykrył i co byś zrobił jako administrator.

## 9. Blokowanie adresów (później)

Gdy alerty wyglądają sensownie, włącz najpierw `blocker.dry_run: true` i sprawdź w logach, co
zostałoby zablokowane. Prawdziwe blokowanie wymaga roota i `iptables`. Zanim je włączysz:

- dodaj swój stały adres do `whitelist` (kreator `--setup` o to zapyta),
- zostaw otwarte drugie okno SSH na czas testu.

Blokada adresu, z którego sam się łączysz, to najczęstszy sposób na zamknięcie sobie dostępu do serwera.
