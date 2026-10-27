#!/usr/bin/env bash
# BRUTU$ installer: virtualenv + dependencies, config via the setup wizard,
# configuration check and (optionally) a systemd service.
#
#   ./install.sh                 install + guided setup
#   ./install.sh --service       additionally install the systemd unit (root/sudo)
#   ./install.sh --print-service print the systemd unit for this directory and exit
#   ./install.sh --no-setup      do not run the wizard (copy config.example.yaml)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
ROOT="$(pwd)"
PYTHON="${PYTHON:-python3}"
WITH_SERVICE=0
PRINT_SERVICE=0
NO_SETUP=0

for arg in "$@"; do
  case "$arg" in
    --service)       WITH_SERVICE=1 ;;
    --print-service) PRINT_SERVICE=1 ;;
    --no-setup)      NO_SETUP=1 ;;
    -h|--help)       sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $arg (see --help)" >&2; exit 2 ;;
  esac
done

render_service() {
  case "$ROOT" in
    *[[:space:]#]*) echo "Install path must not contain spaces or '#': $ROOT" >&2; exit 1 ;;
  esac
  local unit
  unit="$(sed "s#/opt/brutus#${ROOT}#g" deploy/brutus.service)"
  # The unit hardens the service with ProtectHome=yes, which would hide a /home install.
  case "$ROOT" in
    /home/*) unit="$(printf '%s\n' "$unit" | sed 's/^ProtectHome=yes/ProtectHome=read-only/')" ;;
  esac
  printf '%s\n' "$unit"
}

if [ "$PRINT_SERVICE" -eq 1 ]; then
  render_service
  exit 0
fi

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "python3 not found. Install Python 3.10 or newer and retry." >&2
  exit 1
fi
if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "Python 3.10 or newer is required (found: $("$PYTHON" -V 2>&1))." >&2
  exit 1
fi

if [ ! -x .venv/bin/python ]; then
  echo "==> Creating virtualenv (.venv)"
  "$PYTHON" -m venv .venv || {
    rm -rf .venv
    echo "Could not create a virtualenv. On Debian/Ubuntu: sudo apt install python3-venv" >&2
    exit 1
  }
fi

echo "==> Installing dependencies"
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -r requirements.txt

# The unit's ReadWritePaths must exist or systemd refuses to start it.
mkdir -p reports logs

case "${LANG:-}" in pl*) LANG_OPT=pl ;; *) LANG_OPT=en ;; esac

if [ ! -f config.yaml ]; then
  if [ "$NO_SETUP" -eq 0 ] && [ -t 0 ]; then
    echo "==> Setup wizard"
    .venv/bin/python main.py --lang "$LANG_OPT" --setup
  fi
  if [ ! -f config.yaml ]; then
    cp config.example.yaml config.yaml
    chmod 600 config.yaml
    echo "==> Created config.yaml from config.example.yaml — edit it or run: .venv/bin/python main.py --setup"
  fi
else
  echo "==> Keeping existing config.yaml"
fi

echo "==> Checking configuration"
.venv/bin/python main.py --lang "$LANG_OPT" --check || \
  echo "(Fix the problems above, then re-run: .venv/bin/python main.py --check)"

if [ "$WITH_SERVICE" -eq 1 ]; then
  SUDO=""
  [ "$(id -u)" -eq 0 ] || SUDO="sudo"
  echo "==> Installing systemd service"
  render_service | $SUDO tee /etc/systemd/system/brutus.service >/dev/null
  $SUDO systemctl daemon-reload
  echo "Service installed. Start it once the check above is clean:"
  echo "  sudo systemctl enable --now brutus && journalctl -u brutus -f"
fi

cat <<EOF

Done. Next steps:
  .venv/bin/python main.py --test        # send a simulated attack to your webhooks
  .venv/bin/python main.py               # run in the foreground
  .venv/bin/python main.py --dashboard   # run with the web dashboard (127.0.0.1:8080)
EOF
