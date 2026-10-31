#!/usr/bin/env bash
# DKCISSP Privacy Posture Assessment — one-click launcher (Linux / macOS)
#
# Double-click this file (or run `./run.sh` / `bash run.sh`) and it will:
#   1. Create a private virtual environment on first run (./.venv)
#   2. Install everything needed (first run only — fast after that)
#   3. Start the local web UI
#   4. Open it in your browser automatically
#
# Only assess domains you own or are authorized to test.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
if ! command -v "$PY" >/dev/null 2>&1 || \
   ! "$PY" -c 'import sys, venv, ensurepip; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
  echo "Python 3.9+ with the 'venv' module is required but was not found."
  echo "Debian/Ubuntu/Kali: sudo apt install python3 python3-venv python3-pip"
  echo "Otherwise: https://www.python.org/downloads/  — then run this again."
  [ -t 0 ] && read -rp "Press Enter to exit..." _
  exit 1
fi

# Install on first run, after an interrupted install, or when pyproject.toml changed.
if [ ! -x ".venv/bin/python" ] || [ ! -f ".venv/.installed" ] || [ pyproject.toml -nt ".venv/.installed" ]; then
  echo "Setting up — this takes a minute..."
  [ -x ".venv/bin/python" ] || { rm -rf .venv; "$PY" -m venv .venv; }
  ./.venv/bin/python -m pip install -q --upgrade pip
  ./.venv/bin/python -m pip install -q -e ".[web,dynamic-scan]"
  touch .venv/.installed
fi

# Always use port 1009. If a previous copy of this app is still running (an older
# install, or this one from an earlier launch), stop it so the new one takes over.
PORT="${PORT:-1009}"
export PORT
port_busy() {
  "$PWD/.venv/bin/python" -c 'import socket, sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(0)
sys.exit(1)' "$PORT"
}
if port_busy; then
  echo "Port $PORT is in use — stopping any previous copy of this app..."
  pkill -f "[d]kcissp-privacy-assessment-web" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do port_busy || break; sleep 0.5; done
  if port_busy; then
    echo "Error: port $PORT is held by a different program, not this app." >&2
    echo "Stop that program (see: ss -ltnp | grep :$PORT) and run this again." >&2
    exit 1
  fi
fi
URL="http://127.0.0.1:${PORT}"

(
  sleep 1.5
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1
  elif command -v open >/dev/null 2>&1; then open "$URL" >/dev/null 2>&1
  fi
) &

echo ""
echo "DKCISSP Privacy Posture Assessment is starting at $URL"
echo "Leave this window open while you use it. Close it (Ctrl+C) when done."
echo ""
exec ./.venv/bin/dkcissp-privacy-assessment-web
