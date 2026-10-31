#!/usr/bin/env bash
# DKCISSP Privacy Posture Assessment — single-command installer (Linux / macOS)
#
#   curl -fsSL https://raw.githubusercontent.com/deepakkumarcissp/Public-Website-Privacy-Posture-Assessment/main/install.sh | bash
#
# Installs any missing prerequisites (Python, venv, git, Chromium), downloads the
# project, sets up a private virtual environment, installs dependencies, starts the local web UI, and opens it in your browser.
# Only assess domains you own or are authorized to test.
set -euo pipefail

REPO_URL="https://github.com/deepakkumarcissp/Public-Website-Privacy-Posture-Assessment"
INSTALL_DIR="${DKCISSP_INSTALL_DIR:-$HOME/dkcissp-privacy-posture-assessment}"

echo "DKCISSP Privacy Posture Assessment — installer"
echo "Installing to: $INSTALL_DIR"
echo ""

# ── Prerequisites ────────────────────────────────────────────────────────────
# Anything missing (Python 3.9+, venv support, git, Chromium for the dynamic
# scan) is installed with the system package manager. Package installs need
# admin rights, so you may be asked for your sudo password once.
SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi

PM=""
for m in apt-get dnf pacman zypper brew; do
  if command -v "$m" >/dev/null 2>&1; then PM="$m"; break; fi
done

pm_install() {  # pm_install <pkg>...   (returns non-zero on failure)
  case "$PM" in
    apt-get) $SUDO apt-get update -qq && $SUDO apt-get install -y "$@" ;;
    dnf)     $SUDO dnf install -y "$@" ;;
    pacman)  $SUDO pacman -S --noconfirm --needed "$@" ;;
    zypper)  $SUDO zypper --non-interactive install "$@" ;;
    brew)    brew install "$@" ;;
    *)       return 1 ;;
  esac
}

py_ok() {  # Python >= 3.9 with working venv + pip
  command -v python3 >/dev/null 2>&1 &&
  python3 -c 'import sys, venv, ensurepip; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1
}

have_chrome() {
  for b in chromium chromium-browser google-chrome google-chrome-stable chrome microsoft-edge; do
    command -v "$b" >/dev/null 2>&1 && return 0
  done
  [ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ] && return 0
  [ -x "/Applications/Chromium.app/Contents/MacOS/Chromium" ] && return 0
  [ -x "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" ] && return 0
  return 1
}

if ! py_ok; then
  echo "Python 3.9+ (with venv) not found — installing it..."
  case "$PM" in
    apt-get) pm_install python3 python3-venv python3-pip ;;
    dnf|zypper) pm_install python3 python3-pip ;;
    pacman)  pm_install python python-pip ;;
    brew)    pm_install python ;;
    *)       false ;;
  esac || true
  if ! py_ok; then
    echo "Error: could not install Python 3.9+ automatically." >&2
    echo "Install Python 3.9+ (including the 'venv' module) from https://www.python.org/downloads/ and re-run." >&2
    exit 1
  fi
fi

if ! command -v git >/dev/null 2>&1 && { ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; }; then
  echo "git not found — installing it..."
  pm_install git curl unzip || true
fi

if ! have_chrome; then
  echo "Chrome/Chromium not found — installing Chromium (needed for the full dynamic scan)..."
  case "$PM" in
    apt-get) pm_install chromium || pm_install chromium-browser ;;
    dnf|zypper|pacman) pm_install chromium ;;
    brew)    brew install --cask google-chrome ;;
    *)       false ;;
  esac || true
  if ! have_chrome; then
    echo "Note: could not install a browser automatically. The app will still run using the"
    echo "static scan only (no Reject-All / pre-consent network testing). Install Chrome or"
    echo "Chromium any time and the dynamic scan is picked up automatically."
  fi
fi

if [ -d "$INSTALL_DIR/.git" ]; then
  echo "Existing install found — updating..."
  git -C "$INSTALL_DIR" pull --ff-only
elif command -v git >/dev/null 2>&1; then
  echo "Downloading (git clone)..."
  git clone --depth 1 "$REPO_URL.git" "$INSTALL_DIR"
else
  echo "git not found — downloading a zip archive instead..."
  if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
    echo "Error: need either 'git', or both 'curl' and 'unzip', to install." >&2
    exit 1
  fi
  TMP_DIR=$(mktemp -d)
  curl -fsSL "$REPO_URL/archive/refs/heads/main.zip" -o "$TMP_DIR/repo.zip"
  unzip -q "$TMP_DIR/repo.zip" -d "$TMP_DIR"
  rm -rf "$INSTALL_DIR"
  mv "$TMP_DIR"/Public-Website-Privacy-Posture-Assessment-main "$INSTALL_DIR"
  rm -rf "$TMP_DIR"
fi

cd "$INSTALL_DIR"
chmod +x run.sh run.command 2>/dev/null || true

echo ""
echo "Starting the app..."
echo ""
exec ./run.sh
