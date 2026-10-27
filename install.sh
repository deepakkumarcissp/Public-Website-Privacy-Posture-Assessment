#!/usr/bin/env bash
# DKCISSP Privacy Posture Assessment — single-command installer (Linux / macOS)
#
#   curl -fsSL https://raw.githubusercontent.com/deepakkumarcissp/Public-Website-Privacy-Posture-Assessment/main/install.sh | bash
#
# Downloads the project, sets up a private virtual environment, installs
# dependencies, starts the local web UI, and opens it in your browser.
# Only assess domains you own or are authorized to test.
set -euo pipefail

REPO_URL="https://github.com/deepakkumarcissp/Public-Website-Privacy-Posture-Assessment"
INSTALL_DIR="${DKCISSP_INSTALL_DIR:-$HOME/dkcissp-privacy-posture-assessment}"

echo "DKCISSP Privacy Posture Assessment — installer"
echo "Installing to: $INSTALL_DIR"
echo ""

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
