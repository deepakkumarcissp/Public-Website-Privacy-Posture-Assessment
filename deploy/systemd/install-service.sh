#!/usr/bin/env bash
# Install DKCISSP Privacy Posture Assessment as a systemd --user service so
# it starts automatically on login/boot and restarts itself if it crashes.
#
# Run this from inside your installed copy of the repo (where run.sh lives):
#   ./deploy/systemd/install-service.sh
#
# It only touches your own user systemd config (~/.config/systemd/user) —
# no root/sudo needed for the service itself. The service binds to
# 127.0.0.1 only, exactly like running it by hand.
#
# To start the service on BOOT even before you log in (not just on login),
# this also enables "lingering" for your user via `loginctl enable-linger`,
# which may prompt for sudo on some systems.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
INSTALL_DIR="$(pwd)"
UNIT_NAME="dkcissp-privacy-assessment.service"
USER_UNIT_DIR="$HOME/.config/systemd/user"

if [ ! -d ".venv" ]; then
  echo "No .venv found here — run ./run.sh once first to set it up, then re-run this script."
  exit 1
fi

mkdir -p "$USER_UNIT_DIR"
sed "s|__INSTALL_DIR__|$INSTALL_DIR|g" \
  "deploy/systemd/${UNIT_NAME}.template" > "$USER_UNIT_DIR/$UNIT_NAME"

systemctl --user daemon-reload
systemctl --user enable --now "$UNIT_NAME"

if command -v loginctl >/dev/null 2>&1; then
  if ! loginctl show-user "$(whoami)" -p Linger 2>/dev/null | grep -q "Linger=yes"; then
    echo "Enabling lingering so the service also starts before you log in (may ask for sudo)..."
    loginctl enable-linger "$(whoami)" 2>/dev/null || sudo loginctl enable-linger "$(whoami)" || \
      echo "Could not enable lingering automatically — the service will still start at login; run 'sudo loginctl enable-linger $(whoami)' yourself for true boot-time start."
  fi
fi

echo ""
echo "Installed and started. It will now:"
echo "  - start automatically at login (and at boot, once lingering is enabled)"
echo "  - restart itself automatically if it crashes"
echo "  - run at http://127.0.0.1:1009"
echo ""
echo "Manage it with:"
echo "  systemctl --user status $UNIT_NAME"
echo "  systemctl --user stop $UNIT_NAME"
echo "  systemctl --user disable --now $UNIT_NAME   # to remove it"
echo "  journalctl --user -u $UNIT_NAME -f           # to follow logs"
