#!/usr/bin/env bash
# Remove the DKCISSP Privacy Posture Assessment systemd --user service
# installed by install-service.sh.
set -euo pipefail
UNIT_NAME="dkcissp-privacy-assessment.service"
USER_UNIT_DIR="$HOME/.config/systemd/user"

systemctl --user disable --now "$UNIT_NAME" 2>/dev/null || true
rm -f "$USER_UNIT_DIR/$UNIT_NAME"
systemctl --user daemon-reload
echo "Removed. (Lingering, if it was enabled, is left as-is — disable it yourself with "
echo "'loginctl disable-linger $(whoami)' if nothing else needs it.)"
