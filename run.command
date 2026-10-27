#!/usr/bin/env bash
# macOS double-clickable launcher. Just forwards to run.sh.
cd "$(dirname "${BASH_SOURCE[0]}")"
exec ./run.sh
