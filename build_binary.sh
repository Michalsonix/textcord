#!/usr/bin/env bash
# Build a single-file binary installer from installer.py.
# Works on PEP 668 distros (Debian 12+/Ubuntu 24+) by using an isolated venv.
#
#   ./build_binary.sh
#
# Output:  ./dist/textcord-installer
set -e
cd "$(dirname "$0")"

VENV="${VENV:-/tmp/textcord-build-venv}"
if [ ! -x "$VENV/bin/python" ]; then
    echo "  → Creating build venv at $VENV"
    python3 -m venv "$VENV" || {
        echo "  ! python3-venv missing. Install it (e.g.: sudo apt install python3-venv python3-full) and retry." >&2
        exit 1
    }
fi

"$VENV/bin/pip" install --quiet --upgrade pip pyinstaller
"$VENV/bin/pyinstaller" --onefile --name textcord-installer \
    --add-data "app.py:." \
    --add-data "models.py:." \
    --add-data "requirements.txt:." \
    --add-data "templates:templates" \
    --add-data "static:static" \
    installer.py

echo
echo "✔ Built: $(pwd)/dist/textcord-installer"
echo "  Run as root on the target machine: sudo ./dist/textcord-installer"