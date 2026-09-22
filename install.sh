#!/bin/sh
#
# install.sh — POSIX entry point for the Antigravity Harness installer.
# All installation logic lives in install.py (single implementation for every platform);
# this wrapper only locates a Python 3.10+ interpreter and forwards all arguments.
#
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
      exec "$candidate" "$SCRIPT_DIR/install.py" "$@"
    fi
  fi
done

printf '%s\n' "Error: Python 3.10 or newer is required (python3 was not found)." >&2
exit 1
