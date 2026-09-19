#!/bin/sh
#
# install.sh — Antigravity Harness Unix Installer
# POSIX-compliant installer for Linux, macOS, FreeBSD, and OpenBSD base systems.
# Symlinks or installs the harness, constitution, subagents, and skills into ~/.gemini/config/
#

set -eu

# Resolve script directory in POSIX /bin/sh (without bashisms)
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
TARGET_DIR="${HOME}/.gemini/config"
BACKUP_DIR="${TARGET_DIR}/backup_$(date +%Y%m%d_%H%M%S)"

echo "========================================================"
echo "          Antigravity Harness Setup & Installer         "
echo "========================================================"

mkdir -p "$TARGET_DIR"

backup_if_needed() {
  target="$1"
  if [ -e "$target" ] && [ ! -L "$target" ]; then
    mkdir -p "$BACKUP_DIR"
    echo "[BACKUP] Moving existing $(basename "$target") -> $BACKUP_DIR/"
    mv "$target" "$BACKUP_DIR/"
  fi
}

link_or_copy() {
  src="$1"
  dest="$2"

  backup_if_needed "$dest"
  rm -f "$dest"
  ln -sf "$src" "$dest"
  echo "[LINKED] $(basename "$dest") -> $src"
}

# Core constitution, design contracts, and porter CLI
link_or_copy "${SCRIPT_DIR}/GEMINI.md" "${TARGET_DIR}/GEMINI.md"
link_or_copy "${SCRIPT_DIR}/DESIGN.md" "${TARGET_DIR}/DESIGN.md"
link_or_copy "${SCRIPT_DIR}/MISTAKES.md" "${TARGET_DIR}/MISTAKES.md"
link_or_copy "${SCRIPT_DIR}/hooks.json" "${TARGET_DIR}/hooks.json"
link_or_copy "${SCRIPT_DIR}/porter.py" "${TARGET_DIR}/porter.py"
[ -d "${SCRIPT_DIR}/porter" ] && link_or_copy "${SCRIPT_DIR}/porter" "${TARGET_DIR}/porter"
[ -d "${SCRIPT_DIR}/.harness" ] && link_or_copy "${SCRIPT_DIR}/.harness" "${TARGET_DIR}/.harness"

# Autonomous subagents directory
mkdir -p "${TARGET_DIR}/agents"
for agent in "${SCRIPT_DIR}/agents"/*.md; do
  [ -f "$agent" ] || continue
  link_or_copy "$agent" "${TARGET_DIR}/agents/$(basename "$agent")"
done

# Modular skills directory
mkdir -p "${TARGET_DIR}/skills"
for skill in "${SCRIPT_DIR}/skills"/*; do
  [ -d "$skill" ] || continue
  link_or_copy "$skill" "${TARGET_DIR}/skills/$(basename "$skill")"
done

# Initialize config.json if not present
if [ ! -f "${TARGET_DIR}/config.json" ]; then
  cp "${SCRIPT_DIR}/templates/config.example.json" "${TARGET_DIR}/config.json"
  echo "[CREATED] Initialized ~/.gemini/config/config.json from template."
fi

# Ensure watcher scripts are executable on POSIX systems
if [ -f "${TARGET_DIR}/skills/upstream-auditor/scripts/upstream_watcher.py" ]; then
  chmod +x "${TARGET_DIR}/skills/upstream-auditor/scripts/upstream_watcher.py"
fi
if [ -f "${TARGET_DIR}/skills/upstream-auditor/scripts/check_skills.sh" ]; then
  chmod +x "${TARGET_DIR}/skills/upstream-auditor/scripts/check_skills.sh"
fi

echo "========================================================"
echo "[SUCCESS] Antigravity Harness successfully installed!"
echo "Target directory: $TARGET_DIR"
if [ -d "$BACKUP_DIR" ]; then
  echo "Previous files backed up at: $BACKUP_DIR"
fi
echo "========================================================"
