#!/usr/bin/env bash
#
# install.sh — Antigravity Harness Installer
# Symlinks or installs the harness, constitution, subagents, and skills into ~/.gemini/config/
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${HOME}/.gemini/config"
BACKUP_DIR="${TARGET_DIR}/backup_$(date +%Y%m%d_%H%M%S)"

echo "========================================================"
echo "          Antigravity Harness Setup & Installer         "
echo "========================================================"

mkdir -p "$TARGET_DIR"

backup_if_needed() {
  local target="$1"
  if [ -e "$target" ] && [ ! -L "$target" ]; then
    mkdir -p "$BACKUP_DIR"
    echo "[BACKUP] Moving existing $(basename "$target") -> $BACKUP_DIR/"
    mv "$target" "$BACKUP_DIR/"
  fi
}

link_or_copy() {
  local src="$1"
  local dest="$2"

  backup_if_needed "$dest"
  rm -f "$dest"
  ln -sf "$src" "$dest"
  echo "[LINKED] $(basename "$dest") -> $src"
}

# Core constitution and design contracts
link_or_copy "${SCRIPT_DIR}/GEMINI.md" "${TARGET_DIR}/GEMINI.md"
link_or_copy "${SCRIPT_DIR}/DESIGN.md" "${TARGET_DIR}/DESIGN.md"
link_or_copy "${SCRIPT_DIR}/hooks.json" "${TARGET_DIR}/hooks.json"

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

# Ensure watcher scripts are executable
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
