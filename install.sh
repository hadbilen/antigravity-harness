#!/bin/sh
#
# install.sh — Antigravity Harness Unix Installer
# POSIX-compliant installer for Linux, macOS, FreeBSD, and OpenBSD base systems.
# Installs clean AI workspace configuration into ~/.gemini/config/
# Installs standalone Antigravity Guard (agy-guard) binary into ~/.local/bin/
#

set -eu

# Resolve script directory in POSIX /bin/sh (without bashisms)
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
TARGET_DIR="${HOME}/.gemini/config"
BACKUP_DIR="${TARGET_DIR}/backup_$(date +%Y%m%d_%H%M%S)"

FROM_SOURCE=false
ENABLE_STARTUP=false

for arg in "$@"; do
  case "$arg" in
    --from-source|--dev) FROM_SOURCE=true ;;
    --enable-startup) ENABLE_STARTUP=true ;;
  esac
done

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

# 1. Clean Policy Plane: Core constitution, design contracts, mistakes
link_or_copy "${SCRIPT_DIR}/GEMINI.md" "${TARGET_DIR}/GEMINI.md"
link_or_copy "${SCRIPT_DIR}/DESIGN.md" "${TARGET_DIR}/DESIGN.md"
link_or_copy "${SCRIPT_DIR}/MISTAKES.md" "${TARGET_DIR}/MISTAKES.md"
[ -d "${SCRIPT_DIR}/.harness" ] && link_or_copy "${SCRIPT_DIR}/.harness" "${TARGET_DIR}/.harness"

# 2. Control Plane: Standalone binary or launcher installation
mkdir -p "${HOME}/.local/bin"
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH_NAME="x86_64" ;;
  arm64|aarch64) ARCH_NAME="arm64" ;;
  *) ARCH_NAME="$ARCH" ;;
esac

case "$OS" in
  Linux) BINARY_NAME="agy-guard-linux-${ARCH_NAME}" ;;
  Darwin) BINARY_NAME="agy-guard-macos-${ARCH_NAME}" ;;
  *) BINARY_NAME="" ;;
esac

INSTALLED_STANDALONE=false
if [ "$FROM_SOURCE" = "false" ] && [ -n "$BINARY_NAME" ]; then
  # 2.1 Try local dist/ build first
  if [ -f "${SCRIPT_DIR}/dist/${BINARY_NAME}" ]; then
    cp -f "${SCRIPT_DIR}/dist/${BINARY_NAME}" "${HOME}/.local/bin/agy-guard"
    chmod +x "${HOME}/.local/bin/agy-guard"
    echo "[STANDALONE] Installed local binary -> ${HOME}/.local/bin/agy-guard"
    INSTALLED_STANDALONE=true
  # 2.2 Download compiled standalone binary from GitHub Releases
  elif command -v curl >/dev/null 2>&1; then
    RELEASE_URL="https://github.com/hadbilen/antigravity-harness/releases/download/v1.2.6/${BINARY_NAME}"
    echo "[FETCH] Downloading standalone binary from GitHub Releases (${BINARY_NAME})..."
    if curl -fsSL "$RELEASE_URL" -o "${HOME}/.local/bin/agy-guard"; then
      chmod +x "${HOME}/.local/bin/agy-guard"
      echo "[STANDALONE] Downloaded and installed -> ${HOME}/.local/bin/agy-guard"
      INSTALLED_STANDALONE=true
    else
      echo "[NOTICE] Could not download standalone binary. Falling back to Python launcher."
    fi
  fi
fi

# Fallback: Python script launcher
if [ "$INSTALLED_STANDALONE" = "false" ] && [ -f "${SCRIPT_DIR}/bin/agy-guard" ]; then
  chmod +x "${SCRIPT_DIR}/bin/agy-guard"
  link_or_copy "${SCRIPT_DIR}/bin/agy-guard" "${HOME}/.local/bin/agy-guard"
fi

# Link porter CLI to ~/.local/bin/porter
if [ -f "${SCRIPT_DIR}/porter.py" ]; then
  link_or_copy "${SCRIPT_DIR}/porter.py" "${HOME}/.local/bin/porter"
  chmod +x "${HOME}/.local/bin/porter"
fi

# 3. Autonomous subagents directory
mkdir -p "${TARGET_DIR}/agents"
for agent in "${SCRIPT_DIR}/agents"/*.md; do
  [ -f "$agent" ] || continue
  link_or_copy "$agent" "${TARGET_DIR}/agents/$(basename "$agent")"
done

# 4. Modular skills directory
mkdir -p "${TARGET_DIR}/skills"
for skill in "${SCRIPT_DIR}/skills"/*; do
  [ -d "$skill" ] || continue
  link_or_copy "$skill" "${TARGET_DIR}/skills/$(basename "$skill")"
done

# 5. Initialize config.json if not present
if [ ! -f "${TARGET_DIR}/config.json" ]; then
  cp "${SCRIPT_DIR}/templates/config.example.json" "${TARGET_DIR}/config.json"
  echo "[CREATED] Initialized ~/.gemini/config/config.json from template."
fi

# 6. Ensure watcher scripts are executable on POSIX systems
if [ -f "${TARGET_DIR}/skills/upstream-auditor/scripts/upstream_watcher.py" ]; then
  chmod +x "${TARGET_DIR}/skills/upstream-auditor/scripts/upstream_watcher.py"
fi
if [ -f "${TARGET_DIR}/skills/upstream-auditor/scripts/check_skills.sh" ]; then
  chmod +x "${TARGET_DIR}/skills/upstream-auditor/scripts/check_skills.sh"
fi

# 7. Configure hooks.json to point to exact TARGET_DIR
cat > "${TARGET_DIR}/hooks.json" << EOF
{
  "upstream-watchdog": {
    "PreInvocation": [
      {
        "type": "command",
        "command": "python3 ${TARGET_DIR}/skills/upstream-auditor/scripts/upstream_watcher.py",
        "timeout": 15
      }
    ]
  }
}
EOF
echo "[CONFIGURED] hooks.json -> python3 ${TARGET_DIR}/skills/upstream-auditor/scripts/upstream_watcher.py"

# 8. Optional Pre-Session Boot Sentinel registration
if [ "$ENABLE_STARTUP" = "true" ] && [ -x "${HOME}/.local/bin/agy-guard" ]; then
  echo "\n[STARTUP] Enabling Pre-Session Boot Sentinel..."
  "${HOME}/.local/bin/agy-guard" startup enable || echo "[WARN] Startup registration skipped or failed."
fi

echo "========================================================"
echo "[SUCCESS] Antigravity Harness successfully installed!"
echo "Target directory : ${TARGET_DIR}"
[ -d "$BACKUP_DIR" ] && echo "Previous backup  : ${BACKUP_DIR}"
echo "========================================================"
