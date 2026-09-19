#!/usr/bin/env bash
#
# check_skills.sh — Upstream Auditor 72h Lightweight CLI Tracker
# Checks GitHub HEAD commits for 7 tracked community skills without LLM overhead.
#

set -e

CONFIG_DIR="${HOME}/.gemini/config"
STATE_FILE="${CONFIG_DIR}/skills/upstream-auditor/upstream_state.json"

if [ ! -f "$STATE_FILE" ]; then
  echo "[ERROR] State file not found: $STATE_FILE" >&2
  exit 1
fi

python3 - <<'EOF'
import json
import os
import sys
import urllib.request
from datetime import datetime

state_file = os.path.expanduser("~/.gemini/config/skills/upstream-auditor/upstream_state.json")

try:
    with open(state_file, "r", encoding="utf-8") as f:
        state = json.load(f)
except Exception as e:
    print(f"[ERROR] Failed to read JSON: {e}", file=sys.stderr)
    sys.exit(1)

tracked = state.get("tracked_repositories", {})
if not tracked:
    print("[INFO] No external tracked repositories defined.")
    sys.exit(0)

print("=" * 80)
print(f"{'REPOSITORY':<22} | {'SAVED SHA':<11} | {'REMOTE SHA':<11} | {'STATUS':<15}")
print("=" * 80)

updates_found = []

for name, info in tracked.items():
    repo = info.get("repo")
    branch = info.get("branch", "main")
    recorded_sha = info.get("last_synced_commit", "")[:7]
    
    url = f"https://api.github.com/repos/{repo}/commits?sha={branch}&per_page=1"
    req = urllib.request.Request(url, headers={"User-Agent": "UpstreamAuditor-Watchdog/1.0"})
    
    current_sha = "UNKNOWN"
    status = "ERROR"
    
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
            if data and isinstance(data, list):
                current_sha = data[0]["sha"][:7]
                if recorded_sha == current_sha:
                    status = "UP TO DATE"
                else:
                    status = "UPDATE FOUND"
                    updates_found.append((name, recorded_sha, current_sha))
    except Exception as e:
        status = "NETWORK ERROR"

    print(f"{name:<22} | {recorded_sha:<11} | {current_sha:<11} | {status:<15}")

print("=" * 80)

if updates_found:
    print(f"\n[ALERT] {len(updates_found)} repositories have new remote commits:")
    for name, old_s, new_s in updates_found:
        print(f"  - {name}: {old_s} -> {new_s}")
    print("\nTo inspect diffs and apply constitutional filter:")
    print("  /audit-upstream --skills")
else:
    print("\n[OK] All external skill repositories are synchronized with local state.")

EOF
