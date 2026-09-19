#!/usr/bin/env python3
"""
Upstream Watchdog — PreInvocation Lifecycle Hook & 72h External Skills Monitor
Monitors changes to the active LLM model, Antigravity builtin environment,
and performs a 72-hour (3-day) periodic check of 7 tracked community skill repositories.
Fires only on invocationNum == 1 to guarantee zero overhead on subsequent turns.
"""

import sys
import os
import json
import hashlib
import re
import urllib.request
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

CONFIG_DIR = os.path.expanduser(os.environ.get("ANTIGRAVITY_CONFIG_DIR", "~/.gemini/config"))
SKILL_DIR = os.path.join(CONFIG_DIR, "skills", "upstream-auditor")
CUSTOM_SKILLS_DIR = os.path.join(CONFIG_DIR, "skills")
STATE_FILE = os.path.join(SKILL_DIR, "upstream_state.json")
BUILTIN_DIR = os.path.expanduser("~/.gemini/antigravity/builtin/skills")
PBTXT_FILE = os.path.expanduser("~/.gemini/antigravity/antigravity_state.pbtxt")

def safe_exit_empty():
    sys.stdout.write("{}\n")
    sys.stdout.flush()
    sys.exit(0)

def normalize_model_name(name: str) -> str:
    if not name:
        return ""
    return re.sub(r'[\s\-_\(\)]+', '', name).lower()

def check_skill_namespace_collisions():
    """Detects any naming conflicts between builtin Google skills and local custom skills."""
    if not os.path.isdir(BUILTIN_DIR) or not os.path.isdir(CUSTOM_SKILLS_DIR):
        return []
    try:
        builtin_names = {d for d in os.listdir(BUILTIN_DIR) if os.path.isdir(os.path.join(BUILTIN_DIR, d))}
        custom_names = {
            d for d in os.listdir(CUSTOM_SKILLS_DIR)
            if os.path.isdir(os.path.join(CUSTOM_SKILLS_DIR, d)) or os.path.islink(os.path.join(CUSTOM_SKILLS_DIR, d))
        }
        return sorted(builtin_names.intersection(custom_names))
    except Exception:
        return []

def get_builtin_skills_list():
    """Returns sorted list of current builtin skill directory names."""
    if not os.path.isdir(BUILTIN_DIR):
        return []
    try:
        return sorted([d for d in os.listdir(BUILTIN_DIR) if os.path.isdir(os.path.join(BUILTIN_DIR, d))])
    except Exception:
        return []

def compute_builtin_hash():
    if not os.path.isdir(BUILTIN_DIR):
        return ""
    hasher = hashlib.sha256()
    for root, dirs, files in os.walk(BUILTIN_DIR):
        dirs.sort()
        for f in sorted(files):
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, BUILTIN_DIR)
            hasher.update(rel_path.encode("utf-8"))
            try:
                stat = os.stat(full_path)
                hasher.update(str(stat.st_mtime_ns).encode("utf-8"))
                hasher.update(str(stat.st_size).encode("utf-8"))
            except OSError:
                pass
    return hasher.hexdigest()

def get_pbtxt_model():
    if not os.path.isfile(PBTXT_FILE):
        return ""
    try:
        with open(PBTXT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if "last_selected_agent_model" in line:
                    return line.split(":", 1)[1].strip().strip('"')
    except Exception:
        pass
    return ""

def check_tracked_skills(state: dict):
    """Checks tracked repositories every 72 hours (3 days) with zero LLM cost using parallel HTTP requests."""
    last_audit_str = state.get("last_skills_audit_timestamp")
    last_failed = state.get("last_audit_failed", False)
    interval_hours = state.get("skills_audit_retry_hours", 2) if last_failed else state.get("skills_audit_interval_hours", 72)

    now = datetime.now(timezone.utc)
    if last_audit_str:
        try:
            last_dt = datetime.fromisoformat(last_audit_str)
            if (now - last_dt).total_seconds() < interval_hours * 3600:
                return []
        except Exception:
            pass

    tracked = state.get("tracked_repositories", {})
    if not tracked:
        return []

    successful_checks = 0

    def fetch_repo_status(name: str, info: dict):
        nonlocal successful_checks
        repo = info.get("repo")
        branch = info.get("branch", "main")
        recorded_sha = info.get("last_synced_commit", "")[:7]
        url = f"https://api.github.com/repos/{repo}/commits?sha={branch}&per_page=1"
        req = urllib.request.Request(url, headers={"User-Agent": "UpstreamAuditor-Watchdog/1.1"})
        try:
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode())
                if data and isinstance(data, list):
                    successful_checks += 1
                    current_sha = data[0]["sha"][:7]
                    if recorded_sha and current_sha and recorded_sha != current_sha:
                        return f"{name} ({recorded_sha}->{current_sha})"
        except Exception:
            return None
        return None

    changed_repos = []
    try:
        with ThreadPoolExecutor(max_workers=min(len(tracked), 8)) as executor:
            futures = [executor.submit(fetch_repo_status, name, info) for name, info in tracked.items()]
            for future in as_completed(futures, timeout=4.0):
                try:
                    res = future.result()
                    if res:
                        changed_repos.append(res)
                except Exception:
                    continue
    except Exception:
        pass

    # Record timestamp and mark whether network checks succeeded or failed
    state["last_skills_audit_timestamp"] = now.isoformat()
    state["last_audit_failed"] = (successful_checks == 0)
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except Exception:
        pass

    return changed_repos

def main():
    try:
        raw_input = sys.stdin.read().strip()
        payload = json.loads(raw_input) if raw_input else {}
    except Exception:
        payload = {}

    # Only inspect on the first invocation of a turn
    invocation_num = payload.get("invocationNum", 1)
    if invocation_num > 1:
        safe_exit_empty()

    if not os.path.isfile(STATE_FILE):
        safe_exit_empty()

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
    except Exception:
        safe_exit_empty()

    current_builtin_hash = compute_builtin_hash()
    current_pbtxt_model = get_pbtxt_model()
    payload_model = payload.get("modelName", "").strip()

    recorded_hash = state.get("builtin_skills_hash", "")
    recorded_model = state.get("last_audited_model", "")
    recorded_pbtxt = state.get("last_pbtxt_model", "")

    changed_reasons = []

    # 0. Check skill namespace collisions / shadowing
    collisions = check_skill_namespace_collisions()
    if collisions:
        changed_reasons.append(f"Namespace collision / shadowing detected: {', '.join(collisions)}")

    # 1. Check builtin skills delta
    if recorded_hash and current_builtin_hash and current_builtin_hash != recorded_hash:
        current_builtins = get_builtin_skills_list()
        recorded_builtins = state.get("recorded_builtin_skills", [])
        if recorded_builtins:
            added = sorted(set(current_builtins) - set(recorded_builtins))
            removed = sorted(set(recorded_builtins) - set(current_builtins))
            details = []
            if added: details.append(f"added: {', '.join(added)}")
            if removed: details.append(f"removed: {', '.join(removed)}")
            if details:
                changed_reasons.append(f"Delta in builtin skills ({'; '.join(details)})")
            else:
                changed_reasons.append("Delta detected in Antigravity builtin environment (builtin/skills)")
        else:
            changed_reasons.append("Delta detected in Antigravity builtin environment (builtin/skills)")

    # 2. Check model delta (via payload or pbtxt)
    norm_payload = normalize_model_name(payload_model)
    norm_recorded = normalize_model_name(recorded_model)
    norm_current_pbtxt = normalize_model_name(current_pbtxt_model)
    norm_recorded_pbtxt = normalize_model_name(recorded_pbtxt)

    def is_pro_flash_switch(old_m: str, new_m: str) -> bool:
        if not old_m or not new_m: return False
        old_pf = "pro" in old_m or "flash" in old_m
        new_pf = "pro" in new_m or "flash" in new_m
        return old_pf and new_pf

    if norm_payload and norm_payload != "auto" and norm_recorded:
        if norm_payload != norm_recorded and not is_pro_flash_switch(norm_recorded, norm_payload):
            changed_reasons.append(f"Model change: '{recorded_model}' -> '{payload_model}'")
    elif norm_current_pbtxt and norm_recorded_pbtxt and norm_current_pbtxt != norm_recorded_pbtxt:
        if not is_pro_flash_switch(norm_recorded_pbtxt, norm_current_pbtxt):
            changed_reasons.append(f"Model configuration change: '{recorded_pbtxt}' -> '{current_pbtxt_model}'")

    # 3. Check 72-hour periodic external skills delta
    skills_delta = check_tracked_skills(state)
    if skills_delta:
        changed_reasons.append(f"72h periodic watchdog: New commits in tracked repositories ({', '.join(skills_delta)})")

    if changed_reasons:
        reasons_str = "; ".join(changed_reasons)
        suggested_cmd = "/audit-upstream --skills" if (skills_delta and len(changed_reasons) == 1) else "/audit-upstream"
        message = (
            f"[UPSTREAM WATCHDOG] Upstream changes detected ({reasons_str}). "
            f"To verify compatibility with existing rules and custom skills, "
            f"recommend running `{suggested_cmd}`."
        )
        output = {
            "injectSteps": [
                {
                    "ephemeralMessage": message
                }
            ]
        }
        sys.stdout.write(json.dumps(output, ensure_ascii=False) + "\n")
        sys.stdout.flush()
        return

    safe_exit_empty()

if __name__ == "__main__":
    try:
        main()
    except Exception:
        safe_exit_empty()
