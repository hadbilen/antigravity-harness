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
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

CONFIG_DIR = os.path.expanduser(os.environ.get("ANTIGRAVITY_CONFIG_DIR", "~/.gemini/config"))
SKILL_DIR = os.path.join(CONFIG_DIR, "skills", "upstream-auditor")
CUSTOM_SKILLS_DIR = os.path.join(CONFIG_DIR, "skills")
SEED_STATE_FILE = os.path.join(SKILL_DIR, "upstream_state.seed.json")      # shipped, read-only
LEGACY_STATE_FILE = os.path.join(SKILL_DIR, "upstream_state.json")         # pre-1.4 location, read-only

DEFAULT_STATE_DIR = os.path.expanduser(
    os.environ.get("AGY_GUARD_STATE_DIR")
    or os.path.join(os.environ.get("XDG_STATE_HOME", "~/.local/state"), "antigravity-harness")
)
STATE_FILE = os.environ.get("UPSTREAM_STATE_FILE", os.path.join(DEFAULT_STATE_DIR, "upstream_state.json"))
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
            # Content hash (not mtime/size), so touching or re-checking-out files is not "drift".
            try:
                with open(full_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        hasher.update(chunk)
            except OSError:
                hasher.update(b"<unreadable>")
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

def is_pro_flash_switch(old_m: str, new_m: str) -> bool:
    """True only for a Pro <-> Flash toggle within the SAME model family and version."""
    if not old_m or not new_m:
        return False
    def split(m: str):
        tier = "pro" if "pro" in m else ("flash" if "flash" in m else "")
        family = re.sub(r"\b(pro|flash|high|low|medium|thinking)\b|[()]", " ", m)
        return tier, " ".join(family.split())
    old_tier, old_family = split(old_m)
    new_tier, new_family = split(new_m)
    return bool(old_tier and new_tier) and old_family == new_family


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
    failed_checks = 0

    def fetch_repo_status(name: str, info: dict):
        nonlocal successful_checks, failed_checks
        repo = str(info.get("repo", ""))
        branch = str(info.get("branch", "main"))
        recorded_sha = str(info.get("last_synced_commit", "")).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            failed_checks += 1
            return None
        query = urllib.parse.urlencode({"sha": branch, "per_page": 1})
        url = f"https://api.github.com/repos/{repo}/commits?{query}"
        req = urllib.request.Request(url, headers={"User-Agent": "UpstreamAuditor-Watchdog/1.2"})
        try:
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode())
                if data and isinstance(data, list):
                    successful_checks += 1
                    current_sha = data[0]["sha"].strip()
                    is_match = False
                    if recorded_sha and current_sha:
                        if (
                            recorded_sha == current_sha
                            or current_sha.startswith(recorded_sha)
                            or recorded_sha.startswith(current_sha)
                        ):
                            is_match = True
                    if recorded_sha and current_sha and not is_match:
                        return f"{name} ({recorded_sha[:7]}->{current_sha[:7]})"
        except Exception:
            failed_checks += 1
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
    # Any failed repository triggers the short retry interval (partial failures are failures).
    state["last_audit_failed"] = failed_checks > 0 or successful_checks < len(tracked)
    # Runtime state is only ever written to the per-user state directory (never the skill tree).
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except Exception:
        pass

    return sorted(changed_repos)

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

    # Seed the per-user state file from the legacy file or the shipped seed if absent
    seed_source = LEGACY_STATE_FILE if os.path.isfile(LEGACY_STATE_FILE) else SEED_STATE_FILE
    if not os.path.isfile(STATE_FILE) and os.path.isfile(seed_source):
        try:
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            with open(seed_source, "r", encoding="utf-8") as f:
                seed_data = json.load(f)
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(seed_data, f, indent=2, ensure_ascii=False)
                f.write("\n")
        except Exception:
            pass

    state_path = STATE_FILE if os.path.isfile(STATE_FILE) else seed_source
    if not os.path.isfile(state_path):
        safe_exit_empty()

    try:
        with open(state_path, "r", encoding="utf-8") as f:
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
