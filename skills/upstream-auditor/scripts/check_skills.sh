#!/usr/bin/env bash
#
# check_skills.sh — Upstream Auditor 72h Lightweight CLI Tracker
# Checks GitHub HEAD commits and release tags for 8 tracked community skills without LLM overhead.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="${ANTIGRAVITY_CONFIG_DIR:-${HOME}/.gemini/config}"
STATE_DIR="${AGY_GUARD_STATE_DIR:-${XDG_STATE_HOME:-${HOME}/.local/state}/antigravity-harness}"
STATE_FILE="${UPSTREAM_STATE_FILE:-${STATE_DIR}/upstream_state.json}"
SEED_FILE="${CONFIG_DIR}/skills/upstream-auditor/upstream_state.seed.json"
BUNDLED_SEED="$(cd "${SCRIPT_DIR}/.." && pwd)/upstream_state.seed.json"
SYSTEM_SHARE_SEED="${ANTIGRAVITY_SHARE_DIR:-/usr/share/antigravity-harness}/skills/upstream-auditor/upstream_state.seed.json"

GITHUB_API_BASE="${GITHUB_API_BASE:-https://api.github.com}"
GITHUB_API_BASE="${GITHUB_API_BASE%/}"
if [[ ! "$GITHUB_API_BASE" =~ ^https://api\.github\.com(:443)?$ ]]; then
  echo "[ERROR] Invalid GITHUB_API_BASE (must be https://api.github.com): $GITHUB_API_BASE" >&2
  exit 1
fi

RESOLVED_SEED=""
if [ -f "$SEED_FILE" ]; then
  RESOLVED_SEED="$SEED_FILE"
elif [ -f "$BUNDLED_SEED" ]; then
  RESOLVED_SEED="$BUNDLED_SEED"
elif { [ -n "${ANTIGRAVITY_SHARE_DIR:-}" ] || [ -z "${ANTIGRAVITY_CONFIG_DIR:-}" ]; } && [ -f "$SYSTEM_SHARE_SEED" ]; then
  RESOLVED_SEED="$SYSTEM_SHARE_SEED"
fi

if [ -n "${UPSTREAM_STATE_FILE:-}" ]; then
  if [ ! -f "$UPSTREAM_STATE_FILE" ]; then
    echo "[ERROR] Explicit UPSTREAM_STATE_FILE does not exist: $UPSTREAM_STATE_FILE" >&2
    exit 1
  fi
else
  if [ ! -f "$STATE_FILE" ] && [ -n "$RESOLVED_SEED" ]; then
    STATE_FILE="$RESOLVED_SEED"
  fi
  if [ ! -f "$STATE_FILE" ]; then
    echo "[ERROR] No upstream state found (looked in the state directory, $SEED_FILE, $BUNDLED_SEED, and $SYSTEM_SHARE_SEED)" >&2
    exit 1
  fi
fi

AGY_UPSTREAM_STATE="$STATE_FILE" AGY_UPSTREAM_SEED="$RESOLVED_SEED" AGY_SCRIPT_DIR="$SCRIPT_DIR" GITHUB_API_BASE="$GITHUB_API_BASE" python3 -B - <<'EOF'
import concurrent.futures
import copy
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
from datetime import datetime, timezone

script_dir = os.environ.get("AGY_SCRIPT_DIR", "")
repo_candidate = os.path.abspath(os.path.join(script_dir, "..", "..", "..")) if script_dir else ""
default_data = os.path.join(os.path.expanduser(os.environ.get("XDG_DATA_HOME", "~/.local/share")), "antigravity-harness")
data_root = os.path.expanduser(os.environ.get("AGY_GUARD_DATA_DIR") or default_data)
for cand in (repo_candidate, os.path.join(data_root, "runtime"), "/usr/lib/antigravity-guard"):
    if cand and os.path.isfile(os.path.join(cand, "porter", "net.py")) and cand not in sys.path:
        sys.path.insert(0, cand)

from porter.net import safe_fetch_url

state_file = os.environ["AGY_UPSTREAM_STATE"]
seed_file = os.environ.get("AGY_UPSTREAM_SEED", "").strip()
api_base = os.environ.get("GITHUB_API_BASE", "https://api.github.com").rstrip("/")
parsed_base = urllib.parse.urlparse(api_base)
if not (
    parsed_base.scheme == "https"
    and (parsed_base.hostname or "").lower() == "api.github.com"
    and parsed_base.port in (None, 443)
    and parsed_base.path in ("", "/")
    and not parsed_base.username
    and not parsed_base.password
    and not parsed_base.params
    and not parsed_base.query
    and not parsed_base.fragment
):
    print(f"[ERROR] Invalid GITHUB_API_BASE: {api_base}", file=sys.stderr)
    sys.exit(1)

HEX_RE = re.compile(r"[0-9a-fA-F]{7,40}")
SUBPATH_RE = re.compile(r"[A-Za-z0-9_./-]+")
TAG_RE = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")
MAX_API_BYTES = 262_144


def short_ref(val: str) -> str:
    val = str(val or "").strip()
    return val[:7] if HEX_RE.fullmatch(val) else val


def sha_matches(recorded: str, current: str) -> bool:
    if not (recorded and current):
        return False
    if recorded == current:
        return True
    if HEX_RE.fullmatch(recorded) and HEX_RE.fullmatch(current):
        return current.startswith(recorded) or recorded.startswith(current)
    return False


def parse_ts(val):
    if not isinstance(val, str) or not val.strip():
        return None
    try:
        dt = datetime.fromisoformat(val.strip().replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def seed_digest(seed: dict) -> str:
    canonical = {
        "last_audited_model": seed.get("last_audited_model"),
        "last_model_slug": seed.get("last_model_slug"),
        "last_pbtxt_model": seed.get("last_pbtxt_model"),
        "environment_Target": seed.get("environment_Target"),
        "builtin_skills_hash": seed.get("builtin_skills_hash"),
        "recorded_builtin_skills": seed.get("recorded_builtin_skills"),
        "tracked_repositories": seed.get("tracked_repositories"),
    }
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def reconcile_in_memory(state: dict, seed: dict) -> None:
    if not isinstance(state, dict) or not isinstance(seed, dict):
        return
    had_explicit_repos = "tracked_repositories" in state
    is_full_ledger = any(
        k in state
        for k in (
            "last_audit_timestamp",
            "last_skills_audit_timestamp",
            "last_audited_model",
            "last_seen_model",
            "last_ack_timestamp",
            "builtin_skills_hash",
            "_reconciled_seed_digest",
        )
    )
    s_digest = seed_digest(seed)
    prev_digest = state.get("_reconciled_seed_digest")
    has_prev = isinstance(prev_digest, str) and bool(prev_digest)
    seed_changed = (prev_digest != s_digest) if has_prev else False
    seed_ts = parse_ts(seed.get("last_audit_timestamp") or seed.get("last_skills_audit_timestamp"))
    state_ts = parse_ts(state.get("last_audit_timestamp") or state.get("last_skills_audit_timestamp"))
    can_sync = seed_changed or (not has_prev and (seed_ts is None or state_ts is None or seed_ts >= state_ts))

    seed_repos = seed.get("tracked_repositories")
    if isinstance(seed_repos, dict):
        if not had_explicit_repos:
            state["tracked_repositories"] = {}
        state_repos = state.get("tracked_repositories")
        if isinstance(state_repos, dict):
            for rname, sinfo in seed_repos.items():
                if not isinstance(sinfo, dict):
                    continue
                cur = state_repos.get(rname)
                if rname not in state_repos:
                    if (not had_explicit_repos) or is_full_ledger:
                        state_repos[rname] = copy.deepcopy(sinfo)
                elif isinstance(cur, dict) and can_sync:
                    for rk in ("repo", "branch", "track", "path", "last_synced_commit", "target_skills"):
                        if rk in sinfo:
                            cur[rk] = copy.deepcopy(sinfo[rk])


try:
    with open(state_file, "r", encoding="utf-8") as f:
        state = json.load(f)
except Exception as e:
    print(f"[ERROR] Failed to read JSON: {e}", file=sys.stderr)
    sys.exit(1)

if not isinstance(state, dict):
    print("[ERROR] Upstream state root must be a JSON object.", file=sys.stderr)
    sys.exit(1)

if seed_file and os.path.isfile(seed_file) and os.path.abspath(seed_file) != os.path.abspath(state_file):
    try:
        with open(seed_file, "r", encoding="utf-8") as sf:
            seed_data = json.load(sf)
        if isinstance(seed_data, dict):
            reconcile_in_memory(state, seed_data)
    except Exception:
        pass

tracked = state.get("tracked_repositories", {})
if not isinstance(tracked, dict) or not tracked:
    print("[ERROR] No external tracked repositories defined.", file=sys.stderr)
    sys.exit(1)

print("=" * 90)
print(f"{'REPOSITORY':<22} | {'SAVED REF':<18} | {'REMOTE REF':<18} | {'STATUS':<15}")
print("=" * 90)

updates_found = []
errors_found = []


def check_one(item):
    name, info = item
    if not isinstance(info, dict):
        return f"{name:<22} | {'-':<18} | {'-':<18} | {'INVALID ENTRY':<15}", None, (name, "INVALID ENTRY")
    repo = str(info.get("repo", "")).strip()
    branch = str(info.get("branch", "main")).strip() or "main"
    track = str(info.get("track", "commits")).strip().lower()
    subpath = str(info.get("path", "")).strip()
    recorded_raw = str(info.get("last_synced_commit", "")).strip()
    recorded_sha = short_ref(recorded_raw)

    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        return f"{name:<22} | {'-':<18} | {'-':<18} | {'INVALID REPO':<15}", None, (name, "INVALID REPO")
    if track == "release":
        url = f"{api_base}/repos/{repo}/releases/latest"
    elif track == "commits":
        params = {"sha": branch, "per_page": 1}
        if subpath:
            if not SUBPATH_RE.fullmatch(subpath) or any(seg in ("", ".", "..") for seg in subpath.split("/")):
                return f"{name:<22} | {'-':<18} | {'-':<18} | {'INVALID PATH':<15}", None, (name, "INVALID PATH")
            params["path"] = subpath
        url = f"{api_base}/repos/{repo}/commits?" + urllib.parse.urlencode(params)
    else:
        return f"{name:<22} | {'-':<18} | {'-':<18} | {'INVALID TRACK':<15}", None, (name, "INVALID TRACK")

    current_sha = "UNKNOWN"
    status = "ERROR"
    update = None
    err_item = None

    try:
        raw_body = safe_fetch_url(
            url,
            user_agent="UpstreamAuditor-Watchdog/1.4",
            timeout=4.0,
            max_bytes=MAX_API_BYTES,
        )
        data = json.loads(raw_body)
        if track == "release" and isinstance(data, dict) and str(data.get("tag_name", "")).strip():
            remote_raw = str(data.get("tag_name", "")).strip()
            if not TAG_RE.fullmatch(remote_raw):
                status = "INVALID TAG"
                err_item = (name, status)
            else:
                current_sha = short_ref(remote_raw)
                if sha_matches(recorded_raw, remote_raw):
                    status = "UP TO DATE"
                else:
                    status = "UPDATE FOUND"
                    update = (name, recorded_sha, current_sha)
        elif track == "commits" and data and isinstance(data, list) and isinstance(data[0], dict) and str(data[0].get("sha", "")).strip():
            remote_raw = str(data[0].get("sha", "")).strip()
            if not HEX_RE.fullmatch(remote_raw):
                status = "INVALID SHA"
                err_item = (name, status)
            else:
                current_sha = short_ref(remote_raw)
                if sha_matches(recorded_raw, remote_raw):
                    status = "UP TO DATE"
                else:
                    status = "UPDATE FOUND"
                    update = (name, recorded_sha, current_sha)
        else:
            status = "EMPTY REPLY"
            err_item = (name, status)
    except urllib.error.HTTPError as exc:
        try:
            status = f"HTTP {exc.code}"
        finally:
            exc.close()
        err_item = (name, status)
    except Exception:
        status = "NETWORK ERROR"
        err_item = (name, status)

    return f"{name:<22} | {recorded_sha:<18} | {current_sha:<18} | {status:<15}", update, err_item


with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(tracked)))) as executor:
    for row_line, update_item, err_item in executor.map(check_one, tracked.items()):
        print(row_line)
        if update_item is not None:
            updates_found.append(update_item)
        if err_item is not None:
            errors_found.append(err_item)

print("=" * 90)

if updates_found:
    print(f"\n[ALERT] {len(updates_found)} repositories have new remote commits:")
    for name, old_s, new_s in updates_found:
        print(f"  - {name}: {old_s} -> {new_s}")
    print("\nTo inspect diffs and apply constitutional filter:")
    print("  /audit-upstream --skills")

if errors_found:
    print(f"\n[WARN] {len(errors_found)} repository check(s) failed; upstream synchronization is NOT verified:", file=sys.stderr)
    for name, reason in errors_found:
        print(f"  - {name}: {reason}", file=sys.stderr)
    sys.exit(1)

if not updates_found:
    print("\n[OK] All external skill repositories are synchronized with local state.")

EOF
