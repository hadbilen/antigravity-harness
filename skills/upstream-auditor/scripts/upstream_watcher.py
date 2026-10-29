#!/usr/bin/env python3
"""
Upstream Watchdog — PreInvocation Lifecycle Hook & 72h External Skills Monitor
Monitors changes to the active LLM model, the Antigravity builtin environment and,
every 72 hours (3 days), the tracked community skill repositories.

Hook mode (no arguments): reads the hook payload (JSON) on stdin and writes a JSON
response on stdout. It only inspects invocationNum == 1. A change set is surfaced as ONE
short operator notice: once per conversation when the payload carries a conversation or
session id, otherwise at most once per cooldown window. The notice is addressed to the
human operator and never asks the agent to do anything.

Operator commands:
  upstream_watcher.py --status              print the current findings (writes nothing)
  upstream_watcher.py --ack [--model NAME]  record the current environment as reviewed;
                                            the notice stays silent until something changes
"""

import argparse
import hashlib
import json
import os
import queue
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

WATCHER_VERSION = "1.4"
USER_AGENT = f"UpstreamAuditor-Watchdog/{WATCHER_VERSION}"

CONFIG_DIR = os.path.expanduser(os.environ.get("ANTIGRAVITY_CONFIG_DIR", "~/.gemini/config"))
SKILL_DIR = os.path.join(CONFIG_DIR, "skills", "upstream-auditor")
CUSTOM_SKILLS_DIR = os.path.join(CONFIG_DIR, "skills")
SEED_STATE_FILE = os.path.join(SKILL_DIR, "upstream_state.seed.json")      # shipped, read-only
# Seed that ships next to this script (used when the watcher runs from a source checkout).
BUNDLED_SEED_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "upstream_state.seed.json")
SYSTEM_SHARE_SEED_FILE = os.path.join(
    os.path.expanduser(os.environ.get("ANTIGRAVITY_SHARE_DIR", "/usr/share/antigravity-harness")),
    "skills",
    "upstream-auditor",
    "upstream_state.seed.json",
)
# In-tree ledger written by releases up to 1.3.0; 1.4 only reads it once, as a migration source.
LEGACY_STATE_FILE = os.path.join(SKILL_DIR, "upstream_state.json")

DEFAULT_STATE_DIR = os.path.expanduser(
    os.environ.get("AGY_GUARD_STATE_DIR")
    or os.path.join(os.environ.get("XDG_STATE_HOME", "~/.local/state"), "antigravity-harness")
)
STATE_FILE = os.environ.get("UPSTREAM_STATE_FILE", os.path.join(DEFAULT_STATE_DIR, "upstream_state.json"))
BUILTIN_DIR = os.path.expanduser(os.environ.get("ANTIGRAVITY_BUILTIN_SKILLS_DIR") or "~/.gemini/antigravity/builtin/skills")
PBTXT_FILE = os.path.expanduser(os.environ.get("ANTIGRAVITY_PBTXT_FILE") or "~/.gemini/antigravity/antigravity_state.pbtxt")


def _ensure_runtime_sys_path() -> None:
    repo_candidate = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    )
    if os.name == "nt":
        default_data = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "antigravity-harness")
    else:
        default_data = os.path.join(os.path.expanduser(os.environ.get("XDG_DATA_HOME", "~/.local/share")), "antigravity-harness")
    data_root = os.path.expanduser(os.environ.get("AGY_GUARD_DATA_DIR") or default_data)
    candidates = [
        repo_candidate,
        os.path.join(data_root, "runtime"),
        "/usr/lib/antigravity-guard",
    ]
    for cand in candidates:
        if cand and os.path.isfile(os.path.join(cand, "porter", "net.py")) and cand not in sys.path:
            sys.path.insert(0, cand)


_ensure_runtime_sys_path()

# The host kills the hook after 15 s; the whole repository check must finish well before that.
NETWORK_DEADLINE_SECONDS = 6.0
REQUEST_TIMEOUT_SECONDS = 2.5
MAX_NETWORK_WORKERS = 10
NOTICE_COOLDOWN_HOURS = 12          # used only when the payload carries no session id
# Even with session ids, the same notice is not repeated sooner than this (guards against an id
# that turns out to change on every turn).
SESSION_MIN_INTERVAL_MINUTES = 60
MAX_SESSIONS_PER_SIGNATURE = 20
MAX_NOTICE_SIGNATURES = 20
MAX_NOTICE_CHARS = 700
SESSION_ID_KEYS = (
    "conversationId", "conversation_id", "sessionId", "session_id",
    "trajectoryId", "trajectory_id", "cascadeId", "cascade_id",
)
NOTIFY_TITLE = "Antigravity Harness — upstream change"
REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
HEX_SHA_RE = re.compile(r"[0-9a-fA-F]{7,40}")
SUBPATH_RE = re.compile(r"[A-Za-z0-9_./-]+")
TAG_NAME_RE = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")
MAX_API_RESPONSE_BYTES = 262_144


# ----------------------------------------------------------------------
# Environment inspection
# ----------------------------------------------------------------------
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
                if "last_selected_agent_model" in line and ":" in line:
                    val = line.split(":", 1)[1].strip().strip('"')
                    if val.upper().startswith("MODEL_PLACEHOLDER"):
                        return ""
                    return val
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


def model_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9.]+", "-", name.lower()).strip("-")


# ----------------------------------------------------------------------
# State (per-user ledger; the skill tree is never written)
# ----------------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value):
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _read_json_object(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("upstream state is not a JSON object")
    return data


def atomic_write_json(path: str, data: dict) -> None:
    """Same-directory temp file + fsync + os.replace, owner-only (0600) permissions."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        if os.name != "nt":
            os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def save_state(state: dict) -> bool:
    try:
        atomic_write_json(STATE_FILE, state)
        return True
    except Exception:
        return False


def _shipped_seed_candidates():
    candidates = [SEED_STATE_FILE, BUNDLED_SEED_FILE]
    if "ANTIGRAVITY_SHARE_DIR" in os.environ or "ANTIGRAVITY_CONFIG_DIR" not in os.environ:
        candidates.append(SYSTEM_SHARE_SEED_FILE)
    return candidates


def load_shipped_seed():
    """Returns (seed_state, source_path) strictly from the shipped seed candidates."""
    for candidate in _shipped_seed_candidates():
        if os.path.isfile(candidate):
            try:
                return _read_json_object(candidate), candidate
            except (OSError, ValueError):
                continue
    return None, ""


def load_seed():
    """Returns (seed_state, source_path) from the legacy ledger or the shipped seed."""
    for candidate in [LEGACY_STATE_FILE] + _shipped_seed_candidates():
        if os.path.isfile(candidate):
            try:
                data = _read_json_object(candidate)
                if candidate == LEGACY_STATE_FILE:
                    shipped, _ = load_shipped_seed()
                    if shipped is not None:
                        _reconcile_with_seed(data, shipped)
                return data, candidate
            except (OSError, ValueError):
                continue
    return None, ""


def _compute_seed_digest(seed: dict) -> str:
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


def quarantine_corrupt_state() -> str:
    """Moves an unreadable ledger aside (kept for inspection) so it can be re-seeded."""
    base = f"{STATE_FILE}.corrupt-{_now().strftime('%Y%m%dT%H%M%SZ')}"
    target, n = base, 1
    while os.path.exists(target):
        target, n = f"{base}-{n}", n + 1
    try:
        os.replace(STATE_FILE, target)
        return target
    except OSError:
        return ""


def _copy_repo_entry(info: dict) -> dict:
    out = dict(info)
    if "target_skills" in out:
        raw_ts = out["target_skills"]
        out["target_skills"] = [s for s in raw_ts if isinstance(s, str)] if isinstance(raw_ts, list) else []
    return out


def _reconcile_with_seed(state: dict, seed: dict) -> bool:
    """
    Synchronizes tracked_repositories and audited environment baselines from a newer shipped seed
    into an existing per-user ledger so repository/platform updates applied in the source checkout
    take effect after install.py without requiring direct agent writes to the Guard-protected state directory.
    """
    if not isinstance(state, dict) or not isinstance(seed, dict):
        return False

    changed = False
    raw_state_tracked = state.get("tracked_repositories")
    if raw_state_tracked is not None and not isinstance(raw_state_tracked, dict):
        state["tracked_repositories"] = {}
        raw_state_tracked = {}
        changed = True

    seed_digest = _compute_seed_digest(seed)
    prev_seed_digest = state.get("_reconciled_seed_digest")
    has_prev_digest = isinstance(prev_seed_digest, str) and bool(prev_seed_digest)
    seed_changed = (prev_seed_digest != seed_digest) if has_prev_digest else False

    seed_ts = _parse_time(seed.get("last_audit_timestamp"))
    state_ts = _parse_time(state.get("last_audit_timestamp"))
    seed_newer = seed_ts is not None and (state_ts is None or seed_ts > state_ts)
    ack_ts = _parse_time(state.get("last_ack_timestamp"))
    seed_newer_than_ack = ack_ts is None or (seed_ts is not None and seed_ts > ack_ts)

    seed_tracked = seed.get("tracked_repositories")
    if not isinstance(seed_tracked, dict):
        seed_tracked = {}
    if not seed_tracked and not seed_newer and not seed_changed:
        if state.get("_reconciled_seed_digest") != seed_digest:
            state["_reconciled_seed_digest"] = seed_digest
            return True
        return changed

    state_tracked = dict(raw_state_tracked) if isinstance(raw_state_tracked, dict) else {}
    tracked_changed = False
    can_sync_commits = seed_changed or (not has_prev_digest and (seed_newer or seed_ts is None or state_ts is None))

    for name, seed_info in seed_tracked.items():
        if not isinstance(seed_info, dict):
            continue
        cur_info = state_tracked.get(name)
        if not isinstance(cur_info, dict):
            state_tracked[name] = _copy_repo_entry(seed_info)
            tracked_changed = True
            continue
        merged = _copy_repo_entry(cur_info)
        for key in ("repo", "branch", "track", "path", "target_skills"):
            if key in seed_info:
                new_val = (
                    [s for s in seed_info[key] if isinstance(s, str)]
                    if key == "target_skills" and isinstance(seed_info[key], list)
                    else seed_info[key]
                )
                if merged.get(key) != new_val:
                    merged[key] = new_val
                    tracked_changed = True
            elif key in ("track", "path") and key in merged:
                merged.pop(key, None)
                tracked_changed = True
        if can_sync_commits and isinstance(seed_info.get("last_synced_commit"), str) and seed_info["last_synced_commit"].strip():
            if merged.get("last_synced_commit") != seed_info["last_synced_commit"]:
                merged["last_synced_commit"] = seed_info["last_synced_commit"]
                tracked_changed = True
        state_tracked[name] = merged

    if seed_newer or seed_changed:
        raw_audit_ts = seed.get("last_audit_timestamp")
        if seed_newer and isinstance(raw_audit_ts, str) and state.get("last_audit_timestamp") != raw_audit_ts:
            state["last_audit_timestamp"] = raw_audit_ts
            changed = True
        raw_skills_ts = seed.get("last_skills_audit_timestamp")
        seed_skills_ts = _parse_time(raw_skills_ts)
        state_skills_ts = _parse_time(state.get("last_skills_audit_timestamp"))
        if seed_tracked and isinstance(raw_skills_ts, str) and seed_skills_ts is not None:
            if state_skills_ts is None or seed_skills_ts > state_skills_ts:
                if state.get("last_skills_audit_timestamp") != raw_skills_ts:
                    state["last_skills_audit_timestamp"] = raw_skills_ts
                    changed = True
                if state.get("last_audit_failed"):
                    state["last_audit_failed"] = False
                    changed = True
        if seed_changed or (not has_prev_digest and seed_newer_than_ack):
            if "recorded_builtin_skills" in seed and isinstance(seed.get("recorded_builtin_skills"), list):
                clean_rbs = [s for s in seed["recorded_builtin_skills"] if isinstance(s, str)]
                if state.get("recorded_builtin_skills") != clean_rbs:
                    state["recorded_builtin_skills"] = clean_rbs
                    changed = True
            b_hash = seed.get("builtin_skills_hash")
            if isinstance(b_hash, str) and b_hash.strip() and state.get("builtin_skills_hash") != b_hash:
                state["builtin_skills_hash"] = b_hash
                changed = True
        if seed_changed or (not has_prev_digest and (seed_newer or seed_newer_than_ack)):
            for env_key in (
                "last_audited_model",
                "last_model_slug",
                "last_pbtxt_model",
                "environment_Target",
            ):
                val = seed.get(env_key)
                if isinstance(val, str) and val.strip() and not val.strip().upper().startswith("MODEL_PLACEHOLDER"):
                    if state.get(env_key) != val:
                        state[env_key] = val
                        if env_key == "last_audited_model" and state.get("last_seen_model") and state.get("last_seen_model") != val:
                            state["last_seen_model"] = val
                        changed = True

    if tracked_changed:
        state["tracked_repositories"] = state_tracked
        changed = True
        raw_pending = state.get("pending_repo_updates")
        if isinstance(raw_pending, dict):
            pending = dict(raw_pending)
            for name in list(pending):
                entry = pending.get(name)
                info = state_tracked.get(name)
                if not isinstance(entry, dict) or not isinstance(info, dict):
                    pending.pop(name, None)
                    continue
                if str(info.get("last_synced_commit", "")).strip() != str(entry.get("recorded", "")).strip():
                    pending.pop(name, None)
            state["pending_repo_updates"] = pending

    if state.get("_reconciled_seed_digest") != seed_digest:
        state["_reconciled_seed_digest"] = seed_digest
        changed = True
    return changed


def load_state(write: bool = True):
    """
    Returns (state, source_description) or (None, reason).
    With write=True a missing ledger is seeded and a corrupt one is quarantined and re-seeded;
    with write=False nothing on disk changes.
    """
    note = ""
    if os.path.isfile(STATE_FILE):
        try:
            state = _read_json_object(STATE_FILE)
            seed, _ = load_shipped_seed()
            if seed is not None and _reconcile_with_seed(state, seed) and write:
                save_state(state)
            return state, STATE_FILE
        except ValueError:
            if write:
                moved = quarantine_corrupt_state()
                if not moved:
                    return None, f"corrupt ledger at {STATE_FILE} could not be quarantined; refusing to overwrite"
                note = f"corrupt ledger moved to {moved}"
            else:
                note = "ledger is corrupt; the next hook run moves it aside and re-seeds it"
        except OSError as e:
            return None, f"ledger unreadable: {e}"
    seed, source = load_seed()
    if seed is None:
        return None, "no ledger and no shipped seed found"
    if write and not save_state(seed):
        return None, "ledger could not be written"
    if write:
        description = f"seeded from {source}"
    elif note:
        description = f"showing seed {source}"
    else:
        description = f"not created yet; showing seed {source}"
    return seed, f"{description} ({note})" if note else description


# ----------------------------------------------------------------------
# Tracked repositories (network, bounded by a real overall deadline)
# ----------------------------------------------------------------------
def _short_ref(ref: str) -> str:
    ref = str(ref or "").strip()
    return ref[:7] if HEX_SHA_RE.fullmatch(ref) else ref


def _valid_subpath(path: str) -> bool:
    return bool(path) and bool(SUBPATH_RE.fullmatch(path)) and not any(seg in ("", ".", "..") for seg in path.split("/"))


def _sha_matches(recorded: str, current: str) -> bool:
    if not (recorded and current):
        return False
    if recorded == current:
        return True
    if HEX_SHA_RE.fullmatch(recorded) and HEX_SHA_RE.fullmatch(current):
        return current.startswith(recorded) or recorded.startswith(current)
    return False


def _valid_tag_or_ref(value: str) -> bool:
    return bool(TAG_NAME_RE.fullmatch(str(value or "").strip()))


def fetch_remote_head(info: dict):
    """Returns the remote HEAD sha or release tag of a tracked repository, or None on any failure."""
    repo = str(info.get("repo", "")).strip()
    branch = str(info.get("branch", "main")).strip() or "main"
    track = str(info.get("track", "commits")).strip().lower()
    subpath = str(info.get("path", "")).strip()
    if not REPO_RE.fullmatch(repo):
        return None
    if track == "release":
        url = f"https://api.github.com/repos/{repo}/releases/latest"
    elif track == "commits":
        params = {"sha": branch, "per_page": 1}
        if subpath:
            if not _valid_subpath(subpath):
                return None
            params["path"] = subpath
        url = f"https://api.github.com/repos/{repo}/commits?{urllib.parse.urlencode(params)}"
    else:
        return None
    try:
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme != "https" or (parsed_url.hostname or "").lower() != "api.github.com":
            return None
        from porter.net import safe_fetch_url

        raw_text = safe_fetch_url(
            url,
            user_agent=USER_AGENT,
            timeout=REQUEST_TIMEOUT_SECONDS,
            max_bytes=MAX_API_RESPONSE_BYTES,
        )
        data = json.loads(raw_text)
        if track == "release":
            if isinstance(data, dict):
                tag = str(data.get("tag_name", "")).strip()
                if tag and _valid_tag_or_ref(tag):
                    return tag
                return None
        elif data and isinstance(data, list):
            sha = str(data[0]["sha"]).strip()
            if sha and HEX_SHA_RE.fullmatch(sha):
                return sha
            return None
    except urllib.error.HTTPError as exc:
        exc.close()
        return None
    except Exception:
        return None
    return None


def _fetch_all(tracked: dict, deadline_seconds: float) -> dict:
    """
    Queries every repository on daemon threads and returns whatever finished before the deadline.
    Daemon threads (not a ThreadPoolExecutor, whose workers are joined at interpreter exit) mean a
    slow DNS lookup or socket can never keep the hook process alive past the deadline.
    """
    work: "queue.Queue" = queue.Queue()
    done: "queue.Queue" = queue.Queue()
    for item in tracked.items():
        work.put(item)

    def worker():
        while True:
            try:
                name, info = work.get_nowait()
            except queue.Empty:
                return
            try:
                done.put((name, fetch_remote_head(info)))
            except Exception:
                done.put((name, None))

    for _ in range(min(len(tracked), MAX_NETWORK_WORKERS)):
        threading.Thread(target=worker, name="upstream-watchdog-fetch", daemon=True).start()

    results = {}
    deadline = time.monotonic() + deadline_seconds
    while len(results) < len(tracked):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            name, sha = done.get(timeout=remaining)
        except queue.Empty:
            break
        results[name] = sha
    return results


def check_tracked_skills(state: dict, now=None) -> bool:
    """
    Checks the tracked repositories when the 72 h interval (2 h after a failure) has elapsed.
    Findings are kept in state["pending_repo_updates"] until the ledger's recorded commit changes.
    Returns True when a check was attempted.
    """
    now = now or _now()
    try:
        failed = bool(state.get("last_audit_failed", False))
        interval_hours = float(state.get("skills_audit_retry_hours", 2) if failed
                               else state.get("skills_audit_interval_hours", 72))
    except (TypeError, ValueError):
        interval_hours = 72.0
    last_dt = _parse_time(state.get("last_skills_audit_timestamp"))
    if last_dt is not None and (now - last_dt).total_seconds() < interval_hours * 3600:
        return False

    raw_tracked = state.get("tracked_repositories")
    tracked = {
        k: v
        for k, v in (raw_tracked.items() if isinstance(raw_tracked, dict) else ())
        if isinstance(v, dict)
    }
    if not tracked:
        return False

    # Record the attempt BEFORE any network I/O: if the host kills this hook, the next turn
    # must not retry immediately. It counts as a failed attempt until results are in.
    state["last_skills_audit_timestamp"] = now.isoformat()
    state["last_audit_failed"] = True
    if not save_state(state):
        return False  # without a persisted timestamp every turn would hit the network

    results = _fetch_all(tracked, NETWORK_DEADLINE_SECONDS)

    pending = state.get("pending_repo_updates")
    pending = dict(pending) if isinstance(pending, dict) else {}
    successes = 0
    for name, info in tracked.items():
        remote = results.get(name)
        if not remote:
            continue  # failed or timed out: keep any earlier finding for this repository
        successes += 1
        recorded = str(info.get("last_synced_commit", "")).strip()
        if recorded and not _sha_matches(recorded, remote):
            pending[name] = {"recorded": recorded, "remote": remote}
        else:
            pending.pop(name, None)
    for name in list(pending):
        if name not in tracked:
            pending.pop(name, None)
    state["pending_repo_updates"] = pending
    # Any failed repository triggers the short retry interval (partial failures are failures).
    failed_any = successes < len(tracked)
    state["last_audit_failed"] = failed_any
    if not failed_any:
        state["last_checked_iso"] = now.isoformat()
    return save_state(state)


# ----------------------------------------------------------------------
# Findings
# ----------------------------------------------------------------------
def collect_reasons(state: dict, payload_model: str = "") -> list:
    """Returns the current findings as short human-readable strings (no network access)."""
    reasons = []

    collisions = check_skill_namespace_collisions()
    if collisions:
        reasons.append(f"Namespace collision / shadowing detected: {', '.join(collisions)}")

    current_builtin_hash = compute_builtin_hash()
    recorded_hash = state.get("builtin_skills_hash", "")
    if recorded_hash and current_builtin_hash and current_builtin_hash != recorded_hash:
        current_builtins = get_builtin_skills_list()
        raw_rb = state.get("recorded_builtin_skills")
        recorded_builtins = [s for s in raw_rb if isinstance(s, str)] if isinstance(raw_rb, list) else []
        added = sorted(set(current_builtins) - set(recorded_builtins))
        removed = sorted(set(recorded_builtins) - set(current_builtins))
        details = []
        if recorded_builtins and added:
            details.append(f"added: {', '.join(added)}")
        if recorded_builtins and removed:
            details.append(f"removed: {', '.join(removed)}")
        if details:
            reasons.append(f"Delta in builtin skills ({'; '.join(details)})")
        else:
            reasons.append("Delta detected in Antigravity builtin environment (builtin/skills)")

    recorded_model = str(state.get("last_audited_model", "") or "")
    recorded_pbtxt = str(state.get("last_pbtxt_model", "") or "")
    current_pbtxt_model = get_pbtxt_model()
    norm_payload = normalize_model_name(payload_model)
    norm_recorded = normalize_model_name(recorded_model)
    norm_current_pbtxt = normalize_model_name(current_pbtxt_model)
    norm_recorded_pbtxt = normalize_model_name(recorded_pbtxt)
    if norm_payload and norm_payload != "auto" and norm_recorded:
        if norm_payload != norm_recorded and not is_pro_flash_switch(norm_recorded, norm_payload):
            reasons.append(f"Model change: '{recorded_model}' -> '{payload_model}'")
    elif norm_current_pbtxt and norm_recorded_pbtxt and norm_current_pbtxt != norm_recorded_pbtxt:
        if not is_pro_flash_switch(norm_recorded_pbtxt, norm_current_pbtxt):
            reasons.append(f"Model configuration change: '{recorded_pbtxt}' -> '{current_pbtxt_model}'")

    tracked = state.get("tracked_repositories") or {}
    pending = state.get("pending_repo_updates") or {}
    updates = []
    if isinstance(pending, dict) and isinstance(tracked, dict):
        for name in sorted(pending):
            entry, info = pending.get(name), tracked.get(name)
            if not isinstance(entry, dict) or not isinstance(info, dict):
                continue
            recorded = str(entry.get("recorded", "")).strip()
            remote_val = str(entry.get("remote", "")).strip()
            if not _valid_tag_or_ref(recorded) or not _valid_tag_or_ref(remote_val):
                continue
            if str(info.get("last_synced_commit", "")).strip() != recorded:
                continue  # the ledger was synchronized since this finding
            updates.append(f"{name} ({_short_ref(recorded)}->{_short_ref(remote_val)})")
    if updates:
        reasons.append(f"New commits in tracked repositories ({', '.join(updates)})")
    return reasons


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def reason_fingerprint(reason: str) -> str:
    return _digest(reason)


def reasons_signature(reasons) -> str:
    return _digest("\n".join(sorted(reason_fingerprint(r) for r in reasons)))


def unacknowledged(state: dict, reasons) -> list:
    acked = state.get("acknowledged_reasons") or []
    acked = set(acked) if isinstance(acked, list) else set()
    return [r for r in reasons if reason_fingerprint(r) not in acked]


def session_key(payload: dict) -> str:
    """A stable, hashed conversation/session id when the payload carries one ('' otherwise)."""
    containers = [payload] + [v for v in payload.values() if isinstance(v, dict)]
    for container in containers:
        for key in SESSION_ID_KEYS:
            value = container.get(key)
            if isinstance(value, bool) or not isinstance(value, (str, int)):
                continue
            text = str(value).strip()
            if text:
                return _digest(text)
    return ""


def should_notice(state: dict, signature: str, session: str, now: datetime):
    """Returns (inject, first_time_seen) for this signature in this session."""
    log = state.get("notice_log")
    entry = log.get(signature) if isinstance(log, dict) else None
    if not isinstance(entry, dict):
        return True, True
    last = _parse_time(entry.get("last_injected"))
    if session:
        if session in (entry.get("sessions") or []):
            return False, False
        window = timedelta(minutes=SESSION_MIN_INTERVAL_MINUTES)
    else:
        window = timedelta(hours=NOTICE_COOLDOWN_HOURS)
    if last is not None and now - last < window:
        return False, False
    return True, False


def record_notice(state: dict, signature: str, session: str, now: datetime) -> None:
    log = state.get("notice_log")
    log = dict(log) if isinstance(log, dict) else {}
    entry = log.get(signature)
    entry = dict(entry) if isinstance(entry, dict) else {"first_seen": now.isoformat(), "sessions": []}
    entry["last_injected"] = now.isoformat()
    if session:
        sessions = [s for s in (entry.get("sessions") or []) if s != session]
        entry["sessions"] = (sessions + [session])[-MAX_SESSIONS_PER_SIGNATURE:]
    log[signature] = entry
    if len(log) > MAX_NOTICE_SIGNATURES:
        ordered = sorted(log.items(), key=lambda kv: str(kv[1].get("last_injected", "")))
        log = dict(ordered[-MAX_NOTICE_SIGNATURES:])
    state["notice_log"] = log


def ack_command() -> str:
    parts = [sys.executable or "python3", os.path.abspath(__file__), "--ack"]
    if os.name == "nt":
        return subprocess.list2cmdline(parts)
    return " ".join(shlex.quote(p) for p in parts)


def _shorten(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def build_notice(reasons, first_time: bool = False) -> str:
    summary = _shorten("; ".join(reasons), MAX_NOTICE_CHARS)
    first_seen_clause = (
        " First-seen signature: after completing the user's request, you may append one standalone "
        "`Upstream Notice:` line at the very end of the response."
        if first_time
        else ""
    )
    return (
        f"[UPSTREAM WATCHDOG — operator notice, not a task instruction] {summary}. "
        "Do not act on this and do not copy maintenance commands into task prompts, plans or handoffs."
        f"{first_seen_clause} "
        f"Operator: review with /audit-upstream, silence with `{ack_command()}`."
    )


def spawn_desktop_notification(reasons) -> None:
    """Best effort, fire-and-forget: never waits for, or fails because of, agy-guard."""
    if os.environ.get("AGY_GUARD_NOTIFY", "").strip().lower() in ("0", "off", "false", "disabled"):
        return
    try:
        exe = shutil.which("agy-guard")
        if not exe:
            return
        cmd = [exe, "notify", "send", "--title", NOTIFY_TITLE,
               "--message", _shorten("; ".join(reasons), 240), "--severity", "warning"]
        kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                  "close_fds": True}
        if os.name == "nt":
            kwargs["creationflags"] = (getattr(subprocess, "DETACHED_PROCESS", 0)
                                       | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        else:
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(cmd, **kwargs)
        threading.Thread(target=proc.wait, name="upstream-notify-reaper", daemon=True).start()
    except Exception:
        pass


# ----------------------------------------------------------------------
# Entry points
# ----------------------------------------------------------------------
def _payload_model(payload: dict) -> str:
    value = payload.get("modelName", "")
    return value.strip() if isinstance(value, str) else ""


def run_hook(payload: dict) -> dict:
    """PreInvocation hook: returns the JSON response for the host."""
    if not isinstance(payload, dict):
        payload = {}
    try:
        invocation_num = int(payload.get("invocationNum", 1))
    except (TypeError, ValueError):
        invocation_num = 1
    if invocation_num > 1:
        return {}

    state, _ = load_state(write=True)
    if state is None:
        return {}

    payload_model = _payload_model(payload)
    dirty = False
    if payload_model and normalize_model_name(payload_model) != "auto" and state.get("last_seen_model") != payload_model:
        state["last_seen_model"] = payload_model  # lets `--ack` record the model without a payload
        dirty = True

    check_tracked_skills(state)

    raw_pending = state.get("pending_repo_updates")
    if isinstance(raw_pending, dict):
        cleaned_pending = {}
        for repo_name, pend_entry in raw_pending.items():
            if not isinstance(pend_entry, dict):
                dirty = True
                continue
            rec_tag = str(pend_entry.get("recorded", "")).strip()
            rem_tag = str(pend_entry.get("remote", "")).strip()
            if not _valid_tag_or_ref(rec_tag) or not _valid_tag_or_ref(rem_tag):
                dirty = True
                continue
            cleaned_pending[repo_name] = pend_entry
        if len(cleaned_pending) != len(raw_pending):
            state["pending_repo_updates"] = cleaned_pending

    active = unacknowledged(state, collect_reasons(state, payload_model))
    now = _now()
    inject, first_time = (False, False)
    if active:
        signature = reasons_signature(active)
        session = session_key(payload)
        inject, first_time = should_notice(state, signature, session, now)
        if inject:
            record_notice(state, signature, session, now)
            dirty = True
    if dirty and not save_state(state):
        return {}  # never inject a notice that could not be remembered (it would repeat every turn)
    if not inject:
        return {}
    if first_time:
        spawn_desktop_notification(active)
    return {"injectSteps": [{"ephemeralMessage": build_notice(active, first_time=first_time)}]}


def cmd_status(model: str = "") -> int:
    state, source = load_state(write=False)
    print("Upstream watchdog status")
    print(f"  ledger : {STATE_FILE}")
    print(f"  source : {source}")
    if state is None:
        return 1
    audit_failed = bool(state.get("last_audit_failed"))
    last = state.get("last_skills_audit_timestamp") or "never"
    outcome = "failed" if audit_failed else "ok"
    print(f"  last repository check: {last} ({outcome})")
    reasons = collect_reasons(state, model or str(state.get("last_seen_model", "") or ""))
    if audit_failed:
        print("\n[WARN] Last upstream repository check failed (HTTP rate-limit or network error); synchronization is unverified.")
    if not reasons:
        if audit_failed:
            return 1
        print("\nNo upstream changes detected.")
        return 0
    active = set(unacknowledged(state, reasons))
    print("\nFindings:")
    for reason in reasons:
        print(f"  - [{'new' if reason in active else 'acknowledged'}] {reason}")
    if active:
        print(f"\nReview with /audit-upstream; silence with: {ack_command()}")
    return 1 if audit_failed else 0


def cmd_ack(model: str = "") -> int:
    state, source = load_state(write=True)
    if state is None:
        print(f"[ERROR] Upstream ledger unavailable: {source}", file=sys.stderr)
        return 1
    if "corrupt ledger moved to" in str(source):
        print(f"[WARN] Upstream ledger recovered from corruption: {source}", file=sys.stderr)
    model = model or str(state.get("last_seen_model", "") or "")
    reasons = collect_reasons(state, model)

    current_hash = compute_builtin_hash()
    if current_hash:
        state["builtin_skills_hash"] = current_hash
        state["recorded_builtin_skills"] = get_builtin_skills_list()
    pbtxt_model = get_pbtxt_model()
    if pbtxt_model:
        state["last_pbtxt_model"] = pbtxt_model
    if model and normalize_model_name(model) != "auto":
        state["last_audited_model"] = model
        state["last_model_slug"] = model_slug(model)
    state["acknowledged_reasons"] = sorted({reason_fingerprint(r) for r in reasons})
    state["acknowledged_signature"] = reasons_signature(reasons) if reasons else ""
    state["last_ack_timestamp"] = _now().isoformat()
    if not save_state(state):
        print(f"[ERROR] Could not write {STATE_FILE}", file=sys.stderr)
        return 1
    print(f"[OK] Acknowledged {len(reasons)} finding(s) in {STATE_FILE}")
    for reason in reasons:
        print(f"  - {reason}")
    print(f"  builtin skills hash : {state.get('builtin_skills_hash') or '(builtin directory not found)'}")
    print(f"  model               : {state.get('last_audited_model') or '(unknown; pass --model NAME)'}")
    if pbtxt_model:
        print(f"  pbtxt model         : {pbtxt_model}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="upstream_watcher.py",
        description="Upstream watchdog. Without arguments it runs as the PreInvocation hook (JSON on stdin/stdout).",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ack", action="store_true",
                       help="Record the current builtin skills, model and findings as reviewed (silences the notice).")
    group.add_argument("--status", action="store_true", help="Print the current findings without writing anything.")
    parser.add_argument("--model", default="", metavar="NAME",
                        help="Active model name to record with --ack (default: the last model seen by the hook).")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.status or args.ack:
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(errors="replace")  # e.g. a cp1252 Windows console
            except (AttributeError, ValueError):
                pass
    if args.status:
        return cmd_status(args.model.strip())
    if args.ack:
        return cmd_ack(args.model.strip())
    try:
        raw_input = sys.stdin.read().strip()
        payload = json.loads(raw_input) if raw_input else {}
    except Exception:
        payload = {}
    try:
        response = run_hook(payload)
    except Exception as exc:
        print(f"[WARN] upstream_watcher hook error: {type(exc).__name__}: {exc}", file=sys.stderr)
        response = {}
    # ASCII-escaped JSON: valid for any consumer regardless of the console/pipe encoding.
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(main())
    try:
        main()
    except Exception:
        sys.stdout.write("{}\n")
        sys.stdout.flush()
    sys.exit(0)
