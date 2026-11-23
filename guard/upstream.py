"""
guard/upstream.py — Bridge to Upstream Auditor Watchdog
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
HEX_SHA_RE = re.compile(r"[0-9a-fA-F]{7,40}")
SUBPATH_RE = re.compile(r"[A-Za-z0-9_./-]+")
KNOWN_BUILTIN_SKILLS: Tuple[str, ...] = (
    "agy-customizations",
    "antigravity_guide",
    "automation",
    "generative_ui",
    "mcp-app-development",
    "migrate-agent-settings",
    "migrate-workflows",
    "native_swarm",
    "permissioned-github",
    "plugin",
    "run-workflow",
    "swarm_monitor",
    "swarm_narrator",
    "swarm_pane",
    "ui-plugin-navigation",
)
DEFAULT_BUILTIN_BUNDLE_CHECKSUM = "builtin:c0a2d240a0b68a3e3fc8607cace71c4d32d74a1ee097cc4dd96cb8dd0ee0cc13"
DEFAULT_KNOWN_PLACEHOLDER_MODELS: Dict[str, str] = {
    "MODEL_PLACEHOLDER_M535": "Gemini 4 Neon (XHigh)",
    "MODEL_PLACEHOLDER_M427": "Gemini 4 Carbon (High)",
}
MAX_COMPACTION_CEILING = 100_000_000
BUILTIN_CHECKSUM_RE = re.compile(r"^(?:[A-Za-z0-9._-]{1,32}:)?[0-9a-fA-F]{16,128}$")
_ANSI_ESC_RE = re.compile(r"\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\)|\[[0-9;?]*[ -/]*[@-~]|[@-Z\\-_])")
_CTRL_BIDI_RE = re.compile(r"[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]")
DEFAULT_MODEL_COMPACTION_CEILINGS: Dict[str, int] = {
    "gemini-4-neon-xhigh": 512_000,
    "gemini-4-carbon-high": 512_000,
    "gemini-4": 512_000,
    "gemini-3": 512_000,
    "claude-opus": 180_000,
    "claude-sonnet": 180_000,
    "gpt-5": 240_000,
    "default": 200_000,
}


def short_ref(ref: Any) -> str:
    text = str(ref or "").strip()
    return text[:7] if HEX_SHA_RE.fullmatch(text) else text


def _sanitize_checksum_display(value: Any) -> str:
    text = _ANSI_ESC_RE.sub("", str(value or ""))
    text = _CTRL_BIDI_RE.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def short_checksum(value: Any, *, peer: Any = "") -> str:
    text = _sanitize_checksum_display(value)
    peer_text = _sanitize_checksum_display(peer)
    if not text:
        return ""
    if ":" in text:
        prefix, rest = text.split(":", 1)
        safe_pre = prefix[:32]
        safe_full = f"{safe_pre}:{rest}"
        cand = f"{safe_pre}:{rest[:12]}" if len(rest) > 12 else safe_full
        if peer_text and peer_text != text and ":" in peer_text:
            p_pre, p_rest = peer_text.split(":", 1)
            p_safe_pre = p_pre[:32]
            peer_cand = f"{p_safe_pre}:{p_rest[:12]}" if len(p_rest) > 12 else f"{p_safe_pre}:{p_rest}"
            if cand == peer_cand:
                return safe_full[:48]
        return cand
    cand = text[:12] if len(text) > 12 else text
    if peer_text and peer_text != text and peer_text[:12] == cand:
        return text[:48]
    return cand


def _clean_compaction_ceilings(raw: Any) -> Dict[str, int]:
    if not isinstance(raw, dict):
        return {}
    cleaned: Dict[str, int] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or isinstance(v, bool) or not isinstance(v, int):
            continue
        key = k.strip().lower()
        if key and 32_000 <= v <= MAX_COMPACTION_CEILING:
            cleaned[key] = v
    return cleaned


def read_builtin_bundle_checksum_checked(builtin_dir: Optional[Path] = None) -> Tuple[str, Optional[str]]:
    """
    Safely reads `~/.gemini/antigravity/builtin/.checksum` and returns `(checksum, error)`.
    Cleanly returns `("", None)` only when the default Antigravity path is absent; returns
    `("", "<reason>")` on missing explicit env override, symlink, non-regular file, read error,
    or malformed checksum content.
    """
    explicit = os.environ.get("ANTIGRAVITY_BUILTIN_CHECKSUM_FILE", "").strip()
    if explicit:
        cs_path = Path(explicit).expanduser()
    else:
        if builtin_dir is None:
            raw_dir = os.environ.get("ANTIGRAVITY_BUILTIN_SKILLS_DIR")
            base = Path(raw_dir).expanduser() if raw_dir else (Path.home() / ".gemini" / "antigravity" / "builtin" / "skills")
        else:
            base = Path(builtin_dir).expanduser()
        cs_path = (base.parent / ".checksum") if base.name == "skills" else (base / ".checksum")
    try:
        path_str = os.fspath(cs_path)
    except (OSError, TypeError, ValueError) as exc:
        return "", f"Invalid builtin/.checksum path: {exc}"
    if "\x00" in path_str:
        return "", "Invalid NUL byte in builtin/.checksum path"
    try:
        exists = os.path.lexists(path_str)
    except OSError as exc:
        return "", f"Cannot stat builtin/.checksum ({cs_path}): {exc}"
    if not exists:
        if explicit:
            return "", f"Configured ANTIGRAVITY_BUILTIN_CHECKSUM_FILE does not exist: {cs_path}"
        return "", None
    if os.path.islink(path_str):
        return "", f"Refusing symlinked builtin/.checksum: {cs_path}"
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path_str, flags)
    except OSError as exc:
        return "", f"Cannot open builtin/.checksum ({cs_path}): {exc}"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            return "", f"Non-regular builtin/.checksum entry: {cs_path}"
        fh = os.fdopen(fd, "rb")
    except OSError as exc:
        try:
            os.close(fd)
        except OSError:
            pass
        return "", f"Cannot inspect builtin/.checksum ({cs_path}): {exc}"
    try:
        with fh:
            raw_bytes = fh.read(257)
    except OSError as exc:
        return "", f"Cannot read builtin/.checksum ({cs_path}): {exc}"
    if len(raw_bytes) > 256:
        return "", f"Oversized builtin/.checksum (>256 bytes): {cs_path}"
    raw = raw_bytes.decode("utf-8", errors="replace")
    for line in raw.splitlines():
        val = line.strip()
        if val:
            if not BUILTIN_CHECKSUM_RE.fullmatch(val):
                return "", f"Malformed builtin/.checksum content in {cs_path}"
            return val, None
    return "", f"Empty builtin/.checksum file: {cs_path}"


def read_builtin_bundle_checksum(builtin_dir: Optional[Path] = None) -> str:
    """Safely reads `~/.gemini/antigravity/builtin/.checksum` (bounded non-symlink regular file; '' if absent/invalid)."""
    return read_builtin_bundle_checksum_checked(builtin_dir)[0]


def _valid_subpath(path: str) -> bool:
    return bool(path) and bool(SUBPATH_RE.fullmatch(path)) and not any(seg in ("", ".", "..") for seg in path.split("/"))


def sha_matches(recorded: str, current: str) -> bool:
    if not (recorded and current):
        return False
    if recorded == current:
        return True
    if HEX_SHA_RE.fullmatch(recorded) and HEX_SHA_RE.fullmatch(current):
        return current.startswith(recorded) or recorded.startswith(current)
    return False


def _clean_model_name(val: Any) -> str:
    if not isinstance(val, str):
        return ""
    cleaned = val.strip()
    if not cleaned or cleaned.upper().startswith("MODEL_PLACEHOLDER"):
        return ""
    return cleaned


def _clean_known_placeholder_map(raw: Any) -> Dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    cleaned: Dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not k.strip().upper().startswith("MODEL_PLACEHOLDER"):
            continue
        concrete = _clean_model_name(v)
        if concrete and concrete.lower() != "auto":
            cleaned[k.strip()] = concrete
    return cleaned


def _lookup_known_placeholder(placeholder_id: Any, *sources: Any) -> str:
    if not isinstance(placeholder_id, str):
        return ""
    target_up = placeholder_id.strip().upper()
    if not target_up.startswith("MODEL_PLACEHOLDER"):
        return ""
    for src in sources:
        if not isinstance(src, dict):
            continue
        for k, mapped in _clean_known_placeholder_map(src.get("known_placeholder_models")).items():
            if k.upper() == target_up:
                return mapped
    return ""


def _parse_iso_ts(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def compute_seed_digest(seed: Dict[str, Any]) -> str:
    canonical: Dict[str, Any] = {
        "last_audited_model": seed.get("last_audited_model"),
        "last_model_slug": seed.get("last_model_slug"),
        "last_pbtxt_model": seed.get("last_pbtxt_model"),
        "environment_Target": seed.get("environment_Target"),
        "builtin_skills_hash": seed.get("builtin_skills_hash"),
        "recorded_builtin_skills": seed.get("recorded_builtin_skills"),
        "tracked_repositories": seed.get("tracked_repositories"),
    }
    if "approved_customization_models" in seed:
        canonical["approved_customization_models"] = seed.get("approved_customization_models")
    if "known_placeholder_models" in seed:
        canonical["known_placeholder_models"] = seed.get("known_placeholder_models")
    if "builtin_bundle_checksum" in seed:
        canonical["builtin_bundle_checksum"] = seed.get("builtin_bundle_checksum")
    if "model_compaction_ceilings" in seed:
        canonical["model_compaction_ceilings"] = seed.get("model_compaction_ceilings")
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def reconcile_state_with_seed(state: Dict[str, Any], seed: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """
    Merges missing or newer baseline entries from `upstream_state.seed.json` into `state`
    without letting an operator `last_ack_timestamp` permanently lock out newer shipped
    seed model or repository baselines.
    """
    if not isinstance(state, dict) or not isinstance(seed, dict) or not seed:
        return state, False

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
    changed = False
    seed_digest = compute_seed_digest(seed)
    prev_seed_digest = state.get("_reconciled_seed_digest")
    has_prev_digest = isinstance(prev_seed_digest, str) and bool(prev_seed_digest)
    seed_changed = (prev_seed_digest != seed_digest) if has_prev_digest else False

    seed_ts = _parse_iso_ts(seed.get("last_audit_timestamp") or seed.get("last_skills_audit_timestamp"))
    state_ts = _parse_iso_ts(state.get("last_audit_timestamp") or state.get("last_skills_audit_timestamp"))
    ack_ts = _parse_iso_ts(state.get("last_ack_timestamp"))

    seed_newer_than_ack = ack_ts is None or (seed_ts is not None and seed_ts > ack_ts)
    seed_newer_than_audit = state_ts is None or (seed_ts is not None and seed_ts > state_ts)

    # Builtin skill & bundle baselines: respect a newer operator --ack unless the shipped seed itself changed afterwards.
    if seed_changed or (not has_prev_digest and seed_newer_than_ack):
        for k in ("builtin_skills_hash", "recorded_builtin_skills"):
            if k in seed and state.get(k) != seed.get(k):
                state[k] = copy.deepcopy(seed[k])
                changed = True
        raw_seed_bundle_cs = seed.get("builtin_bundle_checksum")
        if isinstance(raw_seed_bundle_cs, str):
            clean_bundle_cs = raw_seed_bundle_cs.strip()
            if clean_bundle_cs and BUILTIN_CHECKSUM_RE.fullmatch(clean_bundle_cs) and state.get("builtin_bundle_checksum") != clean_bundle_cs:
                state["builtin_bundle_checksum"] = clean_bundle_cs
                changed = True
    elif (
        isinstance(seed.get("builtin_bundle_checksum"), str)
        and BUILTIN_CHECKSUM_RE.fullmatch(seed["builtin_bundle_checksum"].strip())
        and "builtin_bundle_checksum" not in state
    ):
        state["builtin_bundle_checksum"] = seed["builtin_bundle_checksum"].strip()
        changed = True

    # Model & environment baselines: never let an earlier/unrelated ack lock out a newer seed audit.
    if seed_changed or (not has_prev_digest and (seed_newer_than_ack or seed_newer_than_audit)):
        seed_model = _clean_model_name(seed.get("last_audited_model"))
        if seed_model and state.get("last_audited_model") != seed_model:
            state["last_audited_model"] = seed_model
            state["current_model"] = seed_model
            seen_model = _clean_model_name(state.get("last_seen_model"))
            if seen_model and seen_model != seed_model:
                state.pop("last_seen_model", None)
            changed = True
        seed_slug = seed.get("last_model_slug")
        target_slug = (
            seed_slug.strip()
            if isinstance(seed_slug, str) and seed_slug.strip()
            else (re.sub(r"[^a-z0-9.]+", "-", seed_model.lower()).strip("-") if seed_model else "")
        )
        if target_slug and state.get("last_model_slug") != target_slug:
            state["last_model_slug"] = target_slug
            changed = True
        raw_seed_pbtxt = seed.get("last_pbtxt_model")
        seed_pbtxt = raw_seed_pbtxt.strip() if isinstance(raw_seed_pbtxt, str) and raw_seed_pbtxt.strip() else ""
        if seed_pbtxt:
            is_seed_ph = seed_pbtxt.upper().startswith("MODEL_PLACEHOLDER")
            if (not is_seed_ph or not _clean_model_name(state.get("last_pbtxt_model"))) and state.get("last_pbtxt_model") != seed_pbtxt:
                state["last_pbtxt_model"] = seed_pbtxt
                changed = True
        if "environment_Target" in seed and state.get("environment_Target") != seed.get("environment_Target"):
            state["environment_Target"] = seed["environment_Target"]
            changed = True
    elif not _clean_model_name(state.get("last_audited_model")) and _clean_model_name(seed.get("last_audited_model")):
        seed_model = _clean_model_name(seed.get("last_audited_model"))
        state["last_audited_model"] = seed_model
        seed_slug = seed.get("last_model_slug")
        target_slug = (
            seed_slug.strip()
            if isinstance(seed_slug, str) and seed_slug.strip()
            else re.sub(r"[^a-z0-9.]+", "-", seed_model.lower()).strip("-")
        )
        if not state.get("last_model_slug") and target_slug:
            state["last_model_slug"] = target_slug
        raw_seed_pbtxt = seed.get("last_pbtxt_model")
        seed_pbtxt = raw_seed_pbtxt.strip() if isinstance(raw_seed_pbtxt, str) and raw_seed_pbtxt.strip() else ""
        if not _clean_model_name(state.get("last_pbtxt_model")) and seed_pbtxt:
            state["last_pbtxt_model"] = seed_pbtxt
        if isinstance(seed.get("approved_customization_models"), list) and "approved_customization_models" not in state:
            state["approved_customization_models"] = [
                m for m in seed["approved_customization_models"] if isinstance(m, str) and m.strip()
            ]
        if isinstance(seed.get("known_placeholder_models"), dict) and "known_placeholder_models" not in state:
            state["known_placeholder_models"] = _clean_known_placeholder_map(seed["known_placeholder_models"])
        changed = True
    elif isinstance(seed.get("known_placeholder_models"), dict) and "known_placeholder_models" not in state:
        state["known_placeholder_models"] = _clean_known_placeholder_map(seed["known_placeholder_models"])
        changed = True

    if seed_changed or not has_prev_digest:
        if isinstance(seed.get("approved_customization_models"), list):
            clean_acm = [m for m in seed["approved_customization_models"] if isinstance(m, str) and m.strip()]
            if state.get("approved_customization_models") != clean_acm:
                state["approved_customization_models"] = clean_acm
                changed = True
        if isinstance(seed.get("known_placeholder_models"), dict) and (
            state.get("known_placeholder_models") is None
            or isinstance(state.get("known_placeholder_models"), dict)
        ):
            clean_kpm = _clean_known_placeholder_map(seed["known_placeholder_models"])
            if state.get("known_placeholder_models") != clean_kpm:
                state["known_placeholder_models"] = clean_kpm
                changed = True
        if isinstance(seed.get("model_compaction_ceilings"), dict) and (
            state.get("model_compaction_ceilings") is None
            or isinstance(state.get("model_compaction_ceilings"), dict)
        ):
            clean_mcc = _clean_compaction_ceilings(seed["model_compaction_ceilings"])
            if clean_mcc and state.get("model_compaction_ceilings") != clean_mcc:
                state["model_compaction_ceilings"] = clean_mcc
                changed = True
    elif isinstance(seed.get("model_compaction_ceilings"), dict) and "model_compaction_ceilings" not in state:
        clean_mcc = _clean_compaction_ceilings(seed["model_compaction_ceilings"])
        if clean_mcc:
            state["model_compaction_ceilings"] = clean_mcc
            changed = True

    if seed_ts is not None and (state_ts is None or seed_ts > state_ts):
        if seed.get("last_audit_timestamp") and state.get("last_audit_timestamp") != seed.get("last_audit_timestamp"):
            state["last_audit_timestamp"] = seed["last_audit_timestamp"]
            changed = True
        seed_skills_ts = _parse_iso_ts(seed.get("last_skills_audit_timestamp"))
        cur_skills_ts = _parse_iso_ts(state.get("last_skills_audit_timestamp"))
        if seed_skills_ts is not None and (cur_skills_ts is None or seed_skills_ts > cur_skills_ts):
            state["last_skills_audit_timestamp"] = seed["last_skills_audit_timestamp"]
            state.pop("last_audit_failed", None)
            changed = True

    if "skills_audit_interval_hours" not in state and "skills_audit_interval_hours" in seed:
        state["skills_audit_interval_hours"] = seed["skills_audit_interval_hours"]
        changed = True

    seed_repos = seed.get("tracked_repositories")
    if isinstance(seed_repos, dict):
        if not had_explicit_repos:
            state["tracked_repositories"] = {}
            changed = True
        state_repos = state.get("tracked_repositories")
        if isinstance(state_repos, dict):
            pending = state.get("pending_repo_updates")
            can_sync_existing = seed_changed or (
                not has_prev_digest and (seed_ts is None or state_ts is None or seed_ts >= state_ts)
            )
            for name, seed_info in seed_repos.items():
                if not isinstance(seed_info, dict):
                    continue
                cur = state_repos.get(name)
                if name not in state_repos:
                    if (not had_explicit_repos) or is_full_ledger:
                        state_repos[name] = copy.deepcopy(seed_info)
                        changed = True
                elif isinstance(cur, dict) and can_sync_existing:
                    for rk in ("repo", "branch", "track", "path", "last_synced_commit", "target_skills"):
                        if rk in seed_info:
                            if cur.get(rk) != seed_info.get(rk):
                                cur[rk] = copy.deepcopy(seed_info[rk])
                                changed = True
                        elif rk in ("track", "path") and rk in cur:
                            cur.pop(rk, None)
                            changed = True
                    if isinstance(pending, dict) and name in pending:
                        pend_entry = pending.get(name)
                        if isinstance(pend_entry, dict) and sha_matches(
                            str(seed_info.get("last_synced_commit", "")),
                            str(pend_entry.get("remote", "")),
                        ):
                            pending.pop(name, None)
                            changed = True
                elif isinstance(cur, dict) and "target_skills" in seed_info:
                    if cur.get("target_skills") != seed_info.get("target_skills"):
                        cur["target_skills"] = copy.deepcopy(seed_info["target_skills"])
                        changed = True
            if seed_repos:
                for retired_name, retired_repo in (("procoder", "azrtydxb/procoder"),):
                    if retired_name in state_repos and retired_name not in seed_repos:
                        retired_entry = state_repos.get(retired_name)
                        if isinstance(retired_entry, dict) and str(retired_entry.get("repo", "")).strip() == retired_repo:
                            state_repos.pop(retired_name, None)
                            if isinstance(pending, dict):
                                pending.pop(retired_name, None)
                            changed = True

    tracked_schema_ok = not isinstance(seed_repos, dict) or isinstance(state.get("tracked_repositories"), dict)
    kpm_schema_ok = state.get("known_placeholder_models") is None or isinstance(
        state.get("known_placeholder_models"), dict
    )
    mcc_schema_ok = state.get("model_compaction_ceilings") is None or isinstance(
        state.get("model_compaction_ceilings"), dict
    )
    if tracked_schema_ok and kpm_schema_ok and mcc_schema_ok and state.get("_reconciled_seed_digest") != seed_digest:
        state["_reconciled_seed_digest"] = seed_digest
        changed = True

    return state, changed


class UpstreamAuditorBridge:
    """
    Proactively checks the 8 tracked community repositories and active model status
    without requiring LLM token expenditure.
    """

    SYSTEM_SHARE_SEED = Path("/usr/share/antigravity-harness/skills/upstream-auditor/upstream_state.seed.json")

    def __init__(self, target_dir: Optional[Path] = None):
        explicit_target = target_dir is not None or bool(os.environ.get("ANTIGRAVITY_CONFIG_DIR"))
        if target_dir is None:
            config_env = os.environ.get("ANTIGRAVITY_CONFIG_DIR")
            self.target_dir = Path(config_env).resolve() if config_env else Path.home() / ".gemini" / "config"
        else:
            self.target_dir = Path(target_dir).resolve()

        from guard.paths import state_dir

        default_state_dir = state_dir()
        skill_dir = self.target_dir / "skills" / "upstream-auditor"
        seed_candidates: List[Path] = [(skill_dir / "upstream_state.seed.json").resolve()]
        share_env = os.environ.get("ANTIGRAVITY_SHARE_DIR")
        if share_env:
            seed_candidates.append(
                (Path(share_env).expanduser() / "skills" / "upstream-auditor" / "upstream_state.seed.json").resolve()
            )
        elif not explicit_target:
            seed_candidates.append(self.SYSTEM_SHARE_SEED)
        self.seed_file: Optional[Path] = next((p for p in seed_candidates if p.is_file()), None)

        state_file_env = os.environ.get("UPSTREAM_STATE_FILE")
        if state_file_env:
            self.state_file = Path(state_file_env).resolve()
        else:
            candidate_state = (default_state_dir / "upstream_state.json").resolve()
            legacy_state = (skill_dir / "upstream_state.json").resolve()
            if candidate_state.is_file():
                self.state_file = candidate_state
            elif legacy_state.is_file():
                self.state_file = legacy_state
            elif self.seed_file is not None:
                self.state_file = self.seed_file
            else:
                self.state_file = candidate_state
        self.last_load_error: Optional[str] = None
        self.last_seed_error: Optional[str] = None

    def _load_seed(self) -> Dict[str, Any]:
        self.last_seed_error = None
        if self.seed_file is None or not self.seed_file.is_file():
            return {}
        try:
            data = json.loads(self.seed_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                self.last_seed_error = f"Upstream seed file {self.seed_file} is not a JSON object."
                return {}
            return data
        except (OSError, ValueError) as exc:
            self.last_seed_error = f"Corrupt or unreadable upstream seed file {self.seed_file}: {exc}"
            return {}

    def load_state(self) -> Dict[str, Any]:
        """Loads state from upstream_state.json (reconciled against upstream_state.seed.json) or defaults."""
        self.last_load_error = None
        seed = self._load_seed()
        if self.state_file.is_file():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if not isinstance(data, dict):
                    raise ValueError("upstream state root is not a JSON object")
                if seed and self.seed_file != self.state_file:
                    data, _ = reconcile_state_with_seed(data, seed)
                return data
            except (OSError, ValueError) as exc:
                self.last_load_error = f"Corrupt or unreadable upstream state file {self.state_file}: {exc}"
        elif seed:
            return copy.deepcopy(seed)

        # Default fallback tracked repositories (aligned with upstream_state.seed.json)
        return {
            "last_skills_audit_timestamp": None,
            "skills_audit_interval_hours": 72,
            "approved_customization_models": [
                "gemini-4-neon-xhigh",
                "gemini-4-carbon-high",
            ],
            "known_placeholder_models": dict(DEFAULT_KNOWN_PLACEHOLDER_MODELS),
            "model_compaction_ceilings": dict(DEFAULT_MODEL_COMPACTION_CEILINGS),
            "builtin_bundle_checksum": DEFAULT_BUILTIN_BUNDLE_CHECKSUM,
            "recorded_builtin_skills": list(KNOWN_BUILTIN_SKILLS),
            "tracked_repositories": {
                "anti-slop": {
                    "repo": "miqdadbadjuber/anti-slop",
                    "branch": "main",
                    "last_synced_commit": "35b54dc",
                    "target_skills": ["antislop"],
                },
                "Chisle": {
                    "repo": "JayPokale/Chisle",
                    "branch": "main",
                    "last_synced_commit": "b2e1658",
                    "target_skills": ["chisle"],
                },
                "unlazy": {
                    "repo": "Leonxlnx/unlazy",
                    "branch": "main",
                    "last_synced_commit": "1667149",
                    "target_skills": ["skills/harness/references/unlazy.md"],
                },
                "silk-design": {
                    "repo": "bendrape1-byte/silk-design",
                    "branch": "main",
                    "last_synced_commit": "0f530f0",
                    "target_skills": ["skills/antislop/references/silk-design.md"],
                },
                "everything-claude-code": {
                    "repo": "affaan-m/everything-claude-code",
                    "branch": "main",
                    "last_synced_commit": "d2ef268",
                    "target_skills": [
                        "database-migrations",
                        "skills/harness/references/adr.md",
                        "skills/audit/references/security-review.md",
                        "agents/build-error-resolver.md",
                    ],
                },
                "mattpocock-skills": {
                    "repo": "mattpocock/skills",
                    "branch": "main",
                    "last_synced_commit": "5863806",
                    "target_skills": ["deep-grill", "diagnosing-bugs", "skills/harness/references/test-design.md", "retro"],
                },
                "rea": {
                    "repo": "morluto/rea",
                    "branch": "main",
                    "track": "release",
                    "last_synced_commit": "rea-agents-6.9.0",
                    "target_skills": ["reverse-engineer-anything"],
                },
                "rust-anything": {
                    "repo": "erkamyaman/rust-anything",
                    "branch": "main",
                    "track": "release",
                    "last_synced_commit": "v2.1.0",
                    "target_skills": ["rustify", "rust-harden"],
                },
            },
        }

    def check_repositories(self, timeout: float = 3.0) -> List[Dict[str, Any]]:
        """Queries tracked repositories in parallel to detect upstream commit drift."""
        state = self.load_state()
        if self.last_load_error:
            return [
                {
                    "name": "<upstream_state>",
                    "repo": "",
                    "branch": "",
                    "local_sha": "",
                    "remote_sha": "",
                    "status": f"Invalid state ledger: {self.last_load_error}",
                    "commit_message": "",
                }
            ]
        tracked = state.get("tracked_repositories", {})
        if not isinstance(tracked, dict):
            return [
                {
                    "name": "<tracked_repositories>",
                    "repo": "",
                    "branch": "",
                    "local_sha": "",
                    "remote_sha": "",
                    "status": "Invalid tracked_repositories schema",
                    "commit_message": "",
                }
            ]
        results: List[Dict[str, Any]] = []

        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not token:
            try:
                p = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=2)
                if p.returncode == 0 and p.stdout.strip():
                    token = p.stdout.strip()
            except Exception:
                pass

        from guard import __version__

        def query_repo(name: str, info: dict) -> Dict[str, Any]:
            if not isinstance(info, dict):
                return {"name": str(name), "repo": "", "branch": "", "local_sha": "",
                        "remote_sha": "", "status": "Invalid repository entry", "commit_message": ""}
            repo = str(info.get("repo", "")).strip()
            branch = str(info.get("branch", "main")).strip() or "main"
            track = str(info.get("track", "commits")).strip().lower()
            subpath = str(info.get("path", "")).strip()
            recorded_raw = str(info.get("last_synced_commit", "")).strip()
            local_sha = short_ref(recorded_raw)
            if not REPO_RE.fullmatch(repo):
                return {"name": name, "repo": repo, "branch": branch, "local_sha": local_sha,
                        "remote_sha": "", "status": "Invalid repository id", "commit_message": ""}
            if track == "release":
                url = f"https://api.github.com/repos/{repo}/releases/latest"
            elif track == "commits":
                params = {"sha": branch, "per_page": 1}
                if subpath:
                    if not _valid_subpath(subpath):
                        return {"name": name, "repo": repo, "branch": branch, "local_sha": local_sha,
                                "remote_sha": "", "status": "Invalid repository path", "commit_message": ""}
                    params["path"] = subpath
                url = f"https://api.github.com/repos/{repo}/commits?{urllib.parse.urlencode(params)}"
            else:
                return {"name": name, "repo": repo, "branch": branch, "local_sha": local_sha,
                        "remote_sha": "", "status": "Invalid track mode", "commit_message": ""}
            user_agent = f"AntigravityGuard-Watchdog/{__version__}"
            max_bytes = 262_144

            remote_sha = ""
            status = "Unknown"
            commit_msg = ""

            try:
                parsed_url = urllib.parse.urlparse(url)
                if parsed_url.scheme != "https" or (parsed_url.hostname or "").lower() != "api.github.com":
                    raise ValueError(f"Disallowed upstream endpoint: {url}")
                from porter.net import safe_fetch_url

                raw_text = safe_fetch_url(
                    url,
                    user_agent=user_agent,
                    timeout=timeout,
                    max_bytes=max_bytes,
                    headers={"Authorization": f"token {token}"} if token else None,
                )
                data = json.loads(raw_text)
                if track == "release" and isinstance(data, dict):
                    remote_raw = str(data.get("tag_name", "")).strip()
                    remote_sha = short_ref(remote_raw)
                    commit_msg = str(data.get("name") or remote_raw or "").splitlines()[0] if (data.get("name") or remote_raw) else ""
                    if recorded_raw and remote_raw:
                        status = "Up-to-date" if sha_matches(recorded_raw, remote_raw) else "Updates Available"
                    elif remote_raw:
                        status = "Remote Found"
                elif track == "commits" and data and isinstance(data, list):
                    remote_raw = str(data[0]["sha"]).strip()
                    remote_sha = short_ref(remote_raw)
                    commit_msg = data[0].get("commit", {}).get("message", "").splitlines()[0]
                    if recorded_raw and remote_raw:
                        status = "Up-to-date" if sha_matches(recorded_raw, remote_raw) else "Updates Available"
                    else:
                        status = "Remote Found"
            except urllib.error.HTTPError as e:
                try:
                    status = f"HTTP Error {e.code}"
                finally:
                    e.close()
            except Exception as e:
                status = f"Network Error ({type(e).__name__})"

            return {
                "name": name,
                "repo": repo,
                "branch": branch,
                "local_sha": local_sha,
                "remote_sha": remote_sha,
                "status": status,
                "commit_message": commit_msg,
            }

        with ThreadPoolExecutor(max_workers=min(len(tracked) or 1, 10)) as executor:
            future_to_name = {executor.submit(query_repo, name, info): name for name, info in tracked.items()}
            for future in as_completed(future_to_name):
                try:
                    results.append(future.result())
                except Exception as exc:
                    rname = str(future_to_name.get(future, "unknown"))
                    results.append(
                        {
                            "name": rname,
                            "repo": "",
                            "branch": "",
                            "local_sha": "",
                            "remote_sha": "",
                            "status": f"Worker Error ({type(exc).__name__})",
                            "commit_message": "",
                        }
                    )

        # Sort results deterministically by name
        results.sort(key=lambda x: x["name"])
        return results

    def _get_pbtxt_model(self) -> str:
        """Reads last_selected_agent_model from antigravity_state.pbtxt adjacent to target_dir."""
        pbtxt_env = os.environ.get("ANTIGRAVITY_PBTXT_FILE")
        pbtxt_path = Path(pbtxt_env).expanduser() if pbtxt_env else (self.target_dir.parent / "antigravity" / "antigravity_state.pbtxt")
        if not pbtxt_path.is_file():
            return ""
        try:
            with open(pbtxt_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if "last_selected_agent_model" in line and ":" in line:
                        return line.split(":", 1)[1].strip().strip('"')
        except OSError:
            pass
        return ""

    def get_model_drift_status(self) -> Dict[str, str]:
        """Reports the active model ONLY when it is actually known; nothing here is inferred."""
        env_model = _clean_model_name(os.environ.get("ANTIGRAVITY_MODEL"))
        raw_pbtxt = self._get_pbtxt_model()
        pbtxt_model = _clean_model_name(raw_pbtxt)
        state = self.load_state()
        seed = self._load_seed()
        mapped_pbtxt = _lookup_known_placeholder(raw_pbtxt, state, seed) if not pbtxt_model else ""
        recorded = (
            _clean_model_name(state.get("last_seen_model"))
            or _clean_model_name(state.get("current_model"))
            or _clean_model_name(state.get("last_audited_model"))
            or _clean_model_name(state.get("last_pbtxt_model"))
            or _lookup_known_placeholder(state.get("last_pbtxt_model"), state, seed)
        )
        if env_model:
            active_model, source = env_model, "ANTIGRAVITY_MODEL environment variable"
        elif pbtxt_model:
            active_model, source = pbtxt_model, "antigravity_state.pbtxt"
        elif mapped_pbtxt:
            active_model, source = mapped_pbtxt, f"antigravity_state.pbtxt ({raw_pbtxt.strip()} via known_placeholder_models)"
        elif recorded:
            active_model, source = str(recorded), "last value recorded by the upstream watcher"
        else:
            active_model, source = "Unknown (not detected)", "none"
        tracked_raw = state.get("tracked_repositories", {})
        tracked_count = len(tracked_raw) if isinstance(tracked_raw, dict) else 0
        out = {
            "active_model": active_model,
            "model_source": source,
            "context_saturation_guard": "Constitution rule (turn count is not measured by Guard)",
            "tracked_ecosystems": str(tracked_count),
        }
        if self.last_load_error:
            out["state_error"] = self.last_load_error
        return out

    def get_summary(self) -> Dict[str, Any]:
        """Returns a health and synchronization summary surfacing corrupt state and failed audits."""
        model_info = self.get_model_drift_status()
        state = self.load_state()
        corrupt = bool(self.last_load_error)
        audit_failed = bool(state.get("last_audit_failed", False))
        warnings: List[str] = []
        if corrupt and self.last_load_error:
            warnings.append(self.last_load_error)
        if self.last_seed_error:
            warnings.append(self.last_seed_error)
        schema_mismatch = False
        tracked_raw = state.get("tracked_repositories", {})
        if not isinstance(tracked_raw, dict):
            schema_mismatch = True
            warnings.append(f"Upstream state field 'tracked_repositories' in {self.state_file} is not a JSON object.")
            tracked_count = 0
        else:
            tracked_count = len(tracked_raw)
        pending_raw = state.get("pending_repo_updates", {})
        if pending_raw is not None and not isinstance(pending_raw, dict):
            schema_mismatch = True
            warnings.append(f"Upstream state field 'pending_repo_updates' in {self.state_file} is not a JSON object.")
        kpm_raw = state.get("known_placeholder_models")
        if kpm_raw is not None and not isinstance(kpm_raw, dict):
            schema_mismatch = True
            warnings.append(f"Upstream state field 'known_placeholder_models' in {self.state_file} is not a JSON object.")
        mcc_raw = state.get("model_compaction_ceilings")
        if mcc_raw is not None and not isinstance(mcc_raw, dict):
            schema_mismatch = True
            warnings.append(f"Upstream state field 'model_compaction_ceilings' in {self.state_file} is not a JSON object.")
        elif isinstance(mcc_raw, dict) and mcc_raw and len(_clean_compaction_ceilings(mcc_raw)) < len(mcc_raw):
            schema_mismatch = True
            warnings.append(
                f"Upstream state field 'model_compaction_ceilings' in {self.state_file} contains invalid or out-of-range entries."
            )
        raw_rec_bundle = state.get("builtin_bundle_checksum")
        if raw_rec_bundle is not None and not isinstance(raw_rec_bundle, str):
            schema_mismatch = True
            warnings.append(f"Upstream state field 'builtin_bundle_checksum' in {self.state_file} is not a string.")
        recorded_bundle_cs = raw_rec_bundle.strip() if isinstance(raw_rec_bundle, str) else ""
        current_bundle_cs, bundle_cs_err = read_builtin_bundle_checksum_checked()
        if bundle_cs_err:
            warnings.append(f"Antigravity builtin/.checksum error: {bundle_cs_err}")
        builtin_bundle_drift = bool(recorded_bundle_cs and current_bundle_cs and current_bundle_cs != recorded_bundle_cs)
        if builtin_bundle_drift:
            warnings.append(
                f"Delta detected in Antigravity builtin bundle (builtin/.checksum: "
                f"{short_checksum(recorded_bundle_cs, peer=current_bundle_cs)} -> "
                f"{short_checksum(current_bundle_cs, peer=recorded_bundle_cs)})."
            )
        if audit_failed:
            warnings.append(f"Last upstream repository check failed in {self.state_file}.")
        if corrupt:
            status = "FAIL"
        elif audit_failed or schema_mismatch or bool(self.last_seed_error) or builtin_bundle_drift or bool(bundle_cs_err):
            status = "WARN"
        else:
            status = "OK"
        return {
            "status": status,
            "state_file": str(self.state_file),
            "state_corrupt": corrupt,
            "last_audit_failed": audit_failed,
            "last_checked_iso": state.get("last_checked_iso") or state.get("last_skills_audit_timestamp"),
            "active_model": model_info["active_model"],
            "tracked_count": tracked_count,
            "builtin_bundle_checksum": (current_bundle_cs or recorded_bundle_cs) if not bundle_cs_err else "",
            "builtin_bundle_drift": builtin_bundle_drift,
            "warnings": warnings,
        }

    def acknowledge_drift(
        self,
        model_name: Optional[str] = None,
        *,
        acknowledged_model: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Records the current model and upstream state as reviewed in upstream_state.json."""
        from guard.paths import atomic_write_json, file_lock, state_dir

        dest = self.state_file
        if "UPSTREAM_STATE_FILE" not in os.environ or dest.name == "upstream_state.seed.json":
            dest = (state_dir() / "upstream_state.json").resolve()
            self.state_file = dest
        try:
            with file_lock(dest):
                return self._acknowledge_drift_locked(
                    dest,
                    model_name=model_name,
                    acknowledged_model=acknowledged_model,
                    atomic_write_json_fn=atomic_write_json,
                )
        except (OSError, TimeoutError) as e:
            return False, f"Could not lock upstream state {dest}: {e}"

    def _acknowledge_drift_locked(
        self,
        dest: Path,
        *,
        model_name: Optional[str],
        acknowledged_model: Optional[str],
        atomic_write_json_fn: Any,
    ) -> tuple[bool, str]:
        atomic_write_json = atomic_write_json_fn

        state = self.load_state()
        if self.last_load_error:
            return False, f"Cannot acknowledge drift while upstream state is corrupt: {self.last_load_error}"
        pbtxt_model = self._get_pbtxt_model()
        raw_seen = state.get("last_seen_model")
        seen_clean = _clean_model_name(raw_seen)
        seen_model = "" if seen_clean.lower() == "auto" else seen_clean
        clean_pbtxt_raw = _clean_model_name(pbtxt_model)
        clean_pbtxt = "" if clean_pbtxt_raw.lower() == "auto" else clean_pbtxt_raw
        seed = self._load_seed()
        mapped_pbtxt = _lookup_known_placeholder(pbtxt_model, state, seed) if not clean_pbtxt else ""
        raw_explicit = model_name if model_name is not None else acknowledged_model
        explicit_str = raw_explicit.strip() if isinstance(raw_explicit, str) else ""
        explicit_clean = _clean_model_name(explicit_str)
        if explicit_clean.lower() == "auto":
            explicit_clean = ""
        explicit_mapped = _lookup_known_placeholder(explicit_str, state, seed) if not explicit_clean else ""
        env_raw = os.environ.get("ANTIGRAVITY_MODEL", "").strip()
        env_clean = _clean_model_name(env_raw)
        if env_clean.lower() == "auto":
            env_clean = ""
        env_mapped = _lookup_known_placeholder(env_raw, state, seed) if not env_clean else ""
        audited_clean = _clean_model_name(state.get("last_audited_model"))
        if audited_clean.lower() == "auto":
            audited_clean = ""
        resolved_model = (
            explicit_clean
            or explicit_mapped
            or env_clean
            or env_mapped
            or ("" if explicit_str.upper().startswith("MODEL_PLACEHOLDER") else seen_model)
            or clean_pbtxt
            or mapped_pbtxt
            or audited_clean
        )
        if resolved_model and resolved_model.lower() != "auto":
            state["last_audited_model"] = resolved_model
            state["current_model"] = resolved_model
            state["last_model_slug"] = re.sub(r"[^a-z0-9.]+", "-", resolved_model.lower()).strip("-")
        if explicit_str.upper().startswith("MODEL_PLACEHOLDER"):
            state["last_pbtxt_model"] = explicit_str
        elif pbtxt_model:
            state["last_pbtxt_model"] = pbtxt_model

        reasons: list[str] = []
        if (
            seen_model
            and seen_model.lower() != "auto"
            and resolved_model
            and resolved_model.lower() != "auto"
            and re.sub(r"\s+", " ", seen_model.lower()) != re.sub(r"\s+", " ", resolved_model.lower())
        ):
            reasons.append(f"Model change: '{resolved_model}' -> '{seen_model}'")

        builtin_dir = Path(
            os.environ.get("ANTIGRAVITY_BUILTIN_SKILLS_DIR")
            or (Path.home() / ".gemini" / "antigravity" / "builtin" / "skills")
        ).expanduser()
        custom_skills_dir = self.target_dir / "skills"
        if builtin_dir.is_dir() and custom_skills_dir.is_dir():
            try:
                builtin_set = {p.name for p in builtin_dir.iterdir() if p.is_dir()}
                custom_set = {p.name for p in custom_skills_dir.iterdir() if p.is_dir() or p.is_symlink()}
                collisions = sorted(builtin_set & custom_set)
                if collisions:
                    reasons.append(f"Namespace collision / shadowing detected: {', '.join(collisions)}")
            except OSError as e:
                return False, f"Could not inspect builtin/custom skills directories: {e}"

        if builtin_dir.is_dir():
            try:
                builtin_names = sorted(p.name for p in builtin_dir.iterdir() if p.is_dir())
                state["recorded_builtin_skills"] = builtin_names
                hasher = hashlib.sha256()
                for root, dirs, files in os.walk(builtin_dir):
                    dirs.sort()
                    for fname in sorted(files):
                        fpath = Path(root) / fname
                        rel = os.path.relpath(fpath, builtin_dir)
                        hasher.update(rel.encode("utf-8"))
                        try:
                            with open(fpath, "rb") as fh:
                                for chunk in iter(lambda: fh.read(65536), b""):
                                    hasher.update(chunk)
                        except OSError:
                            hasher.update(b"<unreadable>")
                state["builtin_skills_hash"] = hasher.hexdigest()
            except OSError as e:
                return False, f"Could not hash builtin skills directory {builtin_dir}: {e}"

        current_bundle_cs, bundle_cs_err = read_builtin_bundle_checksum_checked(builtin_dir)
        if bundle_cs_err:
            return False, f"Could not verify builtin/.checksum: {bundle_cs_err}"
        recorded_bundle_cs = str(state.get("builtin_bundle_checksum", "") or "").strip()
        if recorded_bundle_cs and current_bundle_cs and current_bundle_cs != recorded_bundle_cs:
            reasons.append(
                f"Delta detected in Antigravity builtin bundle (builtin/.checksum: "
                f"{short_checksum(recorded_bundle_cs, peer=current_bundle_cs)} -> "
                f"{short_checksum(current_bundle_cs, peer=recorded_bundle_cs)}; inspect builtin/plugins & sidecars)"
            )
        if current_bundle_cs:
            state["builtin_bundle_checksum"] = current_bundle_cs

        tracked = state.get("tracked_repositories") or {}
        pending = state.setdefault("pending_repo_updates", {})
        if isinstance(pending, dict) and isinstance(tracked, dict):
            updates = []
            for name in sorted(pending):
                entry, info = pending.get(name), tracked.get(name)
                if not isinstance(entry, dict) or not isinstance(info, dict):
                    continue
                recorded = str(entry.get("recorded", ""))
                if str(info.get("last_synced_commit", "")).strip() != recorded:
                    continue
                updates.append(f"{name} ({short_ref(recorded)}->{short_ref(entry.get('remote', ''))})")
            if updates:
                reasons.append(f"New commits in tracked repositories ({', '.join(updates)})")

        def _fp(text: str) -> str:
            return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

        state["acknowledged_reasons"] = sorted({_fp(r) for r in reasons})
        state["acknowledged_signature"] = _fp("\n".join(state["acknowledged_reasons"])) if state["acknowledged_reasons"] else ""
        state["last_ack_timestamp"] = datetime.now(timezone.utc).isoformat()
        seed = self._load_seed()
        if seed:
            state["_reconciled_seed_digest"] = compute_seed_digest(seed)

        try:
            atomic_write_json(dest, state)
            return True, f"Acknowledged upstream state in {dest} (model: {state.get('last_audited_model') or 'unchanged'})."
        except OSError as e:
            return False, f"Could not write upstream state to {dest}: {e}"


UpstreamMonitor = UpstreamAuditorBridge


