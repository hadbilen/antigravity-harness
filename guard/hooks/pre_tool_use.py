"""
guard/hooks/pre_tool_use.py — PreToolUse core router, governance/customization shield & lazy tool-scoped dispatcher (ADR-0008, ADR-0013).
Part of Plumbwork (https://github.com/hadbilen/plumbwork)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from guard.paths import HOOK_LOCK_TIMEOUT, is_within, read_json

from .common import (
    _CONV_ID_FALLBACK_RE,
    _FENCE_RE,
    _HARNESS_PLUGIN_NAMES,
    _HEX_OID_RE,
    _INLINE_TAG_CODE_RE,
    _PASTED_RE,
    _UNRECOVERED_FLIGHT_STATES,
    _LazyRegex,
    _conversation_id,
    _extract_ws_flight_conversations,
    _facade,
    _facade_attr,
    _flight_recorder_file,
    _is_git_repo_workspace,
    _is_harness_repo_root,
    _iter_jsonl_tail_entries,
    _read_ledger_checked,
    _read_ledger_safe,
    _rebuild_ws_flight_entry,
    _repo_root,
    _safe_int,
    _upstream_seed_candidates,
    _utc_now_iso,
    _workspaces_from_payload,
    atomic_write_json,
    config_dir,
    configured_config_dir,
    data_dir,
    file_lock,
    json,
    state_dir,
    subprocess,
)


# File-mutating tool names in Antigravity 2.0 and portable agent environments
WRITE_TOOL_NAMES = frozenset({
    "write_to_file",
    "write_file",
    "replace_file_content",
    "multi_replace_file_content",
    "edit_file",
    "create_file",
    "write",
    "edit",
    "multiedit",
    "notebookedit",
})

COMMAND_TOOL_NAMES = frozenset({
    "run_command",
    "bash",
    "execute_command",
    "shell",
    "send_command_input",
    "manage_task",
})

HIGH_RISK_MCP_TOOL_NAMES = frozenset({
    "execute_rizin_command",
    "gdb_console",
    "rizin_debug_command",
    "cutter_command",
    "instrument_with_frida",
    "load_frida_script",
})

def _active_artifact_dir(payload: Dict[str, Any]) -> Optional[Path]:
    """
    Returns the active conversation's own non-symlink `artifactDirectoryPath` (rejecting governance
    roots, root/home/brain container dirs, `..` traversal, and cross-conversation brain paths).
    """
    conv_id = _conversation_id(payload)
    home = Path.home()
    brain_root = home / ".gemini" / "antigravity" / "brain"
    forbidden_roots: set[str] = set()
    for fr in (Path("/"), home, home / ".gemini", home / ".gemini" / "antigravity", brain_root):
        try:
            forbidden_roots.add(str(fr.resolve()))
        except (OSError, RuntimeError):
            forbidden_roots.add(os.path.abspath(str(fr)))

    raw_explicit = ""
    for key in ("artifactDirectoryPath", "artifact_directory_path", "artifactDir", "artifact_dir"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            raw_explicit = val.strip()
            break

    cand: Optional[Path] = None
    if raw_explicit:
        if "\x00" in raw_explicit:
            return None
        norm_slashes = raw_explicit.replace("\\", "/")
        if ".." in norm_slashes.split("/"):
            return None
        exp = Path(os.path.expanduser(raw_explicit))
        if not (exp.is_absolute() or (os.name == "nt" and norm_slashes.startswith("/") and not norm_slashes.startswith("//"))):
            return None
        cand = exp
    elif conv_id and conv_id != "default" and "\x00" not in conv_id and _CONV_ID_FALLBACK_RE.match(conv_id):
        cand = brain_root / conv_id
    else:
        return None

    try:
        # Reject symlinked brain root or symlinked artifact directory itself
        if brain_root.is_symlink() or cand.is_symlink():
            return None
        cand_abs = Path(os.path.abspath(cand))
        brain_abs = Path(os.path.abspath(brain_root))
        cand_res = cand.resolve()
        if str(cand_res) in forbidden_roots:
            return None
        if _targets_governance_dir(str(cand_abs)) or _targets_governance_dir(str(cand_res)):
            return None
        brain_res = brain_root.resolve()
        lex_in_brain = is_within(cand_abs, brain_abs)
        res_in_brain = is_within(cand_res, brain_res)
        if lex_in_brain:
            if cand_abs == brain_abs or not res_in_brain:
                return None
            cur_anc = brain_abs
            for part in cand_abs.relative_to(brain_abs).parts:
                cur_anc = cur_anc / part
                if cur_anc.is_symlink():
                    return None
        if res_in_brain:
            if cand_res == brain_res:
                return None
            if not conv_id or conv_id == "default":
                return None
            rel_parts = cand_res.relative_to(brain_res).parts
            if not rel_parts or rel_parts[0] != conv_id:
                return None
        return cand_abs
    except (OSError, RuntimeError, ValueError):
        return None


def _is_path_strictly_within_dir(
    raw_path: str,
    allowed_dir: Path,
    *,
    base_dir: Optional[Path] = None,
) -> bool:
    """
    Returns True iff `raw_path` has no `..` segments, resolves strictly inside `allowed_dir`
    (not equal to `allowed_dir`), and has zero symlink components at or below `allowed_dir`.
    """
    if not raw_path or "\x00" in raw_path:
        return False
    norm_slashes = raw_path.replace("\\", "/")
    if ".." in norm_slashes.split("/"):
        return False
    is_win_drive = bool(re.match(r"^[A-Za-z]:/", norm_slashes))
    if is_win_drive and os.name != "nt":
        return False
    is_abs_like = norm_slashes.startswith("/") or is_win_drive or Path(raw_path).is_absolute()
    if is_abs_like:
        cand_raw = Path(norm_slashes)
    elif base_dir is not None:
        cand_raw = base_dir / norm_slashes
    else:
        return False
    try:
        dir_abs = Path(os.path.abspath(allowed_dir))
        cand_abs = Path(os.path.abspath(cand_raw))
        if cand_abs == dir_abs or not is_within(cand_abs, dir_abs):
            return False
        if dir_abs.is_symlink():
            return False
        rel = cand_abs.relative_to(dir_abs)
        cur = dir_abs
        for part in rel.parts:
            cur = cur / part
            if cur.is_symlink():
                return False
        dir_res = dir_abs.resolve()
        cand_res = cand_abs.resolve()
        if cand_res == dir_res or not is_within(cand_res, dir_res):
            return False
        return True
    except (OSError, RuntimeError, ValueError):
        return False

def _has_linked_git_file(workspace: Path) -> bool:
    """True when `workspace` (or an ancestor) has a `.git` file pointer (linked worktree)."""
    cur = workspace
    try:
        cur = workspace.resolve()
    except (OSError, RuntimeError):
        pass
    for cand in (cur, *cur.parents):
        git_marker = cand / ".git"
        try:
            if git_marker.is_file():
                return True
            if git_marker.is_dir():
                return False
        except OSError:
            continue
    return False

def _capture_git_baseline(workspace: Path) -> Tuple[str, str]:
    """
    Captures `(base_head, pre_edit_stash)` for `workspace` before the first write of a session.
    If the working tree has pre-existing uncommitted tracked modifications, `git stash create`
    produces a commit object without mutating the working tree, index, or `refs/stash`, and
    pins it at `refs/harness/pre-edit` so `git gc` preserves it across crashes.
    """
    base_head = ""
    pre_edit_stash = ""
    try:
        head_res = subprocess.run(
            ["git", "-C", str(workspace), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            stdin=subprocess.DEVNULL,
        )
        if head_res.returncode == 0:
            candidate = head_res.stdout.strip()
            if _HEX_OID_RE.match(candidate):
                base_head = candidate
    except (OSError, subprocess.SubprocessError):
        return "", ""

    if not base_head:
        return "", ""

    try:
        stash_res = subprocess.run(
            ["git", "-C", str(workspace), "stash", "create"],
            capture_output=True,
            text=True,
            timeout=2,
            stdin=subprocess.DEVNULL,
        )
        if stash_res.returncode == 0:
            candidate_stash = stash_res.stdout.strip()
            if _HEX_OID_RE.match(candidate_stash):
                from guard.paths import path_key
                from guard.test_boundary import TestBoundaryGuard

                ref_name = "refs/harness/pre-edit"
                if (
                    TestBoundaryGuard.resolve_linked_worktree_root(workspace) is not None
                    or _has_linked_git_file(workspace)
                ):
                    ref_name = f"refs/harness/pre-edit-wt-{path_key(workspace)}"
                ref_res = subprocess.run(
                    ["git", "-C", str(workspace), "update-ref", ref_name, candidate_stash],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    stdin=subprocess.DEVNULL,
                )
                if ref_res.returncode == 0:
                    pre_edit_stash = candidate_stash
                else:
                    sys.stderr.write(
                        f"[Harness Flight Recorder] `git update-ref {ref_name}` failed in `{workspace}` "
                        f"(exit {ref_res.returncode}).\n"
                    )
        else:
            sys.stderr.write(
                f"[Harness Flight Recorder] `git stash create` failed in `{workspace}` (exit {stash_res.returncode}).\n"
            )
    except (OSError, subprocess.SubprocessError) as exc:
        sys.stderr.write(
            f"[Harness Flight Recorder] Failed to capture pre-edit stash in `{workspace}` ({type(exc).__name__}): {exc}\n"
        )

    return base_head, pre_edit_stash

def _record_flight_pre_write(
    payload: Dict[str, Any],
    workspace: Optional[Path],
    tool_name: str,
    target_path_str: str,
) -> None:
    """
    Records an in-flight file mutation in `state_dir() / "flight_recorder.json"` (`fsync` +
    `os.replace`) before a workspace file-write tool executes. If the session is cut off by
    quota exhaustion, network loss, or power failure before `handle_stop` runs, the status
    remains `"in_flight"` on disk so the next `PreInvocation` surfaces a recovery directive.
    """
    if (
        workspace is None
        or not target_path_str
        or "\x00" in target_path_str
        or not target_path_str.strip()
    ):
        return
    try:
        if not workspace.is_dir():
            return
    except (OSError, ValueError):
        return

    raw_target = target_path_str.strip()
    if raw_target.lower().startswith("file:"):
        parsed_target = _parse_file_uri(raw_target)
        if parsed_target is None:
            sys.stderr.write(
                f"[Harness Flight Recorder] Skipping unparsable `file:` target `{target_path_str}`.\n"
            )
            return
        raw_target = parsed_target
    expanded = Path(os.path.expanduser(raw_target))
    candidate = (workspace / expanded) if not expanded.is_absolute() else expanded
    try:
        ws_resolved = workspace.resolve()
        cand_resolved = candidate.resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        sys.stderr.write(
            f"[Harness Flight Recorder] Failed to resolve target `{target_path_str}` in `{workspace}` "
            f"({type(exc).__name__}): {exc}\n"
        )
        return

    if not is_within(cand_resolved, ws_resolved):
        return

    try:
        rel_target = str(cand_resolved.relative_to(ws_resolved)).replace("\\", "/")
    except ValueError:
        rel_target = target_path_str.strip().replace("\\", "/")
    if not rel_target or rel_target == ".":
        return

    ws_key = str(ws_resolved)
    conv_id = _conversation_id(payload)
    flight_file = _flight_recorder_file()

    try:
        with file_lock(flight_file, timeout=HOOK_LOCK_TIMEOUT):
            ledger_ok, ledger = _read_ledger_checked(flight_file, quarantine=True)
            if not ledger_ok and flight_file.exists():
                sys.stderr.write(f"[Harness Flight Recorder] Refusing to clobber unreadable `{flight_file}`.\n")
                return
            convs = _extract_ws_flight_conversations(ledger.get(ws_key))
            prev = convs.get(conv_id) if isinstance(convs.get(conv_id), dict) else {}
            if prev:
                preserve_lineage = True
            else:
                prev_unrecovered: Dict[str, Any] = {}
                for cid, rec in reversed(list(convs.items())):
                    if cid != conv_id and str(rec.get("status") or "") in ("interrupted_notified", "in_progress_blocked"):
                        prev_unrecovered = rec
                        break
                if prev_unrecovered:
                    prev = prev_unrecovered
                    preserve_lineage = True
                else:
                    preserve_lineage = False

            if preserve_lineage:
                base_head = str(prev.get("base_head") or "")
                pre_edit_stash = str(prev.get("pre_edit_stash") or "")
                touched: List[str] = [
                    str(x) for x in (prev.get("touched_files") or []) if isinstance(x, str) and x
                ]
                has_shell_write = bool(prev.get("has_shell_write")) or any(t.startswith("<") for t in touched)
                touched_overflow = bool(prev.get("touched_overflow"))
            else:
                base_head, pre_edit_stash = _capture_git_baseline(ws_resolved)
                touched = []
                has_shell_write = False
                touched_overflow = False

            if rel_target.startswith("<"):
                has_shell_write = True
            if rel_target not in touched:
                touched.append(rel_target)
            if len(touched) > 30:
                touched_overflow = True
                # Preserve shell sentinels and test-like paths first so Rule 9 provenance cannot be evicted.
                priority = [
                    t
                    for t in touched
                    if t.startswith("<")
                    or any(tok in t.lower() for tok in ("test", "spec", "tasks.md"))
                ]
                regular = [t for t in touched if t not in priority]
                keep_reg = max(0, 30 - len(priority))
                touched = (priority[-30:] + regular[-keep_reg:]) if keep_reg > 0 else priority[-30:]
            seq = max((_safe_int(r.get("seq"), default=0) for r in convs.values()), default=0) + 1

            rec_entry: Dict[str, Any] = {
                "workspace": ws_key,
                "conversation_id": conv_id,
                "status": "in_flight",
                "seq": seq,
                "updated_at": _utc_now_iso(),
                "base_head": base_head,
                "pre_edit_stash": pre_edit_stash,
                "last_tool": tool_name,
                "last_target": rel_target,
                "touched_files": touched,
                "last_stop_findings_count": _safe_int(prev.get("last_stop_findings_count"), default=0),
            }
            if has_shell_write:
                rec_entry["has_shell_write"] = True
            if touched_overflow:
                rec_entry["touched_overflow"] = True
            convs[conv_id] = rec_entry
            if ws_key in ledger:
                del ledger[ws_key]
            ledger[ws_key] = _rebuild_ws_flight_entry(ws_key, convs, primary_conv=conv_id)
            while len(ledger) > 50:
                oldest = next(iter(ledger))
                del ledger[oldest]
            atomic_write_json(flight_file, ledger)
    except (OSError, TimeoutError) as exc:
        sys.stderr.write(
            f"[Harness Flight Recorder] Failed to persist `{flight_file}` ({type(exc).__name__}): {exc}\n"
        )

def _workspace_for_target(
    target_path_str: str,
    workspaces: Sequence[Path],
    fallback: Optional[Path] = None,
) -> Optional[Path]:
    """Selects the workspace root that owns `target_path_str` in multi-root sessions."""
    if not workspaces:
        return fallback
    if not target_path_str or not target_path_str.strip() or "\x00" in target_path_str:
        return fallback if fallback is not None else workspaces[0]
    raw_target = target_path_str.strip()
    if raw_target.lower().startswith("file:"):
        parsed_target = _parse_file_uri(raw_target)
        if parsed_target is None:
            return fallback if fallback is not None else workspaces[0]
        raw_target = parsed_target
    expanded = Path(os.path.expanduser(raw_target))
    if expanded.is_absolute():
        matched: List[Tuple[int, Path]] = []
        for ws in workspaces:
            if is_within(expanded, ws):
                matched.append((len(os.path.abspath(ws)), ws))
                continue
            try:
                ws_res = ws.resolve()
                if is_within(expanded.resolve(), ws_res):
                    matched.append((len(str(ws_res)), ws))
            except (OSError, RuntimeError, ValueError):
                continue
        if matched:
            matched.sort(key=lambda item: item[0], reverse=True)
            return matched[0][1]
        return fallback if fallback is not None else workspaces[0]
    if fallback is not None:
        return fallback
    for ws in workspaces:
        try:
            if (ws / expanded).exists():
                return ws
        except (OSError, ValueError):
            continue
    return workspaces[0]

# ----------------------------------------------------------------------
# 2. PreToolUse: Governance Shield & Bash Guard
# ----------------------------------------------------------------------
_BROAD_RUNTIME_DOTDIR_SEAMS: Dict[str, Tuple[str, ...]] = {
    ".gemini": (
        ".gemini/GEMINI.md",
        ".gemini/AGENTS.md",
        ".gemini/rules",
        ".gemini/skills",
        ".gemini/agents",
        ".gemini/hooks.json",
        ".gemini/mcp_config.json",
    ),
    ".claude": ("CLAUDE.md", ".claude/agents", ".claude/commands", ".claude/skills"),
    ".codex": ("AGENTS.md", "CODEX.md", "CONVENTIONS.md", ".agents/skills", ".agents/rules"),
    ".cursor": (".cursorrules", ".cursor/rules", ".cursor/skills", ".cursor/agents"),
}

def _environments_registry_corrupt() -> bool:
    """Returns True when `state_dir() / 'environments.json'` exists and cannot be parsed as a valid registry dict."""
    env_file = state_dir() / "environments.json"
    if not env_file.exists() and not env_file.is_symlink():
        return False
    ok, data = _read_ledger_checked(env_file, quarantine=False)
    if not ok:
        return True
    raw_envs = data.get("environments")
    return raw_envs is not None and not isinstance(raw_envs, (list, dict))


def _custom_enforced_governance_roots() -> List[Path]:
    """Loads custom `policy == 'enforced'` governance seams from `state_dir() / 'environments.json'`."""
    out: List[Path] = []
    env_file = state_dir() / "environments.json"
    if not env_file.is_file():
        return out
    ok, data = _read_ledger_checked(env_file, quarantine=False)
    if not ok or not isinstance(data, dict):
        return out
    raw_envs = data.get("environments")
    if isinstance(raw_envs, list):
        entries = raw_envs
    elif isinstance(raw_envs, dict):
        entries = list(raw_envs.values())
    else:
        return out
    home_abs = Path(os.path.abspath(Path.home()))
    home_dot_gemini_abs = Path(os.path.abspath(home_abs / ".gemini"))

    def _append_custom_seam(candidate: Path) -> None:
        cand_abs = Path(os.path.abspath(candidate))
        # `$HOME` (or an ancestor) is never a workspace governance tree; `~/.gemini` holds
        # Antigravity's runtime `antigravity/brain` state while `~/.gemini/config` is protected globally.
        if cand_abs == home_abs or home_abs.is_relative_to(cand_abs):
            return
        if cand_abs == home_dot_gemini_abs:
            for rel in _BROAD_RUNTIME_DOTDIR_SEAMS[".gemini"]:
                narrowed = home_abs / rel
                if narrowed not in out:
                    out.append(narrowed)
            return
        if candidate not in out:
            out.append(candidate)

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("enabled", True) is False:
            continue
        if str(entry.get("policy") or "").strip().lower() != "enforced":
            continue
        env_id = str(entry.get("id") or "").strip().lower()
        if env_id == "antigravity":
            continue
        is_global_entry = entry.get("is_global") is True
        raw_root = entry.get("root_path")
        root_p = (
            Path(os.path.expanduser(raw_root.strip()))
            if isinstance(raw_root, str) and raw_root.strip()
            else None
        )
        gov_paths = entry.get("governance_paths")
        if root_p is not None and (not isinstance(gov_paths, list) or not gov_paths):
            _append_custom_seam(root_p)
        if isinstance(gov_paths, list):
            for gp in gov_paths:
                if isinstance(gp, str) and gp.strip():
                    gp_clean = gp.strip()
                    gp_norm = gp_clean.rstrip("/\\")
                    if not is_global_entry and gp_norm in _BROAD_RUNTIME_DOTDIR_SEAMS and root_p is not None:
                        for rel_seam in _BROAD_RUNTIME_DOTDIR_SEAMS[gp_norm]:
                            _append_custom_seam(root_p / rel_seam)
                        continue
                    gp_path = Path(os.path.expanduser(gp_clean))
                    if not gp_path.is_absolute() and root_p is not None:
                        gp_path = root_p / gp_path
                    _append_custom_seam(gp_path)
    return out

def _config_root_candidates() -> List[Path]:
    out: List[Path] = []
    for cand in (
        configured_config_dir(),
        config_dir(),
        Path(os.path.abspath(Path.home() / ".gemini" / "config")),
    ):
        if cand not in out:
            out.append(cand)
        try:
            if not cand.is_symlink():
                res = cand.resolve()
                if res not in out:
                    out.append(res)
        except (OSError, RuntimeError, ValueError):
            pass
    return out

def _state_root_candidates() -> List[Path]:
    home = Path.home()
    out: List[Path] = []
    for cand in (
        state_dir(),
        Path(os.path.abspath(home / ".local" / "state" / "plumbwork")),
        Path(os.path.abspath(home / ".local" / "state" / "plumb-guard")),
    ):
        if cand not in out:
            out.append(cand)
        try:
            if not cand.is_symlink():
                res = cand.resolve()
                if res not in out:
                    out.append(res)
        except (OSError, RuntimeError, ValueError):
            pass
    return out

def _governance_roots() -> List[Path]:
    roots: List[Path] = []
    home = Path.home()
    cfg_cands = _config_root_candidates()
    gemini_parent_files: List[Path] = [
        Path(os.path.abspath(home / ".gemini" / "GEMINI.md")),
        Path(os.path.abspath(home / ".gemini" / "AGENTS.md")),
    ]
    for cfg_cand in cfg_cands:
        if cfg_cand.name == "config" and cfg_cand.parent.name == ".gemini":
            gemini_parent_files.append(cfg_cand.parent / "GEMINI.md")
            gemini_parent_files.append(cfg_cand.parent / "AGENTS.md")
    candidates: List[Path] = [
        *cfg_cands,
        *gemini_parent_files,
        *_state_root_candidates(),
        data_dir(),
        data_dir() / "runtime",
        data_dir() / "snapshots",
        home / ".local" / "bin" / "plumb-guard",
        home / ".local" / "bin" / "plumb-porter",
    ]
    porter_bin = home / ".local" / "bin" / "porter"
    try:
        if not porter_bin.exists():
            candidates.append(porter_bin)
        elif porter_bin.is_file():
            porter_head = porter_bin.read_text(encoding="utf-8", errors="ignore")[:512].lower()
            if "plumbwork launcher" in porter_head or "plumbwork cli launcher" in porter_head:
                candidates.append(porter_bin)
    except OSError:
        candidates.append(porter_bin)
    if os.name == "nt":
        local_app = Path(os.environ.get("LOCALAPPDATA") or (home / "AppData" / "Local"))
        candidates.append(local_app / "Programs" / "plumb-guard")
    else:
        candidates.extend([
            Path("/usr/bin/plumb-guard"),
            Path("/usr/bin/plumb-porter"),
            Path("/usr/lib/plumb-guard"),
            Path("/usr/share/plumbwork"),
        ])
    share_env = os.environ.get("PLUMBWORK_SHARE_DIR", "").strip()
    if share_env:
        candidates.append(Path(os.path.abspath(Path(share_env).expanduser())))
    candidates.extend(_custom_enforced_governance_roots())
    for candidate in candidates:
        if candidate not in roots:
            roots.append(candidate)
    return roots

_RUNTIME_CONFIG_SUBDIRS = ("plugins", "sidecars", "projects", "cache")

_PLUGIN_GOVERNANCE_SEGMENTS = frozenset({
    "skills",
    "agents",
    "rules",
    "hooks",
    "scripts",
    "bin",
    "hooks.json",
    "mcp_config.json",
    ".mcp.json",
})

_PLUGIN_EXEC_SUFFIXES = (
    ".md",
    ".mdc",
    ".py",
    ".pyc",
    ".pyo",
    ".pyw",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ksh",
    ".pl",
    ".rb",
    ".php",
    ".ps1",
    ".bat",
    ".cmd",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".wasm",
)

def _is_plugin_governance_path(candidate: Path, plugin_root: Path) -> bool:
    glob_meta_chars = "*?[{}$`!@+("
    rel_part_sets: List[Tuple[str, ...]] = []
    try:
        rel_part_sets.append(candidate.relative_to(plugin_root).parts)
    except ValueError:
        try:
            rel_part_sets.append(
                Path(os.path.abspath(candidate)).relative_to(Path(os.path.abspath(plugin_root))).parts
            )
        except ValueError:
            pass
    try:
        rel_part_sets.append(candidate.resolve().relative_to(plugin_root.resolve()).parts)
    except (OSError, RuntimeError, ValueError):
        pass
    if not rel_part_sets:
        return True
    for rel_parts in rel_part_sets:
        if len(rel_parts) == 0:
            return True
        if any(part in (".", "..") for part in rel_parts):
            return True
        first_seg = rel_parts[0]
        if any(ch in glob_meta_chars for ch in first_seg):
            return True
        if first_seg.rstrip(". ").lower() in _HARNESS_PLUGIN_NAMES:
            return True
        if any(part.lower() in _PLUGIN_GOVERNANCE_SEGMENTS for part in rel_parts):
            return True
        if rel_parts[-1].lower().endswith(_PLUGIN_EXEC_SUFFIXES):
            return True
    return False

def _is_runtime_config_subdir(candidate: Path, root: Path) -> bool:
    if root in _state_root_candidates():
        staging_path = root / "staging"
        within_staging = is_within(candidate, staging_path)
        if not within_staging:
            return False
        try:
            if staging_path.is_symlink():
                return False
            resolved_cand = candidate.resolve()
            resolved_staging = staging_path.resolve()
            resolved_within = is_within(resolved_cand, resolved_staging)
        except (OSError, RuntimeError, ValueError):
            return False
        return bool(within_staging and resolved_within)

    if root not in _config_root_candidates():
        return False
    for sub in _RUNTIME_CONFIG_SUBDIRS:
        sub_path = root / sub
        within = is_within(candidate, sub_path)
        if not within:
            continue
        try:
            resolved_cand = candidate.resolve()
            resolved_sub = sub_path.resolve()
            resolved_within = is_within(resolved_cand, resolved_sub)
        except (OSError, RuntimeError, ValueError):
            return False
        if not resolved_within:
            return False
        if sub == "plugins" and _is_plugin_governance_path(candidate, sub_path):
            return False
        return True
    return False

_URI_SCHEME_PREFIX_RE = _LazyRegex(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def _parse_file_uri(raw_uri: str) -> Optional[str]:
    """Parses a local `file:` / `file://` URI (RFC 8089, POSIX, WSL, or Windows drive) into a filesystem path, or `None` if remote/malformed."""
    s = raw_uri.strip()
    if not s.lower().startswith("file:"):
        return None
    if "\x00" in s or "%00" in s.lower():
        return None
    import urllib.parse
    if s.lower().startswith("file://"):
        rest = s[7:].replace("\\", "/")
        raw_netloc, sep, raw_path = rest.partition("/")
        netloc = urllib.parse.unquote(raw_netloc).replace("\\", "/").strip()
        uri_path = ("/" + urllib.parse.unquote(raw_path).replace("\\", "/")) if sep else ""
        if "\x00" in netloc or "\x00" in uri_path:
            return None
        m_drive_auth = re.match(r"^([A-Za-z])[:|$](?:/(.*))?$", netloc)
        if m_drive_auth:
            drv = m_drive_auth.group(1)
            rem_auth = m_drive_auth.group(2)
            uri_path = f"{drv}:/{rem_auth}{uri_path}" if rem_auth is not None else f"{drv}:{uri_path}"
        elif netloc == "" or netloc.lower() in ("localhost", "localhost.", ".", "?", "[::1]") or bool(
            re.match(r"^127(?:\.\d{1,3}){3}$", netloc)
        ):
            pass
        elif netloc.lower() in ("wsl.localhost", "wsl$"):
            m_wsl = re.match(r"^/[^/]+(/.*)$", uri_path)
            if not m_wsl:
                return None
            uri_path = m_wsl.group(1)
        else:
            return None
        uri_path = re.sub(r"^/+([A-Za-z])[:|$](?=/|$)", r"\1:", uri_path)
        cleaned = uri_path.strip()
        return cleaned or None
    rest_single = urllib.parse.unquote(s[5:]).replace("\\", "/")
    if "\x00" in rest_single:
        return None
    rest_single = re.sub(r"^/+([A-Za-z])[:|$](?=/|$)", r"\1:", rest_single)
    rest_single = re.sub(r"^([A-Za-z])[|$](?=/|$)", r"\1:", rest_single)
    cleaned_single = rest_single.strip()
    return cleaned_single or None


def _canonicalize_check_path(raw_target: str) -> str:
    """Normalizes `file:` URIs, `//`, `.`/`..` segments, and Win32 trailing dots/spaces for boundary checks."""
    s = raw_target.strip()
    if s.lower().startswith("file:"):
        parsed = _parse_file_uri(s)
        if parsed is not None:
            s = parsed
        elif "%" in s:
            import urllib.parse

            s = urllib.parse.unquote(s)
    elif "%" in s:
        import urllib.parse

        s = urllib.parse.unquote(s)
    s = s.replace("\\", "/")
    prefix = ""
    m_drv = re.match(r"^([A-Za-z]:)(?:/|$)(.*)$", s)
    if m_drv:
        prefix = m_drv.group(1) + "/"
        body = m_drv.group(2)
    elif s.startswith("/"):
        prefix = "/"
        body = s.lstrip("/")
    else:
        body = s
    stack: List[str] = []
    for seg in body.split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            if stack and stack[-1] != "..":
                stack.pop()
            elif not prefix:
                stack.append("..")
            continue
        trimmed = seg.rstrip(". ")
        stack.append(trimmed if trimmed else seg)
    return prefix + "/".join(stack)


def _targets_governance_dir(target_path_str: str, base_dir: Optional[Path] = None) -> bool:
    if not target_path_str:
        return False
    if "\x00" in target_path_str:
        return False
    cleaned = target_path_str.strip()
    if not cleaned:
        return False
    if cleaned.lower().startswith("file:") or _URI_SCHEME_PREFIX_RE.match(cleaned):
        parsed_local = _parse_file_uri(cleaned)
        if parsed_local is None:
            return False
        cleaned = parsed_local
    if os.name != "nt" and re.match(
        r"^(?:~|\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})|%[A-Za-z_][A-Za-z0-9_]*%|[A-Za-z]:)\\",
        cleaned,
        re.IGNORECASE,
    ):
        cleaned = cleaned.replace("\\\\", "/").replace("\\", "/")

    def _expand_leading_env(m: re.Match[str]) -> str:
        raw_var = m.group(1) or m.group(2) or m.group(3) or ""
        upper_var = raw_var.upper()
        if upper_var in ("HOME", "USERPROFILE"):
            return str(Path.home())
        if upper_var == "ANTIGRAVITY_CONFIG_DIR":
            return str(configured_config_dir())
        if upper_var in ("PLUMB_GUARD_STATE_DIR", "ANTIGRAVITY_STATE_DIR"):
            return str(state_dir())
        if upper_var == "PLUMB_GUARD_DATA_DIR":
            return str(data_dir())
        if upper_var == "PLUMBWORK_SHARE_DIR":
            raw_share = (os.environ.get("PLUMBWORK_SHARE_DIR") or "").strip()
            return os.path.abspath(Path(raw_share).expanduser()) if raw_share else "/usr/share/plumbwork"
        val = os.environ.get(raw_var) or os.environ.get(upper_var)
        return val if val else m.group(0)

    cleaned = re.sub(
        r"^(?:\$\{(HOME|USERPROFILE|LOCALAPPDATA|ANTIGRAVITY_CONFIG_DIR|PLUMB_GUARD_STATE_DIR|ANTIGRAVITY_STATE_DIR|PLUMB_GUARD_DATA_DIR|PLUMBWORK_SHARE_DIR|XDG_CONFIG_HOME|XDG_STATE_HOME|XDG_DATA_HOME)\}|"
        r"\$(HOME|USERPROFILE|LOCALAPPDATA|ANTIGRAVITY_CONFIG_DIR|PLUMB_GUARD_STATE_DIR|ANTIGRAVITY_STATE_DIR|PLUMB_GUARD_DATA_DIR|PLUMBWORK_SHARE_DIR|XDG_CONFIG_HOME|XDG_STATE_HOME|XDG_DATA_HOME)|"
        r"%(USERPROFILE|LOCALAPPDATA|ANTIGRAVITY_CONFIG_DIR|PLUMB_GUARD_STATE_DIR|ANTIGRAVITY_STATE_DIR|PLUMB_GUARD_DATA_DIR|PLUMBWORK_SHARE_DIR)%)(?=[/\\]|$)",
        _expand_leading_env,
        cleaned,
        flags=re.IGNORECASE,
    )
    if os.name != "nt" and re.match(r"^(?:~|[A-Za-z]:)\\", cleaned):
        cleaned = cleaned.replace("\\\\", "/").replace("\\", "/")
    expanded = Path(os.path.expanduser(cleaned))
    exp_str = str(expanded)
    is_explicit_abs = (
        expanded.is_absolute()
        or bool(re.match(r"^[A-Za-z]:[/\\]", exp_str))
        or exp_str.startswith("\\\\")
    )
    if not is_explicit_abs:
        if os.name == "nt" and bool(expanded.root) and not expanded.drive:
            seen_drives: List[str] = []
            for r in _governance_roots():
                if r.drive and r.drive.upper() not in seen_drives:
                    seen_drives.append(r.drive.upper())
                    if _targets_governance_dir(f"{r.drive}{expanded}"):
                        return True
            return False
        if base_dir is None:
            if re.match(r"^\.\.(?:[/\\]|$)", cleaned):
                if os.name == "nt":
                    stripped_up = re.sub(r"^(?:\.\.(?:[/\\]|$))+", "", cleaned)
                    if re.match(r"^[A-Za-z]:[/\\]", stripped_up):
                        return _targets_governance_dir(stripped_up)
                    rel_up = stripped_up.lstrip("/\\")
                    seen_drives_up: List[str] = []
                    for r in _governance_roots():
                        if r.drive and r.drive.upper() not in seen_drives_up:
                            seen_drives_up.append(r.drive.upper())
                            if _targets_governance_dir(f"{r.drive}\\{rel_up}"):
                                return True
                    return False
                expanded = Path("/") / expanded
                exp_str = str(expanded)
            else:
                return False
        else:
            base_exp = Path(os.path.expanduser(str(base_dir)))
            base_str = str(base_exp)
            if not (
                base_exp.is_absolute()
                or bool(re.match(r"^[A-Za-z]:[/\\]", base_str))
                or base_str.startswith("\\\\")
            ):
                return False
            expanded = base_exp / expanded
            exp_str = str(expanded)
    if not expanded.is_absolute():
        norm_win_exp = Path("/" + exp_str.replace("\\", "/").lstrip("/").lower())
        for st_root in _state_root_candidates():
            if not st_root.is_absolute():
                norm_st = Path("/" + str(st_root).replace("\\", "/").lstrip("/").lower()) / "staging"
                if is_within(norm_win_exp, norm_st):
                    return False
        for cfg_root in _config_root_candidates():
            if not cfg_root.is_absolute():
                norm_cfg = Path("/" + str(cfg_root).replace("\\", "/").lstrip("/").lower())
                for sub in _RUNTIME_CONFIG_SUBDIRS:
                    sub_p = norm_cfg / sub
                    if is_within(norm_win_exp, sub_p) and not (
                        sub == "plugins" and _is_plugin_governance_path(norm_win_exp, sub_p)
                    ):
                        return False
        for root in _governance_roots():
            if root.is_absolute():
                continue
            norm_win_root = Path("/" + str(root).replace("\\", "/").lstrip("/").lower())
            if is_within(norm_win_exp, norm_win_root):
                return True
        return False
    if any(
        _is_runtime_config_subdir(expanded, rt_root)
        for rt_root in (*_config_root_candidates(), *_state_root_candidates())
    ):
        return False
    for root in _governance_roots():
        if _is_runtime_config_subdir(expanded, root):
            continue
        if is_within(expanded, root):
            return True
        try:
            if is_within(expanded.resolve(), root.resolve()):
                return True
        except (OSError, RuntimeError, ValueError, AttributeError):
            pass
    return False

def _normalize_shell_paths(cmd: str) -> str:
    """Normalizes duplicate slashes, current-directory `.` segments, and parent-directory `..` segments inside shell command text."""
    def _collapse_slashes(text: str) -> str:
        collapsed_drive = re.sub(r"((?:^|(?<=[^A-Za-z0-9+.-]))[A-Za-z]:)/{2,}", r"\1/", text)
        return re.sub(r"(?<!:)/{2,}", "/", collapsed_drive)

    norm = cmd.replace("${HOME}", "$HOME")
    norm = _collapse_slashes(norm)
    for _ in range(16):
        collapsed_dot = re.sub(r"/\.(?=/|\s|$|[;&|'\"()])", "", norm)
        if collapsed_dot == norm:
            break
        norm = collapsed_dot
    for _ in range(32):
        collapsed = re.sub(
            r"/(?!\.\.?(?:/|\s|$|[;&|'\"()]))[^/\s;|&'\"():]+/\.\.(?=/|\s|$|[;&|'\"()])",
            "",
            norm,
        )
        collapsed = re.sub(
            r"((?:^|(?<=[\s;|&'\"()=<>]))[A-Za-z]:)/\.\.(?=/|\s|$|[;&|'\"()])",
            r"\1",
            collapsed,
        )
        collapsed = re.sub(
            r"(^|(?<=[\s;|&'\"()=<>]))/\.\.(?=/|\s|$|[;&|'\"()])",
            r"\1/",
            collapsed,
        )
        collapsed = _collapse_slashes(collapsed)
        if collapsed == norm:
            break
        norm = collapsed
    norm = _collapse_slashes(norm)
    return norm

_CUSTOMIZATION_BASENAMES = frozenset({
    "gemini.md",
    "agents.md",
    "claude.md",
    "hooks.json",
    "mcp_config.json",
    "skills.json",
    "plugins.json",
    ".cursorrules",
    "skill.md",
})

_CUSTOMIZATION_DIR_SEGMENTS = frozenset({
    ".agents",
    ".agent",
    "_agents",
    "_agent",
    ".claude",
    ".cursor",
    ".harness",
})

_HARNESS_SOURCE_TOP_DIRS = frozenset({
    "skills",
    "agents",
    "guard",
    "porter",
    "templates",
    ".harness",
})

_HARNESS_SOURCE_FILES = frozenset({
    "gemini.md",
    "agents.md",
    "design.md",
    "hooks.json",
    "guard.py",
    "porter.py",
    "install.py",
    "scripts/build_plugins.py",
    "scripts/meta_audit.py",
    "scripts/verify_invariants.py",
})

_ALLOWED_TOP_EFFORT_VALUES = frozenset({
    "high",
    "max",
    "maximum",
    "xhigh",
    "extra",
    "extra-high",
    "extrahigh",
    "1",
    "1.0",
    "1.00",
    "100%",
})

_SETTINGS_MODEL_RE = _LazyRegex(
    r"changed\s+setting\s+`?Model\s+Selection`?\s+from\s+[^\n]+?\s+to\s+([^\n]+?)\.(?=\s|$)",
    re.IGNORECASE,
)

_SETTINGS_EFFORT_RE = _LazyRegex(
    r"changed\s+setting\s+`?(?:Effort(?:\s+Level)?|Thinking\s+Level|Reasoning\s+Effort)`?\s+from\s+[^\n]+?\s+to\s+([^\n]+?)\.(?=\s|$)",
    re.IGNORECASE,
)

_SETTINGS_KV_MODEL_RE = _LazyRegex(
    r"(?:^|[\n,{])\s*['\"`]?(?:modelName|model_name|model|Model\s+Selection)['\"`]?\s*:\s*['\"`]?([^\n,\"'`\}]+)",
    re.IGNORECASE,
)

_SETTINGS_KV_EFFORT_RE = _LazyRegex(
    r"(?:^|[\n,{])\s*['\"`]?(?:effort|effortLevel|effort_level|thinkingLevel|thinking_level|reasoningEffort|Effort(?:\s+Level)?)['\"`]?\s*:\s*['\"`]?([^\n,\"'`\}]+)",
    re.IGNORECASE,
)

_MODEL_EMBEDDED_EFFORT_RE = _LazyRegex(
    r"(?:(?:\(\s*|(?:,|\s+-\s+)\s*)(xhigh|extra(?:\s*-\s*high|\s+high)?|high|max|maximum|medium|med|low|minimal|min)\s*\)\s*$|"
    r"-(xhigh|extra-high|extra|high|max|maximum|medium|low|minimal)$)",
    re.IGNORECASE,
)

_USER_REQUEST_BLOCK_RE = _LazyRegex(r"(?is)<USER_REQUEST\b[^<>]*>.*?</USER_REQUEST\s*>")

_USER_SETTINGS_BLOCK_RE = _LazyRegex(r"(?is)<USER_SETTINGS_CHANGE\b[^<>]*>(.*?)</USER_SETTINGS_CHANGE\s*>")

_CUST_CMD_UNIVERSAL_TARGET_PAT = (
    r"(?:\.agents?\b|_agents?\b|\.claude\b|\.cursor\b|\.harness\b|"
    r"GEMINI\.md\b|AGENTS\.md\b|CLAUDE\.md\b|hooks\.json\b|"
    r"mcp_config\.json\b|skills\.json\b|plugins\.json\b|\.cursorrules\b|"
    r"SKILL\.md\b|[A-Za-z0-9_.-]+\.mdc\b|"
    r"guard\.py\b|porter\.py\b|install\.py\b|scripts/build_plugins\.py\b|scripts/meta_audit\.py\b|scripts/verify_invariants\.py\b)"
)

_CUST_CMD_HARNESS_DIRS_PAT = r"(?:^|[\s'\"=/])(?:skills|agents|guard|porter|templates)(?:/|\b)"

_CUST_CMD_HARNESS_SLASH_DIRS_PAT = r"(?:^|[\s'\"=/])(?:skills|agents|guard|porter|templates)/(?=[^\s;|&'\"]|$)"

_CUST_CMD_TARGET_PAT = (
    r"(?:\.agents?\b|_agents?\b|\.claude\b|\.cursor\b|\.harness\b|"
    r"(?:^|[\s'\"=/])(?:skills|agents|guard|porter|templates)(?:/|\b)|"
    r"GEMINI\.md\b|AGENTS\.md\b|CLAUDE\.md\b|DESIGN\.md\b|hooks\.json\b|"
    r"mcp_config\.json\b|skills\.json\b|plugins\.json\b|\.cursorrules\b|"
    r"SKILL\.md\b|[A-Za-z0-9_.-]+\.mdc\b|"
    r"guard\.py\b|porter\.py\b|install\.py\b|scripts/build_plugins\.py\b|scripts/meta_audit\.py\b|scripts/verify_invariants\.py\b)"
)

_READONLY_SUBAGENT_TYPES = frozenset({
    "research",
    "meta-auditor",
    "consistency-auditor",
    "specification-gap-auditor",
    "security-boundary-verifier",
    "silent-failure-hunter",
    "contract-change-auditor",
    "test-adequacy-auditor",
    "simplicity-auditor",
    "build-error-resolver",
})

def _normalize_model_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9.]+", "-", (name or "").lower()).strip("-")

_HIGHEST_EFFORT_SLUG_SUFFIXES = (
    "-high",
    "-max",
    "-maximum",
    "-xhigh",
    "-extra",
    "-extra-high",
)

def _normalize_effort_value(raw: str) -> str:
    return re.sub(r"[\s_]+", "-", (raw or "").strip().lower()).strip("-")

def _allowed_slug_suffixes_for_effort(norm_effort: str) -> Tuple[str, ...]:
    if norm_effort in ("1", "1.0", "1.00", "100%"):
        return ("high", "max", "maximum", "xhigh", "extra", "extra-high")
    if norm_effort in ("xhigh", "extra-high", "extrahigh", "extra"):
        return ("xhigh", "extra-high", "extra")
    if norm_effort in ("max", "maximum"):
        return ("max", "maximum")
    if norm_effort == "high":
        return ("high",)
    return ()

def _expand_highest_effort_slug_aliases(slug: str) -> set[str]:
    expanded = {slug}
    for sfx in ("-extra-high", "-extra", "-xhigh"):
        if slug.endswith(sfx):
            stem = slug[: -len(sfx)]
            if stem:
                expanded.update({f"{stem}-extra", f"{stem}-xhigh", f"{stem}-extra-high"})
            return expanded
    for sfx in ("-maximum", "-max"):
        if slug.endswith(sfx):
            stem = slug[: -len(sfx)]
            if stem:
                expanded.update({f"{stem}-max", f"{stem}-maximum"})
            return expanded
    return expanded

def _catalog_top_model_spec() -> Tuple[str, set[str]]:
    """
    Loads the authoritative top catalog model and high-effort slug from
    `skills/upstream-auditor/upstream_state.seed.json`, plus operator-approved peer
    flagship slugs listed in its `approved_customization_models` array and any
    operator-acknowledged high/max flagship slug in `upstream_state.json`.
    """
    top_name = "Gemini 4 Neon (XHigh)"
    top_slug = "gemini-4-neon-xhigh"
    peer_slugs: set[str] = _expand_highest_effort_slug_aliases("gemini-4-carbon-high")
    loaded_seed: Optional[Dict[str, Any]] = None
    seed_candidates = _upstream_seed_candidates()
    for candidate in seed_candidates:
        if candidate.is_file():
            data = read_json(candidate, default={})
            if isinstance(data, dict) and data:
                raw_name = str(data.get("last_audited_model") or "").strip()
                raw_slug = _normalize_model_slug(str(data.get("last_model_slug") or raw_name))
                if not (raw_name or raw_slug):
                    continue
                loaded_seed = data
                peer_slugs = set()
                if raw_name:
                    top_name = raw_name
                if raw_slug:
                    top_slug = raw_slug
                approved_peers = data.get("approved_customization_models")
                if isinstance(approved_peers, list):
                    for peer in approved_peers:
                        if not isinstance(peer, str):
                            continue
                        peer_slug = _normalize_model_slug(peer)
                        # Only highest-effort flagship slugs may widen the gate (GEMINI.md Rule 17).
                        if peer_slug.endswith(_HIGHEST_EFFORT_SLUG_SUFFIXES):
                            peer_slugs.update(_expand_highest_effort_slug_aliases(peer_slug))
                break

    allowed = _expand_highest_effort_slug_aliases(top_slug) | peer_slugs
    state_candidates = [
        state_dir() / "upstream_state.json",
        Path.home() / ".local" / "state" / "plumbwork" / "upstream_state.json",
    ]
    for st_path in state_candidates:
        if st_path.is_file():
            st_data = read_json(st_path, default={})
            if isinstance(st_data, dict):
                if loaded_seed is not None:
                    from guard.upstream import reconcile_state_with_seed

                    st_data, _ = reconcile_state_with_seed(dict(st_data), loaded_seed)
                acked_slug = _normalize_model_slug(
                    str(st_data.get("last_model_slug") or st_data.get("last_audited_model") or "")
                )
                if acked_slug and acked_slug.endswith(_HIGHEST_EFFORT_SLUG_SUFFIXES):
                    allowed.update(_expand_highest_effort_slug_aliases(acked_slug))
    return top_name, allowed

def _infer_effort_from_model_label(model_label: str) -> str:
    if not model_label:
        return ""
    m = _MODEL_EMBEDDED_EFFORT_RE.search(model_label.strip())
    if m:
        raw_eff = (m.group(1) or m.group(2) or "").strip().lower()
        return re.sub(r"[\s_-]+", "-", raw_eff)
    slug = _normalize_model_slug(model_label)
    for suffix in ("xhigh", "extra-high", "extra", "high", "max", "maximum", "medium", "low", "minimal"):
        if slug.endswith(f"-{suffix}"):
            return suffix
    return ""

def _extract_transcript_model_and_effort(payload: Dict[str, Any]) -> Tuple[str, str]:
    transcript = payload.get("transcriptPath") or payload.get("transcript_path")
    if not isinstance(transcript, str) or not transcript.strip():
        return "", ""
    path = Path(transcript).expanduser()
    found_model = ""
    found_effort = ""
    for entry in _iter_jsonl_tail_entries(path, max_scan_bytes=16 * 1024 * 1024):
        step_type = str(entry.get("type", "")).upper()
        source = str(entry.get("source", "")).upper()
        is_user_entry = (
            step_type == "USER_INPUT" and source in ("", "USER_EXPLICIT")
        ) or (not step_type and source == "USER_EXPLICIT")
        if not is_user_entry:
            continue
        content = str(entry.get("content") or "")
        if "USER_SETTINGS_CHANGE" not in content.upper():
            continue
        cleaned_content = _USER_REQUEST_BLOCK_RE.sub(
            " ",
            _INLINE_TAG_CODE_RE.sub(
                " ",
                _FENCE_RE.sub(" ", _PASTED_RE.sub(" ", content)),
            ),
        )
        blocks = _USER_SETTINGS_BLOCK_RE.findall(cleaned_content)
        for block in reversed(blocks):
            if not found_effort:
                eff_matches = _SETTINGS_EFFORT_RE.findall(block) or _SETTINGS_KV_EFFORT_RE.findall(block)
                if eff_matches:
                    found_effort = eff_matches[-1].strip()
            if not found_model:
                mod_matches = _SETTINGS_MODEL_RE.findall(block) or _SETTINGS_KV_MODEL_RE.findall(block)
                if mod_matches:
                    found_model = mod_matches[-1].strip()
                    if not found_effort:
                        found_effort = _infer_effort_from_model_label(found_model)
                    return found_model, found_effort
            if found_model and found_effort:
                return found_model, found_effort
    return found_model, found_effort

def _extract_transcript_model_setting(payload: Dict[str, Any]) -> str:
    return _extract_transcript_model_and_effort(payload)[0]

def _find_harness_repo_root(path: Path) -> Optional[Path]:
    """Walks bounded ancestors of `path` (both lexical and resolved) to locate an enclosing Plumbwork checkout."""
    starts: List[Path] = []
    try:
        starts.append(Path(os.path.abspath(path)))
    except (OSError, RuntimeError, ValueError):
        pass
    try:
        res_p = Path(path).resolve()
        if res_p not in starts:
            starts.append(res_p)
    except (OSError, RuntimeError, ValueError):
        pass
    for cur in starts:
        for idx, anc in enumerate((cur, *cur.parents)):
            if idx > 24 or anc == Path(anc.anchor):
                break
            if _is_harness_repo_root(anc) and not _targets_governance_dir(str(anc)):
                return anc
    return None

def _workspaces_in_harness_scope(workspaces: Sequence[Path], effective_cwd: Optional[Path]) -> bool:
    """True when active workspace/cwd context is a `plumbwork` source checkout."""
    if effective_cwd is not None:
        return _find_harness_repo_root(effective_cwd) is not None
    if workspaces:
        return any(_find_harness_repo_root(ws) is not None for ws in workspaces)
    try:
        cwd = Path.cwd()
    except OSError:
        return False
    if _targets_governance_dir(str(cwd)):
        return False
    return _find_harness_repo_root(cwd) is not None

def _targets_customization_structure(target_path_str: str, workspace: Optional[Path] = None) -> bool:
    """
    Returns True when `target_path_str` targets a harness governance/customization artifact
    inside a `plumbwork` repository checkout or a protected global governance root
    (`~/.gemini/config`, `~/.gemini/{GEMINI,AGENTS}.md`, `data_dir()/runtime`).
    External non-harness projects' own `AGENTS.md`, `GEMINI.md`, `SKILL.md`, and `.cursor/`
    files are NOT Rule-17 model-gated (workspace `.agents/hooks.json` remains separately
    protected via `force_ask`).
    """
    if not target_path_str or not target_path_str.strip():
        return False
    cleaned_target = target_path_str.strip()
    if "\x00" in cleaned_target or (cleaned_target.lower().startswith("file:") and "%00" in cleaned_target.lower()):
        return True
    if cleaned_target.lower().startswith("file:"):
        parsed_cust_uri = _parse_file_uri(cleaned_target)
        if parsed_cust_uri is not None:
            cleaned_target = parsed_cust_uri
        elif "%" in cleaned_target:
            import urllib.parse

            cleaned_target = urllib.parse.unquote(cleaned_target)
        if "\x00" in cleaned_target:
            return True
    if _targets_governance_dir(cleaned_target):
        return True
    if workspace is not None and workspace.is_absolute() and _targets_governance_dir(cleaned_target, base_dir=workspace):
        return True

    canon_cust = _canonicalize_check_path(cleaned_target)
    raw = os.path.expanduser(canon_cust or cleaned_target).replace("\\", "/")
    collapsed = _normalize_shell_paths(raw if raw.startswith("/") else f"/{raw}")
    norm = re.sub(r"^/+", "", collapsed) if not raw.startswith("/") else collapsed
    norm = re.sub(r"^\./+", "", norm)
    parts = [p for p in norm.split("/") if p and p != "."]
    if not parts:
        return False

    expanded = Path(os.path.expanduser(cleaned_target))
    if expanded.is_absolute():
        cand_raw = expanded
        check_gov = True
    elif workspace is not None and workspace.is_absolute():
        cand_raw = workspace / expanded
        check_gov = True
    else:
        # Never resolve relative paths against a governance/runtime `os.getcwd()` (CWD-isolation invariant).
        # With no workspace provided, fail closed on harness-owned source paths (e.g. `guard/hooks/...`, `skills/...`).
        norm_lower = norm.lower()
        parts_lower = [p.lower() for p in parts]
        if (
            norm_lower in _HARNESS_SOURCE_FILES
            or (len(parts_lower) >= 2 and parts_lower[0] in _HARNESS_SOURCE_TOP_DIRS)
        ):
            return True
        try:
            cwd = Path.cwd()
        except OSError:
            return False
        if _targets_governance_dir(str(cwd)) or _find_harness_repo_root(cwd) is None:
            return False
        cand_raw = cwd / expanded
        check_gov = True

    candidates: List[Path] = []
    try:
        candidates.append(Path(os.path.abspath(cand_raw)))
    except (OSError, RuntimeError, ValueError):
        pass
    try:
        res_cand = cand_raw.resolve()
        if res_cand not in candidates:
            candidates.append(res_cand)
    except (OSError, RuntimeError, ValueError):
        pass

    for cand_path in candidates:
        if check_gov and _targets_governance_dir(str(cand_path)):
            return True
        h_root = _find_harness_repo_root(cand_path)
        if h_root is not None:
            try:
                rel = cand_path.relative_to(h_root)
            except (OSError, RuntimeError, ValueError):
                rel = None
            if rel is not None:
                rel_norm = str(rel).replace("\\", "/").lower()
                rel_parts = [p.lower() for p in rel.parts if p]
                if rel_parts and (
                    rel_parts[-1] in _CUSTOMIZATION_BASENAMES
                    or rel_parts[-1].endswith(".mdc")
                    or any(p in _CUSTOMIZATION_DIR_SEGMENTS for p in rel_parts)
                    or rel_norm in _HARNESS_SOURCE_FILES
                    or rel_parts[0] in _HARNESS_SOURCE_TOP_DIRS
                ):
                    return True
    return False

def _text_targets_customization(
    text: str,
    workspaces: Sequence[Path],
    fallback_ws: Optional[Path] = None,
    effective_cwd: Optional[Path] = None,
    extra_tokens: Sequence[str] = (),
) -> bool:
    """Checks subagent/swarm/workflow natural-language descriptions without bare English word false positives."""
    def _abs_ws(p: Optional[Path]) -> Optional[Path]:
        if p is None:
            return None
        ps = str(p)
        if p.is_absolute() or bool(re.match(r"^[A-Za-z]:[/\\]", ps)) or ps.startswith("\\\\"):
            return p
        return None

    abs_eff = _abs_ws(effective_cwd)
    abs_fb = _abs_ws(fallback_ws)
    abs_workspaces = [w for w in (_abs_ws(ws) for ws in workspaces) if w is not None]
    ws_ctx = abs_eff if abs_eff is not None else (abs_fb if abs_fb is not None else (abs_workspaces[0] if abs_workspaces else None))
    if _workspaces_in_harness_scope(abs_workspaces, ws_ctx) and (
        re.search(_CUST_CMD_UNIVERSAL_TARGET_PAT, text, re.IGNORECASE)
        or re.search(_CUST_CMD_HARNESS_SLASH_DIRS_PAT, text, re.IGNORECASE)
    ):
        return True
    gov_bases: List[Path] = []
    for b in (ws_ctx, abs_fb, *abs_workspaces):
        if b is not None and b not in gov_bases:
            gov_bases.append(b)
    if any(_targets_governance_dir(str(b)) or _targets_customization_structure(str(b), workspace=ws_ctx) for b in gov_bases):
        return True
    candidate_tokens: List[str] = list(extra_tokens)

    def _add_cand_tok(raw_t: str) -> None:
        for sub_t in (raw_t, raw_t.strip("*")):
            if not sub_t:
                continue
            variants = [sub_t]
            if "=" in sub_t and not sub_t.lower().startswith("file:"):
                rhs = sub_t.split("=", 1)[1].strip("*")
                if rhs:
                    variants.append(rhs)
            for v in variants:
                if "/" in v or "\\" in v or "." in v or v.startswith(("~", "$", "%")):
                    if v not in candidate_tokens:
                        candidate_tokens.append(v)
                    stripped_v = v.rstrip(".,:;!?*")
                    if (
                        stripped_v
                        and stripped_v != v
                        and ("/" in stripped_v or "\\" in stripped_v or "." in stripped_v or stripped_v.startswith(("~", "$", "%")))
                        and stripped_v not in candidate_tokens
                    ):
                        candidate_tokens.append(stripped_v)

    for tok in re.findall(r"(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|[^\s'\"`,;()\[\]{}<>])+", text):
        _add_cand_tok(tok)
    for cand in candidate_tokens:
        if _targets_governance_dir(cand) or any(_targets_governance_dir(cand, base_dir=b) for b in gov_bases):
            return True
        if _targets_customization_structure(cand, workspace=ws_ctx):
            return True
        for ws in gov_bases:
            if ws != ws_ctx and _targets_customization_structure(cand, workspace=ws):
                return True
    return False

def _is_model_placeholder(label: Any) -> bool:
    """Returns True when `label` is an opaque Antigravity model placeholder such as `MODEL_PLACEHOLDER_M535`."""
    return isinstance(label, str) and label.strip().upper().startswith("MODEL_PLACEHOLDER")

def _seed_placeholder_diagnostic(placeholder_id: str, *, effort_verified: bool = False) -> str:
    """Checks canonical `upstream_state.seed.json` entries to produce a diagnostic alias hint."""
    target_up = placeholder_id.strip().upper()
    eff_note = (
        "effort verified in payload, model identity unverified"
        if effort_verified
        else "effort unverified in payload"
    )
    from guard.paths import share_dir_candidates

    seed_paths = [
        _repo_root() / "skills" / "upstream-auditor" / "upstream_state.seed.json",
        configured_config_dir() / "skills" / "upstream-auditor" / "upstream_state.seed.json",
        config_dir() / "skills" / "upstream-auditor" / "upstream_state.seed.json",
        *(sh / "skills" / "upstream-auditor" / "upstream_state.seed.json" for sh in share_dir_candidates()),
    ]
    for seed_file in seed_paths:
        try:
            if seed_file.is_file():
                data = json.loads(seed_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    raw_kpm = data.get("known_placeholder_models")
                    if isinstance(raw_kpm, dict):
                        for k, v in raw_kpm.items():
                            if (
                                isinstance(k, str)
                                and k.strip().upper() == target_up
                                and isinstance(v, str)
                                and v.strip()
                                and not _is_model_placeholder(v)
                                and v.strip().lower() != "auto"
                            ):
                                mapped = v.strip()
                                seed_pbtxt = str(data.get("last_pbtxt_model") or "").strip()
                                if seed_pbtxt and seed_pbtxt.upper() == target_up:
                                    return f"matches seed `last_pbtxt_model` / `known_placeholder_models` -> `{mapped}`, {eff_note}"
                                return f"matches seed `known_placeholder_models` -> `{mapped}`, {eff_note}"
                    seed_pbtxt = str(data.get("last_pbtxt_model") or "").strip()
                    seed_model = str(data.get("last_audited_model") or "").strip()
                    if seed_pbtxt and seed_pbtxt.upper() == target_up and seed_model and not _is_model_placeholder(seed_model):
                        return f"matches seed `last_pbtxt_model` -> `{seed_model}`, {eff_note}"
        except (OSError, ValueError):
            continue
    state_file = state_dir() / "upstream_state.json"
    try:
        if state_file.is_file():
            st_data = json.loads(state_file.read_text(encoding="utf-8"))
            if isinstance(st_data, dict):
                st_kpm = st_data.get("known_placeholder_models")
                if isinstance(st_kpm, dict):
                    for k, v in st_kpm.items():
                        if (
                            isinstance(k, str)
                            and k.strip().upper() == target_up
                            and isinstance(v, str)
                            and v.strip()
                            and not _is_model_placeholder(v)
                            and v.strip().lower() != "auto"
                        ):
                            return f"matches state `known_placeholder_models` -> `{v.strip()}`, {eff_note}"
                st_pbtxt = str(st_data.get("last_pbtxt_model") or "").strip()
                st_model = str(st_data.get("last_audited_model") or "").strip()
                if st_pbtxt and st_pbtxt.upper() == target_up and st_model and not _is_model_placeholder(st_model):
                    return f"matches state `last_pbtxt_model` -> `{st_model}`, {eff_note}"
    except (OSError, ValueError):
        pass
    return "unmapped placeholder not registered in `upstream_state.seed.json` — run `/audit-upstream --model`"

_NON_FLAGSHIP_MODEL_TOKEN_RE = _LazyRegex(
    r"(?:flash(?:lite)?|haiku|sonnet|(?:^|-)(?:lite|mini|nano|small|gpt-4o|gpt-3\.5)(?:-|$))"
)
_PRO_ORCHESTRATOR_RE = _LazyRegex(r"(?:^|-)orchestrator(?:-|$)")
_PRO_TIER_TOKEN_RE = _LazyRegex(r"(?:^|-)pro(?:-|$)")

def _is_pro_orchestrator_slug(eff_slug: str, model_suffix: str = "") -> bool:
    """True for Pro-class Orchestrator slugs (e.g. `gemini-pro-orchestrator-neon`) without low/medium effort or non-flagship tokens."""
    if not eff_slug:
        return False
    if model_suffix in ("medium", "med", "low", "minimal", "min"):
        return False
    if re.search(r"(?:^|-)(?:low|med|medium|minimal|min)(?:-|$)", eff_slug):
        return False
    if _NON_FLAGSHIP_MODEL_TOKEN_RE.search(eff_slug):
        return False
    return bool(_PRO_ORCHESTRATOR_RE.search(eff_slug) and _PRO_TIER_TOKEN_RE.search(eff_slug))

def _evaluate_customization_model_and_effort(payload: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """
    Evaluates Rule 17 top-catalog model and highest-effort requirements for customization writes.
    Returns `("deny", reason)` on downgraded/malformed model or effort, `("force_ask", reason)`
    when model/effort metadata is absent or only an opaque `MODEL_PLACEHOLDER_*` without
    corroborating concrete model identity, or `None` when compliant.
    """
    model_keys = ("modelName", "model_name", "model", "selectedModel", "selected_model", "activeModel", "active_model")
    effort_keys = (
        "effort",
        "effortLevel",
        "effort_level",
        "thinkingLevel",
        "thinking_level",
        "reasoningEffort",
        "reasoning_effort",
    )
    containers: List[Dict[str, Any]] = [payload]
    for sub_k in ("settings", "modelConfig", "model_config"):
        sub_v = payload.get(sub_k)
        if isinstance(sub_v, dict):
            containers.append(sub_v)

    top_name, allowed_slugs = _catalog_top_model_spec()
    has_model_key = False
    raw_model = ""
    placeholder_or_auto = ""
    for container in containers:
        for k in model_keys:
            if k in container:
                has_model_key = True
                val = container.get(k)
                if val is not None and not isinstance(val, str):
                    return (
                        "deny",
                        "[Harness Customization Model Gate] Malformed non-string model identifier in hook payload (GEMINI.md Rule 17).",
                    )
                if isinstance(val, str) and val.strip():
                    val_s = val.strip()
                    if _is_model_placeholder(val_s) or val_s.lower() == "auto":
                        if not placeholder_or_auto or (_is_model_placeholder(val_s) and placeholder_or_auto.lower() == "auto"):
                            placeholder_or_auto = val_s
                    elif not raw_model:
                        raw_model = val_s

    has_effort_key = False
    raw_effort = ""
    for container in containers:
        for k in effort_keys:
            if k in container:
                has_effort_key = True
                val = container.get(k)
                if isinstance(val, bool) or (val is not None and not isinstance(val, (str, int, float))):
                    return (
                        "deny",
                        "[Harness Customization Model Gate] Malformed effort value in hook payload (GEMINI.md Rule 17).",
                    )
                if val is not None and str(val).strip() and not raw_effort:
                    raw_effort = str(val).strip()

    transcript_model, transcript_effort = _extract_transcript_model_and_effort(payload)

    if not has_model_key and not has_effort_key and not transcript_model and not transcript_effort:
        return (
            "force_ask",
            (
                "[Harness Customization Model Gate] Active model and effort metadata are unavailable in the hook "
                f"payload; human confirmation is required to verify `{top_name}` (`High`/`Max` effort) before "
                "modifying customization or governance files (GEMINI.md Rule 17)."
            ),
        )

    # Latest <USER_SETTINGS_CHANGE> in transcript is authoritative over stale session-start payload fields.
    if transcript_model:
        effective_model = transcript_model
    elif raw_model:
        effective_model = raw_model
    else:
        effective_model = placeholder_or_auto

    effective_effort = transcript_effort if transcript_effort else raw_effort
    has_eff = has_effort_key or bool(transcript_effort)
    norm_effort = _normalize_effort_value(effective_effort) if has_eff else ""

    if has_eff:
        if norm_effort not in _ALLOWED_TOP_EFFORT_VALUES:
            return (
                "deny",
                (
                    "[Harness Customization Model Gate] Modifying customization or governance architecture "
                    f"requires the highest effort level (`High` / `XHigh` / `Max`) on `{top_name}`; "
                    f"active effort is `{effective_effort}` (GEMINI.md Rule 17)."
                ),
            )

    if _is_model_placeholder(effective_model):
        diag = _seed_placeholder_diagnostic(effective_model, effort_verified=has_eff)
        return (
            "force_ask",
            (
                "[Harness Customization Model Gate] Modifying customization or governance architecture "
                f"requires `{top_name}` (`High`/`XHigh`/`Max`); runtime reported opaque placeholder "
                f"`{effective_model}` ({diag}). Supply concrete model identity or confirm explicitly (GEMINI.md Rule 17)."
            ),
        )

    compatible_suffixes = (
        _allowed_slug_suffixes_for_effort(norm_effort)
        if has_eff
        else ("high", "max", "maximum", "xhigh", "extra", "extra-high")
    )

    if has_model_key or transcript_model:
        eff_slug = _normalize_model_slug(effective_model)
        eff_slug_alts: List[str] = []
        if eff_slug.endswith("-maximum"):
            eff_slug_alts.append(eff_slug[: -len("-maximum")] + "-max")
        elif eff_slug.endswith("-max"):
            eff_slug_alts.append(eff_slug[: -len("-max")] + "-maximum")
        elif eff_slug.endswith("-xhigh"):
            eff_slug_alts.extend([eff_slug[: -len("-xhigh")] + "-extra", eff_slug[: -len("-xhigh")] + "-extra-high"])
        elif eff_slug.endswith("-extra"):
            eff_slug_alts.extend([eff_slug[: -len("-extra")] + "-xhigh", eff_slug[: -len("-extra")] + "-extra-high"])
        elif eff_slug.endswith("-extra-high"):
            eff_slug_alts.extend([eff_slug[: -len("-extra-high")] + "-xhigh", eff_slug[: -len("-extra-high")] + "-extra"])

        model_suffix = ""
        for cand_sfx in ("extra-high", "xhigh", "extra", "maximum", "max", "high", "medium", "med", "low", "minimal", "min"):
            if eff_slug.endswith(f"-{cand_sfx}"):
                model_suffix = cand_sfx
                break

        direct_slug_match = bool(
            eff_slug in allowed_slugs or any(alt in allowed_slugs for alt in eff_slug_alts)
        )
        combined_top_slug = (
            has_eff
            and not model_suffix
            and any(f"{eff_slug}-{sfx}" in allowed_slugs for sfx in compatible_suffixes)
        )
        effort_mismatch_with_model = (
            has_eff
            and direct_slug_match
            and model_suffix in ("xhigh", "extra", "extra-high")
            and norm_effort == "high"
        )
        if (
            not eff_slug
            or eff_slug == "auto"
            or effort_mismatch_with_model
            or (not direct_slug_match and not combined_top_slug)
        ):
            verified_top_effort = bool(
                (has_eff and norm_effort in _ALLOWED_TOP_EFFORT_VALUES)
                or (not has_eff and model_suffix in ("extra-high", "xhigh", "extra", "maximum", "max", "high"))
            )
            base_model_slug = eff_slug[: -len(model_suffix) - 1] if model_suffix else eff_slug
            is_known_catalog_base = any(
                s == base_model_slug or s.startswith(f"{base_model_slug}-") for s in allowed_slugs
            )
            is_pro_orchestrator = _is_pro_orchestrator_slug(eff_slug, model_suffix)
            if is_pro_orchestrator and not effort_mismatch_with_model:
                return (
                    "force_ask",
                    (
                        "[Harness Customization Model Gate] Pro-class Orchestrator model "
                        f"`{effective_model}` requires explicit human confirmation before modifying customization or "
                        f"governance files; approved unattended allowlist is `{top_name}` "
                        f"(`{', '.join(sorted(allowed_slugs))}`) (GEMINI.md Rule 17)."
                    ),
                )
            is_flash_or_worker = bool(_NON_FLAGSHIP_MODEL_TOKEN_RE.search(eff_slug))
            is_known_non_flagship = bool(
                is_flash_or_worker
                or eff_slug == "orchestrator"
                or eff_slug.startswith("orchestrator-")
            )
            if (
                eff_slug
                and eff_slug != "auto"
                and not effort_mismatch_with_model
                and verified_top_effort
                and not is_known_catalog_base
                and not is_known_non_flagship
            ):
                return (
                    "force_ask",
                    (
                        "[Harness Customization Model Gate] Active model "
                        f"`{effective_model}` at high effort is not yet listed in `upstream_state.seed.json` "
                        f"(`{top_name}` / approved: `{', '.join(sorted(allowed_slugs))}`); "
                        "human confirmation is required to authorize this flagship model before modifying "
                        "customization or governance files (GEMINI.md Rule 17)."
                    ),
                )
            worker_guidance = (
                f" Switch to an approved top model (`{top_name}` / `{', '.join(sorted(allowed_slugs))}`) "
                "or escalate to an approved coordinator before editing governance/customization files."
                if is_flash_or_worker
                else ""
            )
            return (
                "deny",
                (
                    "[Harness Customization Model Gate] Modifying customization or governance architecture "
                    f"requires the catalog's top model and highest effort (`{top_name}` / approved: `{', '.join(sorted(allowed_slugs))}`); "
                    f"active model is `{effective_model or 'auto'}`"
                    f"{f' at effort `{effective_effort}`' if has_eff else ''}.{worker_guidance} (GEMINI.md Rule 17)."
                ),
            )

    if not (has_model_key or transcript_model):
        return (
            "force_ask",
            (
                "[Harness Customization Model Gate] Active model metadata is unavailable in the hook payload; "
                f"human confirmation is required to verify `{top_name}` before modifying customization or "
                "governance files (GEMINI.md Rule 17)."
            ),
        )

    return None

def _check_customization_model_and_effort(payload: Dict[str, Any]) -> Optional[str]:
    """
    Verifies that the active runtime model and effort match the catalog's top model and
    highest effort (`Gemini 4 Neon (XHigh)` / approved flagships in `upstream_state.seed.json`).
    Returns an error reason string on violation, or None if compliant (or missing payload metadata).
    """
    res = _evaluate_customization_model_and_effort(payload)
    if res is not None and res[0] == "deny":
        return res[1]
    return None

_WRITE_TARGET_ARG_KEYS = (
    "TargetFile",
    "targetFile",
    "target_file",
    "Path",
    "file_path",
    "filePath",
    "path",
    "AbsolutePath",
    "absolute_path",
    "absolutePath",
    "notebook_path",
    "notebookPath",
)

def _extract_write_targets(args: Dict[str, Any]) -> List[str]:
    targets: List[str] = []
    for key in _WRITE_TARGET_ARG_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip() and val not in targets:
            targets.append(val)
    edits = args.get("edits")
    if isinstance(edits, list):
        for item in edits:
            if isinstance(item, dict):
                for key in _WRITE_TARGET_ARG_KEYS:
                    val = item.get(key)
                    if isinstance(val, str) and val.strip() and val not in targets:
                        targets.append(val)
    return targets

def _inspect_workflow_script(
    source: str,
    arg_strings: Sequence[str],
    payload: Dict[str, Any],
    workspace: Optional[Path],
    workflow_cwd: Optional[Path] = None,
    *,
    swarm_overlay: Optional[Dict[str, Any]] = None,
    pending_swarm_ops: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[Dict[str, Any], List[Tuple[str, str]]]:
    try:
        from . import _workflow_ast
    except (ImportError, SyntaxError) as exc:
        return (
            {
                "decision": "deny",
                "reason": (
                    f"[Harness Workflow Shield] Failed to load workflow AST verifier "
                    f"({type(exc).__name__}): {exc}"
                ),
            },
            [],
        )

    return _workflow_ast._inspect_workflow_script(
        source,
        arg_strings,
        payload,
        workspace,
        workflow_cwd=workflow_cwd,
        swarm_overlay=swarm_overlay,
        pending_swarm_ops=pending_swarm_ops,
    )

def _payload_cwd(payload: Dict[str, Any], args: Optional[Dict[str, Any]] = None) -> Optional[Path]:
    for container in ((args, payload) if isinstance(args, dict) else (payload,)):
        if not isinstance(container, dict):
            continue
        for key in ("cwd", "Cwd", "workingDirectory", "working_directory"):
            val = container.get(key)
            if isinstance(val, str) and val.strip():
                raw_v = val.strip()
                if os.name != "nt" and re.match(
                    r"^(?:~|\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})|%[A-Za-z_][A-Za-z0-9_]*%|[A-Za-z]:)\\",
                    raw_v,
                    re.IGNORECASE,
                ):
                    raw_v = raw_v.replace("\\\\", "/").replace("\\", "/")
                raw_v = re.sub(
                    r"^(?:\$HOME|\$\{HOME\}|%USERPROFILE%|\$USERPROFILE)(?=[/\\]|$)",
                    lambda _m: str(Path.home()),
                    raw_v,
                    flags=re.IGNORECASE,
                )
                if os.name != "nt" and re.match(r"^[A-Za-z]:\\", raw_v):
                    raw_v = raw_v.replace("\\\\", "/").replace("\\", "/")
                return Path(os.path.expanduser(raw_v))
    return None


def _format_force_ask_reason(
    reason: str,
    *,
    what_changes: str,
    if_approved: str,
    if_denied: str,
) -> str:
    """Formats a PreToolUse `force_ask` reason with a standardized 3-sentence plain-language operator header."""
    raw = (reason or "").strip()
    if raw.startswith("What changes:"):
        return raw
    w = " ".join(what_changes.split()).rstrip(".") + "."
    a = " ".join(if_approved.split()).rstrip(".") + "."
    d = " ".join(if_denied.split()).rstrip(".") + "."
    detail_lines: List[str] = []
    if raw:
        collapsed = " ".join(raw.splitlines()).strip()
        for chunk in collapsed.split(". "):
            c = " ".join(chunk.split())
            if not c:
                continue
            if not c.endswith((".", "!", "?", ")")):
                c += "."
            detail_lines.append(c)
    lines = [
        f"What changes: {w}",
        f"If approved: {a}",
        f"If denied: {d}",
    ]
    if detail_lines:
        lines.append(f"Details: {detail_lines[0]}")
        lines.extend(detail_lines[1:])
    return "\n".join(lines)


def _enrich_force_ask_response(
    res: Dict[str, Any],
    tool_name: str,
) -> Dict[str, Any]:
    """Ensures every `force_ask` PreToolUse response carries a readable 3-sentence operator header."""
    if not isinstance(res, dict) or res.get("decision") != "force_ask":
        return res
    raw_reason = str(res.get("reason") or "").strip()
    if raw_reason.startswith("What changes:"):
        return res
    m_tag = re.match(r"^(\[Harness [^\]]+\])\s*(.*)$", raw_reason, re.DOTALL)
    tag = m_tag.group(1).lower() if m_tag else ""
    body_head = (m_tag.group(2) if m_tag else raw_reason)[:96].lower()
    if tag == "[harness test boundary]":
        what = "Updates `## Authorized Test Modifications` in `tasks.md` to change Rule 9 test-edit permissions"
        approved = "Allows the Stop gate to accept edits to the listed test file(s) under Rule 9"
        denied = "Keeps `tasks.md` unchanged and leaves existing test assertions frozen"
    elif tag == "[harness hook boundary]":
        what = "Modifies workspace `.agents/hooks.json`, which can override or disable global harness hooks"
        approved = "Writes the workspace hook configuration as requested"
        denied = "Leaves `.agents/hooks.json` untouched and preserves current global hook enforcement"
    elif tag in ("[harness customization model gate]", "[harness model & effort gate]"):
        what = f"Runs `{tool_name}` on harness governance/customization files under an unverified or non-allowlisted model/effort"
        approved = "Permits this governance/customization action for this turn"
        denied = "Blocks the edit until an approved top model runs at highest effort"
    elif tag == "[harness supply-chain guard]" or (tag == "[harness bash guard]" and body_head.startswith("unpinned")):
        what = f"Runs `{tool_name}` with an unpinned remote package executable"
        approved = "Downloads and executes the remote package version resolved at runtime"
        denied = "Cancels execution so an exact pinned version can be supplied first"
    elif tag == "[harness mcp shield]":
        what = f"Invokes mutating or high-risk MCP tool `{tool_name}` against project or runtime state"
        approved = "Executes the MCP tool call as requested"
        denied = "Blocks the MCP call and leaves target state unchanged"
    elif tag in ("[harness bash guard]", "[harness workflow guard]") and any(
        tok in body_head for tok in ("high-risk", "destructive", "recursive", "outside the active", "external script", "shutil.rmtree")
    ):
        what = f"Executes a potentially destructive `{tool_name}` operation affecting files or git history"
        approved = "Runs the command immediately with irreversible or persistent side effects"
        denied = "Cancels the operation with zero files or commits modified"
    elif tag in ("[harness swarm guard]", "[harness workflow guard]", "[harness schedule guard]"):
        what = f"Dispatches orchestration tool `{tool_name}` touching governed or sensitive scope"
        approved = "Starts or delivers the delegated agent, workflow, or scheduled job"
        denied = "Blocks the delegation or schedule with no background task launched"
    else:
        what = f"Executes gated `{tool_name}` operation flagged by PreToolUse safety rules"
        approved = "Proceeds with this tool call as requested"
        denied = "Cancels this tool call and leaves workspace state unchanged"
    enriched = dict(res)
    enriched["reason"] = _format_force_ask_reason(
        raw_reason,
        what_changes=what,
        if_approved=approved,
        if_denied=denied,
    )
    return enriched


def handle_pre_tool_use(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {
            "decision": "deny",
            "reason": "[Harness PreToolUse Gate] Malformed non-dict hook payload (failing closed).",
        }
    if "toolCall" in payload:
        raw_tc = payload.get("toolCall")
        if not isinstance(raw_tc, dict):
            return {
                "decision": "deny",
                "reason": "[Harness PreToolUse Gate] Malformed non-dict `toolCall` envelope (failing closed).",
            }
        tool_call = raw_tc
    else:
        raw_input_obj = payload.get("tool_input") if "tool_input" in payload else payload.get("toolInput")
        if raw_input_obj is not None and not isinstance(raw_input_obj, dict):
            return {
                "decision": "deny",
                "reason": "[Harness PreToolUse Gate] Malformed non-dict `tool_input` arguments (failing closed).",
            }
        tool_call = {
            "name": payload.get("tool_name") or payload.get("toolName") or "",
            "args": raw_input_obj if raw_input_obj is not None else {},
        }
    tool_name = str(tool_call.get("name") or "").strip().lower().rsplit(":", 1)[-1]
    raw_args = tool_call.get("args")
    if raw_args is None:
        args: Dict[str, Any] = {}
    elif isinstance(raw_args, dict):
        args = raw_args
    else:
        return {
            "decision": "deny",
            "reason": "[Harness PreToolUse Gate] Malformed non-dict `toolCall.args` (failing closed).",
        }
    res = _handle_pre_tool_use_core(payload, tool_name, args)
    return _enrich_force_ask_response(res, tool_name)


def _handle_pre_tool_use_core(
    payload: Dict[str, Any],
    tool_name: str,
    args: Dict[str, Any],
) -> Dict[str, Any]:
    workspaces = _workspaces_from_payload(payload)
    workspace = workspaces[0] if workspaces else None
    accepts_args_cwd = tool_name in ("run_command", "bash", "execute_command", "shell", "run_workflow")
    for _cwd_src_name, _cwd_container in (
        (("args", args), ("payload", payload)) if accepts_args_cwd else (("payload", payload),)
    ):
        if isinstance(_cwd_container, dict):
            _raw_cwds = [
                _cwd_container.get(_ck).strip()
                for _ck in ("cwd", "Cwd", "workingDirectory", "working_directory")
                if isinstance(_cwd_container.get(_ck), str) and _cwd_container.get(_ck).strip()
            ]
            if len(set(_raw_cwds)) > 1:
                return {
                    "decision": "deny",
                    "reason": (
                        f"[Harness PreToolUse Gate] Conflicting working-directory keys in `{_cwd_src_name}` "
                        f"for `{tool_name}` (failing closed)."
                    ),
                }
    payload_cwd = _payload_cwd(payload, args if accepts_args_cwd else None)
    if payload_cwd is not None:
        _pc_str = str(payload_cwd)
        _pc_abs = payload_cwd.is_absolute() or bool(re.match(r"^[A-Za-z]:[/\\]", _pc_str)) or _pc_str.startswith("\\\\")
        effective_cwd: Optional[Path] = (
            payload_cwd if _pc_abs else ((workspace / payload_cwd) if workspace is not None else None)
        )
    else:
        effective_cwd = workspace

    def _sub_fn(submod: str, fn_name: str) -> Any:
        override = globals().get(fn_name)
        if override is not None:
            return override
        import importlib

        return getattr(importlib.import_module(f"{__package__}.{submod}"), fn_name)

    # 0. MCP tools (`call_mcp_tool` lazy wrapper & `mcp_*` eager native tools — ADR-0004 Decision 1 / H-03)
    if tool_name == "call_mcp_tool" or tool_name.startswith("mcp_"):
        return _sub_fn("_mcp_guard", "_inspect_mcp_tool_call")(
            tool_name,
            args,
            effective_cwd,
            payload=payload,
            workspaces=workspaces,
            workspace=workspace,
        )

    _is_readonly_task_mgmt = (
        tool_name == "manage_task"
        and str(args.get("Action") or args.get("action") or "").strip().lower() != "send_input"
    )
    if (
        not _is_readonly_task_mgmt
        and (
            tool_name in WRITE_TOOL_NAMES
            or tool_name in COMMAND_TOOL_NAMES
            or tool_name in ("invoke_subagent", "swarm", "post_message", "send_message", "define_subagent", "schedule", "run_workflow")
        )
        and _environments_registry_corrupt()
    ):
        return {
            "decision": "deny",
            "reason": (
                "[Harness Governance Shield] Protected environments registry `environments.json` is corrupt or "
                "unreadable (failing closed; run `plumb-guard doctor` in an interactive terminal)."
            ),
        }

    # 1. File-writing tools: enforce Governance Shield (~/.gemini/config governance seams + Guard state/runtime)
    #    and Top-Catalog Model & Effort Gate on customization/governance files (GEMINI.md Rule 17).
    if tool_name in WRITE_TOOL_NAMES:
        targets = _extract_write_targets(args)
        for target in targets:
            if "\x00" in target or (target.strip().lower().startswith("file:") and "%00" in target.lower()):
                return {
                    "decision": "deny",
                    "reason": "[Harness Governance Shield] Null bytes in target paths are prohibited.",
                }
            write_bases: List[Path] = []
            for b in (effective_cwd, workspace, *workspaces):
                if b is not None and b not in write_bases:
                    write_bases.append(b)
            if (
                (not write_bases and _targets_governance_dir(target))
                or any(_targets_governance_dir(target, base_dir=b) for b in write_bases)
            ):
                return {
                    "decision": "deny",
                    "reason": (
                        "[Harness Governance Shield] Direct write to the protected governance tree "
                        f"(`{target}`) is prohibited (GEMINI.md Rule 12 & Rule 15a). Author changes in "
                        "the source repository and ask the human operator to run `install.py`."
                    ),
                }

        def _resolve_target_and_ws(t_str: str) -> Tuple[str, Optional[Path]]:
            raw_t = t_str.strip()
            is_unparsed_file_uri = False
            if raw_t.lower().startswith("file:"):
                parsed_t = _parse_file_uri(raw_t)
                if parsed_t is not None:
                    raw_t = parsed_t
                else:
                    is_unparsed_file_uri = True
            if is_unparsed_file_uri:
                t_ws = _workspace_for_target(
                    raw_t, workspaces, fallback=(effective_cwd if effective_cwd is not None else workspace)
                )
                return raw_t, t_ws
            exp_t = Path(os.path.expanduser(raw_t))
            rel_fallback = effective_cwd if payload_cwd is not None else None
            t_ws = _workspace_for_target(raw_t, workspaces, fallback=rel_fallback)
            base_for_rel = effective_cwd if payload_cwd is not None else (t_ws if t_ws is not None else effective_cwd)
            res_str = str(base_for_rel / exp_t) if (base_for_rel is not None and not exp_t.is_absolute()) else raw_t
            t_ws = _workspace_for_target(
                res_str, workspaces, fallback=(t_ws if t_ws is not None else (effective_cwd or workspace))
            )
            return res_str, t_ws

        if any(
            _targets_customization_structure(res_t, workspace=t_ws)
            for t_raw in targets
            for res_t, t_ws in [_resolve_target_and_ws(t_raw)]
        ):
            mod_eval = _evaluate_customization_model_and_effort(payload)
            if mod_eval is not None:
                return {"decision": mod_eval[0], "reason": mod_eval[1]}
        write_content_str = str(
            args.get("Content")
            or args.get("content")
            or args.get("Replacement")
            or args.get("replacement")
            or args.get("newText")
            or args.get("new_text")
            or ""
        )
        for target in targets:
            res_t, t_ws = _resolve_target_and_ws(target)
            canon_res_t = _canonicalize_check_path(res_t)
            resolved_res_t = ""
            try:
                if not res_t.lower().startswith("file:"):
                    resolved_res_t = str(Path(os.path.expanduser(res_t)).resolve()).replace("\\", "/")
            except (OSError, RuntimeError, ValueError):
                resolved_res_t = ""
            if any(
                re.search(r"(?:^|/)(?:\.agents?|_agents?)/hooks\.json$", cand_h, re.IGNORECASE)
                for cand_h in (canon_res_t, resolved_res_t)
                if cand_h
            ):
                if (
                    bool(write_content_str.strip())
                    or bool(workspaces)
                    or not _workspaces_in_harness_scope(workspaces, effective_cwd or t_ws)
                ):
                    return {
                        "decision": "force_ask",
                        "reason": (
                            "[Harness Governance Shield] Modifying workspace `.agents/hooks.json` can shadow or disable "
                            "global `harness-gate` / `upstream-watchdog` lifecycle hooks and requires explicit human "
                            "confirmation (GEMINI.md Rule 12 & Rule 15a)."
                        ),
                    }
            _low_t = target.strip().lower()
            _tasks_hit = (
                "tasks" in _low_t
                or "tasks" in res_t.lower()
                or "tasks" in canon_res_t.lower()
                or "tasks" in resolved_res_t.lower()
                or _low_t.startswith("file:")
            )
            _tasks_check_target = (
                resolved_res_t
                if (resolved_res_t and Path(resolved_res_t).name.lower() == "tasks.md" and Path(canon_res_t).name.lower() != "tasks.md")
                else target
            )
            if (
                _tasks_hit
                and _sub_fn("_write_guard", "_write_mutates_authorized_test_section")(
                    _tasks_check_target, args, effective_cwd or t_ws, conv_id=_conversation_id(payload)
                )
            ):
                diff_summary = _sub_fn("_write_guard", "_summarize_authorized_test_mutation_diff")(
                    _tasks_check_target, args, effective_cwd or t_ws
                )
                return {
                    "decision": "force_ask",
                    "reason": _format_force_ask_reason(
                        "[Harness Test Boundary] Modifying `## Authorized Test Modifications` in `tasks.md` "
                        "requires explicit human confirmation (GEMINI.md Rule 9).",
                        what_changes=f"Updates `## Authorized Test Modifications` in `tasks.md`: {diff_summary}",
                        if_approved="Authorizes Stop-gate Rule 9 edits strictly for the listed test path(s)",
                        if_denied="Leaves `tasks.md` unchanged and keeps existing test assertions frozen under Rule 9",
                    ),
                }
        for target in targets:
            res_t, t_ws = _resolve_target_and_ws(target)
            _record_flight_pre_write(payload, t_ws, tool_name, res_t)
        return {"decision": "allow"}

    # 2. Command execution tools: lazily dispatch to _shell_guard
    if tool_name in COMMAND_TOOL_NAMES:
        return _sub_fn("_shell_guard", "_handle_command_pre_tool_use")(
            tool_name, payload, args, workspaces, workspace, effective_cwd
        )

    # 3. Subagent delegation & native swarm/messaging/schedule gates: lazily dispatch to _swarm_guard
    if tool_name == "invoke_subagent":
        return _sub_fn("_swarm_guard", "_handle_invoke_subagent_pre_tool_use")(
            payload, args, workspaces, workspace, effective_cwd
        )
    if tool_name == "swarm":
        return _sub_fn("_swarm_guard", "_handle_swarm_pre_tool_use")(
            payload, args, workspaces, workspace, effective_cwd=effective_cwd
        )
    if tool_name == "post_message":
        return _sub_fn("_swarm_guard", "_handle_post_message_pre_tool_use")(
            payload, args, workspaces, workspace, effective_cwd=effective_cwd
        )
    if tool_name == "send_message":
        return _sub_fn("_swarm_guard", "_handle_send_message_pre_tool_use")(
            payload, args, workspaces, workspace, effective_cwd=effective_cwd
        )
    if tool_name == "define_subagent":
        return _sub_fn("_swarm_guard", "_handle_define_subagent_pre_tool_use")(
            payload, args, workspaces, workspace, effective_cwd=effective_cwd
        )
    if tool_name == "schedule":
        return _sub_fn("_swarm_guard", "_handle_schedule_pre_tool_use")(
            payload, args, workspaces, workspace, effective_cwd=effective_cwd
        )

    # 4. Dynamic Python orchestration workflows (`run_workflow`): lazily dispatch to _shell_guard
    if tool_name == "run_workflow":
        return _sub_fn("_shell_guard", "_handle_workflow_pre_tool_use")(
            payload, args, workspaces, workspace, effective_cwd
        )

    # Normal pass-through in Antigravity 2.0 PreToolUse requires explicit {"decision": "allow"}
    return {"decision": "allow"}


_LAZY_SYMBOL_TO_SUBMODULE: Optional[Dict[str, str]] = None


def __getattr__(name: str) -> Any:
    global _LAZY_SYMBOL_TO_SUBMODULE
    if _LAZY_SYMBOL_TO_SUBMODULE is None:
        exports = _facade_attr("_SUBMODULE_EXPORTS", None)
        if not isinstance(exports, dict):
            import guard.agy_hooks as _ah

            exports = getattr(_ah, "_SUBMODULE_EXPORTS", {})
        _LAZY_SYMBOL_TO_SUBMODULE = {
            sym: mod
            for mod in ("_shell_guard", "_swarm_guard", "_mcp_guard", "_write_guard")
            for sym in (exports.get(mod) or ())
        }
    submod = _LAZY_SYMBOL_TO_SUBMODULE.get(name)
    if submod is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    mod = importlib.import_module(f"{__package__}.{submod}")
    return getattr(mod, name)


def __dir__() -> List[str]:
    global _LAZY_SYMBOL_TO_SUBMODULE
    if _LAZY_SYMBOL_TO_SUBMODULE is None:
        exports = _facade_attr("_SUBMODULE_EXPORTS", None)
        if not isinstance(exports, dict):
            import guard.agy_hooks as _ah

            exports = getattr(_ah, "_SUBMODULE_EXPORTS", {})
        _LAZY_SYMBOL_TO_SUBMODULE = {
            sym: mod
            for mod in ("_shell_guard", "_swarm_guard", "_mcp_guard", "_write_guard")
            for sym in (exports.get(mod) or ())
        }
    return sorted(set(globals().keys()) | set(_LAZY_SYMBOL_TO_SUBMODULE.keys()))
