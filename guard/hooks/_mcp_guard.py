"""
guard/hooks/_mcp_guard.py — Lazy PreToolUse MCP tool-call inspection guard (ADR-0013).
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import pre_tool_use as _ptu
from .common import (
    _LazyRegex,
    _conversation_id,
)

_MCP_DEBUGGER_ESCAPE_RE = _LazyRegex(r"^\s*(?:!+|\.!|#!(?:pipe|python3?|ba?sh)\s+|(?:shell|system)\s+)", re.IGNORECASE)

_MCP_MUTATING_TOOL_HINT_RE = _LazyRegex(
    r"(?:write|edit|create|delete|remove|unlink|mv|move|rename|copy|chmod|chown|push|install|uninstall|"
    r"extract|save|exec|command|console|frida|script|gdb|rizin|cutter|adb|patch|modify|update|set_|put)",
    re.IGNORECASE,
)

def _collect_mcp_strings(value: Any, out: List[str], depth: int = 0) -> Optional[str]:
    if depth > 32:
        return "[Harness MCP Shield] MCP `Arguments` exceed maximum nesting depth (failing closed)."
    if isinstance(value, str):
        if "\x00" in value or (value.strip().lower().startswith("file:") and "%00" in value.lower()):
            return "[Harness MCP Shield] Null bytes in MCP arguments are prohibited."
        if value:
            out.append(value)
        return None
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                if "\x00" in k:
                    return "[Harness MCP Shield] Null bytes in MCP argument keys are prohibited."
                if k:
                    out.append(k)
            err = _collect_mcp_strings(v, out, depth + 1)
            if err:
                return err
        return None
    if isinstance(value, (list, tuple)):
        str_elts = [x for x in value if isinstance(x, str) and x]
        if len(str_elts) >= 2:
            out.append(" ".join(str_elts))
        for elt in value:
            err = _collect_mcp_strings(elt, out, depth + 1)
            if err:
                return err
        return None
    return None

_READONLY_MCP_ALLOWLIST = frozenset({"check_contrast"})

_MCP_PATH_ARG_KEYS_LOWER = frozenset({
    *(k.lower() for k in _ptu._WRITE_TARGET_ARG_KEYS),
    "filepath",
    "filename",
    "file",
    "files",
    "paths",
    "target",
    "targetpath",
    "target_path",
    "dest",
    "destination",
    "uri",
    "url",
    "source",
    "src",
    "dst",
    "directory",
    "dir",
})

def _normalize_mcp_path_value(val: str) -> str:
    s = val.strip()
    if s.lower().startswith("file:"):
        return _ptu._parse_file_uri(s) or s
    return s

def _extract_mcp_target_paths(mcp_args: Dict[str, Any], depth: int = 0) -> List[str]:
    if depth > 32 or not isinstance(mcp_args, dict):
        return []
    targets: List[str] = []
    for t in _ptu._extract_write_targets(mcp_args):
        nt = _normalize_mcp_path_value(t)
        if nt and nt not in targets:
            targets.append(nt)
    for k, v in mcp_args.items():
        k_low = str(k).strip().lower()
        if k_low in _MCP_PATH_ARG_KEYS_LOWER:
            if isinstance(v, str) and v.strip():
                nt = _normalize_mcp_path_value(v)
                if nt and nt not in targets:
                    targets.append(nt)
            elif isinstance(v, (list, tuple)):
                for item in v:
                    if isinstance(item, str) and item.strip():
                        nt = _normalize_mcp_path_value(item)
                        if nt and nt not in targets:
                            targets.append(nt)
                    elif isinstance(item, dict):
                        for sub_t in _extract_mcp_target_paths(item, depth + 1):
                            if sub_t not in targets:
                                targets.append(sub_t)
        elif isinstance(v, dict):
            for sub_t in _extract_mcp_target_paths(v, depth + 1):
                if sub_t not in targets:
                    targets.append(sub_t)
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, dict):
                    for sub_t in _extract_mcp_target_paths(item, depth + 1):
                        if sub_t not in targets:
                            targets.append(sub_t)
    return targets

def _inspect_mcp_tool_call(
    tool_name: str,
    args: Dict[str, Any],
    effective_cwd: Optional[Path],
    payload: Optional[Dict[str, Any]] = None,
    workspaces: Sequence[Path] = (),
    workspace: Optional[Path] = None,
) -> Dict[str, Any]:
    if tool_name == "call_mcp_tool":
        raw_inner = (
            args.get("ToolName")
            if "ToolName" in args
            else (args.get("toolName") if "toolName" in args else args.get("tool_name"))
        )
        if not isinstance(raw_inner, str) or not raw_inner.strip():
            return {
                "decision": "deny",
                "reason": "[Harness MCP Shield] `call_mcp_tool` requires a non-empty string `ToolName` (failing closed).",
            }
        raw_mcp_args = args.get("Arguments") if "Arguments" in args else args.get("arguments")
        if raw_mcp_args is None:
            mcp_args: Dict[str, Any] = {}
        elif isinstance(raw_mcp_args, dict):
            mcp_args = raw_mcp_args
        else:
            return {
                "decision": "deny",
                "reason": "[Harness MCP Shield] `call_mcp_tool` `Arguments` must be a JSON object/dict (failing closed).",
            }
        effective_mcp_tool = raw_inner.strip().lower()
        srv = str(args.get("ServerName") or args.get("serverName") or args.get("server_name") or "").strip()
        effective_label = f"{srv}:{effective_mcp_tool}" if srv else effective_mcp_tool
        is_high_risk = effective_mcp_tool in _ptu.HIGH_RISK_MCP_TOOL_NAMES
        is_readonly_allowlisted = effective_mcp_tool in _READONLY_MCP_ALLOWLIST
    else:
        mcp_args = args
        rest_name = tool_name[4:] if tool_name.startswith("mcp_") else tool_name
        effective_mcp_tool = rest_name
        effective_label = tool_name
        is_high_risk = any(
            rest_name == hr or rest_name.endswith(f"_{hr}") for hr in _ptu.HIGH_RISK_MCP_TOOL_NAMES
        )
        is_readonly_allowlisted = any(
            rest_name == ro or rest_name.endswith(f"_{ro}") for ro in _READONLY_MCP_ALLOWLIST
        )

    strings: List[str] = []
    err = _collect_mcp_strings(mcp_args, strings)
    if err:
        return {"decision": "deny", "reason": err}

    checks_gov_path = not is_readonly_allowlisted
    if checks_gov_path and _ptu._environments_registry_corrupt():
        return {
            "decision": "deny",
            "reason": (
                "[Harness Governance Shield] Protected environments registry `environments.json` is corrupt or "
                "unreadable (failing closed; run `agy-guard doctor` in an interactive terminal)."
            ),
        }
    mcp_targets = _extract_mcp_target_paths(mcp_args) if checks_gov_path else []
    if strings:
        from ._shell_guard import (
            _GIT_HOOK_BYPASS_RE,
            _GUARD_ADMIN_RE,
            _GUARD_API_TOKEN_PAT,
            _GUARD_INLINE_PY_RE,
            _INSTALL_PY_RE,
            _command_mutates_governance,
            _command_mutates_governance_in_cwd,
            _extract_shell_c_payloads,
            _mask_quoted_operators,
        )
    for s in strings:
        stripped_esc = _MCP_DEBUGGER_ESCAPE_RE.sub("", s).strip()
        cand_cmds = [s]
        if stripped_esc and stripped_esc not in cand_cmds:
            cand_cmds.append(stripped_esc)
        for base_c in list(cand_cmds):
            for ext_c in _extract_shell_c_payloads(base_c):
                if ext_c not in cand_cmds:
                    cand_cmds.append(ext_c)

        for c_str in cand_cmds:
            masked_c = _mask_quoted_operators(c_str)
            if _GUARD_ADMIN_RE.search(masked_c) or _GUARD_INLINE_PY_RE.search(c_str) or re.search(_GUARD_API_TOKEN_PAT, c_str):
                return {
                    "decision": "deny",
                    "reason": (
                        f"[Harness MCP Shield] Human-only `agy-guard` administration via MCP tool "
                        f"(`{effective_label}`) is prohibited (GEMINI.md Rule 12)."
                    ),
                }
            if _INSTALL_PY_RE.search(masked_c):
                return {
                    "decision": "deny",
                    "reason": (
                        f"[Harness MCP Shield] Executing `install.py` via MCP tool (`{effective_label}`) "
                        "is prohibited (GEMINI.md Rule 12)."
                    ),
                }
            if _GIT_HOOK_BYPASS_RE.search(masked_c):
                return {
                    "decision": "deny",
                    "reason": (
                        f"[Harness MCP Shield] Git hook bypass flags via MCP tool (`{effective_label}`) "
                        "are prohibited."
                    ),
                }
            mcp_cmd_bases: List[Path] = []
            for _mb in (effective_cwd, workspace, *workspaces):
                if _mb is not None and _mb not in mcp_cmd_bases:
                    mcp_cmd_bases.append(_mb)
            if _command_mutates_governance(c_str) or (
                checks_gov_path and any(_command_mutates_governance_in_cwd(c_str, _mb) for _mb in mcp_cmd_bases)
            ):
                return {
                    "decision": "deny",
                    "reason": (
                        f"[Harness MCP Shield] Mutating protected governance or Guard state via MCP tool "
                        f"(`{effective_label}`) is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                    ),
                }

        norm_s = _normalize_mcp_path_value(s)
        if checks_gov_path and any(
            _ptu._targets_governance_dir(cand_p)
            or (effective_cwd is not None and _ptu._targets_governance_dir(cand_p, base_dir=effective_cwd))
            or (workspace is not None and _ptu._targets_governance_dir(cand_p, base_dir=workspace))
            or any(_ptu._targets_governance_dir(cand_p, base_dir=ws) for ws in workspaces)
            for cand_p in ((s, norm_s) if norm_s != s else (s,))
        ):
            return {
                "decision": "deny",
                "reason": (
                    f"[Harness MCP Shield] Targeting protected governance or Guard path (`{s}`) via "
                    f"MCP tool (`{effective_label}`) is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                ),
            }

    mcp_has_explicit_cwd = isinstance(payload, dict) and _ptu._payload_cwd(payload, None) is not None

    def _resolve_mcp_target_and_ws(t_str: str) -> Tuple[str, Optional[Path]]:
        raw_t = t_str.strip()
        is_unparsed_file_uri = False
        if raw_t.lower().startswith("file:"):
            parsed_t = _ptu._parse_file_uri(raw_t)
            if parsed_t is not None:
                raw_t = parsed_t
            else:
                is_unparsed_file_uri = True
        if is_unparsed_file_uri:
            t_ws = _ptu._workspace_for_target(raw_t, workspaces, fallback=(effective_cwd or workspace))
            return raw_t, t_ws
        exp_t = Path(os.path.expanduser(raw_t))
        rel_mcp_fb = effective_cwd if mcp_has_explicit_cwd else None
        t_ws = _ptu._workspace_for_target(raw_t, workspaces, fallback=rel_mcp_fb)
        base_rel = effective_cwd if mcp_has_explicit_cwd else (t_ws if t_ws is not None else effective_cwd)
        res_str = str(base_rel / exp_t) if (base_rel is not None and not exp_t.is_absolute()) else raw_t
        if exp_t.is_absolute() or base_rel is not None:
            t_ws = _ptu._workspace_for_target(
                res_str, workspaces, fallback=(t_ws if t_ws is not None else (effective_cwd or workspace))
            )
        return res_str, t_ws

    if checks_gov_path and mcp_targets:
        if payload is not None and any(
            _ptu._targets_customization_structure(res_t, workspace=t_ws)
            or (res_t == t_raw and _ptu._targets_customization_structure(t_raw, workspace=t_ws))
            for t_raw in mcp_targets
            for res_t, t_ws in [_resolve_mcp_target_and_ws(t_raw)]
        ):
            mod_eval = _ptu._evaluate_customization_model_and_effort(payload)
            if mod_eval is not None:
                return {"decision": mod_eval[0], "reason": mod_eval[1]}

        for t_raw in mcp_targets:
            res_t, t_ws = _resolve_mcp_target_and_ws(t_raw)
            canon_mcp_t = _ptu._canonicalize_check_path(res_t)
            resolved_mcp_str = ""
            try:
                if not res_t.lower().startswith("file:"):
                    resolved_mcp_str = str(Path(os.path.expanduser(res_t)).resolve()).replace("\\", "/")
            except (OSError, RuntimeError, ValueError):
                resolved_mcp_str = ""
            if any(
                re.search(r"(?:^|/)(?:\.agents?|_agents?)/hooks\.json$", cand_h, re.IGNORECASE)
                for cand_h in (canon_mcp_t, resolved_mcp_str)
                if cand_h
            ):
                if bool(workspaces) or not _ptu._workspaces_in_harness_scope(workspaces, effective_cwd or t_ws):
                    return {
                        "decision": "force_ask",
                        "reason": (
                            "[Harness Governance Shield] Modifying workspace `.agents/hooks.json` via MCP tool "
                            f"(`{effective_label}`) can shadow or disable global lifecycle hooks and requires "
                            "explicit human confirmation (GEMINI.md Rule 12 & Rule 15a)."
                        ),
                    }
            if _ptu._write_mutates_authorized_test_section(
                t_raw, mcp_args, effective_cwd or t_ws, conv_id=_conversation_id(payload or {})
            ):
                return {
                    "decision": "force_ask",
                    "reason": (
                        "[Harness Test Boundary] Modifying `## Authorized Test Modifications` in `tasks.md` "
                        "requires explicit human confirmation (GEMINI.md Rule 9)."
                    ),
                }
            if Path(canon_mcp_t).name.lower() == "tasks.md" and not any(
                ck in mcp_args for ck in ("Content", "FileContent", "CodeContent", "content", "file_text")
            ):
                tasks_disk = Path(os.path.expanduser(canon_mcp_t))
                has_auth_heading = any("authorized test modifications" in x.lower() for x in strings)
                if not has_auth_heading:
                    try:
                        if os.path.lexists(tasks_disk):
                            has_auth_heading = (
                                "authorized test modifications"
                                in tasks_disk.read_text(encoding="utf-8", errors="ignore").lower()
                            )
                    except OSError:
                        has_auth_heading = True
                if has_auth_heading:
                    return {
                        "decision": "force_ask",
                        "reason": (
                            "[Harness Test Boundary] Modifying `tasks.md` containing `## Authorized Test Modifications` "
                            f"via MCP tool (`{effective_label}`) requires explicit human confirmation (GEMINI.md Rule 9)."
                        ),
                    }

    if is_high_risk:
        return {
            "decision": "force_ask",
            "reason": (
                f"[Harness MCP Shield] High-risk MCP tool (`{effective_label}`) can execute commands, "
                "instrument processes, or mutate host/device state and requires explicit human confirmation "
                "(GEMINI.md Rule 12)."
            ),
        }

    if checks_gov_path and mcp_targets and payload is not None and not payload.get("_workflowDryCheck"):
        for t_raw in mcp_targets:
            res_t, t_ws = _resolve_mcp_target_and_ws(t_raw)
            _ptu._record_flight_pre_write(payload, t_ws, tool_name, res_t)

    return {"decision": "allow"}
