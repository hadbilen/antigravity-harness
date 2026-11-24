"""
guard/hooks/_swarm_guard.py — Lazy PreToolUse native swarm, messaging, subagent & schedule guard (ADR-0013).
Part of Plumbwork (https://github.com/hadbilen/plumbwork)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from guard.paths import HOOK_LOCK_TIMEOUT

from . import pre_tool_use as _ptu
from .common import (
    _LazyRegex,
    _conversation_id,
    _facade_attr,
    _iter_jsonl_tail_entries,
    _parse_iso_utc,
    _read_ledger_checked,
    _read_ledger_safe,
    _resolve_transcript_path,
    _safe_int,
    _utc_now_iso,
    atomic_write_json,
    file_lock,
    json,
    subprocess,
)

_SWARM_SCOPE_TTL_SECONDS = 21600

def _swarm_workers_file() -> Path:
    return _ptu.state_dir() / "swarm_workers.json"

def _is_tracked_swarm_cust_worker(conv_entry: Any, target_name: str) -> bool:
    if not target_name or not isinstance(conv_entry, dict):
        return False
    exact = conv_entry.get("exact")
    if isinstance(exact, list) and target_name in exact:
        return True
    prefixes = conv_entry.get("prefixes")
    if isinstance(prefixes, list):
        for prefix in prefixes:
            if isinstance(prefix, str) and target_name.startswith(prefix) and target_name[len(prefix) :].isdigit():
                return True
    return False

def _swarm_entry_has_cust(conv_entry: Any) -> bool:
    if not isinstance(conv_entry, dict):
        return False
    return bool(conv_entry.get("conv_has_cust") or conv_entry.get("exact") or conv_entry.get("prefixes"))

def _read_swarm_workers_ledger() -> Tuple[bool, Dict[str, Any]]:
    """Locked read of `swarm_workers.json`; reports `(False, {})` on lock timeout, corrupt JSON, or I/O error."""
    workers_file = _swarm_workers_file()
    if not workers_file.is_file():
        return True, {}
    try:
        with file_lock(workers_file, timeout=HOOK_LOCK_TIMEOUT):
            ok, data = _read_ledger_checked(workers_file, quarantine=False)
            return ok, data
    except (OSError, TimeoutError) as exc:
        sys.stderr.write(f"[Harness Swarm Guard] Failed to lock `{workers_file}` ({type(exc).__name__}): {exc}\n")
        return False, {}

def _swarm_scope_key(
    payload: Dict[str, Any],
    workspaces: Sequence[Path],
    workspace: Optional[Path],
    effective_cwd: Optional[Path] = None,
) -> str:
    """Computes a shared workspace/swarm scope key so workers in separate conversations share `swarm_workers.json`."""
    for key in ("swarmId", "swarm_id", "boardId", "board_id", "swarmName", "swarm_name"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            return f"swarm:{val.strip().lower()}"
    ws_cand = workspaces[0] if workspaces else (workspace if workspace is not None else effective_cwd)
    if ws_cand is None:
        return ""
    try:
        from guard.test_boundary import TestBoundaryGuard

        main_root = TestBoundaryGuard.resolve_linked_worktree_root(ws_cand)
        if main_root is not None:
            return f"ws:{str(main_root.resolve())}"
    except (ImportError, OSError, RuntimeError) as exc:
        sys.stderr.write(f"[Harness Swarm Guard] Worktree root resolution failed ({type(exc).__name__}): {exc}\n")
    try:
        return f"ws:{str(ws_cand.resolve())}"
    except (OSError, RuntimeError):
        return f"ws:{os.path.abspath(str(ws_cand))}"

def _merge_swarm_entries(conv_entry: Any, scope_entry: Any) -> Optional[Dict[str, Any]]:
    """Merges conversation-level and workspace/swarm-scoped `swarm_workers.json` records."""
    c_ok = isinstance(conv_entry, dict)
    s_ok = isinstance(scope_entry, dict)
    if not c_ok and not s_ok:
        return None
    if c_ok and not s_ok:
        return dict(conv_entry)
    if s_ok and not c_ok:
        return dict(scope_entry)
    merged: Dict[str, Any] = {}
    for list_key in ("exact", "prefixes", "downgraded", "custom_subagents", "cust_channels"):
        combined: List[str] = []
        for src in (scope_entry, conv_entry):
            for item in src.get(list_key) or []:
                if isinstance(item, str) and item and item not in combined:
                    combined.append(item)
        if combined or list_key not in ("custom_subagents", "cust_channels"):
            merged[list_key] = combined
    merged["conv_has_cust"] = bool(conv_entry.get("conv_has_cust")) or bool(scope_entry.get("conv_has_cust"))
    channels: Dict[str, List[str]] = {}
    for src in (scope_entry, conv_entry):
        raw_ch = src.get("channels")
        if isinstance(raw_ch, dict):
            for ch_name, members in raw_ch.items():
                if not isinstance(ch_name, str) or not ch_name.strip():
                    continue
                ch_low = ch_name.strip().lstrip("#").lower()
                bucket = channels.setdefault(ch_low, [])
                if isinstance(members, list):
                    for mem in members:
                        if isinstance(mem, str) and mem.strip():
                            ml = mem.strip().lower()
                            if ml not in bucket:
                                bucket.append(ml)
    if channels:
        merged["channels"] = channels
    return merged

def _apply_swarm_entry_mutation(
    ledger: Dict[str, Any],
    conv_id: str,
    *,
    add_worker: str = "",
    sharded: bool = False,
    remove_worker: str = "",
    conv_cust: bool = False,
    downgraded_worker: str = "",
    clear_downgraded: str = "",
    add_custom_subagent: str = "",
    channel_sub: Optional[Tuple[str, Sequence[str]]] = None,
    channel_unsub: Optional[Tuple[str, Sequence[str]]] = None,
    archive_channel: str = "",
    cust_channel: str = "",
    scope_tag: str = "",
) -> None:
    raw_entry = ledger.get(conv_id)
    entry = raw_entry if isinstance(raw_entry, dict) else {}
    exact = [str(x) for x in entry.get("exact", []) if isinstance(x, str)]
    prefixes = [str(x) for x in entry.get("prefixes", []) if isinstance(x, str)]
    downgraded = [str(x) for x in entry.get("downgraded", []) if isinstance(x, str)]
    custom_subagents = [str(x) for x in entry.get("custom_subagents", []) if isinstance(x, str)]
    cust_channels = [str(x).strip().lstrip("#").lower() for x in entry.get("cust_channels", []) if isinstance(x, str) and x.strip()]
    conv_has_cust = bool(entry.get("conv_has_cust")) or conv_cust
    rec_scope_tag = str(entry.get("scope_key") or "").strip() or scope_tag.strip()
    channels: Dict[str, List[str]] = {}
    raw_channels = entry.get("channels")
    if isinstance(raw_channels, dict):
        for ck, cv in raw_channels.items():
            if isinstance(ck, str) and ck.strip():
                ch_low = ck.strip().lstrip("#").lower()
                mems = [
                    str(m).strip().lower()
                    for m in (cv if isinstance(cv, list) else [])
                    if isinstance(m, str) and m.strip()
                ]
                channels[ch_low] = list(dict.fromkeys(mems))[-128:]

    if remove_worker:
        exact = [x for x in exact if x != remove_worker]
        prefixes = [p for p in prefixes if p != f"{remove_worker}-"]
        downgraded = [x for x in downgraded if not _worker_matches_downgraded(x, {remove_worker})]
        for ck in list(channels.keys()):
            channels[ck] = [m for m in channels[ck] if not _worker_matches_downgraded(m, {remove_worker})]
    if add_worker:
        if add_worker not in exact:
            exact.append(add_worker)
        if sharded:
            pref = f"{add_worker}-"
            if pref not in prefixes:
                prefixes.append(pref)
    if downgraded_worker and downgraded_worker not in downgraded:
        downgraded.append(downgraded_worker)
    if clear_downgraded:
        downgraded = [x for x in downgraded if not _worker_matches_downgraded(x, {clear_downgraded})]
    if add_custom_subagent and add_custom_subagent not in custom_subagents:
        custom_subagents.append(add_custom_subagent)
    if channel_sub is not None:
        sub_ch = str(channel_sub[0] or "").strip().lstrip("#").lower()
        if sub_ch:
            bucket = channels.setdefault(sub_ch, [])
            for raw_m in channel_sub[1] or ():
                ml = str(raw_m or "").strip().lower()
                if ml and ml not in bucket:
                    bucket.append(ml)
            channels[sub_ch] = bucket[-128:]
    if cust_channel:
        cch_low = cust_channel.strip().lstrip("#").lower()
        if cch_low and cch_low not in cust_channels:
            cust_channels.append(cch_low)
    if channel_unsub is not None:
        un_ch = str(channel_unsub[0] or "").strip().lstrip("#").lower()
        if un_ch and un_ch in channels:
            drop_set = {str(m or "").strip().lower() for m in (channel_unsub[1] or ()) if str(m or "").strip()}
            if drop_set:
                channels[un_ch] = [m for m in channels[un_ch] if m not in drop_set]
    if archive_channel:
        arch_low = archive_channel.strip().lstrip("#").lower()
        if arch_low:
            channels.pop(arch_low, None)
            cust_channels = [c for c in cust_channels if c != arch_low]
    while len(channels) > 64:
        oldest_ch = next(iter(channels))
        del channels[oldest_ch]

    if conv_id in ledger:
        del ledger[conv_id]
    if exact or prefixes or downgraded or conv_has_cust or custom_subagents or channels or cust_channels:
        updated_entry: Dict[str, Any] = {
            "exact": exact[-128:],
            "prefixes": prefixes[-64:],
            "downgraded": downgraded[-64:],
            "conv_has_cust": conv_has_cust,
            "updated_at": _utc_now_iso(),
        }
        if rec_scope_tag and conv_id != rec_scope_tag:
            updated_entry["scope_key"] = rec_scope_tag
        if custom_subagents:
            updated_entry["custom_subagents"] = custom_subagents[-64:]
        if channels:
            updated_entry["channels"] = channels
        if cust_channels:
            updated_entry["cust_channels"] = cust_channels[-64:]
        ledger[conv_id] = updated_entry
    while len(ledger) > 256:
        oldest = next(iter(ledger))
        del ledger[oldest]

_SWARM_MUTATION_KEYS = (
    "add_worker",
    "remove_worker",
    "conv_cust",
    "downgraded_worker",
    "clear_downgraded",
    "add_custom_subagent",
    "channel_sub",
    "channel_unsub",
    "archive_channel",
    "cust_channel",
)

def _batch_update_swarm_workers_ledger(ops: Sequence[Dict[str, Any]]) -> bool:
    """Applies one or more `swarm_workers.json` mutations atomically under a single file lock."""
    valid_ops = [
        op
        for op in ops
        if isinstance(op, dict)
        and (str(op.get("conv_id") or "").strip() or str(op.get("scope_key") or "").strip())
        and any(op.get(k) for k in _SWARM_MUTATION_KEYS)
    ]
    if not valid_ops:
        return True
    workers_file = _swarm_workers_file()
    try:
        workers_file.parent.mkdir(parents=True, exist_ok=True)
        with file_lock(workers_file, timeout=HOOK_LOCK_TIMEOUT):
            ok, ledger = _read_ledger_checked(workers_file, quarantine=False)
            if not ok:
                sys.stderr.write(f"[Harness Swarm Guard] Refusing to clobber unreadable `{workers_file}`.\n")
                return False
            for op in valid_ops:
                cid = str(op.get("conv_id") or "").strip()
                skey = str(op.get("scope_key") or "").strip()
                mut_kw: Dict[str, Any] = {
                    "add_worker": str(op.get("add_worker") or ""),
                    "sharded": bool(op.get("sharded")),
                    "remove_worker": str(op.get("remove_worker") or ""),
                    "conv_cust": bool(op.get("conv_cust")),
                    "downgraded_worker": str(op.get("downgraded_worker") or ""),
                    "clear_downgraded": str(op.get("clear_downgraded") or ""),
                    "add_custom_subagent": str(op.get("add_custom_subagent") or ""),
                    "channel_sub": op.get("channel_sub"),
                    "channel_unsub": op.get("channel_unsub"),
                    "archive_channel": str(op.get("archive_channel") or ""),
                    "cust_channel": str(op.get("cust_channel") or ""),
                }
                if cid:
                    _apply_swarm_entry_mutation(ledger, cid, scope_tag=skey, **mut_kw)
                if skey and skey != cid:
                    _apply_swarm_entry_mutation(ledger, skey, **mut_kw)
                # Propagate destructive removals across sibling conversations in the same scope so `_merge_swarm_entries` cannot resurrect them.
                destr_kw = {
                    k: mut_kw[k]
                    for k in ("remove_worker", "clear_downgraded", "channel_unsub", "archive_channel")
                    if mut_kw.get(k)
                }
                if destr_kw and skey:
                    for other_cid, other_rec in list(ledger.items()):
                        if other_cid in (cid, skey) or not isinstance(other_rec, dict):
                            continue
                        if str(other_rec.get("scope_key") or "").strip() == skey:
                            _apply_swarm_entry_mutation(ledger, other_cid, **destr_kw)
            atomic_write_json(workers_file, ledger)
        return True
    except (OSError, TimeoutError) as exc:
        sys.stderr.write(f"[Harness Swarm Guard] Failed to update `{workers_file}` ({type(exc).__name__}): {exc}\n")
        return False

def _update_swarm_workers_ledger(
    conv_id: str,
    *,
    add_worker: str = "",
    sharded: bool = False,
    remove_worker: str = "",
    conv_cust: bool = False,
    downgraded_worker: str = "",
    clear_downgraded: str = "",
    add_custom_subagent: str = "",
    scope_key: str = "",
    channel_sub: Optional[Tuple[str, Sequence[str]]] = None,
    channel_unsub: Optional[Tuple[str, Sequence[str]]] = None,
    archive_channel: str = "",
    cust_channel: str = "",
) -> bool:
    return _facade_attr("_batch_update_swarm_workers_ledger", _batch_update_swarm_workers_ledger)(
        [
            {
                "conv_id": conv_id,
                "scope_key": scope_key,
                "add_worker": add_worker,
                "sharded": sharded,
                "remove_worker": remove_worker,
                "conv_cust": conv_cust,
                "downgraded_worker": downgraded_worker,
                "clear_downgraded": clear_downgraded,
                "add_custom_subagent": add_custom_subagent,
                "channel_sub": channel_sub,
                "channel_unsub": channel_unsub,
                "archive_channel": archive_channel,
                "cust_channel": cust_channel,
            }
        ]
    )

def _record_swarm_cust_worker(
    conv_id: str,
    worker_name: str,
    sharded: bool,
    remove: bool = False,
) -> bool:
    return _update_swarm_workers_ledger(
        conv_id,
        add_worker=("" if remove else worker_name),
        sharded=sharded,
        remove_worker=(worker_name if remove else ""),
        conv_cust=(not remove),
    )

def _check_delegated_model_gate(
    payload: Dict[str, Any],
    tool_label: str,
    requested_model: str,
    targets_customization: bool,
    model_arg_name: str = "model",
) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Evaluates Rule 17 top-model/effort constraints and returns `(blocking_response, is_downgraded)`."""
    sub_model = str(requested_model or "").strip()
    sub_model_lower = sub_model.lower()
    sub_slug = _ptu._normalize_model_slug(sub_model_lower) if sub_model_lower and sub_model_lower != "inherit" else ""
    sub_sfx = ""
    for cand_sfx in ("extra-high", "xhigh", "extra", "maximum", "max", "high", "medium", "med", "low", "minimal", "min"):
        if sub_slug.endswith(f"-{cand_sfx}"):
            sub_sfx = cand_sfx
            break
    top_name, allowed_top_slugs = _ptu._catalog_top_model_spec()
    is_downgraded = bool(
        sub_model_lower
        and sub_model_lower != "inherit"
        and sub_slug not in allowed_top_slugs
    )
    if targets_customization:
        if is_downgraded:
            if _ptu._is_pro_orchestrator_slug(sub_slug, sub_sfx):
                return (
                    {
                        "decision": "force_ask",
                        "reason": (
                            f"[Harness Model & Effort Gate] Delegating customization or governance work via "
                            f"`{tool_label}` with Pro-class Orchestrator `{model_arg_name}='{sub_model}'` "
                            f"requires explicit human confirmation; approved unattended allowlist is `{top_name}` "
                            f"(`{', '.join(sorted(allowed_top_slugs))}`) (GEMINI.md Rule 17)."
                        ),
                    },
                    True,
                )
            return (
                {
                    "decision": "deny",
                    "reason": (
                        f"[Harness Model & Effort Gate] Delegating customization or governance work via "
                        f"`{tool_label}` with downgraded `{model_arg_name}='{sub_model_lower}'` is prohibited; use "
                        f"`{model_arg_name}='inherit'` on `{top_name}` "
                        f"(approved: `{', '.join(sorted(allowed_top_slugs))}`) (GEMINI.md Rule 17)."
                    ),
                },
                True,
            )
        mod_eval = _ptu._evaluate_customization_model_and_effort(payload)
        if mod_eval is not None:
            return {"decision": mod_eval[0], "reason": mod_eval[1]}, True
    return None, is_downgraded

_DELEGATION_MUTATION_VERB_RE = _LazyRegex(
    r"\b(?:edit|write|modify|overwrite|replace|update|patch|append|create|delete|remove|rm|unlink|"
    r"chmod|chown|unlock|rebaseline|copy|cp|mv|move|symlink|ln)\b",
    re.IGNORECASE,
)

_DELEGATION_PATH_TOKEN_RE = _LazyRegex(r"(?:~|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[A-Za-z]:)?[^\s'\"`<>|;&(),]+")

_SWARM_MENTION_RE = _LazyRegex(r"(?<![A-Za-z0-9._-])@([a-z0-9][a-z0-9_-]*)", re.IGNORECASE)
_SWARM_CHANNEL_MENTION_RE = _LazyRegex(r"(?<![A-Za-z0-9._-])@#([a-z0-9][a-z0-9._-]*)", re.IGNORECASE)

def _swarm_ledger_context(
    payload: Dict[str, Any],
    conv_id: str,
    scope_key: str = "",
) -> Tuple[bool, Optional[Dict[str, Any]], Callable[..., bool]]:
    """Loads `swarm_workers.json` (merging conversation and workspace/swarm scope) and returns `(ledger_ok, merged_entry, emit_fn)`."""
    dry_check = bool(payload.get("_workflowDryCheck"))
    overlay = payload.get("_swarmOverlay") if isinstance(payload.get("_swarmOverlay"), dict) else None
    pending_ops = payload.get("_pendingSwarmOps") if isinstance(payload.get("_pendingSwarmOps"), list) else None

    def _emit_swarm_mutation(
        *,
        batch_ops: Optional[Sequence[Dict[str, Any]]] = None,
        **mut_kwargs: Any,
    ) -> bool:
        ops_list = (
            [
                {
                    "conv_id": str(op.get("conv_id") or conv_id),
                    "scope_key": str(op.get("scope_key") or scope_key),
                    **{k: v for k, v in op.items() if k not in ("conv_id", "scope_key")},
                }
                for op in batch_ops
            ]
            if batch_ops is not None
            else [{"conv_id": conv_id, "scope_key": scope_key, **mut_kwargs}]
        )
        if dry_check:
            for op in ops_list:
                cid = str(op.get("conv_id") or conv_id)
                skey = str(op.get("scope_key") or scope_key)
                kw = {k: v for k, v in op.items() if k not in ("conv_id", "scope_key")}
                if overlay is not None:
                    if cid:
                        _apply_swarm_entry_mutation(overlay, cid, scope_tag=skey, **kw)
                    if skey and skey != cid:
                        _apply_swarm_entry_mutation(overlay, skey, **kw)
                if pending_ops is not None:
                    pending_ops.append({"conv_id": cid, "scope_key": skey, **kw})
            return True
        if len(ops_list) == 1:
            single_kw = {k: v for k, v in ops_list[0].items() if k != "conv_id"}
            return _update_swarm_workers_ledger(str(ops_list[0].get("conv_id") or conv_id), **single_kw)
        return _facade_attr("_batch_update_swarm_workers_ledger", _batch_update_swarm_workers_ledger)(ops_list)

    need_keys = [k for k in (conv_id, scope_key) if k]
    if overlay is not None and all(k in overlay for k in need_keys):
        ledger_ok, ledger = True, overlay
    else:
        ledger_ok, ledger = _read_swarm_workers_ledger() if need_keys else (True, {})
        if not ledger_ok:
            return False, None, _emit_swarm_mutation
        if overlay is not None:
            for k in need_keys:
                if k not in overlay and isinstance(ledger.get(k), dict):
                    overlay[k] = json.loads(json.dumps(ledger[k]))
    src_ledger = overlay if overlay is not None else ledger
    conv_entry = src_ledger.get(conv_id) if (isinstance(src_ledger, dict) and conv_id) else None
    scope_entry = (
        src_ledger.get(scope_key)
        if (isinstance(src_ledger, dict) and scope_key and scope_key != conv_id)
        else None
    )
    if isinstance(scope_entry, dict) and scope_key.startswith("ws:"):
        s_ts = _parse_iso_utc(str(scope_entry.get("updated_at") or ""))
        if s_ts is not None and (datetime.now(timezone.utc) - s_ts).total_seconds() >= _SWARM_SCOPE_TTL_SECONDS:
            scope_entry = None
    merged_entry = _merge_swarm_entries(conv_entry, scope_entry)
    return True, merged_entry, _emit_swarm_mutation

def _text_mutates_governance_path(
    text: str,
    workspaces: Sequence[Path],
    workspace: Optional[Path],
    effective_cwd: Optional[Path] = None,
) -> bool:
    if not text or not _DELEGATION_MUTATION_VERB_RE.search(text):
        return False
    explicit_bases: List[Path] = []
    for b in (effective_cwd, workspace, *workspaces):
        if b is None:
            continue
        bs = str(b)
        if not (b.is_absolute() or bool(re.match(r"^[A-Za-z]:[/\\]", bs)) or bs.startswith("\\\\")):
            continue
        if b not in explicit_bases:
            explicit_bases.append(b)
    if any(_ptu._targets_governance_dir(str(b)) for b in explicit_bases):
        return True
    bases: List[Optional[Path]] = list(explicit_bases) if explicit_bases else [None]
    for m in _DELEGATION_PATH_TOKEN_RE.finditer(text):
        raw_tok = m.group(0).strip("*").rstrip(".,:;!?\"')]`*")
        cand_toks = [raw_tok]
        if "=" in raw_tok and not raw_tok.lower().startswith("file:"):
            rhs_tok = raw_tok.split("=", 1)[1].strip("*").rstrip(".,:;!?\"')]`*")
            if rhs_tok:
                cand_toks.append(rhs_tok)
        cand_toks = [
            ct
            for ct in cand_toks
            if ct and ("/" in ct or "\\" in ct or ct.startswith(("~", "$", "%")))
        ]
        if not cand_toks:
            continue
        window_start = max(0, m.start() - 64)
        preceding = text[window_start : m.start()]
        for sep in ("\n", ";", ".", ","):
            if sep in preceding:
                preceding = preceding.rsplit(sep, 1)[-1]
        if not _DELEGATION_MUTATION_VERB_RE.search(preceding):
            continue
        if any(
            _ptu._targets_governance_dir(ct) or any(_ptu._targets_governance_dir(ct, base_dir=b) for b in bases)
            for ct in cand_toks
        ):
            return True
    return False

def _inspect_delegation_rule12_text(
    text: str,
    tool_label: str,
    workspaces: Sequence[Path],
    workspace: Optional[Path],
    effective_cwd: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Enforces Rule 12 human-only Guard admin / `install.py` / `--no-verify` / governance shields on delegated prompts."""
    if not text or not text.strip():
        return None
    from ._shell_guard import (
        _DELEGATION_GUARD_ADMIN_RE,
        _DELEGATION_INSTALL_EXEC_RE,
        _GIT_HOOK_BYPASS_RE,
        _GUARD_API_TOKEN_PAT,
        _GUARD_INLINE_PY_RE,
        _command_mutates_governance,
        _command_mutates_governance_in_cwd,
        _extract_shell_c_payloads,
        _normalize_governance_globs,
    )
    deleg_bases: List[Path] = []
    for _db in (effective_cwd, workspace, *workspaces):
        if _db is not None and _db not in deleg_bases:
            deleg_bases.append(_db)
    candidates = [text]
    for ext in _extract_shell_c_payloads(text):
        if ext and ext not in candidates:
            candidates.append(ext)
    for cand in candidates:
        admin_variants = _normalize_governance_globs(cand, admin_variants=True)
        masked = admin_variants[0]
        if (
            any(_DELEGATION_GUARD_ADMIN_RE.search(v) for v in admin_variants)
            or _GUARD_INLINE_PY_RE.search(cand)
            or re.search(_GUARD_API_TOKEN_PAT, cand)
        ):
            return {
                "decision": "deny",
                "reason": (
                    f"[Harness Governance Shield] Human-only `plumb-guard` administration commands are "
                    f"prohibited inside `{tool_label}` (GEMINI.md Rule 12)."
                ),
            }
        if any(_DELEGATION_INSTALL_EXEC_RE.search(v) for v in admin_variants):
            return {
                "decision": "deny",
                "reason": (
                    f"[Harness Governance Shield] Executing `install.py` inside `{tool_label}` is "
                    "prohibited (GEMINI.md Rule 12)."
                ),
            }
        if _GIT_HOOK_BYPASS_RE.search(masked):
            return {
                "decision": "deny",
                "reason": (
                    f"[Harness Governance Shield] Git hook bypass flags (`--no-verify`, `commit -n`, "
                    f"`core.hooksPath`, `HUSKY=0`) are prohibited inside `{tool_label}`."
                ),
            }
        if (
            _command_mutates_governance(cand)
            or any(_command_mutates_governance_in_cwd(cand, _db) for _db in deleg_bases)
            or _text_mutates_governance_path(
                cand, workspaces, workspace, effective_cwd=effective_cwd
            )
        ):
            return {
                "decision": "deny",
                "reason": (
                    f"[Harness Governance Shield] Mutating protected governance or Guard state (`~/.gemini/config`) "
                    f"via `{tool_label}` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                ),
            }
    return None

def _swarm_targets_customization(
    args: Dict[str, Any],
    workspaces: Sequence[Path],
    workspace: Optional[Path],
    conv_entry: Any,
    effective_cwd: Optional[Path] = None,
) -> bool:
    fork_from = str(args.get("fork") or "").strip().lower()
    if fork_from and (
        _is_tracked_swarm_cust_worker(conv_entry, fork_from)
        or (fork_from == "coordinator" and _swarm_entry_has_cust(conv_entry))
    ):
        return True
    parts: List[str] = [
        str(args.get("name") or ""),
        str(args.get("brief") or ""),
        str(args.get("title") or ""),
    ]
    raw_tasks = args.get("tasks")
    task_items: List[str] = []
    if isinstance(raw_tasks, list):
        for item in raw_tasks:
            if isinstance(item, str) and item.strip():
                task_items.append(item.strip())
                parts.append(item.strip())
    combined_brief = "\n".join(parts)
    return _ptu._text_targets_customization(
        combined_brief,
        workspaces,
        fallback_ws=workspace,
        effective_cwd=effective_cwd,
        extra_tokens=task_items,
    )

def _extract_swarm_tokens(args: Dict[str, Any], keys: Sequence[str], sigil: str) -> List[str]:
    out: List[str] = []
    for k in keys:
        val = args.get(k)
        items = [val] if isinstance(val, str) else (val if isinstance(val, list) else [])
        for item in items:
            if isinstance(item, str) and item.strip():
                tok = item.strip().lstrip(sigil).lower()
                if tok and tok not in out:
                    out.append(tok)
    return out

def _handle_swarm_pre_tool_use(
    payload: Dict[str, Any],
    args: Dict[str, Any],
    workspaces: Sequence[Path],
    workspace: Optional[Path],
    effective_cwd: Optional[Path] = None,
) -> Dict[str, Any]:
    """Enforces Rule 15f & Rule 17 on native `swarm` orchestration and tracks customization workers and channels."""
    action = str(args.get("action") or "").strip().lower()
    if action in ("status", "models", "title"):
        return {"decision": "allow"}
    conv_id = _conversation_id(payload)
    scope_key = _swarm_scope_key(payload, workspaces, workspace, effective_cwd)
    ledger_ok, conv_entry, _emit_swarm_mutation = _swarm_ledger_context(payload, conv_id, scope_key=scope_key)

    existing_cust_channels = {
        str(x).strip().lstrip("#").lower()
        for x in ((conv_entry.get("cust_channels") or []) if isinstance(conv_entry, dict) else [])
        if isinstance(x, str) and x.strip()
    }

    if action == "channel":
        ch_op = str(
            args.get("op")
            or args.get("subaction")
            or args.get("channel_action")
            or args.get("operation")
            or ""
        ).strip().lower()
        ch_name = str(args.get("channel") or args.get("name") or "").strip().lstrip("#").lower()
        topic = str(args.get("topic") or args.get("description") or "").strip()
        r12_ch = _inspect_delegation_rule12_text(
            f"{ch_name}\n{topic}".strip(), "swarm", workspaces, workspace, effective_cwd=effective_cwd
        )
        if r12_ch is not None:
            return r12_ch
        if ch_op in ("", "list"):
            return {"decision": "allow"}
        if not ledger_ok:
            return {
                "decision": "force_ask",
                "reason": (
                    "[Harness Swarm Guard] Could not safely read `swarm_workers.json` on `swarm(action='channel')` "
                    "(fail-closed human confirmation required; GEMINI.md Rule 17)."
                ),
            }
        member_list = _extract_swarm_tokens(args, ("members", "workers", "member", "worker"), "@")
        if ch_op in ("create", "subscribe"):
            topic_cust = bool(
                topic
                and _ptu._text_targets_customization(
                    topic, workspaces, fallback_ws=workspace, effective_cwd=effective_cwd
                )
            )
            ch_is_cust = topic_cust or bool(ch_name and ch_name in existing_cust_channels)
            downgraded_set = {
                str(x).lower()
                for x in ((conv_entry.get("downgraded") or []) if isinstance(conv_entry, dict) else [])
                if isinstance(x, str) and x
            }
            if ch_is_cust and member_list:
                hit_down = [m for m in member_list if _worker_matches_downgraded(m, downgraded_set)]
                if hit_down:
                    top_name, _ = _ptu._catalog_top_model_spec()
                    return {
                        "decision": "deny",
                        "reason": (
                            f"[Harness Swarm Guard] Subscribing downgraded swarm worker(s) (`{', '.join(hit_down)}`) "
                            f"to customization/governance channel `#{ch_name}` is prohibited; use `{top_name}` "
                            "(GEMINI.md Rule 17)."
                        ),
                    }
            if ch_is_cust:
                blocked_ch, _ = _check_delegated_model_gate(payload, "swarm", "", True)
                if blocked_ch is not None and blocked_ch.get("decision") == "deny":
                    return blocked_ch
                if ch_name and not _emit_swarm_mutation(
                    channel_sub=(ch_name, member_list), cust_channel=ch_name, conv_cust=True
                ):
                    return {
                        "decision": "force_ask",
                        "reason": "[Harness Swarm Guard] Failed to persist swarm channel subscription; confirm execution.",
                    }
                if blocked_ch is not None:
                    return blocked_ch
                return {"decision": "allow"}
            if ch_name and not _emit_swarm_mutation(channel_sub=(ch_name, member_list)):
                return {
                    "decision": "force_ask",
                    "reason": "[Harness Swarm Guard] Failed to persist swarm channel subscription; confirm execution.",
                }
            return {"decision": "allow"}
        if ch_op == "unsubscribe":
            if ch_name and member_list and not _emit_swarm_mutation(channel_unsub=(ch_name, member_list)):
                return {
                    "decision": "force_ask",
                    "reason": "[Harness Swarm Guard] Failed to update swarm channel unsubscription; confirm execution.",
                }
            return {"decision": "allow"}
        if ch_op == "archive":
            if ch_name and not _emit_swarm_mutation(archive_channel=ch_name):
                return {
                    "decision": "force_ask",
                    "reason": "[Harness Swarm Guard] Failed to archive swarm channel in ledger; confirm execution.",
                }
            return {"decision": "allow"}
        return {"decision": "allow"}

    if action == "kill":
        target_name = str(args.get("name") or "").strip().lower()
        if target_name:
            if not _emit_swarm_mutation(remove_worker=target_name):
                return {
                    "decision": "force_ask",
                    "reason": "[Harness Swarm Guard] Failed to update swarm worker ledger on `kill`; confirm execution.",
                }
        return {"decision": "allow"}

    if "tasks" in args and args.get("tasks") is not None and not isinstance(args.get("tasks"), list):
        return {
            "decision": "deny",
            "reason": "[Harness Swarm Guard] Malformed non-list `tasks` argument to `swarm` (failing closed).",
        }
    raw_n = args.get("n")
    if isinstance(raw_n, bool):
        return {
            "decision": "deny",
            "reason": "[Harness Swarm Guard] Malformed boolean `n` argument to `swarm` (failing closed).",
        }
    if raw_n is not None:
        parsed_n = _safe_int(raw_n, default=-1)
        if parsed_n <= 0:
            return {
                "decision": "deny",
                "reason": "[Harness Swarm Guard] Malformed `n` argument to `swarm` (must be positive integer).",
            }
    else:
        parsed_n = 0

    if not ledger_ok:
        return {
            "decision": "force_ask",
            "reason": (
                "[Harness Swarm Guard] Could not safely read `swarm_workers.json` to verify tracked "
                "customization workers (fail-closed human confirmation required; GEMINI.md Rule 17)."
            ),
        }
    any_harness_ws = _ptu._workspaces_in_harness_scope(workspaces, effective_cwd or workspace) and bool(workspaces or effective_cwd)
    req_model = str(args.get("model") or "").strip()

    if action == "model":
        target_name = str(args.get("name") or "").strip().lower()
        has_tracked_cust = _swarm_entry_has_cust(conv_entry)
        broadcast_cust = bool(
            isinstance(conv_entry, dict)
            and conv_entry.get("conv_has_cust")
            and not conv_entry.get("exact")
            and not conv_entry.get("prefixes")
        )
        targets_cust = (
            any_harness_ws
            or broadcast_cust
            or _is_tracked_swarm_cust_worker(conv_entry, target_name)
            or ((not target_name or target_name == "coordinator") and has_tracked_cust)
        )
        blocked, is_downgraded = _check_delegated_model_gate(payload, "swarm", req_model, targets_cust)
        if blocked is not None:
            if blocked.get("decision") == "force_ask" and target_name:
                if not _emit_swarm_mutation(add_worker=target_name if targets_cust else "", conv_cust=targets_cust):
                    return {
                        "decision": "force_ask",
                        "reason": "[Harness Swarm Guard] Could not persist swarm worker state; human confirmation required.",
                    }
            return blocked
        if is_downgraded:
            if target_name and not _emit_swarm_mutation(downgraded_worker=target_name):
                return {
                    "decision": "force_ask",
                    "reason": "[Harness Swarm Guard] Could not record downgraded swarm worker state; confirm execution.",
                }
            return {
                "decision": "force_ask",
                "reason": (
                    f"[Harness Swarm Guard] Switching swarm worker model to `{req_model}` deviates from "
                    "the coordinator model; confirm only if quota/capacity is exhausted or explicitly "
                    "requested (GEMINI.md Rule 15f)."
                ),
            }
        if target_name and req_model:
            if not _emit_swarm_mutation(clear_downgraded=target_name):
                return {
                    "decision": "force_ask",
                    "reason": "[Harness Swarm Guard] Failed to update swarm worker ledger on model escalation; confirm execution.",
                }
        return {"decision": "allow"}

    if action == "add" or req_model or args.get("brief") is not None or args.get("tasks") is not None:
        swarm_text = "\n".join(
            [
                str(args.get("brief") or ""),
                *(str(t) for t in (args.get("tasks") or []) if isinstance(t, str)),
            ]
        )
        r12 = _inspect_delegation_rule12_text(
            swarm_text, "swarm", workspaces, workspace, effective_cwd=effective_cwd
        )
        if r12 is not None:
            return r12
        targets_cust = _swarm_targets_customization(
            args, workspaces, workspace, conv_entry, effective_cwd=effective_cwd
        )
        fork_from = str(args.get("fork") or "").strip().lower()
        downgraded_set = {
            str(x).lower()
            for x in ((conv_entry.get("downgraded") or []) if isinstance(conv_entry, dict) else [])
            if isinstance(x, str) and x
        }
        fork_is_downgraded = bool(fork_from and _worker_matches_downgraded(fork_from, downgraded_set))
        inherits_fork_model = not req_model or req_model.lower() == "inherit"
        if targets_cust and fork_is_downgraded and inherits_fork_model:
            top_name, _ = _ptu._catalog_top_model_spec()
            return {
                "decision": "deny",
                "reason": (
                    f"[Harness Model & Effort Gate] Forking customization worker from downgraded worker "
                    f"`{fork_from}` with `{req_model or 'inherit'}` is prohibited; use `{top_name}` (GEMINI.md Rule 17)."
                ),
            }
        add_channels = _extract_swarm_tokens(args, ("channels",), "#")
        if any(ch in existing_cust_channels for ch in add_channels):
            targets_cust = True
        blocked, is_downgraded = _check_delegated_model_gate(payload, "swarm", req_model, targets_cust)
        if fork_is_downgraded and inherits_fork_model:
            is_downgraded = True
        worker_name = str(args.get("name") or "").strip().lower()
        task_list = args.get("tasks") if isinstance(args.get("tasks"), list) else []
        has_tasks = len(task_list) > 0
        is_sharded = parsed_n > 1 or has_tasks
        sub_members: List[str] = []
        if worker_name and add_channels:
            sub_members.append(worker_name)
            if is_sharded:
                shard_cnt = min(len(task_list) if has_tasks else parsed_n, 32)
                for idx_s in range(1, shard_cnt + 1):
                    sub_members.append(f"{worker_name}-{idx_s}")

        def _emit_add_state(*, primary_op: Optional[Dict[str, Any]] = None) -> bool:
            ops: List[Dict[str, Any]] = []
            if primary_op:
                ops.append(primary_op)
            for ch in add_channels:
                ops.append({"channel_sub": (ch, sub_members)})
            if not ops:
                return True
            if len(ops) == 1:
                return _emit_swarm_mutation(**ops[0])
            return _emit_swarm_mutation(batch_ops=ops)

        if blocked is not None:
            if blocked.get("decision") == "deny":
                return blocked
            # force_ask (missing coordinator model/effort or Pro-Orchestrator): persist cust/channel registration before yielding
            prim: Optional[Dict[str, Any]] = (
                {"add_worker": worker_name, "sharded": is_sharded, "conv_cust": True}
                if targets_cust
                else None
            )
            if (prim or add_channels) and not _emit_add_state(primary_op=prim):
                return {
                    "decision": "force_ask",
                    "reason": "[Harness Swarm Guard] Failed to persist customization worker ledger; confirm execution.",
                }
            return blocked
        if is_downgraded:
            prim_down: Optional[Dict[str, Any]] = {"downgraded_worker": worker_name} if worker_name else None
            if (prim_down or add_channels) and not _emit_add_state(primary_op=prim_down):
                return {
                    "decision": "force_ask",
                    "reason": "[Harness Swarm Guard] Could not record downgraded worker state; confirm execution.",
                }
            eff_downgraded_label = req_model or f"inherit (fork={fork_from})"
            return {
                "decision": "force_ask",
                "reason": (
                    f"[Harness Swarm Guard] Spawning swarm worker with downgraded model `{eff_downgraded_label}` "
                    "requires explicit user confirmation (GEMINI.md Rule 15f)."
                ),
            }
        prim_cust: Optional[Dict[str, Any]] = (
            {"add_worker": worker_name, "sharded": is_sharded, "conv_cust": True}
            if targets_cust
            else None
        )
        if (prim_cust or add_channels) and not _emit_add_state(primary_op=prim_cust):
            return {
                "decision": "force_ask",
                "reason": "[Harness Swarm Guard] Failed to persist customization worker ledger; confirm execution.",
            }
        return {"decision": "allow"}

    return {"decision": "allow"}

def _worker_matches_downgraded(name: str, downgraded: set[str]) -> bool:
    if not name or not downgraded:
        return False
    if name in downgraded:
        return True
    return any(name.startswith(f"{d}-") for d in downgraded if d)

def _persist_post_message_cust_mentions(
    mentions: List[str],
    emit_fn: Callable[..., bool],
) -> bool:
    concrete = [m for m in mentions if m not in ("all", "coordinator")]
    if not concrete:
        return emit_fn(conv_cust=True)
    if len(concrete) == 1:
        return emit_fn(add_worker=concrete[0], conv_cust=True)
    return emit_fn(
        batch_ops=[
            {"add_worker": target, "conv_cust": (idx == 0)}
            for idx, target in enumerate(concrete)
        ]
    )

def _handle_post_message_pre_tool_use(
    payload: Dict[str, Any],
    args: Dict[str, Any],
    workspaces: Sequence[Path],
    workspace: Optional[Path],
    effective_cwd: Optional[Path] = None,
) -> Dict[str, Any]:
    """Enforces Rule 12, Rule 17, and `swarm_workers.json` tracking on top-level swarm `post_message`."""
    text = str(args.get("text") or args.get("message") or "").strip()
    channel = str(args.get("channel") or "").strip()
    combined = f"{channel}\n{text}".strip()

    r12 = _inspect_delegation_rule12_text(
        combined, "post_message", workspaces, workspace, effective_cwd=effective_cwd
    )
    if r12 is not None:
        return r12

    conv_id = _conversation_id(payload)
    scope_key = _swarm_scope_key(payload, workspaces, workspace, effective_cwd)
    ledger_ok, conv_entry, emit_mutation = _swarm_ledger_context(payload, conv_id, scope_key=scope_key)
    if not ledger_ok:
        return {
            "decision": "force_ask",
            "reason": (
                "[Harness Swarm Guard] Could not safely read `swarm_workers.json` on `post_message` "
                "(fail-closed human confirmation required; GEMINI.md Rule 17)."
            ),
        }

    mentions: List[str] = []
    for m in _SWARM_MENTION_RE.findall(text):
        low = m.lower()
        if low not in mentions:
            mentions.append(low)
    channel_mentions: List[str] = []
    for ch_m in _SWARM_CHANNEL_MENTION_RE.findall(text):
        ch_low = ch_m.rstrip(".").lower()
        if ch_low and ch_low not in channel_mentions:
            channel_mentions.append(ch_low)
    mentions_all = ("all" in mentions) or ("main" in channel_mentions)

    channels_map = (
        conv_entry.get("channels")
        if isinstance(conv_entry, dict) and isinstance(conv_entry.get("channels"), dict)
        else {}
    )
    cust_channels_set = {
        str(x).strip().lstrip("#").lower()
        for x in ((conv_entry.get("cust_channels") or []) if isinstance(conv_entry, dict) else [])
        if isinstance(x, str) and x.strip()
    }
    target_channels = list(channel_mentions)
    norm_arg_channel = channel.lstrip("#").rstrip(".").lower()
    if norm_arg_channel and norm_arg_channel not in target_channels:
        target_channels.append(norm_arg_channel)
    for ch_key in target_channels:
        subs = channels_map.get(ch_key)
        if isinstance(subs, list):
            for sub_m in subs:
                if isinstance(sub_m, str) and sub_m.strip():
                    sm_low = sub_m.strip().lower()
                    if sm_low not in mentions:
                        mentions.append(sm_low)

    downgraded = {
        str(x).lower()
        for x in ((conv_entry.get("downgraded") or []) if isinstance(conv_entry, dict) else [])
        if isinstance(x, str) and x
    }
    hit_downgraded = [m for m in mentions if m != "all" and _worker_matches_downgraded(m, downgraded)]
    if mentions_all and downgraded:
        for d in sorted(downgraded):
            if d not in hit_downgraded:
                hit_downgraded.append(d)

    text_targets_cust = _ptu._text_targets_customization(
        combined, workspaces, fallback_ws=workspace, effective_cwd=effective_cwd
    )
    mentions_tracked_cust = (
        any(_is_tracked_swarm_cust_worker(conv_entry, m) for m in mentions if m != "all")
        or any(ch_key in cust_channels_set for ch_key in target_channels)
        or (mentions_all and _swarm_entry_has_cust(conv_entry))
    )
    targets_cust = text_targets_cust or mentions_tracked_cust

    if targets_cust and hit_downgraded:
        top_name, _ = _ptu._catalog_top_model_spec()
        return {
            "decision": "deny",
            "reason": (
                "[Harness Swarm Guard] Assigning or continuing customization/governance work via `post_message` "
                f"to downgraded swarm worker(s) (`{', '.join(hit_downgraded)}`) is prohibited; use `{top_name}` "
                "(GEMINI.md Rule 17)."
            ),
        }

    def _persist_pm_cust() -> bool:
        if not _persist_post_message_cust_mentions(mentions, emit_mutation):
            return False
        if target_channels:
            ch_ops = [{"cust_channel": ch_k} for ch_k in target_channels if ch_k]
            if ch_ops and not emit_mutation(batch_ops=ch_ops):
                return False
        return True

    if targets_cust:
        blocked, _ = _check_delegated_model_gate(payload, "post_message", "", True)
        if blocked is not None:
            if blocked.get("decision") == "deny":
                return blocked
            if conv_id and not _persist_pm_cust():
                return {
                    "decision": "force_ask",
                    "reason": "[Harness Swarm Guard] Failed to persist customization worker ledger; confirm execution.",
                }
            return blocked
        if conv_id and not _persist_pm_cust():
            return {
                "decision": "force_ask",
                "reason": "[Harness Swarm Guard] Failed to persist `post_message` customization worker ledger; confirm execution.",
            }
    return {"decision": "allow"}

def _transcript_subagent_is_downgraded(payload: Dict[str, Any], recipient: str) -> Optional[bool]:
    """Checks trailing transcript entries to detect if `recipient` conversationId was launched downgraded (None on read error)."""
    if not recipient:
        return False
    path = _resolve_transcript_path(payload)
    if path is None:
        return False
    _, allowed_top_slugs = _ptu._catalog_top_model_spec()
    try:
        for entry in _iter_jsonl_tail_entries(path, max_scan_bytes=2 * 1024 * 1024, raise_on_error=True):
            raw_json = json.dumps(entry, ensure_ascii=False)
            if recipient not in raw_json:
                continue
            tool_calls = entry.get("tool_calls") or entry.get("toolCalls")
            if isinstance(tool_calls, list):
                for tc in tool_calls:
                    if not isinstance(tc, dict):
                        continue
                    t_args = tc.get("args") or tc.get("arguments") or {}
                    if isinstance(t_args, dict):
                        mod = str(t_args.get("Model") or t_args.get("model") or "").strip().lower()
                        if mod and mod != "inherit" and _ptu._normalize_model_slug(mod) not in allowed_top_slugs:
                            return True
    except (OSError, TypeError, ValueError) as exc:
        sys.stderr.write(f"[Harness Swarm Guard] Failed reading transcript `{path}` ({type(exc).__name__}): {exc}\n")
        return None
    return False

def _handle_send_message_pre_tool_use(
    payload: Dict[str, Any],
    args: Dict[str, Any],
    workspaces: Sequence[Path],
    workspace: Optional[Path],
    effective_cwd: Optional[Path] = None,
) -> Dict[str, Any]:
    """Enforces Rule 12 & Rule 17 on direct subagent `send_message` continuations."""
    recipient = str(args.get("Recipient") or args.get("recipient") or "").strip()
    message = str(args.get("Message") or args.get("message") or "").strip()

    r12 = _inspect_delegation_rule12_text(
        message, "send_message", workspaces, workspace, effective_cwd=effective_cwd
    )
    if r12 is not None:
        return r12

    text_targets_cust = _ptu._text_targets_customization(
        message, workspaces, fallback_ws=workspace, effective_cwd=effective_cwd
    )
    conv_id = _conversation_id(payload)
    scope_key = _swarm_scope_key(payload, workspaces, workspace, effective_cwd)
    ledger_ok, conv_entry, emit_mutation = _swarm_ledger_context(payload, conv_id, scope_key=scope_key)
    if not ledger_ok:
        return {
            "decision": "force_ask",
            "reason": (
                "[Harness Model & Effort Gate] Could not verify `swarm_workers.json` on `send_message` "
                "directive (fail-closed confirmation required; GEMINI.md Rule 17)."
            ),
        }
    recipient_low = recipient.lower()
    targets_cust = text_targets_cust or bool(
        recipient_low and _is_tracked_swarm_cust_worker(conv_entry, recipient_low)
    )
    downgraded = {
        str(x).lower()
        for x in ((conv_entry.get("downgraded") or []) if isinstance(conv_entry, dict) else [])
        if isinstance(x, str) and x
    }
    if targets_cust:
        tx_down = _transcript_subagent_is_downgraded(payload, recipient)
        if _worker_matches_downgraded(recipient_low, downgraded) or tx_down is True:
            top_name, _ = _ptu._catalog_top_model_spec()
            return {
                "decision": "deny",
                "reason": (
                    f"[Harness Model & Effort Gate] Sending customization/governance instructions via `send_message` "
                    f"to downgraded recipient `{recipient}` is prohibited; use `{top_name}` (GEMINI.md Rule 17)."
                ),
            }
        if tx_down is None:
            return {
                "decision": "force_ask",
                "reason": (
                    f"[Harness Model & Effort Gate] Could not read transcript to verify recipient `{recipient}` model "
                    "on customization `send_message` (fail-closed confirmation required; GEMINI.md Rule 17)."
                ),
            }
    req_model = str(args.get("Model") or args.get("model") or "").strip()
    blocked, _ = _check_delegated_model_gate(payload, "send_message", req_model, targets_cust)
    if blocked is not None:
        if blocked.get("decision") == "deny":
            return blocked
        if targets_cust and conv_id and recipient_low and not emit_mutation(add_worker=recipient_low, conv_cust=True):
            return {
                "decision": "force_ask",
                "reason": "[Harness Swarm Guard] Failed to persist `send_message` customization worker ledger; confirm execution.",
            }
        return blocked
    if targets_cust and conv_id and recipient_low:
        if not emit_mutation(add_worker=recipient_low, conv_cust=True):
            return {
                "decision": "force_ask",
                "reason": "[Harness Swarm Guard] Failed to persist `send_message` customization worker ledger; confirm execution.",
            }
    return {"decision": "allow"}

def _handle_define_subagent_pre_tool_use(
    payload: Dict[str, Any],
    args: Dict[str, Any],
    workspaces: Sequence[Path],
    workspace: Optional[Path],
    effective_cwd: Optional[Path] = None,
) -> Dict[str, Any]:
    """Enforces Rule 12 & Rule 17 on dynamic `define_subagent` registrations and records writable customization types."""
    name = str(args.get("Name") or args.get("name") or "").strip()
    desc = str(args.get("Description") or args.get("description") or "").strip()
    sys_prompt = str(args.get("SystemPrompt") or args.get("systemPrompt") or args.get("system_prompt") or "").strip()
    combined = "\n".join(p for p in (name, desc, sys_prompt) if p)

    r12 = _inspect_delegation_rule12_text(
        combined, "define_subagent", workspaces, workspace, effective_cwd=effective_cwd
    )
    if r12 is not None:
        return r12

    enable_write = bool(args.get("EnableWriteTools") or args.get("enableWriteTools") or args.get("enable_write_tools"))
    enable_mcp = bool(args.get("EnableMCPTools") or args.get("enableMCPTools") or args.get("enable_mcp_tools"))
    enable_subagents = bool(
        args.get("EnableSubagentTools") or args.get("enableSubagentTools") or args.get("enable_subagent_tools")
    )
    can_mutate = enable_write or enable_mcp or enable_subagents

    if name.lower() in _ptu._READONLY_SUBAGENT_TYPES and can_mutate:
        return {
            "decision": "deny",
            "reason": (
                f"[Harness Model & Effort Gate] Redefining read-only built-in subagent `{name}` with "
                "write, MCP, or subagent delegation tools is prohibited (GEMINI.md Rule 17)."
            ),
        }

    targets_cust = can_mutate and _ptu._text_targets_customization(
        combined, workspaces, fallback_ws=workspace, effective_cwd=effective_cwd
    )
    req_model = str(args.get("Model") or args.get("model") or "").strip()
    blocked, _ = _check_delegated_model_gate(payload, "define_subagent", req_model, targets_cust)
    if blocked is not None and blocked.get("decision") == "deny":
        return blocked

    conv_id = _conversation_id(payload)
    if targets_cust and name and conv_id:
        scope_key = _swarm_scope_key(payload, workspaces, workspace, effective_cwd)
        ledger_ok, _entry, emit_mutation = _swarm_ledger_context(payload, conv_id, scope_key=scope_key)
        if not ledger_ok or not emit_mutation(add_custom_subagent=name.lower()):
            return {
                "decision": "force_ask",
                "reason": (
                    "[Harness Model & Effort Gate] Failed to persist customization `define_subagent` registration; "
                    "human confirmation required (GEMINI.md Rule 17)."
                ),
            }

    if blocked is not None:
        return blocked
    return {"decision": "allow"}

def _handle_schedule_pre_tool_use(
    payload: Dict[str, Any],
    args: Dict[str, Any],
    workspaces: Sequence[Path],
    workspace: Optional[Path],
    effective_cwd: Optional[Path] = None,
) -> Dict[str, Any]:
    """Enforces Rule 12 & Rule 17 on scheduled timer/cron `Prompt` payloads."""
    for daemon_key in ("IsDaemon", "isDaemon", "is_daemon"):
        raw_val = args.get(daemon_key)
        if raw_val is not None and not isinstance(raw_val, bool):
            return {
                "decision": "deny",
                "reason": "[Harness Schedule Guard] Malformed non-boolean `IsDaemon` argument to `schedule` (failing closed).",
            }
    is_daemon = bool(
        args.get("IsDaemon") is True or args.get("isDaemon") is True or args.get("is_daemon") is True
    )
    prompt = str(args.get("Prompt") or args.get("prompt") or "").strip()
    cron_expr = str(args.get("CronExpression") or args.get("cronExpression") or "").strip()
    combined = f"{cron_expr}\n{prompt}".strip()

    r12 = _inspect_delegation_rule12_text(
        combined, "schedule", workspaces, workspace, effective_cwd=effective_cwd
    )
    if r12 is not None:
        return r12

    targets_cust = _ptu._text_targets_customization(
        combined, workspaces, fallback_ws=workspace, effective_cwd=effective_cwd
    )
    req_model = str(args.get("Model") or args.get("model") or "").strip()
    blocked, _ = _check_delegated_model_gate(payload, "schedule", req_model, targets_cust)
    if blocked is not None:
        return blocked

    if is_daemon and targets_cust:
        return {
            "decision": "force_ask",
            "reason": (
                "[Harness Customization Model Gate] Scheduling a persistent daemon (`IsDaemon=true`) that targets "
                "customization or governance files runs unattended after session end and requires explicit human "
                "confirmation (GEMINI.md Rule 12 & Rule 17)."
            ),
        }
    return {"decision": "allow"}


def _handle_invoke_subagent_pre_tool_use(
    payload: Dict[str, Any],
    args: Dict[str, Any],
    workspaces: Sequence[Path],
    workspace: Optional[Path],
    effective_cwd: Optional[Path],
) -> Dict[str, Any]:
    type_name = str(
        args.get("TypeName")
        or args.get("type_name")
        or args.get("typeName")
        or args.get("subagent_type")
        or ""
    ).strip().lower()
    sub_model_raw = (
        args.get("Model")
        if args.get("Model") is not None
        else (args.get("model") if args.get("model") is not None else "inherit")
    )
    sub_model = str(sub_model_raw).strip().lower() or "inherit"
    role_str = str(args.get("Role") or args.get("role") or "")
    prompt_str = str(args.get("Prompt") or args.get("prompt") or "")
    combined_brief = f"{role_str}\n{prompt_str}"
    r12 = _inspect_delegation_rule12_text(
        combined_brief, "invoke_subagent", workspaces, workspace, effective_cwd=effective_cwd
    )
    if r12 is not None:
        return r12
    conv_id = _conversation_id(payload)
    custom_registered = False
    if type_name and conv_id:
        scope_key = _swarm_scope_key(payload, workspaces, workspace, effective_cwd)
        ledger_ok, conv_entry, _ = _swarm_ledger_context(payload, conv_id, scope_key=scope_key)
        if not ledger_ok:
            return {
                "decision": "force_ask",
                "reason": "[Harness Model & Effort Gate] Could not verify `swarm_workers.json`; human confirmation required.",
            }
        if isinstance(conv_entry, dict):
            custom_registered = type_name in [
                str(x).lower() for x in (conv_entry.get("custom_subagents") or []) if isinstance(x, str)
            ]
    targets_cust = (type_name not in _ptu._READONLY_SUBAGENT_TYPES) and (
        custom_registered
        or _ptu._text_targets_customization(
            combined_brief, workspaces, fallback_ws=workspace, effective_cwd=effective_cwd
        )
    )
    blocked, _is_downgraded = _check_delegated_model_gate(
        payload,
        "invoke_subagent",
        sub_model,
        targets_cust,
        model_arg_name="Model",
    )
    if blocked is not None:
        return blocked
    return {"decision": "allow"}

