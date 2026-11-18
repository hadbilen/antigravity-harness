#!/usr/bin/env python3
"""
guard/agy_hooks.py — Native Antigravity 2.0 Lifecycle Hooks CLI Router & Compatibility Facade (ADR-0008, ADR-0010)
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Thin event-scoped lazy dispatcher (`pre-invocation`, `pre-tool-use`, `stop`) and PEP 562
compatibility facade over `guard/hooks/{common,pre_invocation,pre_tool_use,_workflow_ast,stop_gate}.py`.
"""

from __future__ import annotations

import argparse
import functools
import importlib
import importlib.util
import inspect
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

try:
    import tomllib  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

_INIT_FILE = __file__
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
_INIT_REPO_ROOT = REPO_ROOT
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if __name__ == "__main__":
    _main_mod = sys.modules.get("__main__")
    try:
        _is_direct_cli = bool(sys.argv and sys.argv[0]) and Path(sys.argv[0]).resolve() == Path(__file__).resolve()
    except OSError:
        _is_direct_cli = False
    if _is_direct_cli and _main_mod is not None and _main_mod.__dict__ is globals():
        sys.modules.setdefault("guard.agy_hooks", _main_mod)

from guard.paths import (  # noqa: E402
    HOOK_LOCK_TIMEOUT, CorruptStateError, atomic_write_json, config_dir, configured_config_dir,
    data_dir, file_lock, is_within, move_aside, read_json, read_json_strict, state_dir,
)

PRE_TOOL_USE_MATCHER_TOOLS: Tuple[str, ...] = (
    "run_command", "bash", "execute_command", "shell", "send_command_input", "manage_task",
    "run_workflow", "invoke_subagent", "swarm", "post_message", "send_message", "define_subagent",
    "schedule", "call_mcp_tool", "mcp_.*", "write_to_file", "write_file", "replace_file_content",
    "multi_replace_file_content", "edit_file", "create_file", "write", "edit", "multiedit", "notebookedit",
)
PRE_TOOL_USE_MATCHER: str = "|".join(PRE_TOOL_USE_MATCHER_TOOLS)

_SUBMODULE_EXPORTS: Dict[str, Tuple[str, ...]] = {
    "common": tuple((
        "CONTINUATION_WORDS MAX_CONTEXT_SIGNALS MAX_EXPLICIT_HINTS MAX_HINTS MAX_STRIKES MIN_PROMPT_CHARS REHINT_TURN_GAP _AUTH_HEADING_RE _CONV_ID_FALLBACK_RE _EMPTY_AUTH_TOKENS _EXPLICIT_CMD_TOKEN_RE "
        "_FENCE_RE _HEX_OID_RE _INLINE_CODE_RE _INLINE_TAG_CODE_RE _LazyRegex _PASTED_RE _PATH_WORD_POST _PATH_WORD_PRE _SLASH_POST _SLASH_PRE _UNICODE_NEWLINE_RE _UNRECOVERED_FLIGHT_STATES "
        "_USER_REQUEST_TAG_RE _VIABLE_HINT_TOKEN_RE _conversation_id _extract_latest_user_prompt _extract_normalized_auth_section _extract_user_request_prose _extract_user_request_with_inline _facade_attr _flight_recorder_file "
        "_inspect_transcript_turn_state _is_git_repo_workspace _is_harness_repo_root _iter_jsonl_tail_entries _maybe_record_host_fixture _normalize_markdown_newlines _prune_missing_flight_workspaces _read_bounded_markdown "
        "_read_bounded_markdown_checked _read_ledger_checked _read_ledger_safe _resolve_transcript_path _safe_int _sanitize_host_fixture_payload _scan_transcript_turn_window _strip_non_user_prose _utc_now_iso _workspace_from_payload _workspaces_from_payload"
    ).split()),
    "pre_invocation": tuple((
        "ECOSYSTEM_ROUTING_HINTS SKILL_HINTS _ANY_EXPLICIT_SLUG_RE _AUDIO_VIDEO_EXTS _BENIGN_SEARCH_VERBS _BENIGN_STDERR_REDIR_RE _BINARY_ARTIFACT_EXTS _CAMPAIGN_ID_RE _CANVAS_RE _CLEAN_BUILD_PASS_RE _COMPILER_OR_TEST_CMD_VERBS _COMPILER_TRACE_MARKER_RE _DISTINCTIVE_SKILL_SLUGS _GAME_PKG_RE "
        "_HANDOFF_COMMIT_RE _HANDOFF_COMPLETE_RE _HANDOFF_IN_PROGRESS_RE _KNOWN_INLINE_EXPLICIT_SLUGS _KNOWN_INLINE_SLASH_ALIASES _MEDIA_ASSET_DIRS _NONZERO_EXIT_CODE_RE _NON_EXEC_READ_TOOLS _PY_M_BUILD_MODULES _RAF_RE _RASTER_MEDIA_EXTS _ROUTE_EXPLICIT_SLUGS _SHORT_UNATTRIBUTED_BUILD_RE _SUBCMD_BUILD_RUNNERS "
        "_ROUTE_HINT_BY_KEY _ROUTE_SLASH_ALIASES _RUST_BRIDGE_RE _SHELL_EXEC_TOOL_NAMES _SKILL_HINT_BY_NAME _SKILL_SLASH_ALIASES _SPRITE_NAME_RE _TASKS_BLOCKED_RE _TASKS_NEXT_ROW_RE _TASKS_PARTIAL_RE _TASKS_PENDING_RE "
        "_TRACE_ERROR_MARKER_RE _WEB_ICON_IGNORE_RE _WS_SKIP_DIRS _acknowledge_interrupted_flight _collect_context_domain_and_transcript_hints _collect_invocation_skill_hints "
        "_detect_transcript_tool_signals _detect_workspace_domain_signals _detect_workspace_recovery_hint _extract_cmd_from_args_obj _extract_entry_command_line _extract_explicit_inline_command_tokens _has_any_explicit_slug_mention "
        "_has_explicit_route_slug_mention _has_explicit_slash_command _has_explicit_slug_mention _invokes_compiler_or_test_runner _is_pure_search_or_diff_command _is_rea_mcp_available _load_conv_hint_state _optional_plugin_skill_available "
        "_read_bounded_bytes_nofollow _scrub_shell_quotes_and_substitutions _select_tiered_hints handle_pre_invocation"
    ).split()),
    "pre_tool_use": tuple((
        "COMMAND_TOOL_NAMES HIGH_RISK_MCP_TOOL_NAMES WRITE_TOOL_NAMES _ALLOWED_TOP_EFFORT_VALUES _ANY_PYTHON_INLINE_OR_HEREDOC_RE _AUTH_HTML_COMMENT_RE _BACKTICK_SPAN_RE _BROAD_RUNTIME_DOTDIR_SEAMS _CALL_ONLY_PY_NAMES _CD_SEG_RE _CMD_WRAPPER_PREFIX _CUSTOMIZATION_BASENAMES _CUSTOMIZATION_DIR_SEGMENTS "
        "_CUST_CMD_HARNESS_DIRS_PAT _CUST_CMD_HARNESS_SLASH_DIRS_PAT _CUST_CMD_TARGET_PAT _CUST_CMD_UNIVERSAL_TARGET_PAT _C_FLAG_LAUNCH_WRAPPERS _DANGEROUS_PY_ENV_RE _DELEGATION_GUARD_ADMIN_RE _DELEGATION_INSTALL_EXEC_RE _DELEGATION_MUTATION_VERB_RE _DELEGATION_PATH_TOKEN_RE "
        "_DESTRUCTIVE_CMD_PATTERNS _EDIT_REPLACEMENT_KEYS _EDIT_TARGET_KEYS _EXACT_NPM_VER_RE _EXACT_PY_PIN_RE _EXEC_CALL_ARGV_RE _FIND_EXEC_EXTRACT_RE _FORBIDDEN_INLINE_PY_ATTRS _GIT_GLOBAL_OPTS _GIT_HOOK_BYPASS_RE _GIT_OPT_ARG _GUARD_ADMIN_BODY _GUARD_ADMIN_RE _GUARD_API_TOKEN_PAT _GUARD_INLINE_PY_RE "
        "_HANDOFF_ANY_STATUS_RE _HANDOFF_COMPLETE_STATUS_RE _HARNESS_CHECKOUT_GATE_ENTRIES _HARNESS_SOURCE_FILES _HARNESS_SOURCE_TOP_DIRS _HEREDOC_PY_HEADER_RE _HIGHEST_EFFORT_SLUG_SUFFIXES _INLINE_DIR_FLAG_RE _INSTALL_PY_RE _INTERP_SCRIPT_SEG_RE _MCP_DEBUGGER_ESCAPE_RE _MCP_MUTATING_TOOL_HINT_RE _MCP_PATH_ARG_KEYS_LOWER "
        "_MODEL_EMBEDDED_EFFORT_RE _NON_PYTHON_INTERP_RE _NON_SHELL_C_FLAG_OWNERS _NPX_SEGMENT_RE _PATHLIB_CLASS_NAMES _PEP263_ENCODING_RE _PIPE_TO_SH_EXTRACT_RE _PLUGIN_EXEC_SUFFIXES _PLUGIN_GOVERNANCE_SEGMENTS _PURE_READONLY_PY_MODULES _PY_INTERP_OPTS _PY_MODULE_SCRIPT_RUNNERS "
        "_QUOTED_ARG_TOKEN_RE _QUOTED_ITEM_RE _QUOTED_SPAN_RE _READONLY_MCP_ALLOWLIST _READONLY_PY_MODULE_ATTRS _READONLY_PY_M_MODULES _READONLY_SUBAGENT_TYPES _REMOTE_INTERPRETER_PAT _RM_OR_MV_SEGMENT_RE _RUNTIME_CONFIG_SUBDIRS _SAFE_ENVIRON_READ_METHODS _SAFE_PY_CLI_OPT_RE "
        "_SAFE_READONLY_OBJECT_METHODS _SAFE_READONLY_PY_BUILTINS _SCRIPT_C_EXTRACT_RE _SETTINGS_EFFORT_RE _SETTINGS_KV_EFFORT_RE _SETTINGS_KV_MODEL_RE _SETTINGS_MODEL_RE _SHELL_C_EXTRACT_RE _SHELL_DOTDOT_TOKEN_RE _SHELL_MUTATION_INDICATOR_RE _SHELL_PUNCT_CHARS _SHELL_VERB_SKIP_NAMES "
        "_SIMPLE_VAR_ASSIGN_RE _SINGLE_WRAPPER_PAT _STR_ARGV_TOKEN_RE _STR_LIST_SEQ_RE _SUBPARSER_OPTS _SWARM_MENTION_RE _SWARM_MUTATION_KEYS _TERMINAL_INJECTION_RE _TERMINAL_MUX_SEGMENT_RE _URI_SCHEME_PREFIX_RE _USER_REQUEST_BLOCK_RE _USER_SETTINGS_BLOCK_RE "
        "_WORKFLOW_ARCHIVE_READONLY_MODE_RE _WORKFLOW_INSTALL_EXEC_BODY _WORKFLOW_INSTALL_EXEC_RE _WORKFLOW_MAX_ARG_DEPTH _WORKFLOW_MAX_BYTES _WORKFLOW_MAX_FOLDED_LEN _WORKFLOW_READONLY_MODE_RE _WRITE_TARGET_ARG_KEYS _allowed_slug_suffixes_for_effort _apply_swarm_entry_mutation "
        "_auth_sections_differ _batch_update_swarm_workers_ledger _blank_quoted_spans _capture_git_baseline _catalog_top_model_spec _check_customization_model_and_effort _check_delegated_model_gate _check_pep263_cookie _check_worktree_paths_clean_for_reset _cmd_input_buffer_key _collect_mcp_strings "
        "_collect_workflow_arg_strings _command_mutates_customization_in_cwd _command_mutates_customization_structure _command_mutates_governance _command_mutates_governance_in_cwd _compiled_cfg_subdir_patterns _compiled_governance_root_patterns _compiled_state_staging_pattern "
        "_compute_trailing_cmd_buffer _config_root_candidates _custom_enforced_governance_roots _detect_out_of_workspace_rm_or_mv _detect_unpinned_package_exec _environments_registry_corrupt _eval_workflow_path_expr _eval_workflow_str_expr _evaluate_customization_model_and_effort "
        "_expand_highest_effort_slug_aliases _expand_simple_shell_vars _extract_c_flag_payloads _extract_code_map_trace_target _extract_dollar_paren_payloads _extract_edit_pair _extract_indirect_exec_payloads _extract_mcp_target_paths _extract_shell_c_payloads _extract_shell_path_tokens "
        "_extract_transcript_model_and_effort _extract_transcript_model_setting _extract_workflow_sources _extract_workflow_sources_ex _extract_write_targets _find_harness_repo_root _governance_roots _handle_define_subagent_pre_tool_use _handle_post_message_pre_tool_use "
        "_handle_schedule_pre_tool_use _handle_send_message_pre_tool_use _handle_swarm_pre_tool_use _handoff_file_allows_stale_reset _has_linked_git_file _has_unclosed_shell_quote _infer_effort_from_model_label _inspect_delegation_rule12_text _inspect_external_script_command _inspect_mcp_tool_call "
        "_inspect_workflow_script _is_model_placeholder _is_pinned_npm_spec _is_pinned_py_spec _is_plugin_governance_path _is_pure_readonly_python_snippet _is_readonly_open_call _is_runtime_config_subdir _is_safe_stale_auth_reset _is_tracked_swarm_cust_worker _iter_shell_segments_with_cwd "
        "_join_shell_line_continuations _load_cmd_input_prefix _mask_quoted_operators _normalize_effort_value _normalize_governance_globs _normalize_mcp_path_value _normalize_model_slug _normalize_shell_paths _old_auth_has_only_parsed_entries _parse_file_uri _payload_cwd _persist_post_message_cust_mentions "
        "_python_ast_targets_governance _read_swarm_workers_ledger _record_flight_pre_write _record_swarm_cust_worker _resolve_shell_dir_token _save_cmd_input_prefix _scrub_verified_readonly_python_invocations _seed_placeholder_diagnostic _segment_has_unquoted_redirection_or_subst "
        "_shell_has_unquoted_mutation _shell_targets_tasks_md _state_root_candidates _strip_unquoted_shell_comments _swarm_entry_has_cust _swarm_ledger_context _swarm_targets_customization _swarm_workers_file _targets_customization_structure _targets_governance_dir "
        "_text_mutates_governance_path _text_targets_customization _transcript_subagent_is_downgraded _try_extract_standalone_py_c _unescape_dq_payload _unescape_safe_dq_py _unquote_single_tokens _update_swarm_workers_ledger _worker_matches_downgraded _workspace_for_target "
        "_workspaces_in_harness_scope _write_mutates_authorized_test_section handle_pre_tool_use"
    ).split()),
    "_workflow_ast": tuple((
        "_ALLOWED_STDLIB_WORKFLOW_MODULES _FORBIDDEN_ASYNCIO_EXEC_NAMES _FORBIDDEN_CALLABLE_BUILTINS _FORBIDDEN_CHILD_PROC_MODULES _FORBIDDEN_DIRECT_FS_ATTRS _FORBIDDEN_DUNDER_NAMES _FORBIDDEN_EXEC_ATTRS _FORBIDDEN_FRAME_ATTRS _FORBIDDEN_OS_EXEC_NAMES _FORBIDDEN_OS_FS_NAMES "
        "_FORBIDDEN_REEXPORT_ATTRS _FORBIDDEN_REFLECTIVE_ATTRS _FORBIDDEN_SYS_ATTRS _FORBIDDEN_WORKFLOW_MODULES _NON_ALIASABLE_FS_ATTRS _NON_ALIASABLE_WORKFLOW_NAMES _PROTECTED_HOST_PRIMITIVES _SAFE_WORKFLOW_BUILTINS _SAFE_WORKFLOW_HOST_CALLABLES _STDLIB_MODULES "
        "_UNCONDITIONAL_FORBIDDEN_SYS_ATTRS _eval_workflow_const_value _extract_partial_text_and_dynamic"
    ).split()),
    "stop_gate": tuple((
        "_ACTIVE_TEST_ASSERT_RE _CLOCK_INJECTION_RE _CODE_EXTS_FOR_STALE_NEG _COMMENT_ADDED_LINE_RE _INSCOPE_UNTRACKED_CODE_EXTS _ISO_TIMEBOMB_RE _LIVE_CLOCK_CALL_RE _MD_LINK_RE "
        "_NEW_FILE_CAPABILITY_SKIP_RE _NON_NORMAL_STOP_REASONS _PLACEHOLDER_LINK_RE _PY_TEST_DEF_RE _RELAXED_JS_RE _RELAXED_PY_CMP_RE _RELAXED_PY_TRUTHY_RE _RELAXED_UNITTEST_RE "
        "_SCANNER_EXEMPT_SUFFIXES _STRICT_JS_EQ_RE _STRICT_PY_EQ_RE _STRICT_UNITTEST_EQ_RE _STRING_LIT_RE _TAUTOLOGY_JS_RE _TAUTOLOGY_PY_RE _TEST_RUNNER_SNIFF_RE _TEST_SKIP_RE "
        "_UI_SLOP_EXTENSIONS _UI_SLOP_SCANNER_LOADED _UI_SLOP_SCANNER_MOD _UNTRACKED_MAX_BYTES _UNTRACKED_MAX_FILES _audit_stop_strike _authorized_test_modification_text _clear_stop_strikes "
        "_collect_workspace_diff _collect_workspace_diff_status _collect_workspace_diff_status_ex _conversation_has_recorded_writes _extract_latest_assistant_message "
        "_extract_relaxed_assert_subject _extract_strict_assert_subject _finding_structural_key _has_authorized_test_modifications _inspect_markdown_added_links _is_deferrable_question "
        "_is_exempt_harness_scanner_path _is_test_path _load_ui_slop_scanner _normalize_assert_subject _record_flight_stop _resolve_session_flight_base_head _scan_stale_negative_assertions "
        "_session_flight_base_head _unquote_git_diff_path _verify_all_workspaces_test_boundary _verify_workspace_test_boundary handle_stop inspect_git_diff validate_structured_content validate_ui_slop_content"
    ).split()),
}
_SYMBOL_TO_SUBMODULE: Dict[str, str] = {s: m for m, syms in _SUBMODULE_EXPORTS.items() for s in syms}
_SYNTHETIC_PKG_NAME = f"_agy_hooks_pkg_{os.urandom(6).hex()}"


class _HookBootstrapError(RuntimeError):
    pass


def _needs_synthetic_hooks_package() -> bool:
    reg = sys.modules.get("guard.agy_hooks")
    if reg is None or reg.__dict__ is not globals():
        return True
    if getattr(sys, "frozen", False) and not (SCRIPT_DIR / "hooks" / "__init__.py").is_file():
        return False
    guard_mod = sys.modules.get("guard")
    if guard_mod is not None:
        guard_paths = getattr(guard_mod, "__path__", None)
        if guard_paths is not None:
            resolved_dir = str(SCRIPT_DIR.resolve())
            if not any(str(Path(p).resolve()) == resolved_dir for p in guard_paths):
                return True
    return False


def _ensure_hooks_package() -> Tuple[str, Any]:
    if not _needs_synthetic_hooks_package():
        return "guard.hooks", importlib.import_module("guard.hooks")
    pkg_mod = sys.modules.get(_SYNTHETIC_PKG_NAME)
    if pkg_mod is None:
        init_py = SCRIPT_DIR / "hooks" / "__init__.py"
        spec = importlib.util.spec_from_file_location(
            _SYNTHETIC_PKG_NAME, init_py, submodule_search_locations=[str(SCRIPT_DIR / "hooks")]
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load hooks package from {init_py}")
        pkg_mod = importlib.util.module_from_spec(spec)
        sys.modules[_SYNTHETIC_PKG_NAME] = pkg_mod
        try:
            spec.loader.exec_module(pkg_mod)
        except BaseException:
            sys.modules.pop(_SYNTHETIC_PKG_NAME, None)
            raise
    return _SYNTHETIC_PKG_NAME, pkg_mod


def _load_submodule(submod: str) -> Tuple[str, Any, Any]:
    pkg_prefix, pkg_mod = _ensure_hooks_package()
    return pkg_prefix, pkg_mod, importlib.import_module(f"{pkg_prefix}.{submod}")


def _resolve_attr(name: str) -> Any:
    g = globals()
    return g[name] if name in g else __getattr__(name)


class _GlobalsProxy:
    _globals = globals()

    def __getattr__(self, name: str) -> Any:
        return _resolve_attr(name)


_FACADE_PROXY = _GlobalsProxy()


def _call_with_facade(pkg_mod: Any, fn: Any, *args: Any, **kwargs: Any) -> Any:
    tok = pkg_mod._ACTIVE_FACADE.set(_FACADE_PROXY)
    try:
        return fn(*args, **kwargs)
    finally:
        pkg_mod._ACTIVE_FACADE.reset(tok)


def _bind_facade_callable(pkg_mod: Any, val: Any) -> Any:
    if inspect.isgeneratorfunction(val):
        @functools.wraps(val)
        def _bound_gen(*args: Any, **kwargs: Any) -> Any:
            gen = _call_with_facade(pkg_mod, val, *args, **kwargs)
            try:
                while True:
                    try:
                        item = _call_with_facade(pkg_mod, next, gen)
                    except StopIteration as stop:
                        return stop.value
                    yield item
            finally:
                _call_with_facade(pkg_mod, gen.close)

        return _bound_gen

    @functools.wraps(val)
    def _bound_callable(*args: Any, **kwargs: Any) -> Any:
        return _call_with_facade(pkg_mod, val, *args, **kwargs)

    return _bound_callable


def __getattr__(name: str) -> Any:
    submod = _SYMBOL_TO_SUBMODULE.get(name)
    if submod is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    pkg_prefix, pkg_mod, mod_obj = _load_submodule(submod)
    val = getattr(mod_obj, name)
    if pkg_prefix != "guard.hooks" and callable(val) and not isinstance(val, type):
        return _bind_facade_callable(pkg_mod, val)
    return val


def __dir__() -> list[str]:
    return sorted(set(globals().keys()) | set(_SYMBOL_TO_SUBMODULE.keys()))


def _is_pre_tool_use_event(event: str) -> bool:
    return event.strip().lower().replace("_", "-") in ("pre-tool-use", "pretooluse")


def _is_stop_event(event: str) -> bool:
    return event.strip().lower().replace("_", "-") == "stop"


def _resolve_handler(name: str) -> Any:
    try:
        return _resolve_attr(name)
    except (ImportError, SyntaxError) as exc:
        raise _HookBootstrapError(f"{type(exc).__name__}: {exc}") from exc


def dispatch_hook(event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    if os.environ.get("AGY_RECORD_HOST_FIXTURES", "").strip() in ("1", "true", "yes"):
        _resolve_handler("_maybe_record_host_fixture")(event, payload)
    norm = event.strip().lower().replace("_", "-")
    if norm in ("pre-invocation", "preinvocation"):
        return _resolve_handler("handle_pre_invocation")(payload)
    if norm in ("pre-tool-use", "pretooluse"):
        return _resolve_handler("handle_pre_tool_use")(payload)
    if norm in ("stop",):
        return _resolve_handler("handle_stop")(payload)
    return {}


_RAW_HOOK_EVENT_RE = re.compile(r'"hookEventName"\s*:\s*"([^"]+)"')


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agy_hooks.py", description="Native Antigravity 2.0 lifecycle hooks for Antigravity Harness."
    )
    parser.add_argument("event", nargs="?", default="", help="Hook event: pre-invocation, pre-tool-use, or stop.")
    args = parser.parse_args(argv)

    stdin_invalid = False
    raw = ""
    try:
        raw = sys.stdin.read().strip()
        if not raw:
            stdin_invalid = True
            payload: Dict[str, Any] = {}
        else:
            parsed_stdin = json.loads(raw)
            stdin_invalid = not isinstance(parsed_stdin, dict)
            payload = parsed_stdin if isinstance(parsed_stdin, dict) else {}
    except Exception:
        stdin_invalid = True
        payload = {}

    event = args.event or str(payload.get("hookEventName") or "")
    if stdin_invalid and not event and raw:
        m_ev = _RAW_HOOK_EVENT_RE.search(raw)
        if m_ev:
            event = m_ev.group(1).strip()

    if stdin_invalid and (_is_pre_tool_use_event(event) or not event):
        response: Dict[str, Any] = {
            "decision": "deny",
            "reason": "[Harness PreToolUse Gate] Empty, malformed, or non-object JSON payload on stdin (failing closed).",
        }
    elif stdin_invalid and _is_stop_event(event):
        sys.stderr.write("[Harness Stop Gate] Malformed, empty, or non-object JSON payload on stdin.\n")
        response = {
            "decision": "continue",
            "reason": "[Harness Stop Gate] Empty, malformed, or non-object JSON payload on stdin (failing closed).",
        }
    else:
        try:
            response = globals()["dispatch_hook"](event, payload)
        except Exception as exc:
            if _is_pre_tool_use_event(event) or not event:
                response = {
                    "decision": "deny",
                    "reason": "[Harness PreToolUse Gate] Internal hook error (failing closed).",
                }
            elif _is_stop_event(event):
                sys.stderr.write(f"[Harness Stop Gate] Unhandled internal error ({type(exc).__name__}): {exc}\n")
                try:
                    exec_num = int(payload.get("executionNum") or payload.get("execution_num") or 0)
                except (TypeError, ValueError):
                    exec_num = 0
                if isinstance(exc, _HookBootstrapError) and exec_num < 2:
                    response = {
                        "decision": "continue",
                        "reason": f"[Harness Stop Gate] Failed to load Stop gate submodule ({exc}) — failing closed.",
                    }
                else:
                    response = {}
            else:
                sys.stderr.write(f"[Harness Hook] Unhandled internal error in `{event}` ({type(exc).__name__}): {exc}\n")
                response = {}

    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()
    return 0


__all__ = tuple(sorted(k for k in (set(globals()) | set(_SYMBOL_TO_SUBMODULE)) if not k.startswith("_")))

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        fallback_event = sys.argv[1] if len(sys.argv) > 1 else ""
        if _is_pre_tool_use_event(fallback_event) or not fallback_event:
            fb_resp = {"decision": "deny", "reason": "[Harness PreToolUse Gate] Internal hook error (failing closed)."}
            sys.stdout.write(json.dumps(fb_resp) + "\n")
        elif _is_stop_event(fallback_event):
            sys.stderr.write(f"[Harness Stop Gate] Fatal fallback error ({type(exc).__name__}): {exc}\n")
            fb_stop = {"decision": "continue", "reason": "[Harness Stop Gate] Internal hook error during Stop verification (failing closed)."}
            sys.stdout.write(json.dumps(fb_stop) + "\n")
        else:
            sys.stdout.write("{}\n")
        sys.stdout.flush()
        sys.exit(0)
