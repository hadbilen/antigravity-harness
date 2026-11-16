"""
guard/hooks/common.py — Shared primitives and dynamic facade collaborator proxies (ADR-0008).
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import json as _stdlib_json
import os
import re
import stat
import subprocess as _stdlib_subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from guard.paths import (
    HOOK_LOCK_TIMEOUT,
    CorruptStateError,
    atomic_write_json as _default_atomic_write_json,
    config_dir as _default_config_dir,
    configured_config_dir as _default_configured_config_dir,
    data_dir as _default_data_dir,
    file_lock as _default_file_lock,
    is_within,
    move_aside,
    read_json,
    read_json_strict,
    state_dir as _default_state_dir,
)

from . import _ACTIVE_FACADE

_DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]


def _facade() -> Any:
    """Resolve the active facade module (`_ACTIVE_FACADE` ContextVar first, else `guard.agy_hooks`)."""
    active = _ACTIVE_FACADE.get()
    if active is not None:
        return active
    return sys.modules.get("guard.agy_hooks")


def _facade_attr(attr_name: str, default: Any) -> Any:
    """Resolve `attr_name` on `_facade()` without swallowing lazy submodule `AttributeError`s."""
    fac = _facade()
    if fac is None:
        return default
    fac_dict = getattr(fac, "_globals", None)
    if not isinstance(fac_dict, dict):
        fac_dict = getattr(fac, "__dict__", None)
    if isinstance(fac_dict, dict):
        if attr_name in fac_dict:
            return fac_dict[attr_name]
        sym_map = fac_dict.get("_SYMBOL_TO_SUBMODULE")
        if isinstance(sym_map, dict) and attr_name in sym_map:
            return getattr(fac, attr_name)
        return default
    return getattr(fac, attr_name, default)


def _repo_root() -> Path:
    fac = _facade()
    if fac is None:
        return _DEFAULT_REPO_ROOT
    repo_val = _facade_attr("REPO_ROOT", None)
    init_repo = _facade_attr("_INIT_REPO_ROOT", None)
    if repo_val is not None and (init_repo is None or Path(repo_val) != Path(init_repo)):
        return Path(repo_val)
    file_val = _facade_attr("__file__", None)
    init_file = _facade_attr("_INIT_FILE", None)
    if isinstance(file_val, (str, Path)) and init_file is not None and str(file_val) != str(init_file):
        return Path(file_val).resolve().parent.parent
    return Path(repo_val) if repo_val is not None else _DEFAULT_REPO_ROOT


class _FacadeModuleProxy:
    """Forwards attribute lookups (`json.loads`, `subprocess.run`) through `_facade()`."""

    def __init__(self, attr_name: str, fallback: Any) -> None:
        self._attr_name = attr_name
        self._fallback = fallback

    def __getattr__(self, name: str) -> Any:
        target = _facade_attr(self._attr_name, self._fallback)
        return getattr(target, name)


json: Any = _FacadeModuleProxy("json", _stdlib_json)
subprocess: Any = _FacadeModuleProxy("subprocess", _stdlib_subprocess)


def atomic_write_json(*args: Any, **kwargs: Any) -> Any:
    return _facade_attr("atomic_write_json", _default_atomic_write_json)(*args, **kwargs)


def config_dir(*args: Any, **kwargs: Any) -> Path:
    return _facade_attr("config_dir", _default_config_dir)(*args, **kwargs)


def configured_config_dir(*args: Any, **kwargs: Any) -> Path:
    return _facade_attr("configured_config_dir", _default_configured_config_dir)(*args, **kwargs)


def data_dir(*args: Any, **kwargs: Any) -> Path:
    return _facade_attr("data_dir", _default_data_dir)(*args, **kwargs)


def state_dir(*args: Any, **kwargs: Any) -> Path:
    return _facade_attr("state_dir", _default_state_dir)(*args, **kwargs)


def file_lock(*args: Any, **kwargs: Any) -> Any:
    return _facade_attr("file_lock", _default_file_lock)(*args, **kwargs)


MAX_HINTS = 2

MAX_EXPLICIT_HINTS = 4

MAX_CONTEXT_SIGNALS = 2

MAX_STRIKES = 3

MIN_PROMPT_CHARS = 15

REHINT_TURN_GAP = 8

CONTINUATION_WORDS = frozenset({
    "devam",
    "devam et",
    "evet",
    "hayır",
    "hayir",
    "tamam",
    "peki",
    "olur",
    "ok",
    "okay",
    "yes",
    "no",
    "proceed",
    "continue",
    "go ahead",
    "uygula",
    "başla",
    "basla",
    "onaylıyorum",
    "onayliyorum",
})

class _LazyRegex:
    """Delays compilation of non-Pass-7 regexes until first match/search/sub/finditer call."""

    __slots__ = ("_pattern", "_flags", "_compiled")

    def __init__(self, pattern: str, flags: int = 0) -> None:
        self._pattern = pattern
        self._flags = flags
        self._compiled: Optional[re.Pattern[str]] = None

    def _get(self) -> re.Pattern[str]:
        if self._compiled is None:
            self._compiled = re.compile(self._pattern, self._flags)
        return self._compiled

    def search(self, string: str, pos: int = 0, endpos: int = sys.maxsize) -> Optional[re.Match[str]]:
        return self._get().search(string, pos, endpos)

    def match(self, string: str, pos: int = 0, endpos: int = sys.maxsize) -> Optional[re.Match[str]]:
        return self._get().match(string, pos, endpos)

    def fullmatch(self, string: str, pos: int = 0, endpos: int = sys.maxsize) -> Optional[re.Match[str]]:
        return self._get().fullmatch(string, pos, endpos)

    def finditer(self, string: str, pos: int = 0, endpos: int = sys.maxsize) -> Iterator[re.Match[str]]:
        return self._get().finditer(string, pos, endpos)

    def findall(self, string: str, pos: int = 0, endpos: int = sys.maxsize) -> List[Any]:
        return self._get().findall(string, pos, endpos)

    def sub(self, repl: Any, string: str, count: int = 0) -> str:
        return self._get().sub(repl, string, count)

    def subn(self, repl: Any, string: str, count: int = 0) -> Tuple[str, int]:
        return self._get().subn(repl, string, count)

    def split(self, string: str, maxsplit: int = 0) -> List[Any]:
        return self._get().split(string, maxsplit)

    @property
    def pattern(self) -> str:
        return self._pattern

    @property
    def flags(self) -> int:
        return self._get().flags

    @property
    def groups(self) -> int:
        return self._get().groups

    @property
    def groupindex(self) -> Any:
        return self._get().groupindex


_FENCE_RE = _LazyRegex(r"(?ms)^[ \t]{0,3}(`{3,}(?!`)|~{3,}(?!~)).*?^[ \t]{0,3}\1[ \t]*$")

_PASTED_RE = _LazyRegex(r"(?s)<pasted_content\b[^<>]*>.*?</pasted_content[^<>]*>")

_INLINE_CODE_RE = _LazyRegex(r"`[^`\n]+`")

_INLINE_TAG_CODE_RE = _LazyRegex(r"`[^`\n]*[<>][^`\n]*`")

_USER_REQUEST_TAG_RE = _LazyRegex(r"(?is)<user_request\b[^<>]*>(.*?)</user_request\b[^<>]*>")

_SLASH_PRE = r"(?=[/\$])(?:^|(?<=[\s(\[\"'«“]))"

_SLASH_POST = r"(?=$|[\s,!?;:)\]>\"'»”]|\.(?![A-Za-z0-9_]))"

_PATH_WORD_PRE = r"(?=[\w.$])(?<![/\w\\-])(?<!(?<!\.\.)\.)"

_PATH_WORD_POST = r"(?![/\w\\-])(?!\.[A-Za-z0-9_])"

_EXPLICIT_CMD_TOKEN_RE = _LazyRegex(
    rf"{_SLASH_PRE}[/\$][a-zA-Z][a-zA-Z0-9_-]{{1,63}}{_SLASH_POST}"
)

_VIABLE_HINT_TOKEN_RE = _LazyRegex(r"(?=[\w.$])(?<![/\w\\-])")

def _conversation_id(payload: Dict[str, Any]) -> str:
    for key in (
        "conversationId",
        "conversation_id",
        "sessionId",
        "session_id",
        "trajectoryId",
        "trajectory_id",
        "cascadeId",
        "cascade_id",
    ):
        val = payload.get(key)
        if isinstance(val, (str, int)) and not isinstance(val, bool):
            text = str(val).strip()
            if text:
                return text
    return "default"

def _safe_int(val: Any, default: int = 0) -> int:
    """Parses an integer safely while rejecting booleans, NaN/Inf, and malformed strings."""
    if isinstance(val, bool) or val is None:
        return default
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        try:
            return int(val)
        except (ValueError, OverflowError):
            return default
    if isinstance(val, str):
        stripped = val.strip()
        if not stripped:
            return default
        try:
            return int(stripped)
        except ValueError:
            return default
    return default

def _strip_non_user_prose(text: str, *, strip_inline_code: bool = True) -> str:
    """Removes pasted blocks, fenced code blocks, and optionally inline code from user text before matching."""
    cleaned = _PASTED_RE.sub(" ", text or "")
    cleaned = _FENCE_RE.sub(" ", cleaned)
    if strip_inline_code:
        cleaned = _INLINE_CODE_RE.sub(" ", cleaned)
    return cleaned

def _extract_user_request_prose(raw_prompt: str) -> str:
    """Strips pasted/fenced/inline-code blocks before extracting `<USER_REQUEST>` user prose."""
    sanitized = _strip_non_user_prose(raw_prompt or "", strip_inline_code=True)
    blocks = _USER_REQUEST_TAG_RE.findall(sanitized)
    return _strip_non_user_prose("\n".join(blocks), strip_inline_code=True) if blocks else sanitized


def _extract_user_request_with_inline(raw_prompt: str) -> str:
    """Strips pasted/fenced blocks while preserving inline backticks for turn-equality comparison."""
    sanitized = _strip_non_user_prose(raw_prompt or "", strip_inline_code=False)
    blocks = _USER_REQUEST_TAG_RE.findall(sanitized)
    return _strip_non_user_prose("\n".join(blocks), strip_inline_code=False) if blocks else sanitized


_CONV_ID_FALLBACK_RE = _LazyRegex(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _resolve_transcript_path(payload: Dict[str, Any]) -> Optional[Path]:
    """Resolves a regular non-symlink transcript JSONL path from payload or active conversation brain dir."""
    transcript = payload.get("transcriptPath") or payload.get("transcript_path")
    if isinstance(transcript, str) and transcript.strip():
        raw_tx = transcript.strip()
        if "\x00" in raw_tx:
            return None
        try:
            cand = Path(raw_tx).expanduser()
            if not cand.is_symlink() and cand.is_file():
                return cand
        except (OSError, RuntimeError, ValueError):
            return None
        return None
    conv_id = _conversation_id(payload)
    if conv_id and conv_id != "default" and "\x00" not in conv_id and _CONV_ID_FALLBACK_RE.match(conv_id):
        try:
            brain_root = Path.home() / ".gemini" / "antigravity" / "brain"
            fallback = brain_root / conv_id / ".system_generated" / "logs" / "transcript.jsonl"
            if (
                not fallback.is_symlink()
                and fallback.is_file()
                and is_within(fallback.resolve(), brain_root.resolve())
            ):
                return fallback
        except (OSError, RuntimeError, ValueError):
            return None
    return None


def _scan_transcript_turn_window(
    tx_path: Path, explicit_step: int, max_scan_bytes: int
) -> Tuple[str, Optional[int], int, int, bool]:
    trailing_non_user = 0
    latest_text = ""
    latest_entry_step: Optional[int] = None
    user_input_count = 0
    found_user = False

    for entry in _iter_jsonl_tail_entries(tx_path, max_scan_bytes=max_scan_bytes):
        step_type = str(entry.get("type", "")).upper()
        source = str(entry.get("source", "")).upper()
        if step_type == "USER_INPUT" or source == "USER_EXPLICIT":
            user_input_count += 1
            if not found_user:
                found_user = True
                content = entry.get("content")
                if isinstance(content, str) and content.strip():
                    latest_text = content.strip()[:131072]
                raw_entry_step = entry.get("step_index")
                if raw_entry_step is None:
                    raw_entry_step = entry.get("stepIdx")
                if raw_entry_step is not None:
                    latest_entry_step = max(0, _safe_int(raw_entry_step, default=explicit_step))
        elif not found_user:
            trailing_non_user += 1
    return latest_text, latest_entry_step, user_input_count, trailing_non_user, found_user


def _inspect_transcript_turn_state(payload: Dict[str, Any]) -> Tuple[str, int, bool, bool]:
    """
    Inspects up to 128 KB (widening to 2 MiB on heavy mid-turn output) at the tail of `transcript.jsonl`:
      `(latest_user_text, resolved_step_idx, is_mid_turn_continuation, has_transcript)`.
    `is_mid_turn_continuation` is True when `>= 1` non-`USER_INPUT` entries follow the latest `USER_INPUT`.
    """
    step_raw = payload.get("stepIdx")
    if step_raw is None:
        step_raw = payload.get("initialNumSteps")
    explicit_step = max(0, _safe_int(step_raw, default=0))

    tx_path = _resolve_transcript_path(payload)
    if tx_path is None:
        return "", explicit_step, False, False

    latest_text, latest_entry_step, user_input_count, trailing_non_user, found_user = (
        _scan_transcript_turn_window(tx_path, explicit_step, max_scan_bytes=131072)
    )
    if not found_user and trailing_non_user > 0:
        latest_text, latest_entry_step, user_input_count, trailing_non_user, found_user = (
            _scan_transcript_turn_window(tx_path, explicit_step, max_scan_bytes=2 * 1024 * 1024)
        )

    if not found_user:
        return "", explicit_step, trailing_non_user > 0, True

    explicit_prompt = ""
    for key in ("lastUserInput", "last_user_input", "prompt", "userPrompt", "userMessage", "user_prompt"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            explicit_prompt = val.strip()[:131072]
            break

    explicit_differs = False
    if explicit_prompt and latest_text:
        exp_clean = _extract_user_request_with_inline(explicit_prompt).strip()
        tx_clean = _extract_user_request_with_inline(latest_text).strip()
        if exp_clean != tx_clean:
            explicit_differs = True

    if explicit_step > 0:
        resolved_step = explicit_step
    elif latest_entry_step is not None and latest_entry_step > 0:
        resolved_step = latest_entry_step + (1 if explicit_differs else 0)
    else:
        resolved_step = user_input_count + (1 if explicit_differs else 0)
    is_mid = (trailing_non_user > 0) and (not explicit_differs)
    return latest_text, resolved_step, is_mid, True


def _extract_latest_user_prompt(
    payload: Dict[str, Any],
    *,
    _tx_state: Optional[Tuple[str, int, bool, bool]] = None,
) -> Tuple[str, int]:
    """
    Returns (user_text, step_idx) from explicit payload fields (`lastUserInput`, `last_user_input`, `prompt`, etc.)
    or from transcriptPath JSONL, incorporating transcript step progression when `stepIdx` is omitted.
    """
    step_raw = payload.get("stepIdx")
    if step_raw is None:
        step_raw = payload.get("initialNumSteps")
    explicit_step = max(0, _safe_int(step_raw, default=0))

    tx_text, tx_step, _tx_mid, has_tx = (
        _tx_state if _tx_state is not None else _inspect_transcript_turn_state(payload)
    )

    for key in ("lastUserInput", "last_user_input", "prompt", "userPrompt", "userMessage", "user_prompt"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            resolved = explicit_step if explicit_step > 0 else (tx_step if has_tx else 0)
            return val.strip()[:131072], resolved

    if has_tx and tx_text:
        return tx_text, tx_step
    return "", 0

_HEX_OID_RE = _LazyRegex(r"^[0-9a-fA-F]{40,64}$")

_UNRECOVERED_FLIGHT_STATES = frozenset({"in_flight", "interrupted_notified", "in_progress_blocked"})

def _flight_recorder_file() -> Path:
    return state_dir() / "flight_recorder.json"

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _read_ledger_checked(path: Path, *, quarantine: bool = True) -> Tuple[bool, Dict[str, Any]]:
    """Reads a JSON dict ledger, optionally quarantining corrupt state, and reports whether inspection succeeded."""
    try:
        data = read_json_strict(path)
    except (CorruptStateError, UnicodeDecodeError):
        if quarantine:
            move_aside(path, tag="corrupt")
        return False, {}
    except OSError:
        return False, {}
    if data is None:
        return True, {}
    if not isinstance(data, dict):
        if quarantine:
            move_aside(path, tag="corrupt")
        return False, {}
    return True, data

def _read_ledger_safe(path: Path) -> Dict[str, Any]:
    """Reads a JSON dict ledger, quarantining (`move_aside`) corrupt state rather than silently wiping it."""
    return _read_ledger_checked(path)[1]

def _read_bounded_markdown_checked(path: Path, limit: int = 262144) -> Tuple[bool, str]:
    """Reads up to `limit` bytes from a non-symlink regular file and reports whether a regular read succeeded."""
    try:
        if path.is_symlink() or not path.is_file():
            return True, ""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(path), flags)
        with os.fdopen(fd, "rb") as f:
            return True, f.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return False, ""

def _read_bounded_markdown(path: Path, limit: int = 262144) -> str:
    """Reads up to `limit` bytes from a non-symlink regular file without skipping large logs."""
    return _read_bounded_markdown_checked(path, limit=limit)[1]

def _prune_missing_flight_workspaces(ledger: Dict[str, Any]) -> bool:
    """Removes orphaned flight-recorder entries whose workspace directory was deleted on disk."""
    pruned = False
    for k in list(ledger.keys()):
        if not isinstance(k, str) or not k.strip():
            continue
        try:
            if not Path(k).is_dir() and not os.path.lexists(k):
                del ledger[k]
                pruned = True
        except (OSError, ValueError):
            continue
    return pruned

def _workspaces_from_payload(payload: Dict[str, Any]) -> List[Path]:
    """Returns all valid workspace directories from multi-root or single-root hook payloads."""
    found: List[Path] = []
    seen: set[str] = set()

    def _add_ws(raw: Any) -> None:
        if not isinstance(raw, str) or not raw.strip():
            return
        candidate = Path(raw.strip()).expanduser()
        try:
            if not candidate.is_dir():
                return
            key = str(candidate.resolve())
        except (OSError, RuntimeError, ValueError):
            return
        if key not in seen:
            seen.add(key)
            found.append(candidate)

    paths = payload.get("workspacePaths") or payload.get("workspace_paths")
    if isinstance(paths, list):
        for entry in paths:
            _add_ws(entry)
    for key in ("workspacePath", "workspace_path", "worktreePath", "worktree_path", "cwd", "workspace"):
        _add_ws(payload.get(key))
    return found

def _workspace_from_payload(payload: Dict[str, Any]) -> Optional[Path]:
    workspaces = _workspaces_from_payload(payload)
    return workspaces[0] if workspaces else None

def _iter_jsonl_tail_entries(
    path: Path,
    *,
    max_scan_bytes: int = 2 * 1024 * 1024,
    max_line_bytes: int = 2 * 1024 * 1024,
) -> Iterator[Dict[str, Any]]:
    """Yields valid JSON object lines from the tail of a regular non-symlink JSONL file, newest first."""
    try:
        path_str = os.fspath(path)
        if "\x00" in path_str or path.is_symlink() or not path.is_file():
            return
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path_str, flags)
    except (OSError, TypeError, ValueError):
        return
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            return
        fh = os.fdopen(fd, "rb")
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        return
    try:
        with fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            chunk_size = 131072
            min_offset = max(0, size - max_scan_bytes)
            pos = size
            carry = b""
            while pos > min_offset:
                read_start = max(min_offset, pos - chunk_size)
                to_read = pos - read_start
                fh.seek(read_start, os.SEEK_SET)
                buf = fh.read(to_read) + carry
                pos = read_start
                if pos > min_offset:
                    nl_idx = buf.find(b"\n")
                    if nl_idx == -1:
                        carry = buf if len(buf) <= max_line_bytes else b""
                        continue
                    carry = buf[:nl_idx]
                    complete_bytes = buf[nl_idx + 1 :]
                else:
                    complete_bytes = buf
                    carry = b""

                lines = complete_bytes.decode("utf-8", errors="replace").splitlines()
                for raw in reversed(lines):
                    raw = raw.strip()
                    if not raw.startswith("{"):
                        continue
                    try:
                        entry = json.loads(raw)
                    except ValueError:
                        continue
                    if isinstance(entry, dict):
                        yield entry
    except OSError:
        return

def _is_harness_repo_root(root: Path) -> bool:
    return (root / ".harness" / "manifest.json").is_file() or (root / "guard" / "agy_hooks.py").is_file()

_AUTH_HEADING_RE = _LazyRegex(
    r"(?ims)^[^\S\r\n]*#{1,6}[^\S\r\n]+Authorized\s+Test\s+Modifications(?:\s*:\s*([^\r\n]*))?[^\S\r\n]*\r?$(.*?)(?=^[^\S\r\n]*#{1,6}[^\S\r\n]+|\Z)"
)

_EMPTY_AUTH_TOKENS = frozenset({"", "none", "yok", "n/a", "na", "null", "nil", "false", "hayir", "hayır"})

def _extract_normalized_auth_section(text: str) -> str:
    sections: List[str] = []
    for match in _AUTH_HEADING_RE.finditer(text or ""):
        combined = f"{match.group(1) or ''}\n{match.group(2) or ''}".strip()
        cleaned = re.sub(r"[-*•\[\]\s.`_:;()]+", "", combined.lower())
        if cleaned not in _EMPTY_AUTH_TOKENS:
            sections.append(combined)
    return "\n".join(sections)

def _is_git_repo_workspace(workspace: Path) -> bool:
    cur = workspace
    try:
        cur = workspace.resolve()
    except (OSError, RuntimeError):
        pass
    for candidate in (cur, *cur.parents):
        try:
            if (candidate / ".git").exists():
                return True
        except OSError:
            continue
    return False

def _sanitize_host_fixture_payload(obj: Any, _depth: int = 0) -> Any:
    if _depth > 8:
        return "<truncated>"
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            ks = str(k)
            if ks.lower() in ("apikey", "api_key", "token", "secret", "authorization", "password"):
                out[ks] = "<redacted>"
            elif ks in ("prompt", "userPrompt", "userMessage", "user_prompt", "lastUserInput", "last_user_input", "assistantMessage", "lastAssistantMessage", "diffText") and isinstance(v, str):
                out[ks] = v[:512]
            else:
                out[ks] = _sanitize_host_fixture_payload(v, _depth + 1)
        return out
    if isinstance(obj, list):
        return [_sanitize_host_fixture_payload(item, _depth + 1) for item in obj[:20]]
    if isinstance(obj, str) and len(obj) > 512:
        return obj[:512]
    return obj

def _maybe_record_host_fixture(event: str, payload: Dict[str, Any]) -> None:
    if os.environ.get("AGY_RECORD_HOST_FIXTURES", "").strip() not in ("1", "true", "yes"):
        return
    try:
        cap_dir = state_dir() / "host_fixtures"
        cap_dir.mkdir(parents=True, exist_ok=True)
        norm_ev = re.sub(r"[^a-z0-9_-]+", "-", (event or "unknown").strip().lower()) or "unknown"
        out_file = cap_dir / f"latest_{norm_ev}.json"
        sanitized = _sanitize_host_fixture_payload(payload)
        atomic_write_json(out_file, {"hookEventName": event, "payload": sanitized})
    except Exception:
        pass
