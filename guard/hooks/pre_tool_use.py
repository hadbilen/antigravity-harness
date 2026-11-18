"""
guard/hooks/pre_tool_use.py — PreToolUse bashguard, governance/customization shield, workflow AST & swarm gate (ADR-0008).
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import ast
import functools
import os
import re
import stat
import sys
import textwrap
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from guard.paths import HOOK_LOCK_TIMEOUT, is_within, read_json

from .common import (
    _AUTH_HEADING_RE,
    _FENCE_RE,
    _HEX_OID_RE,
    _INLINE_TAG_CODE_RE,
    _PASTED_RE,
    _UNRECOVERED_FLIGHT_STATES,
    _LazyRegex,
    _conversation_id,
    _extract_normalized_auth_section,
    _facade,
    _facade_attr,
    _flight_recorder_file,
    _is_git_repo_workspace,
    _is_harness_repo_root,
    _iter_jsonl_tail_entries,
    _normalize_markdown_newlines,
    _read_ledger_checked,
    _read_ledger_safe,
    _repo_root,
    _safe_int,
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

_PY_INTERP_OPTS = r"(?:-(?![A-Za-z0-9]*[mc]\b)(?:[WXx]\s+\S+|[A-Za-z0-9]+(?:=\S+)?)\s+)*"

_SINGLE_WRAPPER_PAT = (
    r"(?:[^\s;|&`]*/)?"
    r"(?:"
    r"timeout(?:\s+(?:-[ks]\s+\S+|--(?:signal|kill-after)(?:=\S+|\s+\S+)|-[A-Za-z0-9-]+))*\s+\d+(?:\.\d+)?[smhd]?|"
    r"nice(?:\s+(?:-n\s+-?\d+|--adjustment(?:=-?\d+|\s+-?\d+)|-\d+))*|"
    r"ionice(?:\s+(?:-[cnpt]\s+\S+|--[a-z-]+(?:=\S+|\s+\S+)|-[A-Za-z0-9]+))*|"
    r"chrt(?:\s+-[A-Za-z0-9-]+)*(?:\s+\d+)?|"
    r"taskset(?:\s+(?:-c\s+\S+|--cpu-list(?:=\S+|\s+\S+)|-[A-Za-z0-9]+))*\s+\S+|"
    r"stdbuf(?:\s+(?:-[ioe]\S*|--(?:input|output|error)(?:=\S+|\s+\S+)))+|"
    r"setsid(?:\s+-[A-Za-z0-9-]+)*|"
    r"nohup|"
    r"time(?:\s+-[pP])*|"
    r"sudo(?:\s+(?:-[uUgCp]\s+\S+|--(?:user|group|chdir|other-user)(?:=\S+|\s+\S+)|-[A-Za-z0-9-]+))*|"
    r"env(?:\s+(?:-[uC]\s+\S+|--(?:unset|chdir|split-string)(?:=\S+|\s+\S+)|-[A-Za-z0-9-]+|[A-Za-z_][A-Za-z0-9_]*=\S*))*|"
    r"exec(?:\s+(?:-a\s+\S+|-[cl]))*|"
    r"command(?:\s+-p)*(?!\s+-[A-Za-z]*[vV]\b)|"
    r"xargs(?:\s+(?:-[IinLPsdE]\s*\S+|--[a-z-]+(?:=\S+|\s+\S+)|-[A-Za-z0-9]+))*"
    r")"
)

_CMD_WRAPPER_PREFIX = rf"(?:{_SINGLE_WRAPPER_PAT}\s+)*(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*(?:{_SINGLE_WRAPPER_PAT}\s+)*"

_SUBPARSER_OPTS = (
    r"(?:\s+--?[A-Za-z0-9_-]+"
    r"(?:=\S+|\s+(?!snapshot\b|restore\b|prune\b|stage\b|import\b|policy\b|add\b|remove\b|enable\b|disable\b)--?[^\s;|`]+|\s+(?!snapshot\b|restore\b|prune\b|stage\b|import\b|policy\b|add\b|remove\b|enable\b|disable\b)[^\s;|`-]\S*)?)*"
)

# Human-only Guard administration subcommands (GEMINI.md Rule 12)
_GUARD_ADMIN_BODY = (
    rf"{_CMD_WRAPPER_PREFIX}"
    r"(?:"
    rf"(?:(?:[^\s;|&`]*/)?python3?(?:\.\d+)?\s+{_PY_INTERP_OPTS}(?:-[A-Za-z0-9]*m\s+guard(?:\.cli)?\b|(?:[^\s;|&`]*/)?(?:guard\.py|guard/cli\.py))|(?:[^\s;|&`]*/)?(?:guard\.py|guard/cli\.py|agy-guard))\s+"
    r"(?:--(?:env|registry)(?:\s+\S+|=\S+)\s+)*"
    r"(?:"
    r"unlock\b|"
    r"rebaseline\b|"
    rf"test-boundary{_SUBPARSER_OPTS}\s+snapshot\b|"
    r"test-boundary\b[^\n;|&`]*\s--authorize(?:\b|=)|"
    r"provenance\b[^\n;|&`]*\s--authorize(?:\b|=)|"
    rf"snapshot{_SUBPARSER_OPTS}\s+(?:restore|prune)\b|"
    rf"porter{_SUBPARSER_OPTS}\s+(?:stage\b|import\b[^\n;|&`]*\s--force\b)|"
    rf"env{_SUBPARSER_OPTS}\s+remove\b|"
    rf"env{_SUBPARSER_OPTS}\s+add\b[^\n;|&`]*--policy(?:=|\s+)(?!enforced\b)\S+|"
    rf"env{_SUBPARSER_OPTS}\s+policy\b(?!(?![^\n;|&`]*\b(?:monitored|disabled|relaxed)\b)(?:[^\n;|&`]*\s+\S+\s+enforced\s*(?:$|[;&|()\n`])|[^\n;|&`]*--policy-val(?:=|\s+)enforced\b))|"
    rf"startup{_SUBPARSER_OPTS}\s+(?:enable|disable)\b|"
    rf"notify{_SUBPARSER_OPTS}\s+disable\b|"
    r"doctor\b[^\n;|&`]*\s--(?:fix|recover)\b|"
    r"init\b(?!(?![^\n;|&`]*--uninstall\b)[^\n;|&`]*(?:--dry-run\b|--help\b|-h\b))"
    r")|"
    rf"(?:(?:[^\s;|&`]*/)?python3?(?:\.\d+)?\s+{_PY_INTERP_OPTS}(?:-[A-Za-z0-9]*m\s+porter\b|(?:[^\s;|&`]*/)?porter\.py)|(?:[^\s;|&`]*/)?(?:porter\.py|(?:agy-)?porter)){_SUBPARSER_OPTS}\s+(?:stage\b|import\b[^\n;|&`]*\s--force\b)|"
    rf"(?:(?:[^\s;|&`]*/)?python3?(?:\.\d+)?\s+{_PY_INTERP_OPTS}(?:-[A-Za-z0-9]*m\s+scripts\.verify_invariants\b|(?:[^\s;|&`]*/)?verify_invariants\.py)|(?:[^\s;|&`]*/)?verify_invariants\.py)\b[^\n;|&`]*\s--authorize(?:\b|=)"
    r")"
)

_GUARD_ADMIN_RE = _LazyRegex(rf"(?:^|[;&|()\n`])\s*{_GUARD_ADMIN_BODY}", re.IGNORECASE)

_DELEGATION_GUARD_ADMIN_RE = _LazyRegex(rf"(?:^|[\s;|&()\n`'\"]){_GUARD_ADMIN_BODY}", re.IGNORECASE)

_GUARD_API_TOKEN_PAT = (
    r"(?:"
    r"\b(?:OSProtectionAdapter|PorterBridge|Installer)\b|"
    r"\bguard\.(?:os_adapter|porter_bridge|cli)\b|"
    r"\binstall\.main\s*\(|"
    r"\bauthorized_modifications\s*=|"
    r"\.(?:unlock|save_baseline|snapshot|restore_snapshot|prune_snapshots|stage_and_ingest|set_policy|register_environment|unregister_environment|remove_environment)\s*\("
    r")"
)

# Inline or piped Python (`python -c`, `python -uc`, heredoc, or `... | python3`) invoking human-only Guard or Installer APIs directly
_GUARD_INLINE_PY_RE = _LazyRegex(
    r"(?:"
    rf"\bpython3?(?:\.\d+)?\b[^\n;|&`]*(?:\s-[A-Za-z0-9]*c\b|<<-?\s*['\"]?[A-Za-z0-9_]+['\"]?)[\s\S]*?{_GUARD_API_TOKEN_PAT}|"
    rf"{_GUARD_API_TOKEN_PAT}[\s\S]*?\|\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?python3?(?:\.\d+)?\b"
    r")",
    re.IGNORECASE,
)

# Direct execution of install.py without --dry-run or --help (GEMINI.md Rule 12).
# Anchored to the start of a simple command (or interpreter invocation) so passing `install.py`
# as a path argument to read-only commands (`git diff ... install.py`, `grep ... install.py`) is allowed.
_INSTALL_PY_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}"
    r"(?:(?:[^\s;|&`]*/)?(?:python3?(?:\.\d+)?|py|(?:ba|z|da|k)?sh)\s+(?:-[^\s;|&`]+\s+)*(?:[^\s;|&`]*/)?|(?:[^\s;|&`]*/)?)"
    r"install\.py\b(?![^\n;|&`]*(?:--dry-run|--help|-h\b))",
    re.IGNORECASE,
)

_WORKFLOW_INSTALL_EXEC_BODY = (
    rf"{_CMD_WRAPPER_PREFIX}"
    r"(?:(?:[^\s;|&`]*/)?(?:python3?(?:\.\d+)?|py|(?:ba|z|da|k)?sh)\s+(?:-[^\s;|&`]+\s+)*(?:[^\s;|&`]*/)?|(?:\./|/[^\s;|&`]*/))"
    r"install\.py\b(?![^\n;|&`]*(?:--dry-run|--help|-h\b))"
)

_WORKFLOW_INSTALL_EXEC_RE = _LazyRegex(rf"(?:^|[;&|()\n`])\s*{_WORKFLOW_INSTALL_EXEC_BODY}", re.IGNORECASE)

_DELEGATION_INSTALL_EXEC_RE = _LazyRegex(rf"(?:^|[\s;|&()\n`'\"]){_WORKFLOW_INSTALL_EXEC_BODY}", re.IGNORECASE)

_QUOTED_SPAN_RE = _LazyRegex(r"'[^']*'|\"(?:\\.|[^\"\\])*\"")

_BACKTICK_SPAN_RE = _LazyRegex(r"`((?:\\.|[^`\\])+)`")

_SHELL_C_EXTRACT_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}"
    r"(?:(?:[^\s;|&`]*/)?(?:ba|z|da|k)?sh\b[^\n;|&`]*?\s-(?:[A-Za-z0-9]+\s+)*[A-Za-z0-9]*c[A-Za-z0-9]*|eval)\s+"
    r"(?:'([^']*)'|\"((?:\\.|[^\"\\])*)\")",
    re.IGNORECASE,
)

_SCRIPT_C_EXTRACT_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?script\b[^\n;|&`]*?"
    r"(?:\s-(?:[A-Za-z0-9]+\s+)*[A-Za-z0-9]*c\s*|\s--command(?:=|\s+))"
    r"(?:'([^']*)'|\"((?:\\.|[^\"\\])*)\"|([^\s;|&`'\"]+))",
    re.IGNORECASE,
)

_PIPE_TO_SH_EXTRACT_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*(?:echo|printf)\b(?:\s+-[neE]+)*\s+"
    r"(?:'([^']*)'|\"((?:\\.|[^\"\\])*)\")\s*\|\s*"
    rf"{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?(?:ba|z|da|k)?sh\b",
    re.IGNORECASE,
)

_FIND_EXEC_EXTRACT_RE = _LazyRegex(
    r"\bfind\b[^\n;|&]*?\s-(?:exec|execdir|ok|okdir)\s+([^\n;|]+?)(?:\s+(?:\\;|;|\+))?(?=$|[;&|\n])",
    re.IGNORECASE,
)

# Owners whose `-c`-style flag never takes a shell command line (counters, compilers, SQL clients, archivers,
# network tools) or whose code payload is inspected separately (`_GUARD_INLINE_PY_RE`, `_EXEC_CALL_ARGV_RE`).
_NON_SHELL_C_FLAG_OWNERS = frozenset({
    "grep", "egrep", "fgrep", "rg", "ag", "ack", "git", "jq", "yq", "wc", "tar", "gzip", "gunzip", "bzip2",
    "xz", "zstd", "gcc", "g++", "cc", "c++", "clang", "clang++", "ld", "as", "psql", "mysql", "sqlite3",
    "mongo", "mongosh", "redis-cli", "curl", "wget", "ssh", "scp", "sftp", "rsync", "sort", "uniq", "head",
    "tail", "cut", "awk", "sed", "diff", "cmp", "python", "python3", "py", "node", "nodejs", "deno", "bun",
    "perl", "ruby", "php", "lua", "java", "docker", "podman", "kubectl", "make", "cmake", "npm", "pnpm",
    "yarn", "pip", "pip3", "cargo", "go",
})

# Launch wrappers skipped while locating the real owner of a `-c` flag (`env -u X /tmp/s -qc '...'`).
_C_FLAG_LAUNCH_WRAPPERS = frozenset({
    "env", "sudo", "doas", "nohup", "setsid", "nice", "ionice", "timeout", "stdbuf", "time", "command",
    "exec", "builtin", "unbuffer", "chrt", "taskset",
})

_SHELL_PUNCT_CHARS = ";&|()"

# Terminal multiplexers spawn commands (`tmux new-window '...'`); every argument after the multiplexer
# is treated as a candidate command line. Anchors are matched outside quoted spans only.
_TERMINAL_MUX_SEGMENT_RE = _LazyRegex(
    r"(?:^|[;&|()\n`])\s*(?:[^\s;|&`]*/)?(?:tmux|screen|byobu|tmate|dtach|abduco|zellij)\b([^\n;|&`]*)",
    re.IGNORECASE,
)

# Keystroke or buffer injection into a multiplexer runs arbitrary commands outside `PreToolUse` inspection.
_TERMINAL_INJECTION_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?(?:"
    r"(?:tmux|byobu|tmate)\b[^\n;|&`]*\s(?:send-keys|send|paste-buffer|pasteb|load-buffer|loadb|set-buffer|setb)\b|"
    r"screen\b[^\n;|&`]*\s-X\s+(?:stuff|paste|readbuf|register)\b|"
    r"zellij\b[^\n;|&`]*\s(?:write-chars|write)\b"
    r")",
    re.IGNORECASE,
)

# Exec-like calls whose argv is a string list/tuple (`pty.spawn(['agy-guard', 'unlock'])`,
# `subprocess.run(("python3", "install.py"))`) or a single command string (`os.system('...')`).
_EXEC_CALL_ARGV_RE = _LazyRegex(
    r"\b(?:system|popen|run|call|check_call|check_output|getoutput|getstatusoutput|Popen|spawn|spawnSync|"
    r"execSync|execFile|execFileSync|exec[lv]p?e?|spawn[lv]p?e?)\s*\(\s*"
    r"(?:[\[(]\s*((?:'[^'\n]*'|\"[^\"\n]*\")(?:\s*,\s*(?:'[^'\n]*'|\"[^\"\n]*\"))*)\s*,?\s*[\])]"
    r"|('[^'\n]*'|\"[^\"\n]*\"))"
)

_STR_ARGV_TOKEN_RE = _LazyRegex(r"'([^'\n]*)'|\"([^\"\n]*)\"")

def _blank_quoted_spans(cmd: str) -> str:
    """Returns `cmd` with every quoted span's interior replaced by spaces (same length, quotes kept)."""
    return _QUOTED_SPAN_RE.sub(lambda m: m.group(0)[0] + " " * (len(m.group(0)) - 2) + m.group(0)[-1], cmd)

def _extract_c_flag_payloads(cmd: str) -> List[str]:
    """Returns payloads of `-c`/`--command` flags owned by shells, renamed PTY wrappers, or unknown binaries."""
    import shlex

    text = re.sub(r"\$'", "'", _expand_simple_shell_vars(cmd))
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=_SHELL_PUNCT_CHARS)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return []
    payloads: List[str] = []
    owner: Optional[str] = None
    in_wrapper: Optional[str] = None
    skip_next = False
    for idx, tok in enumerate(tokens):
        if tok and set(tok) <= set(_SHELL_PUNCT_CHARS):
            owner, in_wrapper, skip_next = None, None, False
            continue
        if owner is None:
            if skip_next:
                skip_next = False
                continue
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tok, re.DOTALL):
                continue
            if in_wrapper is not None:
                if tok.startswith("-"):
                    if in_wrapper == "env" and tok in ("-u", "--unset", "-C", "--chdir", "-S", "--split-string"):
                        skip_next = True
                    continue
                if re.fullmatch(r"\d+(?:\.\d+)?[smhd]?", tok):
                    continue
            base = os.path.basename(tok).lower()
            if base in _C_FLAG_LAUNCH_WRAPPERS:
                in_wrapper = base
                continue
            owner = base
            continue
        if owner in _NON_SHELL_C_FLAG_OWNERS:
            continue
        nxt = tokens[idx + 1] if idx + 1 < len(tokens) else ""
        if (re.fullmatch(r"-[A-Za-z0-9]*c[A-Za-z0-9]*", tok) or tok == "--command") and nxt and not (
            set(nxt) <= set(_SHELL_PUNCT_CHARS)
        ):
            payloads.append(nxt)
        elif tok.startswith("--command="):
            payloads.append(tok.split("=", 1)[1])
    return payloads

def _extract_indirect_exec_payloads(cmd: str) -> List[str]:
    """Returns command lines driven indirectly via `-c` flag payloads, terminal multiplexers, or exec-call argv."""
    found: List[str] = []

    def _add(text: str) -> None:
        stripped = text.strip()
        if stripped and stripped != cmd.strip() and stripped not in found:
            found.append(stripped)

    for payload in _extract_c_flag_payloads(cmd):
        _add(payload)
    blanked = _blank_quoted_spans(cmd)
    for m in _TERMINAL_MUX_SEGMENT_RE.finditer(blanked):
        rest = cmd[m.start(1) : m.end(1)]
        tokens = [
            tm.group(1)
            if tm.group(1) is not None
            else (_unescape_dq_payload(tm.group(2)) if tm.group(2) is not None else (tm.group(3) or ""))
            for tm in _QUOTED_ARG_TOKEN_RE.finditer(rest)
        ][:64]
        # `screen -X stuff` / `tmux send-keys -l` encode Enter as a literal `\n` or `\r` escape.
        tokens = [re.sub(r"\\[nr]", " ", tok) for tok in tokens]
        # Every token suffix is a candidate command line (`new-window agy-guard unlock` -> `agy-guard unlock`).
        for idx in range(len(tokens)):
            _add(" ".join(tokens[idx:]))
    for m in _EXEC_CALL_ARGV_RE.finditer(cmd):
        argv_src = m.group(1) if m.group(1) is not None else (m.group(2) or "")
        parts = [
            tm.group(1) if tm.group(1) is not None else (tm.group(2) or "")
            for tm in _STR_ARGV_TOKEN_RE.finditer(argv_src)
        ]
        _add(" ".join(parts))
    return found

_QUOTED_ARG_TOKEN_RE = _LazyRegex(r"'([^']*)'|\"((?:\\.|[^\"\\])*)\"|([^\s'\"]+)")

def _join_shell_line_continuations(cmd: str) -> str:
    """Joins POSIX backslash-newline (`\\` + LF/CRLF) continuations outside single-quoted strings."""
    if "\\" not in cmd or ("\n" not in cmd and "\r" not in cmd):
        return cmd
    out: List[str] = []
    in_sq = False
    i = 0
    n = len(cmd)
    while i < n:
        ch = cmd[i]
        if in_sq:
            out.append(ch)
            if ch == "'":
                in_sq = False
            i += 1
            continue
        if ch == "'":
            in_sq = True
            out.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            if cmd[i + 1] == "\n":
                i += 2
                continue
            if cmd[i + 1] == "\r" and i + 2 < n and cmd[i + 2] == "\n":
                i += 3
                continue
            out.append(ch)
            out.append(cmd[i + 1])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)

def _extract_dollar_paren_payloads(cmd: str) -> List[str]:
    """Extracts command/process substitutions (`$(...)`, `<(...)`, `>(...)`) outside single quotes."""
    results: List[str] = []
    in_sq = False
    in_dq = False
    i = 0
    n = len(cmd)
    while i < n:
        ch = cmd[i]
        if in_sq:
            if ch == "'":
                in_sq = False
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch == "'" and not in_dq:
            in_sq = True
            i += 1
            continue
        if ch == '"':
            in_dq = not in_dq
            i += 1
            continue
        is_cmd_sub = ch == "$" and i + 1 < n and cmd[i + 1] == "("
        is_proc_sub = not in_dq and ch in "<>" and i + 1 < n and cmd[i + 1] == "("
        if is_cmd_sub or is_proc_sub:
            if is_cmd_sub and i + 2 < n and cmd[i + 2] == "(":
                i += 3
                continue
            start = i + 2
            depth = 1
            j = start
            sub_sq = False
            sub_dq = False
            while j < n and depth > 0:
                cj = cmd[j]
                if sub_sq:
                    if cj == "'":
                        sub_sq = False
                    j += 1
                    continue
                if cj == "\\" and j + 1 < n:
                    j += 2
                    continue
                if cj == "'" and not sub_dq:
                    sub_sq = True
                    j += 1
                    continue
                if cj == '"':
                    sub_dq = not sub_dq
                    j += 1
                    continue
                if cj == "(":
                    depth += 1
                elif cj == ")":
                    depth -= 1
                    if depth == 0:
                        inner = cmd[start:j].strip()
                        if inner and inner not in results:
                            results.append(inner)
                        break
                j += 1
            i = start
            continue
        i += 1
    return results

def _strip_unquoted_shell_comments(cmd: str) -> str:
    """Strips unquoted POSIX shell `# ...` comments (at start-of-line or after whitespace/operators)."""
    out: List[str] = []
    in_sq = False
    in_dq = False
    i = 0
    n = len(cmd)
    while i < n:
        ch = cmd[i]
        if in_sq:
            out.append(ch)
            if ch == "'":
                in_sq = False
            i += 1
            continue
        if in_dq:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(cmd[i + 1])
                i += 2
                continue
            if ch == '"':
                in_dq = False
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(ch)
            out.append(cmd[i + 1])
            i += 2
            continue
        if ch == "'":
            in_sq = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_dq = True
            out.append(ch)
            i += 1
            continue
        if ch == "#" and (i == 0 or cmd[i - 1] in " \t\r\n;&|(`"):
            nl = cmd.find("\n", i)
            if nl == -1:
                break
            i = nl
            continue
        out.append(ch)
        i += 1
    return "".join(out)

def _unquote_single_tokens(cmd: str) -> str:
    """Unquotes whitespace-free quoted tokens (`"agy-guard"`, `agy-""guard`, `'--no-verify'`) while preserving multi-word quoted prose."""
    win_drive_re = re.compile(
        r"(?:^|(?<=[\s;|&()<>`'\"=,\[]))"
        r"(?:(?:--?[A-Za-z0-9_-]+|[A-Za-z_][A-Za-z0-9_]*)=|[<>]+)*"
        r"[A-Za-z]:\\[^\s;|&()<>'\"`{}$,]*"
    )

    def _norm_chunk(chunk: str) -> str:
        if "\\" not in chunk:
            return chunk
        with_win_drives = win_drive_re.sub(
            lambda m: m.group(0).replace("\\\\", "/").replace("\\", "/"), chunk
        )
        return re.sub(r"\\([A-Za-z0-9_./~-])", r"\1", with_win_drives)

    raw_pieces: List[Tuple[bool, str]] = []
    last = 0
    for m in _QUOTED_SPAN_RE.finditer(cmd):
        outside = cmd[last : m.start()]
        if outside:
            raw_pieces.append((False, outside))
        span = m.group(0)
        inner = span[1:-1]
        if inner == "":
            adjacent = (m.start() > 0 and not cmd[m.start() - 1].isspace()) or (
                m.end() < len(cmd) and not cmd[m.end()].isspace()
            )
            if not adjacent:
                raw_pieces.append((True, span))
        elif not re.search(r"[\s\\;|&()<>`]", inner):
            raw_pieces.append((True, inner))
        elif re.match(r"^[A-Za-z]:\\", inner) and not re.search(r"[\s;|&()<>`\"'{}$,]", inner):
            raw_pieces.append((True, inner.replace("\\\\", "/").replace("\\", "/")))
        else:
            raw_pieces.append((True, span))
        last = m.end()
    tail = cmd[last:]
    if tail:
        raw_pieces.append((False, tail))

    parts: List[str] = []
    buf: List[str] = []
    for is_quoted, piece in raw_pieces:
        if is_quoted:
            if buf:
                parts.append(_norm_chunk("".join(buf)))
                buf.clear()
            parts.append(piece)
        else:
            buf.append(piece)
    if buf:
        parts.append(_norm_chunk("".join(buf)))
    return "".join(parts)

def _unescape_dq_payload(raw_dq: str) -> str:
    return (
        raw_dq.replace('\\"', '"')
        .replace("\\$", "$")
        .replace("\\`", "`")
        .replace("\\\\", "\\")
    )

def _extract_shell_c_payloads(cmd: str, max_depth: int = 5) -> List[str]:
    """Recursively extracts inner shell scripts from `sh -c`, `eval`, `script -c`, `$(...)`, `<(...)`, backticks, `find -exec`, and `| sh`."""
    max_candidates = 256
    extracted: List[str] = []
    seen: set[str] = set()

    def _record(candidate: str, bucket: List[str]) -> None:
        if candidate and candidate not in seen and len(extracted) < max_candidates:
            seen.add(candidate)
            extracted.append(candidate)
            bucket.append(candidate)

    frontier = [_join_shell_line_continuations(cmd)]
    for _ in range(max_depth):
        if len(extracted) >= max_candidates:
            break
        next_frontier: List[str] = []
        for item in frontier:
            joined_item = _join_shell_line_continuations(item)
            if joined_item != item:
                _record(joined_item, next_frontier)
            for m in _SHELL_C_EXTRACT_RE.finditer(joined_item):
                inner = m.group(1) if m.group(1) is not None else _unescape_dq_payload(m.group(2) or "")
                _record(inner.strip(), next_frontier)
            for sm in _SCRIPT_C_EXTRACT_RE.finditer(joined_item):
                inner_s = (
                    sm.group(1)
                    if sm.group(1) is not None
                    else (_unescape_dq_payload(sm.group(2)) if sm.group(2) is not None else (sm.group(3) or ""))
                )
                _record(inner_s.strip(), next_frontier)
            for pm in _PIPE_TO_SH_EXTRACT_RE.finditer(joined_item):
                inner_p = pm.group(1) if pm.group(1) is not None else _unescape_dq_payload(pm.group(2) or "")
                _record(inner_p.strip(), next_frontier)
            for fm in _FIND_EXEC_EXTRACT_RE.finditer(joined_item):
                _record(fm.group(1).strip(), next_frontier)
            for dp_inner in _extract_dollar_paren_payloads(joined_item):
                _record(dp_inner, next_frontier)
            for ind_inner in _extract_indirect_exec_payloads(joined_item):
                _record(ind_inner, next_frontier)
            no_sq = re.sub(r"'[^']*'", "", joined_item)
            for bm in _BACKTICK_SPAN_RE.finditer(no_sq):
                _record(bm.group(1).strip(), next_frontier)
            if len(extracted) >= max_candidates:
                break
        if not next_frontier:
            break
        frontier = next_frontier
    return extracted

def _mask_quoted_operators(cmd: str) -> str:
    """Replaces shell operators and flags inside multi-word quoted string literals so quoted prose never triggers false positives."""
    uncommented = _strip_unquoted_shell_comments(_join_shell_line_continuations(cmd))
    unquoted = _unquote_single_tokens(uncommented)
    return _QUOTED_SPAN_RE.sub(lambda m: re.sub(r"[;&|()\-`]", "_", m.group(0)), unquoted)

_GIT_OPT_ARG = r"(?:(?:'[^']*'|\"(?:\\.|[^\"\\])*\"|[^\s;|&()'\"])+)"

_GIT_GLOBAL_OPTS = (
    rf"(?:\s+(?:-[Cc](?:\s+{_GIT_OPT_ARG}|{_GIT_OPT_ARG})"
    rf"|--(?:git-dir|work-tree|namespace|config-env|super-prefix|list-cmds)(?:={_GIT_OPT_ARG}|\s+{_GIT_OPT_ARG})"
    rf"|--exec-path(?:={_GIT_OPT_ARG})?"
    r"|--(?:no-pager|bare|literal-pathspecs|glob-pathspecs|noglob-pathspecs|icase-pathspecs|"
    r"no-optional-locks|no-advice|no-replace-objects|no-lazy-fetch|paginate)"
    r"|-[pP]))*"
)

# Git hook bypass flags (--no-verify, git commit -n, core.hooksPath, --config-env=core.hooksPath, HUSKY=0, LEFTHOOK=0)
_GIT_HOOK_BYPASS_RE = _LazyRegex(
    r"(?:"
    r"\bgit\b[^\n;|&]*\s--no-verify\b|"
    rf"\bgit{_GIT_GLOBAL_OPTS}\s+commit\b[^\n;|&]*\s-(?!-)[a-zA-Z]*n[a-zA-Z]*\b|"
    r"\bgit\b[^\n;|&]*(?:\s-c\s*|--config-env(?:=|\s+))['\"]?(?i:core\.hookspath)\s*=|"
    r"\b(?:HUSKY|LEFTHOOK)\s*=\s*(?:0|(?i:false))\b"
    r")"
)

_REMOTE_INTERPRETER_PAT = (
    r"(?:(?:[^\s;|&]*/)?(?:(?:ba|z|da|k|tc|c|fi)?sh|python3?(?:\.\d+)?|py|node|nodejs|deno|bun|perl|ruby|php))"
)

# Destructive shell/git operations that require explicit human confirmation (force_ask)
_DESTRUCTIVE_CMD_PATTERNS: Tuple[Tuple[Any, str], ...] = (
    (
        _LazyRegex(rf"\bgit{_GIT_GLOBAL_OPTS}\s+reset\b[^\n;|&]*--hard\b"),
        "Destructive git operation (`git reset --hard`) discards uncommitted work (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            rf"\bgit{_GIT_GLOBAL_OPTS}\s+(?:checkout\s+(?:--\s+)?\.|restore\s+(?:(?:--worktree|--staged|-[sSW]+)\s+)*(?:--\s+)?\.)(?:\s|$|[;&|])"
        ),
        "Destructive git operation discards workspace modifications across the tree (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(rf"\bgit{_GIT_GLOBAL_OPTS}\s+clean\b[^\n;|&]*(?:--force\b|\s-(?!-)[a-zA-Z]*f)"),
        "Destructive git operation (`git clean -f`) permanently deletes untracked files (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            rf"\bgit{_GIT_GLOBAL_OPTS}\s+push\b[^\n;|&]*(?:\s--force(?![-a-zA-Z])|\s-(?!-)[a-zA-Z]*f[a-zA-Z]*\b|\s['\"]?\+[A-Za-z0-9_./:-]+)"
        ),
        "Force-pushing (`git push --force` / `+refspec`) rewrites remote history (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            rf"\bgit{_GIT_GLOBAL_OPTS}\s+branch\b[^\n;|&]*(?:\s-(?!-)[a-zA-Z]*D[a-zA-Z]*\b|"
            r"(?=[^\n;|&]*--delete\b)(?=[^\n;|&]*(?:--force\b|\s-(?!-)[a-zA-Z]*f)))"
        ),
        "Force-deleting a git branch (`git branch -D` / `--delete --force`) may discard unmerged commits (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(rf"\bgit{_GIT_GLOBAL_OPTS}\s+stash\s+(?:drop|clear)\b"),
        "Dropping or clearing git stashes (`git stash drop` / `git stash clear`) permanently discards stashed work (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            r"\brm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r|--recursive)\b\s+"
            r"(?:/(?:\s|$|[;&|])|~(?:[/\\]|\s|$|[;&|])|\$HOME\b|\.\.(?:[/\\]|\s|$|[;&|])|\*(?:\s|$|[;&|]))"
        ),
        "High-risk recursive deletion (`rm -rf` on root, home, parent, or wildcard) requires confirmation (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            r"\bfind\b[^\n;|&]*(?:\s-delete\b|\s-(?:exec|execdir|ok)\s+(?:[^\s;|&]*/)?rm\b)"
        ),
        "Bulk file deletion via `find -delete` or `find -exec rm` requires explicit human confirmation (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            r"(?:\bdropdb\b|"
            r"\b(?:DROP\s+(?:DATABASE|TABLE|SCHEMA)|TRUNCATE\s+TABLE)\b|"
            r"\bDELETE\s+FROM\s+[A-Za-z0-9_.`\"']+\s*(?:;|$|['\"]))",
            re.IGNORECASE,
        ),
        "Destructive database operation (`dropdb`, `DROP TABLE/DATABASE/SCHEMA`, `TRUNCATE TABLE`, or unconditional `DELETE FROM`) requires explicit human confirmation (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            r"\b(?:docker|podman)\s+(?:system|volume|builder|image|container)\s+prune\b[^\n;|&]*(?:\s--all\b|\s--volumes\b|\s-(?!-)[a-zA-Z]*a[a-zA-Z]*\b)"
        ),
        "Pruning all container/volume/builder caches (`docker/podman ... prune -a/--all/--volumes`) requires explicit human confirmation (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            r"\bchmod\b[^\n;|&]*(?:\s--recursive\b|\s-(?!-)[a-zA-Z]*R[a-zA-Z]*\b)[^\n;|&]*\b(?:0?777|a\+rwx)\b"
        ),
        "Recursive world-writable permission change (`chmod -R 777`) is a security risk and requires explicit human confirmation (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            rf"(?:"
            rf"\b(?:curl|wget)\b[^\n|]*\|\s*{_CMD_WRAPPER_PREFIX}{_REMOTE_INTERPRETER_PAT}\b|"
            rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}(?:{_REMOTE_INTERPRETER_PAT}|source|\.)\b[^\n;|&]*(?:<\(|\$\()\s*(?:[^\s;|&]*/)?(?:curl|wget)\b"
            rf")",
            re.IGNORECASE,
        ),
        "Executing remote scripts directly via a shell or language interpreter is forbidden by supply-chain policy (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(r"\b(?:npx|bunx|pnpm\s+dlx|uvx)\b[^\n;|&]*@latest\b"),
        "Executing unpinned `@latest` packages (`npx/bunx/uvx @latest`) violates supply-chain pinning rules (GEMINI.md Rule 12).",
    ),
)

_RM_OR_MV_SEGMENT_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?(?P<verb>rm|mv)\b(?P<rest>[^\n;|&`]*)"
)

def _detect_out_of_workspace_rm_or_mv(
    cmd: str, workspaces: Sequence[Path], effective_cwd: Optional[Path]
) -> Optional[str]:
    """Detects recursive `rm` (`-r`/`-rf`/`--recursive`) or `mv` targeting paths outside active workspaces and `/tmp`."""
    home_str = str(Path.home())
    base_dir = effective_cwd if effective_cwd is not None else (workspaces[0] if workspaces else _repo_root())
    allowed_roots: List[Path] = [
        Path("/tmp"),
        Path("/var/tmp"),
        Path(os.path.abspath("/tmp")),
        Path(os.path.abspath("/var/tmp")),
    ]
    env_tmp = os.environ.get("TMPDIR", "").strip()
    if env_tmp:
        allowed_roots.append(Path(os.path.abspath(env_tmp)))
    if workspaces:
        for ws in workspaces:
            allowed_roots.append(Path(os.path.abspath(ws)))
    if effective_cwd is not None:
        allowed_roots.append(Path(os.path.abspath(effective_cwd)))
    if not workspaces and effective_cwd is None:
        allowed_roots.append(Path(os.path.abspath(_repo_root())))

    for m in _RM_OR_MV_SEGMENT_RE.finditer(cmd):
        verb = m.group("verb")
        rest = m.group("rest").strip()
        if not rest:
            continue
        raw_tokens = [tok.strip("'\"") for tok in re.findall(r"'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+", rest)]
        is_recursive_rm = False
        pos_args: List[str] = []
        after_ddash = False
        expect_target_dir = False
        for tok in raw_tokens:
            if not tok or re.match(r"^\d*>{1,2}", tok) or tok in ("2>&1", ">/dev/null", "2>/dev/null"):
                continue
            if expect_target_dir:
                pos_args.append(tok.strip("'\""))
                expect_target_dir = False
                continue
            if not after_ddash and tok == "--":
                after_ddash = True
                continue
            if not after_ddash and tok.startswith("-") and len(tok) > 1:
                if tok == "--recursive" or (
                    tok.startswith("--recursive=")
                    and tok.split("=", 1)[1].strip("'\"").lower() not in ("never", "no", "false", "0")
                ):
                    is_recursive_rm = True
                elif not tok.startswith("--") and ("r" in tok[1:] or "R" in tok[1:]):
                    is_recursive_rm = True
                if tok in ("-t", "--target-directory"):
                    expect_target_dir = True
                elif tok.startswith("--target-directory="):
                    td_val = tok.split("=", 1)[1].strip("'\"")
                    if td_val:
                        pos_args.append(td_val)
                elif tok.startswith("-t") and len(tok) > 2:
                    pos_args.append(tok[2:].strip("'\""))
                continue
            pos_args.append(tok)

        if verb == "rm" and not is_recursive_rm:
            continue
        if not pos_args:
            continue

        for arg in pos_args:
            norm_arg = arg.replace("${HOME}", home_str).replace("$HOME", home_str)
            if norm_arg == "~" or norm_arg.startswith(("~/", "~\\")):
                norm_arg = home_str + norm_arg[1:]
            if norm_arg.startswith("$") or (norm_arg.startswith("%") and norm_arg.endswith("%")):
                continue
            if norm_arg in ("/dev/null", "NUL", "nul"):
                continue
            norm_slashes = norm_arg.replace("\\", "/")
            is_win_drive = bool(re.match(r"^[A-Za-z]:/", norm_slashes))
            is_abs_like = norm_slashes.startswith("/") or is_win_drive or Path(norm_arg).is_absolute()
            if not is_abs_like and ".." not in norm_slashes.split("/"):
                continue
            if is_win_drive and os.name != "nt":
                within_allowed = False
            else:
                cand_raw = Path(norm_slashes) if is_abs_like else (base_dir / norm_slashes)
                cand_abs = Path(os.path.abspath(cand_raw))
                within_allowed = any(is_within(cand_abs, root) for root in allowed_roots)
            if not within_allowed:
                if verb == "rm":
                    return (
                        f"High-risk recursive deletion (`rm -rf {arg}`) targeting path outside the active "
                        "workspace requires explicit human confirmation (GEMINI.md Rule 12)."
                    )
                return (
                    f"Moving files (`mv` targeting `{arg}`) outside the active workspace requires explicit "
                    "human confirmation (GEMINI.md Rule 12)."
                )
    return None

_EXACT_NPM_VER_RE = _LazyRegex(r"^(?:\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?|[0-9a-fA-F]{40})$")

_EXACT_PY_PIN_RE = _LazyRegex(r"(?:==\s*\d+\.\d+(?:\.\d+)?[0-9A-Za-z._+-]*|@\s*git\+[^\s@]+@[0-9a-fA-F]{40})$")

_NPX_SEGMENT_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}"
    r"(?:[^\s;|&`]*/)?(?P<runner>npx|bunx|pnpm\s+dlx|uvx|pipx\s+run)\b(?P<rest>[^\n;|&`]*)",
    re.IGNORECASE,
)

def _is_pinned_npm_spec(spec: str) -> bool:
    s = spec.strip().strip("'\"")
    if not s or s.startswith(("./", "../", "/", "~/")) or s.startswith("file:"):
        return True
    if s.startswith("@"):
        slash_idx = s.find("/")
        if slash_idx == -1:
            return False
        at_idx = s.find("@", slash_idx + 1)
        if at_idx == -1:
            return False
        ver = s[at_idx + 1 :]
    else:
        if "@" not in s:
            return False
        ver = s.split("@", 1)[1]
    return bool(_EXACT_NPM_VER_RE.match(ver))

def _is_pinned_py_spec(spec: str) -> bool:
    s = spec.strip().strip("'\"")
    if not s or s.startswith(("./", "../", "/", "~/")):
        return True
    if "," in s:
        return False
    return bool(_EXACT_PY_PIN_RE.search(s))

def _detect_unpinned_package_exec(cmd: str) -> Optional[str]:
    """Detects unpinned remote package execution (`npx -y pkg`, `bunx pkg`, `pnpm dlx pkg`, `uvx pkg`)."""
    for m in _NPX_SEGMENT_RE.finditer(cmd):
        runner = re.sub(r"\s+", " ", m.group("runner").strip().lower())
        rest = m.group("rest").strip()
        if not rest:
            continue
        raw_tokens = [tok.strip("'\"") for tok in re.findall(r"'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+", rest)]
        if runner in ("npx", "bunx", "pnpm dlx"):
            if "--no-install" in raw_tokens or any(t in ("-h", "--help", "-v", "--version") for t in raw_tokens):
                continue
            pkg_specs: List[str] = []
            first_pos: Optional[str] = None
            idx = 0
            while idx < len(raw_tokens):
                tok = raw_tokens[idx]
                if tok == "--":
                    if idx + 1 < len(raw_tokens) and first_pos is None:
                        first_pos = raw_tokens[idx + 1]
                    break
                if tok in ("-p", "--package"):
                    if idx + 1 < len(raw_tokens):
                        pkg_specs.append(raw_tokens[idx + 1])
                    idx += 2
                    continue
                if tok.startswith("--package="):
                    pkg_specs.append(tok.split("=", 1)[1])
                    idx += 1
                    continue
                if tok in ("-c", "--call", "--shell", "--cache", "--userconfig"):
                    idx += 2
                    continue
                if tok.startswith("-"):
                    idx += 1
                    continue
                first_pos = tok
                break
            targets = pkg_specs if pkg_specs else ([first_pos] if first_pos else [])
            if any(not _is_pinned_npm_spec(t) for t in targets):
                return (
                    f"Executing unpinned package via `{runner}` without an exact `pkg@X.Y.Z` version "
                    "(or `--no-install`) violates supply-chain pinning rules (GEMINI.md Rule 12)."
                )
        else:
            if any(t in ("-h", "--help", "-V", "--version", "--offline", "--no-index") for t in raw_tokens):
                continue
            py_specs: List[str] = []
            first_py: Optional[str] = None
            idx = 0
            while idx < len(raw_tokens):
                tok = raw_tokens[idx]
                if tok == "--":
                    if idx + 1 < len(raw_tokens) and first_py is None:
                        first_py = raw_tokens[idx + 1]
                    break
                if tok in ("--from", "--with"):
                    if idx + 1 < len(raw_tokens):
                        py_specs.append(raw_tokens[idx + 1])
                    idx += 2
                    continue
                if tok.startswith(("--from=", "--with=")):
                    py_specs.append(tok.split("=", 1)[1])
                    idx += 1
                    continue
                if tok in ("-p", "--python", "--index-url", "--extra-index-url"):
                    idx += 2
                    continue
                if tok.startswith("-"):
                    idx += 1
                    continue
                first_py = tok
                break
            targets = py_specs if py_specs else ([first_py] if first_py else [])
            if any(not _is_pinned_py_spec(t) for t in targets):
                return (
                    f"Executing unpinned package via `{runner}` without an exact `pkg==X.Y.Z` version "
                    "violates supply-chain pinning rules (GEMINI.md Rule 12)."
                )
    return None

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

    expanded = Path(os.path.expanduser(target_path_str.strip()))
    candidate = (workspace / expanded) if not expanded.is_absolute() else expanded
    try:
        ws_resolved = workspace.resolve()
        cand_resolved = candidate.resolve()
    except (OSError, RuntimeError, ValueError):
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
            ledger = _read_ledger_safe(flight_file)
            prev = ledger.get(ws_key) if isinstance(ledger.get(ws_key), dict) else {}
            preserve_lineage = (
                prev.get("conversation_id") == conv_id
                or str(prev.get("status") or "") in _UNRECOVERED_FLIGHT_STATES
            )

            if preserve_lineage:
                base_head = str(prev.get("base_head") or "")
                pre_edit_stash = str(prev.get("pre_edit_stash") or "")
                touched: List[str] = [
                    str(x) for x in (prev.get("touched_files") or []) if isinstance(x, str) and x
                ]
            else:
                base_head, pre_edit_stash = _capture_git_baseline(ws_resolved)
                touched = []

            if rel_target not in touched:
                touched.append(rel_target)
            touched = touched[-30:]
            seq = _safe_int(prev.get("seq"), default=0) + 1

            if ws_key in ledger:
                del ledger[ws_key]
            ledger[ws_key] = {
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
    expanded = Path(os.path.expanduser(target_path_str.strip()))
    if expanded.is_absolute():
        for ws in workspaces:
            if is_within(expanded, ws):
                return ws
            try:
                if is_within(expanded.resolve(), ws.resolve()):
                    return ws
            except (OSError, RuntimeError, ValueError):
                continue
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
    return out

def _state_root_candidates() -> List[Path]:
    home = Path.home()
    out: List[Path] = []
    for cand in (
        state_dir(),
        Path(os.path.abspath(home / ".local" / "state" / "antigravity-harness")),
        Path(os.path.abspath(home / ".local" / "state" / "antigravity-guard")),
    ):
        if cand not in out:
            out.append(cand)
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
        home / ".local" / "bin" / "agy-guard",
        home / ".local" / "bin" / "agy-porter",
    ]
    porter_bin = home / ".local" / "bin" / "porter"
    try:
        if not porter_bin.exists():
            candidates.append(porter_bin)
        elif porter_bin.is_file():
            porter_head = porter_bin.read_text(encoding="utf-8", errors="ignore")[:512].lower()
            if "antigravity-harness launcher" in porter_head or "antigravity harness cli launcher" in porter_head:
                candidates.append(porter_bin)
    except OSError:
        candidates.append(porter_bin)
    if os.name == "nt":
        local_app = Path(os.environ.get("LOCALAPPDATA") or (home / "AppData" / "Local"))
        candidates.append(local_app / "Programs" / "antigravity-guard")
    else:
        candidates.extend([
            Path("/usr/bin/agy-guard"),
            Path("/usr/bin/agy-porter"),
            Path("/usr/lib/antigravity-guard"),
            Path("/usr/share/antigravity-harness"),
        ])
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
    rel_part_sets: List[Tuple[str, ...]] = []
    try:
        rel_part_sets.append(candidate.relative_to(plugin_root).parts)
    except ValueError:
        pass
    try:
        rel_part_sets.append(candidate.resolve().relative_to(plugin_root.resolve()).parts)
    except (OSError, RuntimeError, ValueError):
        pass
    for rel_parts in rel_part_sets:
        if any(part.lower() in _PLUGIN_GOVERNANCE_SEGMENTS for part in rel_parts):
            return True
        if rel_parts and rel_parts[-1].lower().endswith(_PLUGIN_EXEC_SUFFIXES):
            return True
    return False

def _is_runtime_config_subdir(candidate: Path, root: Path) -> bool:
    if root in _state_root_candidates():
        staging_path = root / "staging"
        within_staging = is_within(candidate, staging_path)
        if not within_staging:
            return False
        try:
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
    """Parses a local `file://` URI (POSIX or Windows drive) into a filesystem path, or `None` if remote/malformed."""
    s = raw_uri.strip()
    if not s.lower().startswith("file://"):
        return None
    if "\x00" in s or "%00" in s.lower():
        return None
    parsed = urllib.parse.urlparse(s.replace("\\", "/"))
    netloc = urllib.parse.unquote(parsed.netloc or "").replace("\\", "/")
    uri_path = urllib.parse.unquote(parsed.path or "").replace("\\", "/")
    if "\x00" in netloc or "\x00" in uri_path:
        return None
    if re.match(r"^[A-Za-z]:(?:/|$)", netloc):
        if "/" in netloc:
            drive_part, rest_part = netloc.split("/", 1)
            uri_path = f"{drive_part}/{rest_part}{uri_path}"
        else:
            uri_path = f"{netloc}{uri_path}"
    elif netloc and netloc.lower() != "localhost":
        return None
    if re.match(r"^/[A-Za-z]:(?:/|$)", uri_path):
        uri_path = uri_path[1:]
    cleaned = uri_path.strip()
    return cleaned or None


def _targets_governance_dir(target_path_str: str, base_dir: Optional[Path] = None) -> bool:
    if not target_path_str:
        return False
    if "\x00" in target_path_str:
        return False
    cleaned = target_path_str.strip()
    if not cleaned:
        return False
    if _URI_SCHEME_PREFIX_RE.match(cleaned):
        parsed_local = _parse_file_uri(cleaned)
        if parsed_local is None:
            return False
        cleaned = parsed_local
    if os.name != "nt" and re.match(r"^[A-Za-z]:\\", cleaned):
        cleaned = cleaned.replace("\\\\", "/").replace("\\", "/")
    expanded = Path(os.path.expanduser(cleaned))
    if not expanded.is_absolute() and base_dir is not None:
        expanded = base_dir / expanded
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
        except (OSError, RuntimeError, ValueError):
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

_SIMPLE_VAR_ASSIGN_RE = _LazyRegex(
    r"(?:^|[;&|()\n\s])([A-Za-z_][A-Za-z0-9_]*)=(?:'([^']*)'|\"([^\"\\]*)\"|([^\s;|&'\"()]+))"
)

def _expand_simple_shell_vars(cmd: str) -> str:
    """Expands simple shell variable assignments (`D=...; ... "$D/..."`) within a command string."""
    var_map: Dict[str, str] = {}
    for m in _SIMPLE_VAR_ASSIGN_RE.finditer(cmd):
        name = m.group(1)
        if name in ("HOME", "PATH", "PWD", "OLDPWD", "IFS"):
            continue
        val = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else (m.group(4) or ""))
        if val:
            var_map[name] = val
    if not var_map:
        return cmd
    expanded = cmd
    for _ in range(4):
        prev = expanded
        for name, val in var_map.items():
            expanded = re.sub(rf"\$\{{{re.escape(name)}\}}|\${re.escape(name)}(?![A-Za-z0-9_])", lambda _m, v=val: v, expanded)
        if expanded == prev:
            break
    return expanded

def _normalize_governance_globs(cmd: str) -> str:
    """Canonicalizes wildcard-obfuscated governance path prefixes (`~/.gem*/config`, `~/.local/bin/agy-*`)."""
    out = re.sub(r"(?:~|\$HOME)/\.gem[^\s;|&'\"/]*/conf[^\s;|&'\"/]*", "~/.gemini/config", cmd)
    out = re.sub(
        r"(?:~|\$HOME)/\.gem[^\s;|&'\"/]*/(GEMINI|AGENTS)\.md\b",
        r"~/.gemini/\1.md",
        out,
        flags=re.IGNORECASE,
    )
    out = re.sub(
        r"(?:~|\$HOME)/\.local/(state|share)/antigravity-[^\s;|&'\"/]*",
        r"~/.local/\1/antigravity-harness",
        out,
    )
    out = re.sub(r"(?:~|\$HOME)/\.local/bin/agy-[^\s;|&'\"/]*", "~/.local/bin/agy-guard", out)
    out = re.sub(r"(?:~|\$HOME)/\.local/bin/por\?ter|(?:~|\$HOME)/\.local/bin/por\*[^\s;|&'\"/]*", "~/.local/bin/porter", out)
    return out

_SHELL_MUTATION_INDICATOR_RE = _LazyRegex(
    r"(?:"
    r">{1,2}\|?|"
    r"\b(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip)\b|"
    r"\bfind\b[^\n;|&]*\s-(?:delete|exec|execdir|ok)\b|"
    r"\bsed\b[^\n;|&]*\s-(?:[A-Za-z]*i\S*|-in-place(?:=\S*)?)\b|"
    r"\b(?:curl|wget)\b[^\n;|&]*\s-(?:o|O)\b|"
    r"\b(?:python3?(?:\.\d+)?|py|node|nodejs|deno|bun|ruby|perl|php|lua)\b[^\n;|&]*(?:\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*|m\s+(?!(?:unittest|pytest|py_compile|mypy|ruff|flake8|doctest|cprofile|profile|ast|tokenize|dis)\b)\S+)\b|<<)|"
    r"\|\s*(?:[A-Za-z0-9_.=/-]+\s+)*(?:python3?(?:\.\d+)?|py|node|nodejs|deno|bun|ruby|perl|php|lua)\b"
    r")"
)

_SHELL_DOTDOT_TOKEN_RE = _LazyRegex(r"(?:^|[\s/'\"=])\.\.(?:$|[\s/'\";&|()])")

@functools.lru_cache(maxsize=256)
def _compiled_cfg_subdir_patterns(root: str) -> Tuple[Tuple[re.Pattern[str], str], ...]:
    sep = r"(?:[/\\]|\\\\)+"
    plugin_gov_tail = (
        rf"(?:{sep}(?:skills|agents|rules|hooks|scripts|bin|hooks\.json|mcp_config\.json|\.mcp\.json)\b"
        r"|\.(?:mdc?|py[cow]?|m?js|cjs|tsx?|jsx|sh|bash|zsh|fish|ksh|pl|rb|php|ps1|bat|cmd|so|dylib|dll|exe|wasm)\b)"
    )
    esc_root = re.escape(root)
    pats: List[Tuple[re.Pattern[str], str]] = []
    for sub in _RUNTIME_CONFIG_SUBDIRS:
        if sub == "plugins":
            pats.append(
                (
                    re.compile(
                        rf"(['\"]){esc_root}{sep}plugins(?=[/\\])(?![^'\"\n]*{plugin_gov_tail})[^'\"\n]*\1",
                        re.IGNORECASE,
                    ),
                    r"\1__RUNTIME_SUBDIR__\1",
                )
            )
            pats.append(
                (
                    re.compile(
                        rf"(?<!['\"]){esc_root}{sep}plugins(?=[/\\]|\s|$|[;&|'\"(),])(?![^\s;|&'\"]*{plugin_gov_tail})",
                        re.IGNORECASE,
                    ),
                    "__RUNTIME_SUBDIR__",
                )
            )
        else:
            pats.append((re.compile(rf"{esc_root}{sep}{re.escape(sub)}(?=[/\\]|\s|$|[;&|'\"(),])"), "__RUNTIME_SUBDIR__"))
    return tuple(pats)


@functools.lru_cache(maxsize=128)
def _compiled_state_staging_pattern(st_root: str) -> re.Pattern[str]:
    return re.compile(rf"{re.escape(st_root)}(?:[/\\]|\\\\)+staging(?=[/\\]|\s|$|[;&|'\"(),])")


_PURE_READONLY_PY_MODULES = frozenset({
    "ast", "base64", "bisect", "calendar", "collections", "collections.abc", "copy", "csv",
    "dataclasses", "datetime", "decimal", "difflib", "dis", "enum", "errno", "fnmatch",
    "fractions", "glob", "hashlib", "heapq", "hmac", "html", "io", "itertools",
    "json", "keyword", "locale", "math", "os", "os.path", "pathlib", "platform",
    "pprint", "re", "secrets", "shlex", "stat", "statistics", "string", "struct", "sys",
    "textwrap", "time", "token", "tokenize", "tomllib", "traceback", "typing", "unicodedata",
    "urllib.parse", "uuid", "zlib",
})

_READONLY_PY_MODULE_ATTRS: Dict[str, frozenset[str]] = {
    "ast": frozenset({
        "parse", "walk", "dump", "literal_eval", "unparse", "get_docstring", "iter_fields",
        "iter_child_nodes", "AST", "Module", "Import", "ImportFrom", "FunctionDef",
        "AsyncFunctionDef", "ClassDef", "Call", "Attribute", "Name", "Constant", "Assign",
        "AnnAssign", "AugAssign", "BinOp", "Compare", "Subscript", "JoinedStr", "List", "Tuple",
        "Dict", "Set", "Load", "Store", "Del", "If", "For", "While", "Try", "With",
    }),
    "base64": frozenset({
        "b64encode", "b64decode", "urlsafe_b64encode", "urlsafe_b64decode",
        "b32encode", "b32decode", "b16encode", "b16decode", "a85encode", "a85decode",
    }),
    "bisect": frozenset({"bisect", "bisect_left", "bisect_right"}),
    "calendar": frozenset({"isleap", "leapdays", "weekday", "monthrange", "monthcalendar", "timegm", "day_name", "month_name"}),
    "collections": frozenset({"Counter", "defaultdict", "deque", "namedtuple", "OrderedDict", "ChainMap", "abc"}),
    "collections.abc": frozenset({"Iterable", "Iterator", "Mapping", "MutableMapping", "Sequence", "Set", "Callable", "Collection", "Container", "Sized"}),
    "copy": frozenset({"copy", "deepcopy"}),
    "csv": frozenset({"reader", "DictReader", "Sniffer", "Error", "field_size_limit"}),
    "dataclasses": frozenset({"fields", "asdict", "astuple", "is_dataclass"}),
    "datetime": frozenset({"date", "time", "datetime", "timedelta", "timezone", "tzinfo", "UTC"}),
    "decimal": frozenset({"Decimal", "Context", "DecimalException", "InvalidOperation", "ROUND_HALF_UP", "ROUND_HALF_EVEN"}),
    "difflib": frozenset({"unified_diff", "context_diff", "ndiff", "get_close_matches", "SequenceMatcher"}),
    "dis": frozenset({"Bytecode", "get_instructions", "opname", "opmap"}),
    "enum": frozenset({"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag", "auto"}),
    "errno": frozenset({"ENOENT", "EACCES", "EPERM", "EEXIST", "EISDIR", "ENOTDIR", "EINVAL", "ENOSPC", "EROFS", "errorcode"}),
    "fnmatch": frozenset({"fnmatch", "fnmatchcase", "filter", "translate"}),
    "fractions": frozenset({"Fraction"}),
    "glob": frozenset({"glob", "iglob", "escape", "has_magic"}),
    "hashlib": frozenset({"sha256", "sha512", "sha384", "sha224", "sha1", "md5", "blake2b", "blake2s", "new", "algorithms_available", "algorithms_guaranteed"}),
    "heapq": frozenset({"nlargest", "nsmallest", "merge"}),
    "hmac": frozenset({"new", "digest", "compare_digest"}),
    "html": frozenset({"escape", "unescape"}),
    "io": frozenset({"StringIO", "BytesIO", "open"}),
    "itertools": frozenset({"chain", "islice", "combinations", "permutations", "product", "groupby", "repeat", "count", "cycle", "takewhile", "dropwhile", "filterfalse", "starmap", "zip_longest", "batched", "pairwise"}),
    "json": frozenset({"loads", "load", "dumps", "JSONDecodeError"}),
    "keyword": frozenset({"iskeyword", "issoftkeyword", "kwlist", "softkwlist"}),
    "locale": frozenset({"getpreferredencoding", "getlocale"}),
    "math": frozenset({"ceil", "floor", "trunc", "sqrt", "isclose", "isfinite", "isinf", "isnan", "log", "log2", "log10", "exp", "pow", "fabs", "factorial", "gcd", "lcm", "pi", "e", "tau", "inf", "nan", "prod", "fsum"}),
    "os": frozenset({
        "path", "getcwd", "getcwdb", "listdir", "scandir", "walk", "stat", "lstat", "readlink",
        "access", "getenv", "environ", "environb", "fspath", "fsencode", "fsdecode", "cpu_count",
        "getpid", "getppid", "getuid", "geteuid", "getgid", "getegid", "uname", "name", "sep",
        "altsep", "extsep", "linesep", "pathsep", "devnull", "curdir", "pardir", "F_OK", "R_OK",
        "W_OK", "X_OK",
    }),
    "os.path": frozenset({
        "abspath", "basename", "commonpath", "commonprefix", "dirname", "exists", "expanduser",
        "expandvars", "getatime", "getctime", "getmtime", "getsize", "isabs", "isdir", "isfile",
        "islink", "ismount", "join", "lexists", "normcase", "normpath", "realpath", "relpath",
        "samefile", "split", "splitdrive", "splitext", "sep", "altsep", "extsep", "pathsep",
        "devnull", "curdir", "pardir",
    }),
    "pathlib": frozenset({"Path", "PurePath", "PosixPath", "WindowsPath", "PurePosixPath", "PureWindowsPath"}),
    "platform": frozenset({"system", "machine", "release", "version", "platform", "python_version", "python_implementation", "architecture", "uname", "node", "processor"}),
    "pprint": frozenset({"pformat", "pprint"}),
    "re": frozenset({"compile", "search", "match", "fullmatch", "findall", "finditer", "sub", "subn", "split", "escape", "Pattern", "Match", "IGNORECASE", "I", "MULTILINE", "M", "DOTALL", "S", "VERBOSE", "X", "ASCII", "A", "UNICODE", "U", "error"}),
    "secrets": frozenset({"token_hex", "token_urlsafe", "token_bytes", "randbelow", "compare_digest"}),
    "shlex": frozenset({"split", "quote", "join"}),
    "stat": frozenset({"S_ISDIR", "S_ISREG", "S_ISLNK", "S_ISFIFO", "S_ISSOCK", "S_ISCHR", "S_ISBLK", "S_IMODE", "S_IFMT", "ST_MODE", "S_IRUSR", "S_IWUSR", "S_IXUSR", "filemode"}),
    "statistics": frozenset({"mean", "fmean", "median", "median_low", "median_high", "mode", "multimode", "stdev", "pstdev", "variance", "pvariance", "quantiles", "StatisticsError"}),
    "string": frozenset({"ascii_letters", "ascii_lowercase", "ascii_uppercase", "digits", "hexdigits", "octdigits", "punctuation", "printable", "whitespace"}),
    "struct": frozenset({"pack", "unpack", "unpack_from", "iter_unpack", "calcsize", "Struct", "error"}),
    "sys": frozenset({
        "version", "version_info", "platform", "maxsize", "byteorder", "stdout", "stderr",
        "argv", "implementation", "prefix", "base_prefix", "exec_prefix", "executable",
        "hexversion", "api_version", "float_info", "int_info", "hash_info",
    }),
    "textwrap": frozenset({"dedent", "indent", "wrap", "fill", "shorten"}),
    "time": frozenset({"time", "time_ns", "monotonic", "monotonic_ns", "perf_counter", "perf_counter_ns", "gmtime", "localtime", "strftime", "strptime"}),
    "token": frozenset({"tok_name", "ISTERMINAL", "ISNONTERMINAL", "ISEOF"}),
    "tokenize": frozenset({"generate_tokens", "tokenize", "TokenInfo", "TokenError"}),
    "tomllib": frozenset({"loads", "load", "TOMLDecodeError"}),
    "traceback": frozenset({"format_exc", "format_exception", "format_tb", "extract_tb"}),
    "typing": frozenset({"Any", "Dict", "List", "Optional", "Sequence", "Set", "Tuple", "Union", "Callable", "Iterator", "Iterable", "Mapping", "Literal", "Final", "ClassVar", "NamedTuple", "TypedDict", "TYPE_CHECKING"}),
    "unicodedata": frozenset({"normalize", "category", "name", "lookup", "combining", "east_asian_width"}),
    "urllib.parse": frozenset({"urlparse", "urlsplit", "urlunparse", "urlunsplit", "urljoin", "urlencode", "parse_qs", "parse_qsl", "quote", "quote_plus", "unquote", "unquote_plus"}),
    "uuid": frozenset({"UUID", "uuid4", "uuid5", "uuid3", "uuid1", "NAMESPACE_DNS", "NAMESPACE_URL", "NAMESPACE_OID", "NAMESPACE_X500"}),
    "zlib": frozenset({"crc32", "adler32", "compress", "decompress", "error"}),
}

_SAFE_READONLY_PY_BUILTINS = frozenset({
    "abs", "all", "any", "ascii", "bin", "bool", "bytearray", "bytes", "callable", "chr",
    "complex", "dict", "dir", "divmod", "enumerate", "filter", "float", "format", "frozenset",
    "hasattr", "hash", "hex", "id", "int", "isinstance", "issubclass", "iter", "len", "list",
    "map", "max", "min", "next", "object", "oct", "open", "ord", "pow", "print", "range",
    "repr", "reversed", "round", "set", "slice", "sorted", "str", "sum", "tuple", "type", "zip",
    "Exception", "BaseException", "ValueError", "TypeError", "KeyError", "IndexError",
    "AttributeError", "OSError", "FileNotFoundError", "PermissionError", "RuntimeError",
    "StopIteration", "UnicodeDecodeError", "UnicodeEncodeError", "AssertionError",
})

_FORBIDDEN_INLINE_PY_ATTRS = frozenset({
    "touch", "unlink", "remove", "removedirs", "rmdir", "mkdir", "makedirs", "rename", "renames",
    "chmod", "fchmod", "lchmod", "chown", "fchown", "lchown", "symlink", "symlink_to",
    "hardlink_to", "link", "write", "writelines", "write_text", "write_bytes", "truncate",
    "ftruncate", "FileIO", "BufferedWriter", "BufferedRandom", "open_code", "utime", "popen",
    "system", "dump", "NamedTemporaryFile", "TemporaryDirectory", "mkstemp", "mkdtemp",
    "mkfifo", "mknod", "putenv", "unsetenv", "chdir", "fchdir", "chroot", "Popen", "run",
    "call", "check_call", "check_output", "spawn", "execv", "execve", "execvp", "execl",
    "extract", "extractall", "urlretrieve", "import_module", "run_path", "run_module",
    "rmtree", "eval", "exec", "compile", "getattr", "setattr", "delattr", "getattr_static",
    "currentframe", "f_builtins", "f_globals", "f_locals", "f_back", "f_code",
    "os", "sys", "io", "builtins", "bltns", "posix", "nt", "shutil", "pathlib",
    "posixpath", "ntpath", "genericpath", "subprocess", "importlib", "codecs",
    "tempfile", "tarfile", "zipfile", "ctypes", "socket",
})

_SAFE_READONLY_OBJECT_METHODS = frozenset({
    "exists", "is_file", "is_dir", "is_symlink", "is_fifo", "is_socket", "is_char_device",
    "is_block_device", "is_mount", "is_absolute", "is_relative_to", "stat", "lstat",
    "read_text", "read_bytes", "readlink", "iterdir", "glob", "rglob", "walk", "open",
    "expanduser", "resolve", "absolute", "as_posix", "as_uri", "joinpath", "relative_to",
    "with_name", "with_stem", "with_suffix", "match", "full_match", "samefile", "inode",
    "read", "readline", "readlines", "getvalue", "tell", "seek", "readable", "fileno", "close",
    "strip", "lstrip", "rstrip", "split", "rsplit", "splitlines", "partition", "rpartition",
    "join", "replace", "lower", "upper", "casefold", "title", "capitalize", "startswith",
    "endswith", "find", "rfind", "index", "rindex", "count", "encode", "decode", "format",
    "isdigit", "isalpha", "isalnum", "isspace", "isascii", "isidentifier", "islower", "isupper",
    "removeprefix", "removesuffix", "zfill", "ljust", "rjust", "center", "hex", "fromhex",
    "get", "keys", "values", "items", "copy", "append", "extend", "insert", "sort", "reverse",
    "add", "update", "union", "intersection", "difference", "symmetric_difference",
    "issubset", "issuperset", "isdisjoint", "most_common",
    "search", "fullmatch", "findall", "finditer", "sub", "subn", "group", "groups", "groupdict",
    "start", "end", "span", "hexdigest", "digest", "isoformat", "strftime", "total_seconds",
    "timestamp", "astimezone",
})

_PATHLIB_CLASS_NAMES = frozenset({"Path", "PurePath", "PosixPath", "WindowsPath", "PurePosixPath", "PureWindowsPath"})

_CALL_ONLY_PY_NAMES = frozenset({"open", "print", "type", "map", "filter", "sorted", "min", "max"})

_READONLY_PY_M_MODULES = frozenset({
    "unittest", "pytest", "py_compile", "mypy", "ruff", "flake8", "doctest",
    "cprofile", "profile", "ast", "tokenize", "dis",
})

_DANGEROUS_PY_ENV_RE = _LazyRegex(
    r"\b(?:PYTHONPATH|PYTHONSTARTUP|PYTHONHOME|PYTHONINSPECT|PYTHONUSERBASE|PYTHONEXECUTABLE|PATH|LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|DYLD_[A-Z0-9_]+)="
)

_SAFE_PY_CLI_OPT_RE = _LazyRegex(r"^-(?:[BEIOPSsUuvqbd]+|[WX](?:=\S+)?)$")


def _is_pure_readonly_python_snippet(source: str) -> bool:
    """Returns True iff `source` parses as a pure read-only Python subset with zero mutating/reflective/FFI capabilities."""
    if not isinstance(source, str) or not source.strip() or len(source) > 65536 or "\x00" in source:
        return False
    dedented = textwrap.dedent(source)
    if _check_pep263_cookie(dedented) is not None or _check_pep263_cookie(source) is not None:
        return False
    try:
        tree = ast.parse(dedented, mode="exec")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False

    module_aliases: Dict[str, str] = {}
    imported_symbols: Dict[str, Tuple[str, str]] = {}
    environ_aliases: set[str] = set()
    local_defs: set[str] = set()
    store_counts: Dict[str, int] = {}
    const_vars: Dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(
            node,
            (
                ast.ClassDef,
                ast.Delete,
                ast.Global,
                ast.Nonlocal,
                ast.AsyncFunctionDef,
                ast.AsyncFor,
                ast.AsyncWith,
                ast.Await,
                ast.Yield,
                ast.YieldFrom,
            ),
        ):
            return False
        if isinstance(node, ast.FunctionDef):
            if node.decorator_list or node.name.startswith("__") or node.name.endswith("__"):
                return False
            local_defs.add(node.name)
            store_counts[node.name] = store_counts.get(node.name, 0) + 1
        elif isinstance(node, ast.Import):
            for alias in node.names:
                mod_name = alias.name
                root_mod = mod_name.split(".", 1)[0]
                if mod_name not in _PURE_READONLY_PY_MODULES and root_mod not in _PURE_READONLY_PY_MODULES:
                    return False
                if mod_name.startswith("urllib.") and mod_name != "urllib.parse":
                    return False
                if mod_name.startswith("collections.") and mod_name != "collections.abc":
                    return False
                if mod_name.startswith("os.") and mod_name != "os.path":
                    return False
                bound = alias.asname or root_mod
                if bound in _CALL_ONLY_PY_NAMES or bound.startswith("__") or bound.endswith("__"):
                    return False
                mapped_mod = mod_name if alias.asname else root_mod
                module_aliases[bound] = mapped_mod
                store_counts[bound] = store_counts.get(bound, 0) + 1
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0 or not node.module:
                return False
            mod_name = node.module
            if mod_name not in _PURE_READONLY_PY_MODULES:
                return False
            mod_allow = _READONLY_PY_MODULE_ATTRS.get(mod_name)
            if mod_allow is None:
                return False
            for alias in node.names:
                if alias.name == "*" or alias.name.startswith("_") or alias.name.endswith("__"):
                    return False
                if alias.name in _FORBIDDEN_INLINE_PY_ATTRS or alias.name not in mod_allow:
                    return False
                bound = alias.asname or alias.name
                if bound.startswith("__") or bound.endswith("__"):
                    return False
                if mod_name == "os" and alias.name == "path":
                    module_aliases[bound] = "os.path"
                elif mod_name == "os" and alias.name in ("environ", "environb"):
                    environ_aliases.add(bound)
                elif mod_name == "collections" and alias.name == "abc":
                    module_aliases[bound] = "collections.abc"
                elif mod_name == "urllib" and alias.name == "parse":
                    module_aliases[bound] = "urllib.parse"
                else:
                    imported_symbols[bound] = (mod_name, alias.name)
                store_counts[bound] = store_counts.get(bound, 0) + 1
        elif isinstance(node, ast.arg):
            if node.arg.startswith("__") or node.arg.endswith("__"):
                return False
            store_counts[node.arg] = store_counts.get(node.arg, 0) + 1
        elif isinstance(node, ast.ExceptHandler) and node.name:
            if node.name.startswith("__") or node.name.endswith("__"):
                return False
            store_counts[node.name] = store_counts.get(node.name, 0) + 1
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            if node.name.startswith("__") or node.name.endswith("__"):
                return False
            store_counts[node.name] = store_counts.get(node.name, 0) + 1
        elif isinstance(node, ast.MatchMapping) and node.rest:
            if node.rest.startswith("__") or node.rest.endswith("__"):
                return False
            store_counts[node.rest] = store_counts.get(node.rest, 0) + 1
        elif type(node).__name__ in ("TypeVar", "ParamSpec", "TypeVarTuple") and getattr(node, "name", None):
            tp_name = str(getattr(node, "name"))
            store_counts[tp_name] = store_counts.get(tp_name, 0) + 1
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            if node.id.startswith("__") or node.id.endswith("__"):
                return False
            store_counts[node.id] = store_counts.get(node.id, 0) + 1
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
            return False
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store):
            if isinstance(node.value, ast.Name) and node.value.id in environ_aliases:
                return False
            if (
                isinstance(node.value, ast.Attribute)
                and node.value.attr in ("environ", "environb")
                and isinstance(node.value.value, ast.Name)
                and module_aliases.get(node.value.value.id) == "os"
            ):
                return False

    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            vname = stmt.targets[0].id
            if store_counts.get(vname, 0) == 1:
                sval = _eval_workflow_str_expr(stmt.value, const_vars)
                if sval is not None:
                    const_vars[vname] = sval

    protected_bindings = (
        set(module_aliases.keys())
        | set(imported_symbols.keys())
        | environ_aliases
        | local_defs
        | _CALL_ONLY_PY_NAMES
    )
    for bname in protected_bindings:
        if store_counts.get(bname, 0) > 1 or (bname in _CALL_ONLY_PY_NAMES and bname in store_counts and bname not in imported_symbols):
            return False

    call_func_ids = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    attr_parent_by_val_id: Dict[int, List[ast.Attribute]] = {}
    safe_environ_use_ids: set[int] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Attribute):
            attr_parent_by_val_id.setdefault(id(n.value), []).append(n)
            if n.attr in _SAFE_ENVIRON_READ_METHODS and id(n) in call_func_ids:
                safe_environ_use_ids.add(id(n.value))
        elif isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Load):
            safe_environ_use_ids.add(id(n.value))
        elif isinstance(n, ast.Compare):
            for op, cmp_node in zip(n.ops, n.comparators):
                if isinstance(op, (ast.In, ast.NotIn)):
                    safe_environ_use_ids.add(id(cmp_node))

    def _is_sys_std_stream(expr: ast.AST) -> bool:
        if (
            isinstance(expr, ast.Attribute)
            and expr.attr in ("stdout", "stderr")
            and isinstance(expr.value, ast.Name)
            and module_aliases.get(expr.value.id) == "sys"
        ):
            return True
        return isinstance(expr, ast.Name) and imported_symbols.get(expr.id) in (("sys", "stdout"), ("sys", "stderr"))

    def _is_environ_node(expr: ast.AST) -> bool:
        if isinstance(expr, ast.Name) and expr.id in environ_aliases:
            return True
        return (
            isinstance(expr, ast.Attribute)
            and expr.attr in ("environ", "environb")
            and isinstance(expr.value, ast.Name)
            and module_aliases.get(expr.value.id) == "os"
        )

    def _is_pathlib_class_expr(expr: ast.AST) -> bool:
        if isinstance(expr, ast.Name) and imported_symbols.get(expr.id, ("", ""))[1] in _PATHLIB_CLASS_NAMES:
            return True
        return (
            isinstance(expr, ast.Attribute)
            and expr.attr in _PATHLIB_CLASS_NAMES
            and isinstance(expr.value, ast.Name)
            and module_aliases.get(expr.value.id) == "pathlib"
        )

    def _is_safe_callback_expr(cb: ast.AST) -> bool:
        if isinstance(cb, ast.Lambda):
            return True
        if isinstance(cb, ast.Name):
            if cb.id in local_defs:
                return True
            if (
                cb.id in _SAFE_READONLY_PY_BUILTINS
                and cb.id not in _CALL_ONLY_PY_NAMES
                and cb.id not in imported_symbols
                and cb.id not in module_aliases
            ):
                return True
        return False

    def _is_safe_sub_repl(repl_node: ast.AST) -> bool:
        if isinstance(repl_node, (ast.Constant, ast.JoinedStr)):
            return True
        return _is_safe_callback_expr(repl_node)

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            nid = id(node)
            nm = node.id
            if nm != "__name__" and (nm.startswith("__") or nm.endswith("__")):
                return False
            if nm in module_aliases:
                if nid not in attr_parent_by_val_id:
                    return False
                continue
            if nm in environ_aliases:
                if nid not in safe_environ_use_ids:
                    return False
                for p_attr in attr_parent_by_val_id.get(nid, []):
                    if p_attr.attr not in _SAFE_ENVIRON_READ_METHODS or id(p_attr) not in call_func_ids:
                        return False
                continue
            if nm in imported_symbols:
                imp_mod, imp_sym = imported_symbols[nm]
                if imp_sym == "open" or (imp_mod == "pprint" and imp_sym == "pprint") or (imp_mod == "re" and imp_sym in ("sub", "subn")):
                    if nid not in call_func_ids:
                        return False
                elif imp_sym in _PATHLIB_CLASS_NAMES:
                    if nid in call_func_ids:
                        continue
                    p_attrs = attr_parent_by_val_id.get(nid, [])
                    if not p_attrs or any(pa.attr not in ("home", "cwd") or id(pa) not in call_func_ids for pa in p_attrs):
                        return False
                continue
            if nm in _CALL_ONLY_PY_NAMES:
                if nid not in call_func_ids:
                    return False

        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            attr = node.attr
            if attr.startswith("__") or attr.endswith("__") or attr in _FORBIDDEN_INLINE_PY_ATTRS:
                return False
            if attr in ("open", "sort", "sub", "subn") and id(node) not in call_func_ids:
                return False
            if isinstance(node.value, ast.Name) and node.value.id in module_aliases:
                if attr.startswith("_"):
                    return False
                m_name = module_aliases[node.value.id]
                allow_set = _READONLY_PY_MODULE_ATTRS.get(m_name)
                if allow_set is None or attr not in allow_set:
                    return False
                if m_name == "os" and attr == "path":
                    if id(node) not in attr_parent_by_val_id:
                        return False
                elif m_name == "os" and attr in ("environ", "environb"):
                    if id(node) not in safe_environ_use_ids:
                        return False
                    for p_attr in attr_parent_by_val_id.get(id(node), []):
                        if p_attr.attr not in _SAFE_ENVIRON_READ_METHODS or id(p_attr) not in call_func_ids:
                            return False
                elif m_name == "pathlib" and attr in _PATHLIB_CLASS_NAMES:
                    if id(node) not in call_func_ids:
                        p_attrs = attr_parent_by_val_id.get(id(node), [])
                        if not p_attrs or any(pa.attr not in ("home", "cwd") or id(pa) not in call_func_ids for pa in p_attrs):
                            return False
                elif (m_name == "io" and attr == "open") or (m_name == "pprint" and attr == "pprint") or (m_name == "re" and attr in ("sub", "subn")):
                    if id(node) not in call_func_ids:
                        return False
                continue
            if (
                isinstance(node.value, ast.Attribute)
                and node.value.attr == "path"
                and isinstance(node.value.value, ast.Name)
                and module_aliases.get(node.value.value.id) == "os"
            ):
                if attr not in _READONLY_PY_MODULE_ATTRS["os.path"]:
                    return False
                continue
            if _is_environ_node(node.value):
                if attr not in _SAFE_ENVIRON_READ_METHODS or id(node) not in call_func_ids:
                    return False
                continue
            if _is_pathlib_class_expr(node.value):
                if attr not in ("home", "cwd") or id(node) not in call_func_ids:
                    return False
                continue

        elif isinstance(node, ast.Call):
            fn = node.func
            has_star_args = any(isinstance(a, ast.Starred) for a in node.args)
            has_star_kwargs = any(kw.arg is None for kw in node.keywords)
            if isinstance(fn, ast.Name):
                fname = fn.id
                if fname in local_defs:
                    continue
                if fname in imported_symbols:
                    imp_mod, imp_sym = imported_symbols[fname]
                    if imp_sym == "open":
                        if not _is_readonly_open_call(node, 1, const_vars):
                            return False
                    elif imp_mod == "pprint" and imp_sym == "pprint":
                        if has_star_kwargs or any(kw.arg == "stream" for kw in node.keywords) or len(node.args) > 1:
                            return False
                    elif imp_mod == "re" and imp_sym in ("sub", "subn"):
                        if has_star_args or has_star_kwargs or len(node.args) < 2:
                            return False
                        if not _is_safe_sub_repl(node.args[1]):
                            return False
                        for kw in node.keywords:
                            if kw.arg == "repl" and not _is_safe_sub_repl(kw.value):
                                return False
                    elif imp_sym in _PATHLIB_CLASS_NAMES:
                        if has_star_args or has_star_kwargs:
                            return False
                    continue
                if fname not in _SAFE_READONLY_PY_BUILTINS:
                    return False
                if fname == "open":
                    if not _is_readonly_open_call(node, 1, const_vars):
                        return False
                elif fname == "print":
                    if has_star_kwargs:
                        return False
                    for kw in node.keywords:
                        if kw.arg == "file" and not _is_sys_std_stream(kw.value):
                            return False
                elif fname == "type":
                    if has_star_args or has_star_kwargs or len(node.args) != 1 or node.keywords:
                        return False
                elif fname in ("sorted", "min", "max"):
                    if has_star_kwargs:
                        return False
                    for kw in node.keywords:
                        if kw.arg == "key" and not (
                            (isinstance(kw.value, ast.Constant) and kw.value.value is None)
                            or _is_safe_callback_expr(kw.value)
                        ):
                            return False
                elif fname in ("map", "filter"):
                    if has_star_args or has_star_kwargs or len(node.args) < 2 or node.keywords:
                        return False
                    cb = node.args[0]
                    if fname == "filter" and isinstance(cb, ast.Constant) and cb.value is None:
                        continue
                    if _is_safe_callback_expr(cb):
                        continue
                    return False
            elif isinstance(fn, ast.Attribute):
                attr = fn.attr
                if isinstance(fn.value, ast.Name) and fn.value.id in module_aliases:
                    if attr.startswith("_"):
                        return False
                    m_name = module_aliases[fn.value.id]
                    allow_set = _READONLY_PY_MODULE_ATTRS.get(m_name)
                    if allow_set is None or attr not in allow_set:
                        return False
                    if m_name == "io" and attr == "open":
                        if not _is_readonly_open_call(node, 1, const_vars):
                            return False
                    elif m_name == "pprint" and attr == "pprint":
                        if has_star_kwargs or any(kw.arg == "stream" for kw in node.keywords) or len(node.args) > 1:
                            return False
                    elif m_name == "re" and attr in ("sub", "subn"):
                        if has_star_args or has_star_kwargs or len(node.args) < 2:
                            return False
                        if not _is_safe_sub_repl(node.args[1]):
                            return False
                        for kw in node.keywords:
                            if kw.arg == "repl" and not _is_safe_sub_repl(kw.value):
                                return False
                    elif m_name == "pathlib" and attr in _PATHLIB_CLASS_NAMES:
                        if has_star_args or has_star_kwargs:
                            return False
                    continue
                if (
                    isinstance(fn.value, ast.Attribute)
                    and fn.value.attr == "path"
                    and isinstance(fn.value.value, ast.Name)
                    and module_aliases.get(fn.value.value.id) == "os"
                ):
                    if attr not in _READONLY_PY_MODULE_ATTRS["os.path"]:
                        return False
                    continue
                if _is_environ_node(fn.value):
                    if attr not in _SAFE_ENVIRON_READ_METHODS:
                        return False
                    continue
                if _is_pathlib_class_expr(fn.value):
                    if attr not in ("home", "cwd") or node.args or node.keywords:
                        return False
                    continue
                if attr not in _SAFE_READONLY_OBJECT_METHODS:
                    return False
                if attr == "open":
                    if not _is_readonly_open_call(node, 0, const_vars):
                        return False
                elif attr == "sort":
                    if has_star_args or has_star_kwargs or node.args:
                        return False
                    for kw in node.keywords:
                        if kw.arg == "key" and not (
                            (isinstance(kw.value, ast.Constant) and kw.value.value is None)
                            or _is_safe_callback_expr(kw.value)
                        ):
                            return False
                elif attr in ("sub", "subn"):
                    if has_star_args or has_star_kwargs:
                        return False
                    if node.args and not _is_safe_sub_repl(node.args[0]):
                        return False
                    for kw in node.keywords:
                        if kw.arg == "repl" and not _is_safe_sub_repl(kw.value):
                            return False
                elif attr == "replace":
                    if has_star_args or has_star_kwargs or len(node.args) not in (2, 3):
                        return False
                    if any(kw.arg != "count" for kw in node.keywords):
                        return False
            else:
                return False

    return True


def _python_ast_targets_governance(source: str, base_dir: Optional[Path] = None) -> bool:
    """Folds constant/home/env path expressions inside a non-readonly Python snippet and checks `_targets_governance_dir`."""
    if not isinstance(source, str) or not source.strip() or len(source) > 65536 or "\x00" in source:
        return True
    dedented = textwrap.dedent(source)
    if _check_pep263_cookie(dedented) is not None or _check_pep263_cookie(source) is not None:
        return True
    try:
        tree = ast.parse(dedented.encode("utf-8"), mode="exec")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return True

    path_vars: Dict[str, str] = {}
    multi_vars: Dict[str, List[str]] = {}

    def _record_var(vname: str, val: Optional[str]) -> bool:
        if not vname or val is None or len(val) > _WORKFLOW_MAX_FOLDED_LEN:
            return False
        bucket = multi_vars.setdefault(vname, [])
        changed_local = False
        if val not in bucket and len(bucket) < 16:
            bucket.append(val)
            changed_local = True
        if path_vars.get(vname) != val:
            path_vars[vname] = val
            changed_local = True
        return changed_local

    for _pass in range(4):
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        changed = _record_var(tgt.id, _eval_workflow_path_expr(node.value, path_vars)) or changed
                    elif isinstance(tgt, (ast.Tuple, ast.List)) and isinstance(node.value, (ast.Tuple, ast.List)):
                        for sub_t, sub_v in zip(tgt.elts, node.value.elts):
                            if isinstance(sub_t, ast.Name):
                                changed = _record_var(sub_t.id, _eval_workflow_path_expr(sub_v, path_vars)) or changed
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                changed = _record_var(node.target.id, _eval_workflow_path_expr(node.value, path_vars)) or changed
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and isinstance(node.op, (ast.Add, ast.Div)):
                lhs_vals = list(multi_vars.get(node.target.id, ()))
                rhs_val = _eval_workflow_path_expr(node.value, path_vars)
                if rhs_val is not None:
                    for lv in lhs_vals:
                        combined = os.path.join(lv, rhs_val) if isinstance(node.op, ast.Div) else f"{lv}{rhs_val}"
                        changed = _record_var(node.target.id, combined) or changed
        if not changed:
            break

    candidate_envs: List[Dict[str, str]] = [path_vars]
    for vname, vals in multi_vars.items():
        for alt in vals:
            if path_vars.get(vname) != alt and len(candidate_envs) < 16:
                candidate_envs.append({**path_vars, vname: alt})

    for env_map in candidate_envs:
        for node in ast.walk(tree):
            if isinstance(node, (ast.Call, ast.BinOp, ast.Constant, ast.JoinedStr, ast.Attribute)):
                cand = _eval_workflow_path_expr(node, env_map)
                if cand and _targets_governance_dir(cand, base_dir=base_dir):
                    return True
    return False


def _unescape_safe_dq_py(inner: str) -> Optional[str]:
    """Unescapes a double-quoted shell string only when free of `$`, backticks, and unsafe escapes."""
    if "$" in inner or "`" in inner:
        return None
    out: List[str] = []
    i = 0
    n = len(inner)
    while i < n:
        ch = inner[i]
        if ch == "\\":
            if i + 1 >= n:
                return None
            nxt = inner[i + 1]
            if nxt in ('"', "\\"):
                out.append(nxt)
                i += 2
                continue
            if nxt == "\n":
                i += 2
                continue
            # POSIX sh preserves literal backslash + nxt inside double quotes for other chars
            out.append("\\")
            out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _segment_has_unquoted_redirection_or_subst(seg: str) -> bool:
    """Returns True if `seg` contains unquoted `>`, `<(`, `>(`, `$(`, backticks, or `$'...'` ANSI-C quotes."""
    i = 0
    n = len(seg)
    mode = ""
    while i < n:
        ch = seg[i]
        if not mode:
            if ch == "\\":
                i += 2
                continue
            if ch == "$" and i + 1 < n and seg[i + 1] in ("'", "("):
                return True
            if ch == "`" or ch == ">":
                return True
            if ch == "<" and i + 1 < n and seg[i + 1] == "(":
                return True
            if ch in ("'", '"'):
                mode = ch
            i += 1
        elif mode == "'":
            if ch == "'":
                mode = ""
            i += 1
        else:
            if ch == "\\":
                i += 2
                continue
            if ch == "`" or (ch == "$" and i + 1 < n and seg[i + 1] == "("):
                return True
            if ch == '"':
                mode = ""
            i += 1
    return bool(mode)


def _try_extract_standalone_py_c(
    seg: str, *, all_candidates: bool = False
) -> Optional[Any]:
    """Extracts Python `-c` source (or `[posix, win_argv]` candidates when `all_candidates=True`) if safe, else None."""
    if _segment_has_unquoted_redirection_or_subst(seg) or _DANGEROUS_PY_ENV_RE.search(seg):
        return None

    def _unescape_win_dq(inner: str) -> Optional[str]:
        if "$" in inner or "`" in inner:
            return None
        out_w: List[str] = []
        wi = 0
        wn = len(inner)
        while wi < wn:
            if inner[wi] == "\\":
                bs = 0
                while wi + bs < wn and inner[wi + bs] == "\\":
                    bs += 1
                if wi + bs < wn and inner[wi + bs] == '"':
                    if bs % 2 == 0:
                        return None
                    out_w.append("\\" * (bs // 2))
                    out_w.append('"')
                    wi += bs + 1
                    continue
                out_w.append("\\" * bs)
                wi += bs
                continue
            out_w.append(inner[wi])
            wi += 1
        return "".join(out_w)

    tokens: List[Tuple[str, str, Optional[str]]] = []
    i = 0
    n = len(seg)
    while i < n:
        while i < n and seg[i].isspace():
            i += 1
        if i >= n:
            break
        if seg[i] == "#":
            break
        raw_parts: List[str] = []
        win_parts: List[str] = []
        win_valid = True
        quote_kinds: set[str] = set()
        while i < n and not seg[i].isspace():
            ch = seg[i]
            if ch == "'":
                quote_kinds.add("sq")
                j = seg.find("'", i + 1)
                if j == -1:
                    return None
                piece = seg[i + 1 : j]
                raw_parts.append(piece)
                win_parts.append(piece)
                i = j + 1
            elif ch == '"':
                quote_kinds.add("dq")
                j = i + 1
                buf: List[str] = []
                closed = False
                while j < n:
                    if seg[j] == "\\" and j + 1 < n:
                        buf.append(seg[j : j + 2])
                        j += 2
                        continue
                    if seg[j] == '"':
                        closed = True
                        i = j + 1
                        break
                    buf.append(seg[j])
                    j += 1
                if not closed:
                    return None
                raw_dq = "".join(buf)
                dec = _unescape_safe_dq_py(raw_dq)
                if dec is None:
                    return None
                raw_parts.append(dec)
                dec_win = _unescape_win_dq(raw_dq)
                if dec_win is None:
                    win_valid = False
                else:
                    win_parts.append(dec_win)
            elif ch == "\\":
                if i + 1 >= n:
                    return None
                quote_kinds.add("esc")
                raw_parts.append(seg[i + 1])
                win_parts.append(seg[i + 1])
                i += 2
            elif ch in "|&;()<>`":
                return None
            else:
                quote_kinds.add("bare")
                raw_parts.append(ch)
                win_parts.append(ch)
                i += 1
        kind = "sq" if quote_kinds == {"sq"} else ("dq" if quote_kinds == {"dq"} else "mixed")
        tokens.append((kind, "".join(raw_parts), "".join(win_parts) if win_valid else None))

    if not tokens:
        return None
    safe_env_assign_re = re.compile(
        r"^(?:PYTHONUTF8|PYTHONIOENCODING|PYTHONDONTWRITEBYTECODE|PYTHONHASHSEED|PYTHONUNBUFFERED|LANG|LC_[A-Z_]+|TZ|NO_COLOR|FORCE_COLOR|TERM)="
    )
    idx = 0
    while idx < len(tokens):
        _k, tok, _wt = tokens[idx]
        if safe_env_assign_re.match(tok) or tok in ("command", "env", "nice", "nohup", "time"):
            idx += 1
            continue
        break
    if idx >= len(tokens):
        return None
    interp_raw = tokens[idx][1]
    if ("/" in interp_raw or "\\" in interp_raw) and not interp_raw.startswith(
        ("/usr/bin/", "/usr/local/bin/", "/bin/", "/opt/homebrew/bin/")
    ):
        return None
    interp_base = Path(interp_raw).name.lower()
    if not re.fullmatch(r"python(?:3(?:\.\d+)?)?", interp_base):
        return None
    idx += 1
    while idx < len(tokens):
        _k, opt, _wo = tokens[idx]
        if opt == "-c" or (opt.startswith("-") and not opt.startswith("--") and opt.endswith("c") and _SAFE_PY_CLI_OPT_RE.match(opt[:-1] or "-B")):
            if idx + 1 != len(tokens) - 1:
                return None
            code_kind, code_str, win_code_str = tokens[idx + 1]
            if code_kind not in ("sq", "dq"):
                return None
            if all_candidates:
                if code_kind == "dq" and win_code_str is not None and win_code_str != code_str:
                    return [code_str, win_code_str]
                return [code_str]
            return code_str
        if opt in ("-W", "-X"):
            idx += 2
            continue
        if _SAFE_PY_CLI_OPT_RE.match(opt):
            idx += 1
            continue
        return None
    return None


_NON_PYTHON_INTERP_RE = _LazyRegex(
    r"(?:"
    r"\b(?:node|nodejs|deno|bun|ruby|perl|php|lua|py)\b[^\n;|&]*(?:\s-(?:[A-Za-z0-9]*[ceip]\S*)\b|<<)|"
    r"\|\s*(?:[A-Za-z0-9_.=/-]+\s+)*(?:python3?(?:\.\d+)?|py|node|nodejs|deno|bun|ruby|perl|php|lua)\b"
    r")",
    re.IGNORECASE,
)

_ANY_PYTHON_INLINE_OR_HEREDOC_RE = _LazyRegex(
    r"\bpython3?(?:\.\d+)?\b[^\n;|&]*(?:\s-(?:[A-Za-z0-9]*[cmi])\b|<<)",
    re.IGNORECASE,
)

_HEREDOC_PY_HEADER_RE = _LazyRegex(
    r"^(?P<lead>\s*(?:(?:command|env|nice|nohup|time)\s+)*(?:[^\s;|&'\"`]*/)?python3?(?:\.\d+)?(?:\s+-(?:[BEIOPSsUuvqbd]+|[WX](?:=\S+|\s+\S+)))*\s+<<(?P<dash>-?)\s*(?P<q>['\"]?)(?P<delim>[A-Za-z0-9_]+)(?P=q))(?P<trail>[^\n]*)$"
)


def _scrub_verified_readonly_python_invocations(cmd: str) -> Tuple[str, bool, List[str]]:
    """
    Replaces standalone top-level verified pure read-only `python3 -c` and `python3 <<EOF` spans
    with `__RO_PY__`. Never scrubs inside `$(...)`, `<(...)`, `>(...)`, or backticks.
    Returns `(scrubbed_cmd, has_unverified_interpreter, mutating_python_sources)`.
    """
    has_unverified = bool(_NON_PYTHON_INTERP_RE.search(cmd))
    mutating_sources: List[str] = []
    if not _ANY_PYTHON_INLINE_OR_HEREDOC_RE.search(cmd):
        return cmd, has_unverified, mutating_sources

    lines = cmd.splitlines(keepends=True)
    processed_lines: List[str] = []
    line_idx = 0
    subst_stack: List[str] = []
    subst_qmode = ""
    in_backtick_subst = False

    def _advance_subst_state(line_str: str) -> None:
        nonlocal subst_qmode, in_backtick_subst
        k = 0
        ln = len(line_str)
        while k < ln:
            ch = line_str[k]
            if not subst_qmode:
                if ch == "\\" and k + 1 < ln:
                    k += 2
                    continue
                if ch == "#" and (k == 0 or line_str[k - 1].isspace()):
                    break
                if ch == "`":
                    in_backtick_subst = not in_backtick_subst
                    k += 1
                    continue
                if ch in ("$", "<", ">") and k + 1 < ln and line_str[k + 1] == "(":
                    subst_stack.append("unq")
                    k += 2
                    continue
                if ch == "(" and subst_stack and subst_stack[-1] == "unq":
                    subst_stack.append("unq")
                    k += 1
                    continue
                if ch == ")" and subst_stack and subst_stack[-1] == "unq":
                    subst_stack.pop()
                    k += 1
                    continue
                if ch in ("'", '"'):
                    subst_qmode = ch
                k += 1
            elif subst_qmode == "'":
                if ch == "'":
                    subst_qmode = ""
                k += 1
            else:
                if ch == "\\" and k + 1 < ln:
                    k += 2
                    continue
                if ch == "`":
                    in_backtick_subst = not in_backtick_subst
                    k += 1
                    continue
                if ch == "$" and k + 1 < ln and line_str[k + 1] == "(":
                    subst_stack.append("dq")
                    k += 2
                    continue
                if ch == "(" and subst_stack and subst_stack[-1] == "dq":
                    subst_stack.append("dq")
                    k += 1
                    continue
                if ch == ")" and subst_stack and subst_stack[-1] == "dq":
                    subst_stack.pop()
                    k += 1
                    continue
                if ch == '"':
                    subst_qmode = ""
                k += 1

    while line_idx < len(lines):
        raw_line = lines[line_idx]
        stripped_nl = raw_line.rstrip("\r\n")
        nl_suffix = raw_line[len(stripped_nl) :]
        if (
            not subst_stack
            and not in_backtick_subst
            and not subst_qmode
            and "<<" in stripped_nl
            and "python" in stripped_nl.lower()
        ):
            m_hd = _HEREDOC_PY_HEADER_RE.match(stripped_nl)
            if m_hd and not _DANGEROUS_PY_ENV_RE.search(stripped_nl):
                lead_part = m_hd.group("lead") or ""
                m_py_bin = re.search(r"(?P<bin>(?:[^\s;|&'\"`]*/)?python3?(?:\.\d+)?)\b", lead_part, re.IGNORECASE)
                py_bin_raw = m_py_bin.group("bin") if m_py_bin else ""
                bin_ok = bool(py_bin_raw) and (
                    ("/" not in py_bin_raw and "\\" not in py_bin_raw)
                    or py_bin_raw.startswith(("/usr/bin/", "/usr/local/bin/", "/bin/", "/opt/homebrew/bin/"))
                )
                dash = m_hd.group("dash")
                quote_ch = m_hd.group("q")
                delim = m_hd.group("delim")
                trail = m_hd.group("trail") or ""
                trail_head = re.split(r"(?:&&|\|\||;)", trail, maxsplit=1)[0]
                trail_head_clean = bool(re.fullmatch(r"\s*(?:#.*)?", trail_head))
                if bin_ok and trail_head_clean and not _segment_has_unquoted_redirection_or_subst(trail):
                    body_lines: List[str] = []
                    end_idx = line_idx + 1
                    found_end = False
                    while end_idx < len(lines):
                        cand_ln = lines[end_idx].rstrip("\r\n")
                        cmp_ln = cand_ln.lstrip("\t") if dash == "-" else cand_ln
                        if cmp_ln == delim:
                            found_end = True
                            break
                        body_lines.append(cmp_ln if dash == "-" else cand_ln)
                        end_idx += 1
                    if found_end:
                        body_src = "\n".join(body_lines)
                        raw_body_block = "".join(lines[line_idx + 1 : end_idx])
                        unquoted_unsafe = (not quote_ch) and (
                            "$" in body_src or "`" in body_src or "\\\n" in raw_body_block or "\\\r\n" in raw_body_block
                        )
                        if not unquoted_unsafe and _is_pure_readonly_python_snippet(body_src):
                            _advance_subst_state(trail)
                            processed_lines.append(f"__RO_PY__{trail}{nl_suffix}")
                            line_idx = end_idx + 1
                            continue
                        has_unverified = True
                        if not unquoted_unsafe:
                            mutating_sources.append(body_src)
                        _advance_subst_state(stripped_nl)
                        processed_lines.extend(lines[line_idx : end_idx + 1])
                        line_idx = end_idx + 1
                        continue
            has_unverified = True
        _advance_subst_state(stripped_nl)
        processed_lines.append(raw_line)
        line_idx += 1

    rebuilt = "".join(processed_lines)
    if not _ANY_PYTHON_INLINE_OR_HEREDOC_RE.search(rebuilt):
        return rebuilt, has_unverified, mutating_sources

    out_chunks: List[str] = []
    seg_start = 0
    i = 0
    n = len(rebuilt)
    qmode = ""
    paren_depth = 0
    saw_pipe_in_seg = False

    def _can_ast_parse_cleanly(source: str) -> bool:
        if not isinstance(source, str) or not source.strip() or len(source) > 65536 or "\x00" in source:
            return False
        dedented = textwrap.dedent(source)
        if _check_pep263_cookie(dedented) is not None or _check_pep263_cookie(source) is not None:
            return False
        try:
            ast.parse(dedented.encode("utf-8"), mode="exec")
            return True
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return False

    def _process_top_segment(seg_text: str, piped: bool) -> str:
        nonlocal has_unverified
        if "python" not in seg_text.lower() or not _ANY_PYTHON_INLINE_OR_HEREDOC_RE.search(seg_text):
            return seg_text
        if piped or paren_depth > 0:
            m_mod = re.search(r"\bpython3?(?:\.\d+)?\b[^\n;|&]*\s-m\s+([A-Za-z0-9_.]+)", seg_text)
            if m_mod and m_mod.group(1).lower() in _READONLY_PY_M_MODULES and not re.search(r"\s-[A-Za-z0-9]*[ci]\b|<<", seg_text):
                return seg_text
            has_unverified = True
            return seg_text
        m_mod_top = re.search(r"\bpython3?(?:\.\d+)?\b[^\n;|&]*\s-m\s+([A-Za-z0-9_.]+)", seg_text)
        if m_mod_top and not re.search(r"\s-[A-Za-z0-9]*[ci]\b|<<", seg_text):
            if m_mod_top.group(1).lower() not in _READONLY_PY_M_MODULES:
                has_unverified = True
            return seg_text
        py_cands = _try_extract_standalone_py_c(seg_text, all_candidates=True)
        if not py_cands:
            has_unverified = True
            return seg_text
        parseable_cands = [c for c in py_cands if _can_ast_parse_cleanly(c)]
        if parseable_cands and all(_is_pure_readonly_python_snippet(c) for c in parseable_cands):
            leading_ws = seg_text[: len(seg_text) - len(seg_text.lstrip())]
            trailing_ws = seg_text[len(seg_text.rstrip()) :]
            return f"{leading_ws}__RO_PY__{trailing_ws}"
        has_unverified = True
        if parseable_cands:
            for c in parseable_cands:
                if not _is_pure_readonly_python_snippet(c):
                    mutating_sources.append(c)
        else:
            mutating_sources.extend(py_cands)
        return seg_text

    while i < n:
        ch = rebuilt[i]
        if not qmode:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch in ("'", '"'):
                qmode = ch
                i += 1
                continue
            if ch == "(":
                paren_depth += 1
                i += 1
                continue
            if ch == ")":
                paren_depth = max(0, paren_depth - 1)
                i += 1
                continue
            if paren_depth == 0:
                if ch in (";", "\n"):
                    out_chunks.append(_process_top_segment(rebuilt[seg_start:i], saw_pipe_in_seg))
                    out_chunks.append(ch)
                    i += 1
                    seg_start = i
                    saw_pipe_in_seg = False
                    continue
                if rebuilt[i : i + 2] in ("&&", "||"):
                    out_chunks.append(_process_top_segment(rebuilt[seg_start:i], saw_pipe_in_seg))
                    out_chunks.append(rebuilt[i : i + 2])
                    i += 2
                    seg_start = i
                    saw_pipe_in_seg = False
                    continue
                if ch == "|" and rebuilt[i : i + 2] != "||":
                    saw_pipe_in_seg = True
            i += 1
        elif qmode == "'":
            if ch == "'":
                qmode = ""
            i += 1
        else:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                qmode = ""
            i += 1

    out_chunks.append(_process_top_segment(rebuilt[seg_start:], saw_pipe_in_seg))
    return "".join(out_chunks), has_unverified, mutating_sources


@functools.lru_cache(maxsize=256)
def _compiled_governance_root_patterns(root: str) -> Tuple[re.Pattern[str], ...]:
    escaped = re.escape(root)
    interp_names = r"(?:python3?(?:\.\d+)?|py|node|nodejs|deno|bun|ruby|perl|php|lua)"
    ro_m_mods = r"(?:unittest|pytest|py_compile|mypy|ruff|flake8|doctest|cprofile|profile|ast|tokenize|dis)"
    non_hd_flags = rf"\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*|m\s+(?!{ro_m_mods}\b)\S+)\b"
    interp_flags = rf"(?:{non_hd_flags}|<<)"
    same_seg_span = r"(?:[^'\"\n;|&]|'[^']*'|\"(?:\\.|[^\"\\])*\")*?"
    return (
        re.compile(rf">{{1,2}}\|?\s*['\"]?{escaped}"),
        re.compile(rf"\b(?:cd|pushd)\s+['\"]?{escaped}"),
        re.compile(
            rf"\b(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip)\b(?:[^\n;|&]*|\s*\$\([\s\S]*?){escaped}"
        ),
        re.compile(
            rf"{escaped}[^\n;&]*\|\s*(?:{_CMD_WRAPPER_PREFIX})*xargs\b[^\n;&]*\b(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip|sed|{interp_names}|(?:ba|z|da|k)?sh)\b"
        ),
        re.compile(rf"\bfind\b[^\n;|&]*{escaped}[^\n;|&]*\s-(?:delete|exec|execdir|ok)\b"),
        re.compile(
            rf"\bsed\b[^\n;|&]*(?:\s-(?:[A-Za-z]*i\S*|-in-place(?:=\S*)?)\b[^\n;|&]*{escaped}|{escaped}[^\n;|&]*\s-(?:[A-Za-z]*i\S*|-in-place(?:=\S*)?)\b)"
        ),
        re.compile(rf"\b(?:curl|wget)\b[^\n;|&]*\s-(?:o|O)\b[^\n;|&]*{escaped}"),
        re.compile(
            rf"(?:\b{interp_names}\b[^\n;|&]*(?:{non_hd_flags}{same_seg_span}{escaped}|<<[\s\S]*?{escaped})|{escaped}{same_seg_span}(?:\b{interp_names}\b[^\n;|&]*{interp_flags}|\|\s*(?:[A-Za-z0-9_.=/-]+\s+)*{interp_names}\b))"
        ),
    )


def _command_mutates_governance(cmd: str) -> bool:
    """Detects shell commands that write, copy, move, delete, or chmod inside protected governance or Guard state/runtime trees."""
    ro_scrubbed_cmd, saw_unverified_interp, mutating_py_sources = _scrub_verified_readonly_python_invocations(cmd)
    unquoted_expanded = _normalize_governance_globs(_unquote_single_tokens(_expand_simple_shell_vars(ro_scrubbed_cmd)))
    norm_cmd = _normalize_shell_paths(unquoted_expanded)
    has_dotdot_escape = bool(_SHELL_DOTDOT_TOKEN_RE.search(norm_cmd))

    def _path_spellings(p: Path) -> List[str]:
        raw_s = str(p)
        posix_s = p.as_posix()
        esc_bs = raw_s.replace("\\", "\\\\")
        if re.match(r"^[A-Za-z]:/", posix_s):
            win_s = posix_s.replace("/", "\\")
            return list(dict.fromkeys([raw_s, posix_s, win_s, esc_bs, win_s.replace("\\", "\\\\")]))
        return list(dict.fromkeys([raw_s, posix_s, esc_bs]))

    has_parent_escape = (
        has_dotdot_escape
        or bool(_SHELL_DOTDOT_TOKEN_RE.search(ro_scrubbed_cmd.replace("\\", "/")))
        or bool(re.search(r"(?:\.parents?\b|\bdirname\b)", ro_scrubbed_cmd))
    )

    for mut_src in mutating_py_sources:
        if _python_ast_targets_governance(mut_src):
            return True

    # Catch unverified/mutating inline/heredoc/piped interpreter scripts referencing home/env governance paths
    if saw_unverified_interp:
        inline_cmd = ro_scrubbed_cmd
        if not has_parent_escape and "symlink" not in ro_scrubbed_cmd:
            st_variants = "|".join(re.escape(s) for s in _path_spellings(state_dir()))
            inline_cmd = re.sub(
                r"(?:['\"]\.local['\"]\s*/\s*['\"]state['\"]\s*/\s*['\"]antigravity-(?:harness|guard)['\"]\s*/\s*['\"]staging['\"]|"
                rf"(?:{st_variants})(?:[/\\]|\\\\)+staging(?=[/\\]|['\"\s,)])|"
                r"(?:~|\$HOME|[^\s'\"]+)(?:[/\\]|\\\\)+\.local(?:[/\\]|\\\\)+state(?:[/\\]|\\\\)+antigravity-(?:harness|guard)(?:[/\\]|\\\\)+staging(?=[/\\]|['\"\s,)]))",
                "__RUNTIME_STAGING__",
                inline_cmd,
            )
        if re.search(
            r"(?:['\"]\.gemini['\"]\s*(?:/|,)\s*['\"](?:config|GEMINI\.md|AGENTS\.md)['\"]|"
            r"\.gemini(?:[/\\]|\\\\)+(?:config|GEMINI\.md|AGENTS\.md)|"
            r"(?:\.local(?:[/\\]|\\\\)+(?:state|share)|/usr/(?:lib|share))(?:[/\\]|\\\\)+antigravity-(?:harness|guard)|"
            r"Programs(?:[/\\]|\\\\)+antigravity-guard|"
            r"['\"](?:state|share|lib|Programs)['\"]\s*(?:/|,)\s*['\"]antigravity-(?:harness|guard)['\"]|"
            r"['\"]\.local['\"]\s*(?:/|,)\s*['\"]bin['\"]\s*(?:/|,)\s*['\"]agy-|"
            r"\.local(?:[/\\]|\\\\)+bin(?:[/\\]|\\\\)+agy-|"
            r"\b(?:ANTIGRAVITY_CONFIG_DIR|AGY_GUARD_STATE_DIR|ANTIGRAVITY_STATE_DIR|AGY_GUARD_DATA_DIR)\b)",
            inline_cmd,
            re.IGNORECASE,
        ):
            return True
        if re.search(r"['\"]\.gemini['\"]", inline_cmd, re.IGNORECASE) and re.search(
            r"['\"](?:config|GEMINI\.md|AGENTS\.md)['\"]", inline_cmd, re.IGNORECASE
        ):
            return True

    home = Path.home()
    cfg_roots = list(
        dict.fromkeys(
            [
                *(sp for p in _config_root_candidates() for sp in _path_spellings(p)),
                "~/.gemini/config",
                "$HOME/.gemini/config",
            ]
        )
    )
    gemini_top_files = [
        *_path_spellings(home / ".gemini" / "GEMINI.md"),
        *_path_spellings(home / ".gemini" / "AGENTS.md"),
        "~/.gemini/GEMINI.md",
        "$HOME/.gemini/GEMINI.md",
        "~/.gemini/AGENTS.md",
        "$HOME/.gemini/AGENTS.md",
    ]
    for cfg_cand in _config_root_candidates():
        if cfg_cand.name == "config" and cfg_cand.parent.name == ".gemini":
            gemini_top_files.extend(_path_spellings(cfg_cand.parent / "GEMINI.md"))
            gemini_top_files.extend(_path_spellings(cfg_cand.parent / "AGENTS.md"))
    state_roots = list(
        dict.fromkeys(
            [
                *(sp for p in _state_root_candidates() for sp in _path_spellings(p)),
                "~/.local/state/antigravity-harness",
                "$HOME/.local/state/antigravity-harness",
                "~/.local/state/antigravity-guard",
                "$HOME/.local/state/antigravity-guard",
            ]
        )
    )
    custom_root_tokens: List[str] = []
    for c_root in _custom_enforced_governance_roots():
        custom_root_tokens.extend(_path_spellings(c_root))
        try:
            rel_home = c_root.relative_to(home).as_posix()
            if rel_home and rel_home != ".":
                custom_root_tokens.append(f"~/{rel_home}")
                custom_root_tokens.append(f"$HOME/{rel_home}")
        except ValueError:
            pass
    guard_roots = list(
        dict.fromkeys(
            state_roots
            + gemini_top_files
            + [
                *_path_spellings(data_dir()),
                *_path_spellings(data_dir() / "runtime"),
                *_path_spellings(data_dir() / "snapshots"),
                "~/.local/share/antigravity-harness",
                "$HOME/.local/share/antigravity-harness",
                "~/.local/share/antigravity-guard",
                "$HOME/.local/share/antigravity-guard",
                *_path_spellings(home / ".local" / "bin" / "agy-guard"),
                *_path_spellings(home / ".local" / "bin" / "agy-porter"),
                "~/.local/bin/agy-guard",
                "$HOME/.local/bin/agy-guard",
                "~/.local/bin/agy-porter",
                "$HOME/.local/bin/agy-porter",
                "/usr/bin/agy-guard",
                "/usr/bin/agy-porter",
                "/usr/lib/antigravity-guard",
                "/usr/share/antigravity-harness",
                *(
                    [
                        *_path_spellings(home / ".local" / "bin" / "porter"),
                        "~/.local/bin/porter",
                        "$HOME/.local/bin/porter",
                    ]
                    if (home / ".local" / "bin" / "porter") in _governance_roots()
                    else []
                ),
                *(
                    _path_spellings(Path(os.environ.get("LOCALAPPDATA") or (home / "AppData" / "Local")) / "Programs" / "antigravity-guard")
                    if os.name == "nt"
                    else []
                ),
                *custom_root_tokens,
            ]
        )
    )
    roots = list(dict.fromkeys(cfg_roots + guard_roots))
    if not any(tok in norm_cmd for tok in roots):
        return False
    # Strip references to non-governance runtime subdirectories under ~/.gemini/config
    # ONLY when no `..`/`.parent` traversal, link creation (`ln`), or archive extraction (`tar`/`unzip`) is present.
    scrubbed = norm_cmd
    if not has_parent_escape and not re.search(r"\b(?:ln|tar|unzip)\b", scrubbed):
        for root in cfg_roots:
            if root in scrubbed:
                for rx_sub, repl_sub in _compiled_cfg_subdir_patterns(root):
                    scrubbed = rx_sub.sub(repl_sub, scrubbed)
        for st_root in state_roots:
            if st_root in scrubbed:
                scrubbed = _compiled_state_staging_pattern(st_root).sub("__RUNTIME_SUBDIR__", scrubbed)
    if not any(tok in scrubbed for tok in roots):
        return False
    # Read-only commands are permitted only when not redirecting or running mutating flags/interpreters
    has_mut_ind: Optional[bool] = None
    for root in roots:
        if root not in scrubbed:
            continue
        rx_redir, rx_cd, rx_verb, rx_xargs, rx_find, rx_sed, rx_dl, rx_interp = _compiled_governance_root_patterns(root)
        if rx_redir.search(scrubbed):
            return True
        if rx_cd.search(scrubbed):
            if has_mut_ind is None:
                has_mut_ind = bool(_SHELL_MUTATION_INDICATOR_RE.search(scrubbed))
            if has_mut_ind:
                return True
        if (
            rx_verb.search(scrubbed)
            or rx_xargs.search(scrubbed)
            or rx_find.search(scrubbed)
            or rx_sed.search(scrubbed)
            or rx_dl.search(scrubbed)
            or rx_interp.search(scrubbed)
        ):
            return True
    return False

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
    r"guard\.py\b|porter\.py\b|install\.py\b|scripts/meta_audit\.py\b|scripts/verify_invariants\.py\b)"
)

_CUST_CMD_HARNESS_DIRS_PAT = r"(?:^|[\s'\"=/])(?:skills|agents|guard|porter|templates)(?:/|\b)"

_CUST_CMD_HARNESS_SLASH_DIRS_PAT = r"(?:^|[\s'\"=/])(?:skills|agents|guard|porter|templates)/(?=[^\s;|&'\"]|$)"

_CUST_CMD_TARGET_PAT = (
    r"(?:\.agents?\b|_agents?\b|\.claude\b|\.cursor\b|\.harness\b|"
    r"(?:^|[\s'\"=/])(?:skills|agents|guard|porter|templates)(?:/|\b)|"
    r"GEMINI\.md\b|AGENTS\.md\b|CLAUDE\.md\b|DESIGN\.md\b|hooks\.json\b|"
    r"mcp_config\.json\b|skills\.json\b|plugins\.json\b|\.cursorrules\b|"
    r"SKILL\.md\b|[A-Za-z0-9_.-]+\.mdc\b|"
    r"guard\.py\b|porter\.py\b|install\.py\b|scripts/meta_audit\.py\b|scripts/verify_invariants\.py\b)"
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
    top_name = "Gemini 4 Hydrogen (XHigh)"
    top_slug = "gemini-4-hydrogen-xhigh"
    peer_slugs: set[str] = set()
    seed_candidates = [
        _repo_root() / "skills" / "upstream-auditor" / "upstream_state.seed.json",
        configured_config_dir() / "skills" / "upstream-auditor" / "upstream_state.seed.json",
        config_dir() / "skills" / "upstream-auditor" / "upstream_state.seed.json",
        Path("/usr/share/antigravity-harness") / "skills" / "upstream-auditor" / "upstream_state.seed.json",
    ]
    for candidate in seed_candidates:
        if candidate.is_file():
            data = read_json(candidate, default={})
            if isinstance(data, dict) and data:
                raw_name = str(data.get("last_audited_model") or "").strip()
                raw_slug = _normalize_model_slug(str(data.get("last_model_slug") or raw_name))
                if not (raw_name or raw_slug):
                    continue
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
        Path.home() / ".local" / "state" / "antigravity-harness" / "upstream_state.json",
    ]
    for st_path in state_candidates:
        if st_path.is_file():
            st_data = read_json(st_path, default={})
            if isinstance(st_data, dict):
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
    """Walks bounded ancestors of `path` to locate an enclosing Antigravity Harness checkout."""
    try:
        cur = Path(os.path.abspath(path))
    except (OSError, RuntimeError, ValueError):
        return None
    for idx, anc in enumerate((cur, *cur.parents)):
        if idx > 24 or anc == Path(anc.anchor):
            break
        if _is_harness_repo_root(anc):
            return anc
    return None

def _workspaces_in_harness_scope(workspaces: Sequence[Path], effective_cwd: Optional[Path]) -> bool:
    """True when active workspace/cwd context is a harness checkout or completely unspecified."""
    if effective_cwd is not None:
        return _find_harness_repo_root(effective_cwd) is not None
    if workspaces:
        return any(_find_harness_repo_root(ws) is not None for ws in workspaces)
    return True

def _targets_customization_structure(target_path_str: str, workspace: Optional[Path] = None) -> bool:
    """
    Returns True when `target_path_str` points to a customization or harness governance
    artifact (`.agents/`, `.claude/`, `.cursor/`, `.harness/`, `GEMINI.md`, `AGENTS.md`,
    `DESIGN.md`, `hooks.json`, `SKILL.md`, `.mdc`, or harness source `skills/`, `agents/`,
    `guard/`, `porter/`, `porter.py`, `install.py`, `scripts/meta_audit.py`).
    """
    if not target_path_str or not target_path_str.strip():
        return False
    raw = os.path.expanduser(target_path_str.strip()).replace("\\", "/")
    collapsed = _normalize_shell_paths(raw if raw.startswith("/") else f"/{raw}")
    norm = re.sub(r"^/+", "", collapsed) if not raw.startswith("/") else collapsed
    norm = re.sub(r"^\./+", "", norm)
    parts = [p for p in norm.split("/") if p and p != "."]
    if not parts:
        return False

    basename_lower = parts[-1].lower()
    if basename_lower in _CUSTOMIZATION_BASENAMES or basename_lower.endswith(".mdc"):
        return True
    if any(p.lower() in _CUSTOMIZATION_DIR_SEGMENTS for p in parts):
        return True

    expanded = Path(os.path.expanduser(target_path_str.strip()))
    base_ws = workspace if workspace is not None else _repo_root()
    cand_raw = expanded if expanded.is_absolute() else (base_ws / expanded)

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
        c_parts = [p.lower() for p in cand_path.parts if p]
        if not c_parts:
            continue
        if c_parts[-1] in _CUSTOMIZATION_BASENAMES or c_parts[-1].endswith(".mdc"):
            return True
        if any(p in _CUSTOMIZATION_DIR_SEGMENTS for p in c_parts):
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
                    rel_norm in _HARNESS_SOURCE_FILES or rel_parts[0] in _HARNESS_SOURCE_TOP_DIRS
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
    if re.search(_CUST_CMD_UNIVERSAL_TARGET_PAT, text, re.IGNORECASE):
        return True
    ws_ctx = effective_cwd if effective_cwd is not None else fallback_ws
    if _workspaces_in_harness_scope(workspaces, ws_ctx) and re.search(
        _CUST_CMD_HARNESS_SLASH_DIRS_PAT, text, re.IGNORECASE
    ):
        return True
    candidate_tokens: List[str] = list(extra_tokens)
    for tok in re.findall(r"[^\s'\"`,;()\[\]{}<>]+", text):
        if "/" in tok or "\\" in tok or "." in tok or tok.startswith("~"):
            candidate_tokens.append(tok)
    for cand in candidate_tokens:
        if _targets_governance_dir(cand):
            return True
        if _targets_customization_structure(cand, workspace=ws_ctx):
            return True
        for ws in workspaces:
            if ws != ws_ctx and _targets_customization_structure(cand, workspace=ws):
                return True
    return False

def _command_mutates_customization_structure(cmd: str, *, harness_scope: bool = True) -> bool:
    """Detects shell commands that write, overwrite, move, delete, or regenerate customization/governance files."""
    if "python" in cmd.lower() or _NON_PYTHON_INTERP_RE.search(cmd):
        ro_cmd, saw_unv_cust, mut_py_cust = _scrub_verified_readonly_python_invocations(cmd)
    else:
        ro_cmd, saw_unv_cust, mut_py_cust = cmd, False, []

    def _neutralize_ro_exec_argv(src_text: str) -> str:
        if not _EXEC_CALL_ARGV_RE.search(src_text):
            return src_text

        def _repl(m: re.Match[str]) -> str:
            argv_src = m.group(1) if m.group(1) is not None else (m.group(2) or "")
            parts = [
                tm.group(1) if tm.group(1) is not None else (tm.group(2) or "")
                for tm in _STR_ARGV_TOKEN_RE.finditer(argv_src)
            ]
            synth = " ".join(parts).strip()
            if (
                synth
                and synth != cmd.strip()
                and not _EXEC_CALL_ARGV_RE.search(synth)
                and not _command_mutates_customization_structure(synth, harness_scope=harness_scope)
            ):
                full_m = m.group(0)
                return full_m[: full_m.find("(") + 1] + "None"
            return m.group(0)

        return _EXEC_CALL_ARGV_RE.sub(_repl, src_text)

    ro_cmd = _neutralize_ro_exec_argv(ro_cmd)
    mut_py_cust = [_neutralize_ro_exec_argv(ms) for ms in mut_py_cust]
    norm_cmd = _normalize_shell_paths(_unquote_single_tokens(_expand_simple_shell_vars(ro_cmd)))
    masked_cmd = _mask_quoted_operators(norm_cmd)
    has_subshell_c = bool(re.search(r"\b(?:ba|z|da|k)?sh\s+-(?:[A-Za-z]*c)\b", norm_cmd))
    verb_haystack = norm_cmd if has_subshell_c else masked_cmd
    target_pat = _CUST_CMD_TARGET_PAT if harness_scope else _CUST_CMD_UNIVERSAL_TARGET_PAT
    cd_harness_dirs = r"['\"]?(?:skills|agents|guard|porter|templates)(?:/|\b)|" if harness_scope else ""
    cmd_start = (
        r"(?:^|[;&|()\n])\s*"
        rf"{_CMD_WRAPPER_PREFIX}"
        r"(?:(?:ba|z|da|k)?sh\s+-(?:[A-Za-z]*c)\s+['\"]?\s*)*"
    )

    if re.search(rf">{{1,2}}\|?\s*['\"]?[^\s;|&'\"]*{target_pat}", norm_cmd):
        return True
    if re.search(
        rf"\b(?:cd|pushd)\s+(?:{cd_harness_dirs}['\"]?[^\s;|&'\"]*{target_pat})",
        norm_cmd,
    ) and _SHELL_MUTATION_INDICATOR_RE.search(norm_cmd):
        return True
    if re.search(
        rf"{cmd_start}(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip)\b[^\n;|&]*{target_pat}",
        verb_haystack,
    ):
        return True
    if re.search(
        rf"{target_pat}[^\n;&]*\|\s*(?:{_CMD_WRAPPER_PREFIX})*xargs\b[^\n;&]*\b(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip|sed)\b",
        norm_cmd,
    ):
        return True
    if re.search(rf"{cmd_start}find\b[^\n;|&]*{target_pat}[^\n;|&]*\s-(?:delete|exec|execdir|ok)\b", norm_cmd):
        return True
    if re.search(
        rf"{cmd_start}sed\b[^\n;|&]*(?:\s-(?:[A-Za-z]*i\S*|-in-place(?:=\S*)?)\b[^\n;|&]*{target_pat}|{target_pat}[^\n;|&]*\s-(?:[A-Za-z]*i\S*|-in-place(?:=\S*)?)\b)",
        norm_cmd,
    ):
        return True
    if re.search(rf"{cmd_start}(?:curl|wget)\b[^\n;|&]*\s-(?:o|O)\b[^\n;|&]*{target_pat}", norm_cmd):
        return True
    if re.search(
        rf"(?:\b(?:python3?(?:\.\d+)?|py|node|nodejs|deno|bun|ruby|perl|php|lua)\b[^\n;|&]*(?:\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*)\b[^\n;|&]*{target_pat}|<<[\s\S]*?{target_pat})|{target_pat}[^\n;|&]*\b(?:python3?(?:\.\d+)?|py|node|nodejs|deno|bun|ruby|perl|php|lua)\b[^\n;|&]*\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*)\b)",
        norm_cmd,
    ):
        return True
    if saw_unv_cust and mut_py_cust:
        for mut_src in mut_py_cust:
            if re.search(target_pat, mut_src):
                return True
    if re.search(r"\bporter\.py\s+manifest\b(?![^\n;|&]*--check)", norm_cmd):
        return True
    return False

def _is_model_placeholder(label: Any) -> bool:
    """Returns True when `label` is an opaque Antigravity model placeholder such as `MODEL_PLACEHOLDER_M417`."""
    return isinstance(label, str) and label.strip().upper().startswith("MODEL_PLACEHOLDER")

def _seed_placeholder_diagnostic(placeholder_id: str, *, effort_verified: bool = False) -> str:
    """Checks canonical `upstream_state.seed.json` entries to produce a diagnostic alias hint."""
    target_up = placeholder_id.strip().upper()
    eff_note = (
        "effort verified in payload, model identity unverified"
        if effort_verified
        else "effort unverified in payload"
    )
    seed_paths = [
        _repo_root() / "skills" / "upstream-auditor" / "upstream_state.seed.json",
        configured_config_dir() / "skills" / "upstream-auditor" / "upstream_state.seed.json",
        config_dir() / "skills" / "upstream-auditor" / "upstream_state.seed.json",
        Path("/usr/share/antigravity-harness/skills/upstream-auditor/upstream_state.seed.json"),
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
            is_known_non_flagship = bool(
                re.search(
                    r"\b(?:flash|lite|mini|nano|small|haiku|sonnet|gpt-4o|gpt-3\.5)\b",
                    eff_slug,
                )
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
            return (
                "deny",
                (
                    "[Harness Customization Model Gate] Modifying customization or governance architecture "
                    f"requires the catalog's top model and highest effort (`{top_name}` / approved: `{', '.join(sorted(allowed_slugs))}`); "
                    f"active model is `{effective_model or 'auto'}`"
                    f"{f' at effort `{effective_effort}`' if has_eff else ''} (GEMINI.md Rule 17)."
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
    highest effort (`Gemini 4 Hydrogen (XHigh)` / approved flagships in `upstream_state.seed.json`).
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

_WORKFLOW_MAX_BYTES = 1024 * 1024

_WORKFLOW_MAX_ARG_DEPTH = 32

_WORKFLOW_MAX_FOLDED_LEN = 16384

_WORKFLOW_READONLY_MODE_RE = _LazyRegex(r"^[rtbU]+$")

_WORKFLOW_ARCHIVE_READONLY_MODE_RE = _LazyRegex(r"^(?:r(?::[a-z0-9*]*)?|[rtb]+)$")

_PEP263_ENCODING_RE = _LazyRegex(r"coding[:=]\s*([-\w.]+)")

_SAFE_ENVIRON_READ_METHODS = frozenset({"get", "keys", "values", "items", "copy"})

def _check_pep263_cookie(source_text: str) -> Optional[str]:
    for header_line in source_text.splitlines()[:2]:
        if header_line.lstrip(" \t\ufeff").startswith("#"):
            m_enc = _PEP263_ENCODING_RE.search(header_line)
            if m_enc and m_enc.group(1).lower() not in (
                "utf-8",
                "utf8",
                "utf_8",
                "utf-8-sig",
                "ascii",
                "us-ascii",
            ):
                return (
                    f"[Harness Workflow Shield] Non-UTF-8 PEP 263 encoding cookie "
                    f"(`{m_enc.group(1)}`) inside `run_workflow` script is prohibited."
                )
    return None

def _collect_workflow_arg_strings(value: Any, out: List[str], depth: int = 0) -> Optional[str]:
    try:
        from . import _workflow_ast
    except (ImportError, SyntaxError) as exc:
        return f"[Harness Workflow Shield] Failed to load workflow AST verifier ({type(exc).__name__}): {exc}"

    return _workflow_ast._collect_workflow_arg_strings(value, out, depth)


def _extract_workflow_sources_ex(
    args: Dict[str, Any], workspace: Optional[Path]
) -> Tuple[List[str], List[str], Optional[Path], List[Tuple[Path, int]], Optional[str]]:
    try:
        from . import _workflow_ast
    except (ImportError, SyntaxError) as exc:
        return (
            [],
            [],
            None,
            [],
            f"[Harness Workflow Shield] Failed to load workflow AST verifier ({type(exc).__name__}): {exc}",
        )

    return _workflow_ast._extract_workflow_sources_ex(args, workspace)


def _extract_workflow_sources(
    args: Dict[str, Any], workspace: Optional[Path]
) -> Tuple[List[str], List[str], Optional[Path], Optional[str]]:
    try:
        from . import _workflow_ast
    except (ImportError, SyntaxError) as exc:
        return (
            [],
            [],
            None,
            f"[Harness Workflow Shield] Failed to load workflow AST verifier ({type(exc).__name__}): {exc}",
        )

    return _workflow_ast._extract_workflow_sources(args, workspace)

def _eval_workflow_str_expr(node: Optional[ast.AST], const_vars: Dict[str, str], depth: int = 0) -> Optional[str]:
    if node is None or depth > 24:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value if len(node.value) <= _WORKFLOW_MAX_FOLDED_LEN else None
    if isinstance(node, ast.Name) and node.id in const_vars:
        val = const_vars[node.id]
        return val if len(val) <= _WORKFLOW_MAX_FOLDED_LEN else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_workflow_str_expr(node.left, const_vars, depth + 1)
        right = _eval_workflow_str_expr(node.right, const_vars, depth + 1)
        if left is not None and right is not None and len(left) + len(right) <= _WORKFLOW_MAX_FOLDED_LEN:
            return left + right
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], (ast.List, ast.Tuple))
    ):
        sep = _eval_workflow_str_expr(node.func.value, const_vars, depth + 1)
        if sep is not None and len(node.args[0].elts) <= 128:
            items = [_eval_workflow_str_expr(elt, const_vars, depth + 1) for elt in node.args[0].elts]
            if all(it is not None for it in items):
                joined = sep.join(it for it in items if it is not None)
                if len(joined) <= _WORKFLOW_MAX_FOLDED_LEN:
                    return joined
    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        total_len = 0
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                total_len += len(val.value)
                if total_len > _WORKFLOW_MAX_FOLDED_LEN:
                    return None
                parts.append(val.value)
            elif isinstance(val, ast.FormattedValue):
                inner = _eval_workflow_str_expr(val.value, const_vars, depth + 1)
                if inner is None:
                    return None
                total_len += len(inner)
                if total_len > _WORKFLOW_MAX_FOLDED_LEN:
                    return None
                parts.append(inner)
            else:
                return None
        return "".join(parts)
    return None

def _eval_workflow_path_expr(node: Optional[ast.AST], const_vars: Dict[str, str], depth: int = 0) -> Optional[str]:
    if node is None or depth > 24:
        return None
    as_str = _eval_workflow_str_expr(node, const_vars, depth)
    if as_str is not None:
        return as_str
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        base_parent = _eval_workflow_path_expr(node.value, const_vars, depth + 1)
        if base_parent is not None:
            trimmed = base_parent.rstrip("/\\") or base_parent
            parent_out = os.path.dirname(trimmed) or "."
            return parent_out if len(parent_out) <= _WORKFLOW_MAX_FOLDED_LEN else None
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
        and (
            (isinstance(node.value, ast.Name) and node.value.id == "environ")
            or (isinstance(node.value, ast.Attribute) and node.value.attr == "environ")
        )
    ):
        env_val = os.environ.get(node.slice.value)
        if env_val:
            return env_val if len(env_val) <= _WORKFLOW_MAX_FOLDED_LEN else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _eval_workflow_path_expr(node.left, const_vars, depth + 1)
        right = _eval_workflow_path_expr(node.right, const_vars, depth + 1)
        if left is not None and right is not None:
            joined = os.path.join(left, right)
            return joined if len(joined) <= _WORKFLOW_MAX_FOLDED_LEN else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_workflow_path_expr(node.left, const_vars, depth + 1)
        right = _eval_workflow_path_expr(node.right, const_vars, depth + 1)
        if left is not None and right is not None:
            concat = f"{left}{right}"
            return concat if len(concat) <= _WORKFLOW_MAX_FOLDED_LEN else None
    if isinstance(node, ast.Call):
        if any(isinstance(a, ast.Starred) for a in node.args) or any(kw.arg is None for kw in node.keywords):
            return None
        if ((isinstance(node.func, ast.Name) and node.func.id in ("Path", "PurePath", "PosixPath", "WindowsPath", "PurePosixPath", "PureWindowsPath")) or (isinstance(node.func, ast.Attribute) and node.func.attr in ("Path", "PurePath", "PosixPath", "WindowsPath", "PurePosixPath", "PureWindowsPath"))):
            if not node.args:
                return "."
            parts = [_eval_workflow_path_expr(a, const_vars, depth + 1) for a in node.args]
            if all(p is not None for p in parts):
                non_none = [p for p in parts if p is not None]
                joined = os.path.join(*non_none) if non_none else "."
                return (joined or ".") if len(joined) <= _WORKFLOW_MAX_FOLDED_LEN else None
        if isinstance(node.func, ast.Name) and node.func.id == "str" and len(node.args) == 1:
            return _eval_workflow_path_expr(node.args[0], const_vars, depth + 1)
        if isinstance(node.func, ast.Name) and node.func.id in ("expanduser", "abspath", "realpath", "normpath") and len(node.args) == 1:
            arg0 = _eval_workflow_path_expr(node.args[0], const_vars, depth + 1)
            if arg0 is not None:
                out = os.path.expanduser(arg0) if node.func.id == "expanduser" else arg0
                return out if len(out) <= _WORKFLOW_MAX_FOLDED_LEN else None
        if isinstance(node.func, ast.Name) and node.func.id == "join" and node.args:
            parts = [_eval_workflow_path_expr(a, const_vars, depth + 1) for a in node.args]
            if all(p is not None for p in parts):
                joined = os.path.join(*(p for p in parts if p is not None))
                return joined if len(joined) <= _WORKFLOW_MAX_FOLDED_LEN else None
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("expanduser", "resolve", "absolute") and not node.args:
                base = _eval_workflow_path_expr(node.func.value, const_vars, depth + 1)
                if base is not None:
                    out = os.path.expanduser(base) if node.func.attr == "expanduser" else base
                    return out if len(out) <= _WORKFLOW_MAX_FOLDED_LEN else None
            if node.func.attr in ("expanduser", "abspath", "realpath", "normpath") and len(node.args) == 1:
                arg0 = _eval_workflow_path_expr(node.args[0], const_vars, depth + 1)
                if arg0 is not None:
                    out = os.path.expanduser(arg0) if node.func.attr == "expanduser" else arg0
                    return out if len(out) <= _WORKFLOW_MAX_FOLDED_LEN else None
            if node.func.attr == "home" and not node.args:
                return str(Path.home())
            if node.func.attr in ("getenv", "get") and len(node.args) >= 1:
                env_key = _eval_workflow_str_expr(node.args[0], const_vars, depth + 1)
                if env_key in (
                    "HOME",
                    "USERPROFILE",
                    "ANTIGRAVITY_CONFIG_DIR",
                    "AGY_GUARD_STATE_DIR",
                    "ANTIGRAVITY_STATE_DIR",
                    "AGY_GUARD_DATA_DIR",
                    "XDG_STATE_HOME",
                    "XDG_DATA_HOME",
                ):
                    env_v = os.environ.get(env_key)
                    if env_v:
                        return env_v if len(env_v) <= _WORKFLOW_MAX_FOLDED_LEN else None
            if node.func.attr == "join" and node.args:
                parts = [_eval_workflow_path_expr(a, const_vars, depth + 1) for a in node.args]
                if all(p is not None for p in parts):
                    joined = os.path.join(*(p for p in parts if p is not None))
                    return joined if len(joined) <= _WORKFLOW_MAX_FOLDED_LEN else None
            if node.func.attr == "joinpath" and node.args:
                base = _eval_workflow_path_expr(node.func.value, const_vars, depth + 1)
                parts = [_eval_workflow_path_expr(a, const_vars, depth + 1) for a in node.args]
                if base is not None and all(p is not None for p in parts):
                    joined = os.path.join(base, *(p for p in parts if p is not None))
                    return joined if len(joined) <= _WORKFLOW_MAX_FOLDED_LEN else None
    return None

def _is_readonly_open_call(node: ast.Call, mode_pos_index: int, const_vars: Dict[str, str], archive: bool = False) -> bool:
    if any(isinstance(a, ast.Starred) for a in node.args):
        return False
    if len(node.args) > mode_pos_index + 1:
        return False
    allowed_kw = (
        ("name", "file", "mode", "fileobj", "pwd", "compresslevel", "preset")
        if archive
        else (
            ("file", "mode", "buffering", "encoding", "errors", "newline", "closefd")
            if mode_pos_index == 1
            else ("mode", "buffering", "encoding", "errors", "newline")
        )
    )
    for kw in node.keywords:
        if kw.arg is None or kw.arg not in allowed_kw:
            return False
    mode_node: Optional[ast.AST] = None
    if len(node.args) > mode_pos_index:
        mode_node = node.args[mode_pos_index]
    else:
        for kw in node.keywords:
            if kw.arg == "mode":
                mode_node = kw.value
                break
    if mode_node is None:
        return True
    mode_val = _eval_workflow_str_expr(mode_node, const_vars)
    if mode_val is None or not mode_val:
        return False
    if archive:
        return bool(_WORKFLOW_ARCHIVE_READONLY_MODE_RE.match(mode_val))
    return bool(_WORKFLOW_READONLY_MODE_RE.match(mode_val)) and ("r" in mode_val or "U" in mode_val)

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

def _payload_cwd(payload: Dict[str, Any], args: Dict[str, Any]) -> Optional[Path]:
    for container in (args, payload):
        if not isinstance(container, dict):
            continue
        for key in ("cwd", "Cwd", "workingDirectory", "working_directory"):
            val = container.get(key)
            if isinstance(val, str) and val.strip():
                return Path(os.path.expanduser(val.strip()))
    return None

def _cmd_input_buffer_key(payload: Dict[str, Any], args: Dict[str, Any]) -> str:
    conv_id = _conversation_id(payload)
    task_id = (
        str(
            args.get("TaskId")
            or args.get("taskId")
            or args.get("task_id")
            or args.get("CommandId")
            or "default"
        ).strip()
        or "default"
    )
    return f"{conv_id}::{task_id}"

def _has_unclosed_shell_quote(text: str) -> bool:
    in_sq = False
    in_dq = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_sq:
            if ch == "'":
                in_sq = False
            i += 1
            continue
        if in_dq:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_dq = False
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch == "'":
            in_sq = True
        elif ch == '"':
            in_dq = True
        i += 1
    return in_sq or in_dq

def _compute_trailing_cmd_buffer(combined_input: str) -> str:
    folded = _join_shell_line_continuations(combined_input)
    if _has_unclosed_shell_quote(folded):
        return folded[-4096:]
    return folded.rsplit("\n", 1)[-1].rsplit("\r", 1)[-1][-4096:]

def _load_cmd_input_prefix(payload: Dict[str, Any], args: Dict[str, Any]) -> Tuple[str, str]:
    buf_key = _cmd_input_buffer_key(payload, args)
    buf_file = state_dir() / "cmd_input_buffers.json"
    buf_ok, data = _read_ledger_checked(buf_file)
    if not buf_ok or not isinstance(data, dict):
        return buf_key, ""
    val = data.get(buf_key)
    return buf_key, (val if isinstance(val, str) else "")

def _save_cmd_input_prefix(buf_key: str, combined_input: str) -> None:
    trailing = _compute_trailing_cmd_buffer(combined_input)
    buf_file = state_dir() / "cmd_input_buffers.json"
    try:
        with file_lock(buf_file, timeout=HOOK_LOCK_TIMEOUT):
            _buf_ok, data = _read_ledger_checked(buf_file)
            if not isinstance(data, dict):
                data = {}
            if trailing:
                data[buf_key] = trailing
                if len(data) > 64:
                    oldest_key = next(iter(data))
                    if oldest_key != buf_key:
                        data.pop(oldest_key, None)
            else:
                data.pop(buf_key, None)
            atomic_write_json(buf_file, data)
    except (OSError, TimeoutError):
        pass

_SHELL_VERB_SKIP_NAMES = frozenset({
    "rm",
    "mv",
    "cp",
    "chmod",
    "chattr",
    "chown",
    "tee",
    "touch",
    "mkdir",
    "rmdir",
    "ln",
    "install",
    "rsync",
    "tar",
    "dd",
    "truncate",
    "shred",
    "patch",
    "unzip",
    "sed",
    "find",
    "xargs",
    "curl",
    "wget",
    "git",
    "sudo",
    "env",
    "timeout",
    "nice",
    "nohup",
    "command",
    "exec",
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "python",
    "python3",
    "py",
    "node",
    "ruby",
    "perl",
    "echo",
    "printf",
    "cat",
})

def _extract_shell_path_tokens(sub_cmd: str) -> List[str]:
    expanded = _unquote_single_tokens(_strip_unquoted_shell_comments(_expand_simple_shell_vars(sub_cmd)))
    no_multi_quotes = _QUOTED_SPAN_RE.sub(" ", expanded)
    out: List[str] = []
    for raw_tok in re.findall(r"[^\s;|&()<>\"'`]+", no_multi_quotes):
        tok = raw_tok.strip()
        if not tok or tok.startswith("-"):
            if "=" in tok:
                tok = tok.split("=", 1)[1].strip()
            else:
                continue
        elif "=" in tok and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok):
            tok = tok.split("=", 1)[1].strip()
        if not tok or tok.lower() in _SHELL_VERB_SKIP_NAMES:
            continue
        if re.match(r"^s/[^/]*/[^/]*/[gip0-9]*$", tok) or tok.isdigit():
            continue
        out.append(tok)
    for m_q in _QUOTED_SPAN_RE.finditer(expanded):
        raw_q = m_q.group(0)
        inner = raw_q[1:-1].strip()
        if raw_q.startswith('"') and re.match(r"^[A-Za-z]:\\", inner):
            inner = inner.replace("\\\\", "\\")
        if inner and "\n" not in inner and ("/" in inner or "\\" in inner or inner.endswith(".md") or inner.endswith(".py") or inner.endswith(".json")):
            out.append(inner)
    return out

def _shell_has_unquoted_mutation(sub_cmd: str) -> bool:
    expanded = _unquote_single_tokens(_strip_unquoted_shell_comments(sub_cmd))
    scrubbed = _QUOTED_SPAN_RE.sub('"__QUOTED__"', expanded)
    if not _SHELL_MUTATION_INDICATOR_RE.search(scrubbed):
        return False
    if "python" in sub_cmd.lower():
        ro_scrubbed, _unverified, _mut_srcs = _scrub_verified_readonly_python_invocations(sub_cmd)
        if ro_scrubbed != sub_cmd:
            exp_ro = _unquote_single_tokens(_strip_unquoted_shell_comments(ro_scrubbed))
            scrubbed_ro = _QUOTED_SPAN_RE.sub('"__QUOTED__"', exp_ro)
            return bool(_SHELL_MUTATION_INDICATOR_RE.search(scrubbed_ro))
    return True

_CD_SEG_RE = _LazyRegex(
    r"^\s*\(*\s*(?:builtin\s+|command\s+)?(?P<verb>cd|pushd|popd)(?:\s+(?P<rest>.*))?$"
)

_INLINE_DIR_FLAG_RE = _LazyRegex(
    r"(?:^|\s)(?:-C\s+(?P<c_arg>'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+)|--(?:directory|chdir)(?:=(?P<eq_arg>'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+)|\s+(?P<sp_arg>'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+)))"
)

def _resolve_shell_dir_token(raw_tok: str, cur_cwd: Optional[Path]) -> Optional[Path]:
    unq = raw_tok.strip().strip("'\"")
    if not unq or unq == "-":
        return cur_cwd
    home_str = str(Path.home())
    unq = unq.replace("${HOME}", home_str)
    unq = re.sub(r"\$HOME(?![A-Za-z0-9_])", lambda _m: home_str, unq)
    exp = Path(os.path.expanduser(unq))
    if exp.is_absolute():
        return Path(os.path.abspath(exp))
    if cur_cwd is not None:
        return Path(os.path.abspath(cur_cwd / exp))
    return None

def _iter_shell_segments_with_cwd(
    sub_cmd: str, initial_cwd: Optional[Path]
) -> List[Tuple[str, Optional[Path]]]:
    cleaned = _strip_unquoted_shell_comments(_join_shell_line_continuations(_expand_simple_shell_vars(sub_cmd)))
    segments = re.split(r"(?:&&|\|\||;|\n|(?<![>&])&(?!>))", cleaned)
    cur_cwd: Optional[Path] = initial_cwd
    dir_stack: List[Optional[Path]] = []
    out: List[Tuple[str, Optional[Path]]] = []
    for seg in segments:
        if not seg.strip():
            continue
        m_cd = _CD_SEG_RE.match(seg)
        if m_cd:
            verb = m_cd.group("verb")
            rest = m_cd.group("rest") or ""
            if verb == "popd":
                if dir_stack:
                    cur_cwd = dir_stack.pop()
                out.append((seg, cur_cwd))
                continue
            toks = re.findall(r"'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+", rest)
            cd_target: Optional[str] = None
            idx = 0
            while idx < len(toks):
                t = toks[idx]
                if t in (">", ">>", "<", "2>", "2>&1", "&>"):
                    idx += 2
                    continue
                if t.startswith((">", "<", "2>")):
                    idx += 1
                    continue
                if t == "--":
                    if idx + 1 < len(toks):
                        cd_target = toks[idx + 1]
                    break
                if t.startswith("-") and t != "-":
                    idx += 1
                    continue
                cd_target = t
                break
            new_cwd = Path.home() if cd_target is None else _resolve_shell_dir_token(cd_target, cur_cwd)
            if verb == "pushd":
                dir_stack.append(cur_cwd)
            cur_cwd = new_cwd
            out.append((seg, cur_cwd))
            continue

        out.append((seg, cur_cwd))
        for m_flag in _INLINE_DIR_FLAG_RE.finditer(seg):
            raw_dir = m_flag.group("c_arg") or m_flag.group("eq_arg") or m_flag.group("sp_arg") or ""
            flag_cwd = _resolve_shell_dir_token(raw_dir, cur_cwd)
            if flag_cwd is not None and flag_cwd != cur_cwd:
                out.append((seg, flag_cwd))
    return out

def _command_mutates_governance_in_cwd(sub_cmd: str, effective_cwd: Optional[Path]) -> bool:
    if "python" in sub_cmd.lower() or _NON_PYTHON_INTERP_RE.search(sub_cmd):
        ro_scrubbed, _saw_unv, mut_srcs = _scrub_verified_readonly_python_invocations(sub_cmd)
    else:
        ro_scrubbed, mut_srcs = sub_cmd, []
    seen_cwds: List[Optional[Path]] = [effective_cwd]
    for seg, seg_cwd in _iter_shell_segments_with_cwd(ro_scrubbed, effective_cwd):
        if seg_cwd not in seen_cwds:
            seen_cwds.append(seg_cwd)
        if not _shell_has_unquoted_mutation(seg):
            continue
        tokens = _extract_shell_path_tokens(seg)
        for tok in tokens:
            if _targets_governance_dir(tok, base_dir=seg_cwd):
                return True
        if seg_cwd is not None and _targets_governance_dir(str(seg_cwd)):
            rel_tokens = [t for t in tokens if not Path(os.path.expanduser(t)).is_absolute()]
            if not tokens or any(_targets_governance_dir(t, base_dir=seg_cwd) for t in rel_tokens):
                return True
    for mut_src in mut_srcs:
        for cand_cwd in seen_cwds:
            if _python_ast_targets_governance(mut_src, base_dir=cand_cwd):
                return True
    return False

def _command_mutates_customization_in_cwd(
    sub_cmd: str, effective_cwd: Optional[Path], workspaces: Sequence[Path], fallback_ws: Optional[Path]
) -> bool:
    if "python" in sub_cmd.lower() or _NON_PYTHON_INTERP_RE.search(sub_cmd):
        ro_sub, saw_unv_c, mut_srcs_c = _scrub_verified_readonly_python_invocations(sub_cmd)
    else:
        ro_sub, saw_unv_c, mut_srcs_c = sub_cmd, False, []

    def _matches_cust_target(cand_str: str, base_dir: Optional[Path]) -> bool:
        exp_c = Path(os.path.expanduser(cand_str))
        if not exp_c.is_absolute() and base_dir is None:
            return False
        res_c = str(base_dir / exp_c) if (not exp_c.is_absolute() and base_dir is not None) else str(exp_c)
        t_ws = _workspace_for_target(res_c, workspaces, fallback=(fallback_ws or base_dir))
        return _targets_customization_structure(res_c, workspace=t_ws)

    seen_cwds_c: List[Optional[Path]] = [effective_cwd if effective_cwd is not None else fallback_ws]
    for seg, seg_cwd in _iter_shell_segments_with_cwd(ro_sub, effective_cwd):
        base_cwd = seg_cwd if seg_cwd is not None else fallback_ws
        if base_cwd not in seen_cwds_c:
            seen_cwds_c.append(base_cwd)
        is_interp = bool(
            re.search(
                r"\b(?:python3?(?:\.\d+)?|py|node|nodejs|deno|bun|ruby|perl|php|lua)\b[^\n;|&]*(?:\s-(?:[A-Za-z0-9]*[ceip])|<<)",
                seg,
            )
        )
        if not _shell_has_unquoted_mutation(seg) and not is_interp:
            continue
        ws_root = (
            _workspace_for_target(str(base_cwd), workspaces, fallback=(fallback_ws or base_cwd))
            if base_cwd is not None
            else None
        )
        tokens = list(_extract_shell_path_tokens(seg))
        if is_interp:
            tokens.extend(re.findall(r"['\"]([^'\"]*[/\\][^'\"]+)['\"]", seg))
        for tok in tokens:
            if _matches_cust_target(tok, base_cwd):
                return True
        if not is_interp and base_cwd is not None and _targets_customization_structure(str(base_cwd), workspace=ws_root):
            if not tokens or any(not Path(os.path.expanduser(t)).is_absolute() for t in tokens):
                return True

    if saw_unv_c:
        in_h_scope = _workspaces_in_harness_scope(workspaces, effective_cwd)

        def _neutralize_ro_exec_cwd(src_text: str) -> str:
            if not _EXEC_CALL_ARGV_RE.search(src_text):
                return src_text

            def _repl_c(m: re.Match[str]) -> str:
                argv_src = m.group(1) if m.group(1) is not None else (m.group(2) or "")
                parts = [
                    tm.group(1) if tm.group(1) is not None else (tm.group(2) or "")
                    for tm in _STR_ARGV_TOKEN_RE.finditer(argv_src)
                ]
                synth = " ".join(parts).strip()
                if (
                    synth
                    and synth != sub_cmd.strip()
                    and not _EXEC_CALL_ARGV_RE.search(synth)
                    and not _command_mutates_customization_in_cwd(synth, effective_cwd, workspaces, fallback_ws)
                    and not _command_mutates_customization_structure(synth, harness_scope=in_h_scope)
                ):
                    full_m = m.group(0)
                    return full_m[: full_m.find("(") + 1] + "None"
                return m.group(0)

            return _EXEC_CALL_ARGV_RE.sub(_repl_c, src_text)

        ro_sub_clean = _neutralize_ro_exec_cwd(ro_sub)
        for cand_str in re.findall(r"['\"]([^'\"\n]{1,512})['\"]", ro_sub_clean):
            for bc in seen_cwds_c:
                if _matches_cust_target(cand_str, bc):
                    return True
        for mut_src in mut_srcs_c:
            mut_src_clean = _neutralize_ro_exec_cwd(mut_src)
            try:
                ded_c = textwrap.dedent(mut_src_clean)
                tree_c = ast.parse(ded_c.encode("utf-8"), mode="exec")
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                return True
            pvars_c: Dict[str, str] = {}
            for _ in range(3):
                for nd in ast.walk(tree_c):
                    if isinstance(nd, ast.Assign) and len(nd.targets) == 1 and isinstance(nd.targets[0], ast.Name):
                        fv = _eval_workflow_path_expr(nd.value, pvars_c)
                        if fv is not None:
                            pvars_c[nd.targets[0].id] = fv
            for nd in ast.walk(tree_c):
                if isinstance(nd, (ast.Call, ast.BinOp, ast.Constant, ast.JoinedStr, ast.Attribute)):
                    fc = _eval_workflow_path_expr(nd, pvars_c)
                    if fc:
                        for bc in seen_cwds_c:
                            if _matches_cust_target(fc, bc):
                                return True
    return False

def _shell_targets_tasks_md(sub_cmd: str) -> bool:
    import fnmatch

    unquoted = _unquote_single_tokens(_strip_unquoted_shell_comments(sub_cmd))
    if re.search(r"(?:^|[\s/'\"=>])tasks\.md\b", unquoted, re.IGNORECASE):
        return True
    for tok in _extract_shell_path_tokens(sub_cmd):
        base = tok.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if any(ch in base for ch in ("*", "?", "[")) and len(base) >= 3 and ("t" in base or "md" in base):
            if fnmatch.fnmatchcase("tasks.md", base):
                return True
    return False

_INTERP_SCRIPT_SEG_RE = _LazyRegex(
    rf"^\s*{_CMD_WRAPPER_PREFIX}"
    r"(?P<interp>(?:[^\s;|&`'\"()]*/)?(?:python3?(?:\.\d+)?|py|(?:ba|z|da|k)?sh|node|nodejs|ruby|perl)|source|\.)\s+"
    r"(?P<rest>.+)$",
    re.IGNORECASE,
)

_PY_MODULE_SCRIPT_RUNNERS = frozenset({
    "pdb",
    "bdb",
    "runpy",
    "trace",
    "cprofile",
    "profile",
    "timeit",
    "doctest",
})

_STR_LIST_SEQ_RE = _LazyRegex(
    r"[\[(]\s*(?:['\"][^'\"\n]+['\"]\s*,\s*)+['\"][^'\"\n]*['\"]\s*,?\s*[\])]"
)

_QUOTED_ITEM_RE = _LazyRegex(r"'([^'\\\n]*)'|\"([^\"\\\n]*)\"")

# Root-level gate entry points of a harness checkout whose edits are held by the Customization Model Gate.
_HARNESS_CHECKOUT_GATE_ENTRIES = (
    "install.py",
    "porter.py",
    "guard.py",
    "scripts/meta_audit.py",
    "scripts/verify_invariants.py",
)

def _extract_code_map_trace_target(rem_tokens: Sequence[str]) -> Optional[str]:
    if not rem_tokens:
        return None
    sub_idx = 0
    while sub_idx < len(rem_tokens) and rem_tokens[sub_idx].startswith("-"):
        sub_idx += 1
    if sub_idx >= len(rem_tokens) or rem_tokens[sub_idx] != "trace":
        return None
    j = sub_idx + 1
    while j < len(rem_tokens):
        t = rem_tokens[j]
        if t == "--":
            return rem_tokens[j + 1] if j + 1 < len(rem_tokens) else None
        if t in ("--timeout", "--max-events", "--limit", "--format", "-o", "--output") and j + 1 < len(rem_tokens):
            j += 2
            continue
        if t.startswith("-"):
            j += 1
            continue
        return t
    return None

def _inspect_external_script_command(
    sub_cmd: str,
    workspaces: Sequence[Path],
    effective_cwd: Optional[Path],
) -> Optional[Dict[str, Any]]:
    uncommented = _unquote_single_tokens(_strip_unquoted_shell_comments(_join_shell_line_continuations(sub_cmd)))
    segments = re.split(r"(?:&&|\|\||[;&|\n])", uncommented)
    trusted_roots: List[Path] = [
        *workspaces,
        _repo_root(),
        config_dir() / "skills",
        configured_config_dir() / "skills",
        Path("/usr/share/antigravity-harness/skills"),
        Path.home() / ".gemini" / "antigravity" / "builtin" / "skills",
    ]
    resolved_trusted_roots: List[Path] = []
    for tr in trusted_roots:
        if tr is None:
            continue
        resolved_trusted_roots.append(tr)
        try:
            r_tr = tr.resolve()
            if r_tr not in resolved_trusted_roots:
                resolved_trusted_roots.append(r_tr)
        except (OSError, RuntimeError):
            pass

    harness_checkout_roots: List[Path] = []
    for h_cand in workspaces:
        try:
            h_resolved = Path(h_cand).resolve()
        except (OSError, RuntimeError):
            continue
        # Only a workspace root carrying `.harness/manifest.json` (itself Customization-Model-Gated) qualifies;
        # an agent-chosen `Cwd` or a nested decoy `guard/agy_hooks.py` never does.
        if h_resolved not in harness_checkout_roots and (h_resolved / ".harness" / "manifest.json").is_file():
            harness_checkout_roots.append(h_resolved)

    for seg in segments:
        m = _INTERP_SCRIPT_SEG_RE.match(seg)
        if not m:
            continue
        interp_base = Path(m.group("interp")).name.lower()
        is_py_interp = interp_base == "py" or interp_base.startswith("python")
        tokens = [t.strip("'\"") for t in re.findall(r"'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+", m.group("rest"))]
        candidate_script_args: List[str] = []
        idx = 0
        skip_seg = False
        while idx < len(tokens):
            tok = tokens[idx]
            if tok in (">", ">>", "<", "2>", "2>&1", "&>"):
                idx += 2
                continue
            if tok.startswith((">", "<", "2>")):
                idx += 1
                continue
            if tok == "--":
                if idx + 1 < len(tokens):
                    candidate_script_args.append(tokens[idx + 1])
                break
            if tok in ("-h", "--help", "-V", "--version", "-v") and interp_base not in ("sh", "bash", "zsh", "dash", "ksh"):
                skip_seg = True
                break
            if tok.startswith("-"):
                if is_py_interp and (tok == "-m" or re.match(r"^-[A-Za-z0-9]*m$", tok)):
                    if idx + 1 < len(tokens):
                        mod_name = tokens[idx + 1]
                        mod_lower = mod_name.lower()
                        if mod_lower in ("scripts.code_map", "code_map"):
                            cm_target = _extract_code_map_trace_target(tokens[idx + 2 :])
                            if cm_target:
                                candidate_script_args.append(cm_target)
                        elif mod_lower in _PY_MODULE_SCRIPT_RUNNERS:
                            j = idx + 2
                            while j < len(tokens):
                                mt = tokens[j]
                                if mt == "--":
                                    if j + 1 < len(tokens):
                                        candidate_script_args.append(tokens[j + 1])
                                    break
                                if mt in ("-c", "-o", "-s", "-m", "--command", "--outfile", "--sort") and j + 1 < len(tokens):
                                    j += 2
                                    continue
                                if mt.startswith("-"):
                                    j += 1
                                    continue
                                candidate_script_args.append(mt)
                                break
                    skip_seg = not bool(candidate_script_args)
                    break
                if tok in ("-c", "-m", "-e", "--eval", "--print", "-p"):
                    skip_seg = True
                    break
                if re.match(r"^-[A-Za-z0-9]*[cme]$", tok):
                    skip_seg = True
                    break
                if tok in ("-W", "-X", "-r", "--require", "-I") and idx + 1 < len(tokens):
                    idx += 2
                    continue
                idx += 1
                continue
            candidate_script_args.append(tok)
            if Path(tok).name == "code_map.py":
                cm_target = _extract_code_map_trace_target(tokens[idx + 1 :])
                if cm_target:
                    candidate_script_args.append(cm_target)
            break

        if skip_seg or not candidate_script_args:
            continue
        base_cwd = effective_cwd if effective_cwd is not None else (workspaces[0] if workspaces else _repo_root())
        for script_arg in candidate_script_args:
            if not script_arg or script_arg in ("-", "/dev/stdin", "/dev/null") or script_arg.startswith("<("):
                continue
            exp = Path(os.path.expanduser(script_arg))
            script_path = (base_cwd / exp) if not exp.is_absolute() else exp
            try:
                resolved_script: Optional[Path] = script_path.resolve()
            except (OSError, RuntimeError):
                resolved_script = None

            lex_trusted = any(is_within(script_path, root) for root in trusted_roots if root is not None)
            res_trusted = (
                resolved_script is not None
                and any(is_within(resolved_script, root) for root in resolved_trusted_roots)
            )
            in_trusted = bool(lex_trusted and res_trusted)
            check_target = resolved_script if resolved_script is not None else script_path
            is_harness_internal = (
                not script_path.is_symlink()
                and is_within(check_target, _repo_root())
                and (
                    any(is_within(check_target, _repo_root() / sub) for sub in ("guard", "scripts", "porter", "skills", "tests"))
                    or any(
                        os.path.abspath(check_target) == os.path.abspath(_repo_root() / entry)
                        for entry in ("install.py", "porter.py", "guard.py")
                    )
                )
            )
            if not is_harness_internal and not script_path.is_symlink():
                # A harness source checkout opened as a workspace runs its own gate entry points
                # (`scripts/meta_audit.py`, `install.py --dry-run`, ...). Only paths whose edits are
                # themselves held by the Customization Model Gate are exempt from content scanning.
                for h_root in harness_checkout_roots:
                    in_gate_set = any(is_within(check_target, h_root / sub) for sub in ("guard", "porter", "skills")) or any(
                        os.path.abspath(check_target) == os.path.abspath(h_root / entry)
                        for entry in _HARNESS_CHECKOUT_GATE_ENTRIES
                    )
                    if in_gate_set and _targets_customization_structure(str(check_target), workspace=h_root):
                        is_harness_internal = True
                        break
            if not is_harness_internal:
                try:
                    if check_target.is_file():
                        f_size = check_target.stat().st_size
                        if f_size > _WORKFLOW_MAX_BYTES:
                            in_trusted = False
                        else:
                            src_text = check_target.read_text(encoding="utf-8", errors="replace")
                            non_comment = "\n".join(
                                ln for ln in src_text.splitlines() if not ln.lstrip().startswith("#")
                            )
                            masked_src = _mask_quoted_operators(non_comment)
                            synth_list_cmds: List[str] = []
                            for m_seq in _STR_LIST_SEQ_RE.finditer(non_comment):
                                items = [
                                    (im.group(1) if im.group(1) is not None else (im.group(2) or ""))
                                    for im in _QUOTED_ITEM_RE.finditer(m_seq.group(0))
                                ]
                                if len(items) >= 2:
                                    synth_list_cmds.append(" ".join(items))
                            if (
                                re.search(_GUARD_API_TOKEN_PAT, non_comment)
                                or _GUARD_ADMIN_RE.search(masked_src)
                                or _INSTALL_PY_RE.search(masked_src)
                                or _GIT_HOOK_BYPASS_RE.search(masked_src)
                                or _command_mutates_governance(non_comment)
                                or any(
                                    _GUARD_ADMIN_RE.search(_mask_quoted_operators(sc))
                                    or _INSTALL_PY_RE.search(_mask_quoted_operators(sc))
                                    or _GIT_HOOK_BYPASS_RE.search(_mask_quoted_operators(sc))
                                    or _command_mutates_governance(sc)
                                    for sc in synth_list_cmds
                                )
                            ):
                                return {
                                    "decision": "deny",
                                    "reason": (
                                        f"[Harness Governance Shield] Script `{script_arg}` invokes human-only Guard "
                                        "administration or mutates protected governance state (GEMINI.md Rule 12)."
                                    ),
                                }
                except OSError:
                    in_trusted = False
            if not in_trusted:
                return {
                    "decision": "force_ask",
                    "reason": (
                        f"[Harness Bash Guard] Executing external script outside the active workspace (`{script_arg}`) "
                        "bypasses inline command inspection and requires explicit human confirmation (GEMINI.md Rule 12)."
                    ),
                }
    return None

_MCP_DEBUGGER_ESCAPE_RE = _LazyRegex(r"^\s*(?:!+|\.!|#!(?:pipe|python3?|ba?sh)\s+|(?:shell|system)\s+)", re.IGNORECASE)

_MCP_MUTATING_TOOL_HINT_RE = _LazyRegex(
    r"(?:write|edit|create|delete|remove|unlink|mv|move|rename|copy|chmod|chown|push|install|uninstall|"
    r"extract|save|exec|command|console|frida|script|gdb|rizin|cutter|adb|patch|modify|update|set_|put)",
    re.IGNORECASE,
)

def _collect_mcp_strings(value: Any, out: List[str], depth: int = 0) -> Optional[str]:
    if depth > _WORKFLOW_MAX_ARG_DEPTH:
        return "[Harness MCP Shield] MCP `Arguments` exceed maximum nesting depth (failing closed)."
    if isinstance(value, str):
        if "\x00" in value or (value.strip().lower().startswith("file://") and "%00" in value.lower()):
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
    *(k.lower() for k in _WRITE_TARGET_ARG_KEYS),
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
    if s.lower().startswith("file://"):
        return _parse_file_uri(s) or ""
    return s

def _extract_mcp_target_paths(mcp_args: Dict[str, Any], depth: int = 0) -> List[str]:
    if depth > _WORKFLOW_MAX_ARG_DEPTH or not isinstance(mcp_args, dict):
        return []
    targets: List[str] = []
    for t in _extract_write_targets(mcp_args):
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
        is_high_risk = effective_mcp_tool in HIGH_RISK_MCP_TOOL_NAMES
        is_readonly_allowlisted = effective_mcp_tool in _READONLY_MCP_ALLOWLIST
    else:
        mcp_args = args
        rest_name = tool_name[4:] if tool_name.startswith("mcp_") else tool_name
        effective_mcp_tool = rest_name
        effective_label = tool_name
        is_high_risk = any(
            rest_name == hr or rest_name.endswith(f"_{hr}") for hr in HIGH_RISK_MCP_TOOL_NAMES
        )
        is_readonly_allowlisted = any(
            rest_name == ro or rest_name.endswith(f"_{ro}") for ro in _READONLY_MCP_ALLOWLIST
        )

    strings: List[str] = []
    err = _collect_mcp_strings(mcp_args, strings)
    if err:
        return {"decision": "deny", "reason": err}

    checks_gov_path = not is_readonly_allowlisted
    if checks_gov_path and _environments_registry_corrupt():
        return {
            "decision": "deny",
            "reason": (
                "[Harness Governance Shield] Protected environments registry `environments.json` is corrupt or "
                "unreadable (failing closed; run `agy-guard doctor` in an interactive terminal)."
            ),
        }
    mcp_targets = _extract_mcp_target_paths(mcp_args) if checks_gov_path else []
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
            if _command_mutates_governance(c_str):
                return {
                    "decision": "deny",
                    "reason": (
                        f"[Harness MCP Shield] Mutating protected governance or Guard state via MCP tool "
                        f"(`{effective_label}`) is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                    ),
                }

        norm_s = _normalize_mcp_path_value(s)
        if checks_gov_path and any(
            _targets_governance_dir(cand_p)
            or (effective_cwd is not None and _targets_governance_dir(cand_p, base_dir=effective_cwd))
            or (workspace is not None and _targets_governance_dir(cand_p, base_dir=workspace))
            or any(_targets_governance_dir(cand_p, base_dir=ws) for ws in workspaces)
            for cand_p in ((s, norm_s) if norm_s != s else (s,))
        ):
            return {
                "decision": "deny",
                "reason": (
                    f"[Harness MCP Shield] Targeting protected governance or Guard path (`{s}`) via "
                    f"MCP tool (`{effective_label}`) is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                ),
            }

    if checks_gov_path and mcp_targets:
        def _resolve_mcp_target_and_ws(t_str: str) -> Tuple[str, Optional[Path]]:
            exp_t = Path(os.path.expanduser(t_str.strip()))
            res_str = str(effective_cwd / exp_t) if (effective_cwd is not None and not exp_t.is_absolute()) else t_str
            t_ws = _workspace_for_target(res_str, workspaces, fallback=(workspace if workspace is not None else effective_cwd))
            return res_str, t_ws

        if payload is not None and any(
            _targets_customization_structure(res_t, workspace=t_ws)
            or (res_t == t_raw and _targets_customization_structure(t_raw, workspace=t_ws))
            for t_raw in mcp_targets
            for res_t, t_ws in [_resolve_mcp_target_and_ws(t_raw)]
        ):
            mod_eval = _evaluate_customization_model_and_effort(payload)
            if mod_eval is not None:
                return {"decision": mod_eval[0], "reason": mod_eval[1]}

        for t_raw in mcp_targets:
            res_t, t_ws = _resolve_mcp_target_and_ws(t_raw)
            if _write_mutates_authorized_test_section(
                t_raw, mcp_args, effective_cwd or t_ws, conv_id=_conversation_id(payload or {})
            ):
                return {
                    "decision": "force_ask",
                    "reason": (
                        "[Harness Test Boundary] Modifying `## Authorized Test Modifications` in `tasks.md` "
                        "requires explicit human confirmation (GEMINI.md Rule 9)."
                    ),
                }
            if Path(t_raw.replace("\\", "/")).name.lower() == "tasks.md" and not any(
                ck in mcp_args for ck in ("Content", "FileContent", "CodeContent", "content", "file_text")
            ):
                tasks_disk = Path(os.path.expanduser(res_t))
                has_auth_heading = any("authorized test modifications" in x.lower() for x in strings)
                if not has_auth_heading:
                    try:
                        if tasks_disk.is_file():
                            has_auth_heading = (
                                "authorized test modifications"
                                in tasks_disk.read_text(encoding="utf-8", errors="ignore").lower()
                            )
                    except OSError:
                        pass
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
            exp_t = Path(os.path.expanduser(t_raw.strip()))
            res_t = str(effective_cwd / exp_t) if (effective_cwd is not None and not exp_t.is_absolute()) else t_raw
            t_ws = _workspace_for_target(res_t, workspaces, fallback=workspace)
            _record_flight_pre_write(payload, t_ws, tool_name, res_t)

    return {"decision": "allow"}

def _swarm_workers_file() -> Path:
    return state_dir() / "swarm_workers.json"

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
) -> None:
    raw_entry = ledger.get(conv_id)
    entry = raw_entry if isinstance(raw_entry, dict) else {}
    exact = [str(x) for x in entry.get("exact", []) if isinstance(x, str)]
    prefixes = [str(x) for x in entry.get("prefixes", []) if isinstance(x, str)]
    downgraded = [str(x) for x in entry.get("downgraded", []) if isinstance(x, str)]
    custom_subagents = [str(x) for x in entry.get("custom_subagents", []) if isinstance(x, str)]
    conv_has_cust = bool(entry.get("conv_has_cust")) or conv_cust

    if remove_worker:
        exact = [x for x in exact if x != remove_worker]
        prefixes = [p for p in prefixes if p != f"{remove_worker}-"]
        downgraded = [x for x in downgraded if not _worker_matches_downgraded(x, {remove_worker})]
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

    if conv_id in ledger:
        del ledger[conv_id]
    if exact or prefixes or downgraded or conv_has_cust or custom_subagents:
        updated_entry: Dict[str, Any] = {
            "exact": exact[-128:],
            "prefixes": prefixes[-64:],
            "downgraded": downgraded[-64:],
            "conv_has_cust": conv_has_cust,
        }
        if custom_subagents:
            updated_entry["custom_subagents"] = custom_subagents[-64:]
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
)

def _batch_update_swarm_workers_ledger(ops: Sequence[Dict[str, Any]]) -> bool:
    """Applies one or more `swarm_workers.json` mutations atomically under a single file lock."""
    valid_ops = [
        op
        for op in ops
        if isinstance(op, dict)
        and str(op.get("conv_id") or "").strip()
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
                _apply_swarm_entry_mutation(
                    ledger,
                    cid,
                    add_worker=str(op.get("add_worker") or ""),
                    sharded=bool(op.get("sharded")),
                    remove_worker=str(op.get("remove_worker") or ""),
                    conv_cust=bool(op.get("conv_cust")),
                    downgraded_worker=str(op.get("downgraded_worker") or ""),
                    clear_downgraded=str(op.get("clear_downgraded") or ""),
                    add_custom_subagent=str(op.get("add_custom_subagent") or ""),
                )
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
) -> bool:
    return _facade_attr("_batch_update_swarm_workers_ledger", _batch_update_swarm_workers_ledger)(
        [
            {
                "conv_id": conv_id,
                "add_worker": add_worker,
                "sharded": sharded,
                "remove_worker": remove_worker,
                "conv_cust": conv_cust,
                "downgraded_worker": downgraded_worker,
                "clear_downgraded": clear_downgraded,
                "add_custom_subagent": add_custom_subagent,
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
    top_name, allowed_top_slugs = _catalog_top_model_spec()
    is_downgraded = bool(
        sub_model_lower
        and sub_model_lower != "inherit"
        and _normalize_model_slug(sub_model_lower) not in allowed_top_slugs
    )
    if targets_customization:
        if is_downgraded:
            return (
                {
                    "decision": "deny",
                    "reason": (
                        f"[Harness Model & Effort Gate] Delegating customization or governance work via "
                        f"`{tool_label}` with downgraded `{model_arg_name}='{sub_model_lower}'` is prohibited; use "
                        f"`{model_arg_name}='inherit'` on `{top_name}` (GEMINI.md Rule 17)."
                    ),
                },
                True,
            )
        mod_eval = _evaluate_customization_model_and_effort(payload)
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

def _swarm_ledger_context(
    payload: Dict[str, Any],
    conv_id: str,
) -> Tuple[bool, Optional[Dict[str, Any]], Callable[..., bool]]:
    """Loads `swarm_workers.json` (or workflow overlay) and returns `(ledger_ok, conv_entry, emit_fn)`."""
    dry_check = bool(payload.get("_workflowDryCheck"))
    overlay = payload.get("_swarmOverlay") if isinstance(payload.get("_swarmOverlay"), dict) else None
    pending_ops = payload.get("_pendingSwarmOps") if isinstance(payload.get("_pendingSwarmOps"), list) else None

    def _emit_swarm_mutation(
        *,
        batch_ops: Optional[Sequence[Dict[str, Any]]] = None,
        **mut_kwargs: Any,
    ) -> bool:
        ops_list = (
            [{"conv_id": str(op.get("conv_id") or conv_id), **{k: v for k, v in op.items() if k != "conv_id"}} for op in batch_ops]
            if batch_ops is not None
            else [{"conv_id": conv_id, **mut_kwargs}]
        )
        if dry_check:
            for op in ops_list:
                cid = str(op.get("conv_id") or conv_id)
                kw = {k: v for k, v in op.items() if k != "conv_id"}
                if overlay is not None:
                    _apply_swarm_entry_mutation(overlay, cid, **kw)
                if pending_ops is not None:
                    pending_ops.append({"conv_id": cid, **kw})
            return True
        if len(ops_list) == 1:
            single_kw = {k: v for k, v in ops_list[0].items() if k != "conv_id"}
            return _update_swarm_workers_ledger(str(ops_list[0].get("conv_id") or conv_id), **single_kw)
        return _facade_attr("_batch_update_swarm_workers_ledger", _batch_update_swarm_workers_ledger)(ops_list)

    if overlay is not None and conv_id in overlay:
        ledger_ok, ledger = True, overlay
    else:
        ledger_ok, ledger = _read_swarm_workers_ledger() if conv_id else (True, {})
        if not ledger_ok:
            return False, None, _emit_swarm_mutation
        if overlay is not None and isinstance(ledger.get(conv_id), dict):
            overlay[conv_id] = json.loads(json.dumps(ledger[conv_id]))
    conv_entry = ledger.get(conv_id) if isinstance(ledger, dict) else None
    return True, conv_entry, _emit_swarm_mutation

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
        if b is not None and b not in explicit_bases:
            explicit_bases.append(b)
    bases: List[Optional[Path]] = list(explicit_bases) if explicit_bases else [None]
    for m in _DELEGATION_PATH_TOKEN_RE.finditer(text):
        tok = m.group(0).rstrip(".,:;!?\"')]`")
        if not tok or ("/" not in tok and "\\" not in tok and "~" not in tok):
            continue
        window_start = max(0, m.start() - 64)
        preceding = text[window_start : m.start()]
        for sep in ("\n", ";", ".", ","):
            if sep in preceding:
                preceding = preceding.rsplit(sep, 1)[-1]
        if not _DELEGATION_MUTATION_VERB_RE.search(preceding):
            continue
        if any(_targets_governance_dir(tok, base_dir=b) for b in bases):
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
    candidates = [text]
    for ext in _extract_shell_c_payloads(text):
        if ext and ext not in candidates:
            candidates.append(ext)
    for cand in candidates:
        masked = _mask_quoted_operators(cand)
        if _DELEGATION_GUARD_ADMIN_RE.search(masked) or _GUARD_INLINE_PY_RE.search(cand) or re.search(_GUARD_API_TOKEN_PAT, cand):
            return {
                "decision": "deny",
                "reason": (
                    f"[Harness Governance Shield] Human-only `agy-guard` administration commands are "
                    f"prohibited inside `{tool_label}` (GEMINI.md Rule 12)."
                ),
            }
        if _DELEGATION_INSTALL_EXEC_RE.search(masked):
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
        if _command_mutates_governance(cand) or _text_mutates_governance_path(
            cand, workspaces, workspace, effective_cwd=effective_cwd
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
    return _text_targets_customization(
        combined_brief,
        workspaces,
        fallback_ws=workspace,
        effective_cwd=effective_cwd,
        extra_tokens=task_items,
    )

def _handle_swarm_pre_tool_use(
    payload: Dict[str, Any],
    args: Dict[str, Any],
    workspaces: Sequence[Path],
    workspace: Optional[Path],
    effective_cwd: Optional[Path] = None,
) -> Dict[str, Any]:
    """Enforces Rule 15f & Rule 17 on native `swarm` orchestration and tracks customization workers."""
    action = str(args.get("action") or "").strip().lower()
    if action in ("status", "models", "title", "channel"):
        return {"decision": "allow"}
    conv_id = _conversation_id(payload)
    ledger_ok, conv_entry, _emit_swarm_mutation = _swarm_ledger_context(payload, conv_id)

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
    any_harness_ws = _workspaces_in_harness_scope(workspaces, effective_cwd or workspace) and bool(workspaces or effective_cwd)
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
            top_name, _ = _catalog_top_model_spec()
            return {
                "decision": "deny",
                "reason": (
                    f"[Harness Model & Effort Gate] Forking customization worker from downgraded worker "
                    f"`{fork_from}` with `{req_model or 'inherit'}` is prohibited; use `{top_name}` (GEMINI.md Rule 17)."
                ),
            }
        blocked, is_downgraded = _check_delegated_model_gate(payload, "swarm", req_model, targets_cust)
        if fork_is_downgraded and inherits_fork_model:
            is_downgraded = True
        if blocked is not None:
            if blocked.get("decision") == "deny":
                return blocked
            # force_ask (missing coordinator model/effort): persist cust registration before yielding
            worker_name = str(args.get("name") or "").strip().lower()
            has_tasks = isinstance(args.get("tasks"), list) and len(args.get("tasks")) > 0
            if targets_cust:
                if not _emit_swarm_mutation(
                    add_worker=worker_name,
                    sharded=(parsed_n > 1 or has_tasks),
                    conv_cust=True,
                ):
                    return {
                        "decision": "force_ask",
                        "reason": "[Harness Swarm Guard] Failed to persist customization worker ledger; confirm execution.",
                    }
            return blocked
        worker_name = str(args.get("name") or "").strip().lower()
        has_tasks = isinstance(args.get("tasks"), list) and len(args.get("tasks")) > 0
        if is_downgraded:
            if worker_name and not _emit_swarm_mutation(downgraded_worker=worker_name):
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
        if targets_cust:
            if not _emit_swarm_mutation(
                add_worker=worker_name,
                sharded=(parsed_n > 1 or has_tasks),
                conv_cust=True,
            ):
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
    ledger_ok, conv_entry, emit_mutation = _swarm_ledger_context(payload, conv_id)
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
    mentions_all = "all" in mentions

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

    text_targets_cust = _text_targets_customization(
        combined, workspaces, fallback_ws=workspace, effective_cwd=effective_cwd
    )
    mentions_tracked_cust = any(
        _is_tracked_swarm_cust_worker(conv_entry, m) for m in mentions if m != "all"
    ) or (mentions_all and _swarm_entry_has_cust(conv_entry))
    targets_cust = text_targets_cust or mentions_tracked_cust

    if targets_cust and hit_downgraded:
        top_name, _ = _catalog_top_model_spec()
        return {
            "decision": "deny",
            "reason": (
                "[Harness Swarm Guard] Assigning or continuing customization/governance work via `post_message` "
                f"to downgraded swarm worker(s) (`{', '.join(hit_downgraded)}`) is prohibited; use `{top_name}` "
                "(GEMINI.md Rule 17)."
            ),
        }

    if targets_cust:
        blocked, _ = _check_delegated_model_gate(payload, "post_message", "", True)
        if blocked is not None:
            if blocked.get("decision") == "deny":
                return blocked
            if conv_id and not _persist_post_message_cust_mentions(mentions, emit_mutation):
                return {
                    "decision": "force_ask",
                    "reason": "[Harness Swarm Guard] Failed to persist customization worker ledger; confirm execution.",
                }
            return blocked
        if conv_id and not _persist_post_message_cust_mentions(mentions, emit_mutation):
            return {
                "decision": "force_ask",
                "reason": "[Harness Swarm Guard] Failed to persist `post_message` customization worker ledger; confirm execution.",
            }
    return {"decision": "allow"}

def _transcript_subagent_is_downgraded(payload: Dict[str, Any], recipient: str) -> bool:
    """Checks trailing transcript entries to detect if `recipient` conversationId was launched downgraded."""
    if not recipient:
        return False
    transcript = payload.get("transcriptPath") or payload.get("transcript_path")
    if not isinstance(transcript, str) or not transcript.strip():
        return False
    path = Path(transcript).expanduser()
    _, allowed_top_slugs = _catalog_top_model_spec()
    try:
        for entry in _iter_jsonl_tail_entries(path, max_scan_bytes=2 * 1024 * 1024):
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
                        if mod and mod != "inherit" and _normalize_model_slug(mod) not in allowed_top_slugs:
                            return True
    except (OSError, TypeError, ValueError):
        return False
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

    text_targets_cust = _text_targets_customization(
        message, workspaces, fallback_ws=workspace, effective_cwd=effective_cwd
    )
    conv_id = _conversation_id(payload)
    ledger_ok, conv_entry, emit_mutation = _swarm_ledger_context(payload, conv_id)
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
    if targets_cust and (
        _worker_matches_downgraded(recipient_low, downgraded)
        or _transcript_subagent_is_downgraded(payload, recipient)
    ):
        top_name, _ = _catalog_top_model_spec()
        return {
            "decision": "deny",
            "reason": (
                f"[Harness Model & Effort Gate] Sending customization/governance instructions via `send_message` "
                f"to downgraded recipient `{recipient}` is prohibited; use `{top_name}` (GEMINI.md Rule 17)."
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

    if name.lower() in _READONLY_SUBAGENT_TYPES and can_mutate:
        return {
            "decision": "deny",
            "reason": (
                f"[Harness Model & Effort Gate] Redefining read-only built-in subagent `{name}` with "
                "write, MCP, or subagent delegation tools is prohibited (GEMINI.md Rule 17)."
            ),
        }

    targets_cust = can_mutate and _text_targets_customization(
        combined, workspaces, fallback_ws=workspace, effective_cwd=effective_cwd
    )
    req_model = str(args.get("Model") or args.get("model") or "").strip()
    blocked, _ = _check_delegated_model_gate(payload, "define_subagent", req_model, targets_cust)
    if blocked is not None and blocked.get("decision") == "deny":
        return blocked

    conv_id = _conversation_id(payload)
    if targets_cust and name and conv_id:
        ledger_ok, _entry, emit_mutation = _swarm_ledger_context(payload, conv_id)
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

    targets_cust = _text_targets_customization(
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
    workspaces = _workspaces_from_payload(payload)
    workspace = workspaces[0] if workspaces else None
    payload_cwd = _payload_cwd(payload, args)
    effective_cwd: Optional[Path] = (
        ((workspace / payload_cwd) if (not payload_cwd.is_absolute() and workspace is not None) else payload_cwd)
        if payload_cwd is not None
        else workspace
    )

    # 0. MCP tools (`call_mcp_tool` lazy wrapper & `mcp_*` eager native tools — ADR-0004 Decision 1 / H-03)
    if tool_name == "call_mcp_tool" or tool_name.startswith("mcp_"):
        return _inspect_mcp_tool_call(
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
                "unreadable (failing closed; run `agy-guard doctor` in an interactive terminal)."
            ),
        }

    # 1. File-writing tools: enforce Governance Shield (~/.gemini/config governance seams + Guard state/runtime)
    #    and Top-Catalog Model & Effort Gate on customization/governance files (GEMINI.md Rule 17).
    if tool_name in WRITE_TOOL_NAMES:
        targets = _extract_write_targets(args)
        for target in targets:
            if "\x00" in target or (target.strip().lower().startswith("file://") and "%00" in target.lower()):
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
            exp_t = Path(os.path.expanduser(t_str.strip()))
            res_str = str(effective_cwd / exp_t) if (effective_cwd is not None and not exp_t.is_absolute()) else t_str
            t_ws = _workspace_for_target(
                res_str, workspaces, fallback=(effective_cwd if effective_cwd is not None else workspace)
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
            norm_res_t = res_t.replace("\\", "/")
            if re.search(r"(?:^|/)(?:\.agents?|_agents?)/hooks\.json$", norm_res_t, re.IGNORECASE):
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
            if _write_mutates_authorized_test_section(
                target, args, effective_cwd or t_ws, conv_id=_conversation_id(payload)
            ):
                return {
                    "decision": "force_ask",
                    "reason": (
                        "[Harness Test Boundary] Modifying `## Authorized Test Modifications` in `tasks.md` "
                        "requires explicit human confirmation (GEMINI.md Rule 9)."
                    ),
                }
        for target in targets:
            res_t, t_ws = _resolve_target_and_ws(target)
            _record_flight_pre_write(payload, t_ws, tool_name, res_t)
        return {"decision": "allow"}

    # 2. Command execution tools: enforce Guard Admin Shield, Governance Shield, Customization Model Gate, and Bash Guard
    if tool_name in COMMAND_TOOL_NAMES:
        def _eval_shell_command_string(raw_cmd_str: str) -> Optional[Dict[str, Any]]:
            joined_top = _join_shell_line_continuations(raw_cmd_str).strip()
            if not joined_top:
                return {"decision": "allow"}
            candidate_cmds = [joined_top]
            if raw_cmd_str.strip() != joined_top:
                candidate_cmds.append(raw_cmd_str.strip())
            for ext_sub in _extract_shell_c_payloads(raw_cmd_str):
                if ext_sub not in candidate_cmds:
                    candidate_cmds.append(ext_sub)

            pending_cmd_force_ask: Optional[Dict[str, Any]] = None
            for sub_cmd in candidate_cmds:
                masked_cmd = _mask_quoted_operators(sub_cmd)

                if _GUARD_ADMIN_RE.search(masked_cmd) or _GUARD_INLINE_PY_RE.search(sub_cmd):
                    return {
                        "decision": "deny",
                        "reason": (
                            "[Harness Governance Shield] Guard administration commands (`agy-guard unlock`, "
                            "`rebaseline`, `test-boundary snapshot`, `--authorize`, `snapshot restore/prune`, `porter stage`, `porter import --force`, "
                            "`env policy/add/remove`, `startup enable/disable`, `notify disable`, `doctor --fix/--recover`, `init`) are reserved exclusively "
                            "for the human operator (GEMINI.md Rule 12). You may only run `agy-guard request-unlock` "
                            "or read-only status/verify/`--dry-run` commands."
                        ),
                    }

                if _INSTALL_PY_RE.search(masked_cmd):
                    return {
                        "decision": "deny",
                        "reason": (
                            "[Harness Governance Shield] Running `install.py` (without `--dry-run`) is reserved "
                            "for the human operator (GEMINI.md Rule 12)."
                        ),
                    }

                if _command_mutates_governance(sub_cmd) or _command_mutates_governance_in_cwd(sub_cmd, effective_cwd):
                    return {
                        "decision": "deny",
                        "reason": (
                            "[Harness Governance Shield] Mutating or changing permissions on the governance tree "
                            "(`~/.gemini/config`) or Guard state via shell commands is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                        ),
                    }

                if _GIT_HOOK_BYPASS_RE.search(masked_cmd):
                    return {
                        "decision": "deny",
                        "reason": (
                            "[Harness Bash Guard] Bypassing repository verification hooks (`--no-verify`, "
                            "`commit -n`, `core.hooksPath`, `HUSKY=0`) is prohibited."
                        ),
                    }

                in_harness_scope = _workspaces_in_harness_scope(workspaces, effective_cwd)
                cmd_cust_hit = _command_mutates_customization_in_cwd(
                    sub_cmd, effective_cwd, workspaces, workspace
                )
                if not cmd_cust_hit:
                    ro_cust_sub = (
                        _scrub_verified_readonly_python_invocations(sub_cmd)[0]
                        if "python" in sub_cmd.lower()
                        else sub_cmd
                    )
                    segs_with_cwd = _iter_shell_segments_with_cwd(
                        ro_cust_sub, effective_cwd if effective_cwd is not None else workspace
                    )
                    if (
                        segs_with_cwd
                        and all(sc is not None for _, sc in segs_with_cwd)
                        and not re.search(
                            rf"\|\s*(?:{_CMD_WRAPPER_PREFIX})*xargs\b|\b(?:ba|z|da|k)?sh\b|\$\(|`",
                            sub_cmd,
                        )
                    ):
                        cmd_cust_hit = any(
                            _command_mutates_customization_structure(
                                seg, harness_scope=(_find_harness_repo_root(sc) is not None)
                            )
                            for seg, sc in segs_with_cwd
                            if sc is not None
                        )
                    else:
                        cmd_cust_hit = _command_mutates_customization_structure(
                            sub_cmd, harness_scope=in_harness_scope
                        )
                if cmd_cust_hit:
                    mod_eval = _evaluate_customization_model_and_effort(payload)
                    if mod_eval is not None:
                        if mod_eval[0] == "deny":
                            return {"decision": "deny", "reason": mod_eval[1]}
                        if pending_cmd_force_ask is None:
                            pending_cmd_force_ask = {"decision": "force_ask", "reason": mod_eval[1]}

                if _shell_targets_tasks_md(sub_cmd) and _shell_has_unquoted_mutation(sub_cmd):
                    if pending_cmd_force_ask is None:
                        pending_cmd_force_ask = {
                            "decision": "force_ask",
                            "reason": (
                                "[Harness Test Boundary] Mutating `tasks.md` via shell command could alter "
                                "`## Authorized Test Modifications` and requires explicit human confirmation (GEMINI.md Rule 9)."
                            ),
                        }

                unquoted_sub = _unquote_single_tokens(sub_cmd)
                sub_variants = (unquoted_sub, sub_cmd) if "\\" in sub_cmd else (unquoted_sub,)
                if (
                    any(
                        re.search(r"(?:^|[\s/\\'\"=])(?:\.agents?|_agents?)[/\\]hooks\.json\b", sv, re.IGNORECASE)
                        for sv in sub_variants
                    )
                    and _shell_has_unquoted_mutation(sub_cmd)
                    and pending_cmd_force_ask is None
                ):
                    pending_cmd_force_ask = {
                        "decision": "force_ask",
                        "reason": (
                            "[Harness Governance Shield] Modifying workspace `.agents/hooks.json` via shell command "
                            "can shadow or disable global `harness-gate` / `upstream-watchdog` lifecycle hooks and "
                            "requires explicit human confirmation (GEMINI.md Rule 12 & Rule 15a)."
                        ),
                    }

                for pattern, reason in _DESTRUCTIVE_CMD_PATTERNS:
                    if any(pattern.search(sv) for sv in sub_variants):
                        if pending_cmd_force_ask is None:
                            pending_cmd_force_ask = {
                                "decision": "force_ask",
                                "reason": f"[Harness Bash Guard] {reason}",
                            }
                        break

                out_ws_msg = _detect_out_of_workspace_rm_or_mv(unquoted_sub, workspaces, effective_cwd)
                if out_ws_msg is None and "\\" in sub_cmd:
                    out_ws_msg = _detect_out_of_workspace_rm_or_mv(sub_cmd, workspaces, effective_cwd)
                if out_ws_msg and pending_cmd_force_ask is None:
                    pending_cmd_force_ask = {
                        "decision": "force_ask",
                        "reason": f"[Harness Bash Guard] {out_ws_msg}",
                    }

                unpinned_msg = _detect_unpinned_package_exec(unquoted_sub)
                if unpinned_msg and pending_cmd_force_ask is None:
                    pending_cmd_force_ask = {
                        "decision": "force_ask",
                        "reason": f"[Harness Bash Guard] {unpinned_msg}",
                    }

                if _TERMINAL_INJECTION_RE.search(_blank_quoted_spans(sub_cmd)) and pending_cmd_force_ask is None:
                    pending_cmd_force_ask = {
                        "decision": "force_ask",
                        "reason": (
                            "[Harness Bash Guard] Injecting keystrokes or buffers into a terminal multiplexer "
                            "(`tmux send-keys`/`paste-buffer`, `screen -X stuff`, `zellij write-chars`) runs commands "
                            "outside `PreToolUse` inspection and requires explicit human confirmation (GEMINI.md Rule 12)."
                        ),
                    }

                ext_res = _inspect_external_script_command(sub_cmd, workspaces, effective_cwd)
                if ext_res is not None:
                    if ext_res.get("decision") == "deny":
                        return ext_res
                    if pending_cmd_force_ask is None:
                        pending_cmd_force_ask = ext_res

            return pending_cmd_force_ask

        is_interactive_input = False
        raw_chunk = ""
        if tool_name == "manage_task":
            action = str(args.get("Action") or args.get("action") or "").strip().lower()
            if action == "send_input":
                is_interactive_input = True
                raw_chunk = str(args.get("Input") if args.get("Input") is not None else (args.get("input") or ""))
            else:
                return {"decision": "allow"}
        elif tool_name == "send_command_input":
            is_interactive_input = True
            raw_chunk = str(
                args.get("Input")
                if args.get("Input") is not None
                else (
                    args.get("input")
                    if args.get("input") is not None
                    else (args.get("CommandLine") if args.get("CommandLine") is not None else (args.get("command") or ""))
                )
            )
        else:
            cmd = str(args.get("CommandLine") or args.get("command") or "").strip()
            if not cmd:
                return {"decision": "allow"}
            cmd_res = _eval_shell_command_string(cmd)
            if cmd_res is not None:
                return cmd_res
            if _shell_has_unquoted_mutation(cmd) or re.search(
                rf"\bgit{_GIT_GLOBAL_OPTS}\s+(?:commit|apply|am|cherry-pick|merge|rebase|revert)\b",
                cmd,
            ):
                cmd_ws = _workspace_for_target(
                    str(effective_cwd) if effective_cwd is not None else "",
                    workspaces,
                    fallback=(effective_cwd if effective_cwd is not None else workspace),
                )
                if cmd_ws is not None:
                    _record_flight_pre_write(payload, cmd_ws, tool_name, f"<shell:{tool_name}>")
            return {"decision": "allow"}

        buf_key = _cmd_input_buffer_key(payload, args)
        buf_file = state_dir() / "cmd_input_buffers.json"
        try:
            with file_lock(buf_file, timeout=HOOK_LOCK_TIMEOUT):
                buf_ok, data = _read_ledger_checked(buf_file)
                if not buf_ok:
                    cmd_res = _eval_shell_command_string(raw_chunk)
                    if cmd_res is not None:
                        return cmd_res
                    return {
                        "decision": "force_ask",
                        "reason": (
                            "[Harness Bash Guard] Interactive input buffer state (`cmd_input_buffers.json`) was "
                            "corrupt and quarantined; human confirmation required."
                        ),
                    }
                if not isinstance(data, dict):
                    data = {}
                prev_prefix = data.get(buf_key) if isinstance(data.get(buf_key), str) else ""
                combined_interactive = prev_prefix + raw_chunk
                if not combined_interactive.strip():
                    return {"decision": "allow"}
                cmd_res = _eval_shell_command_string(combined_interactive)
                if cmd_res is not None:
                    return cmd_res
                trailing = _compute_trailing_cmd_buffer(combined_interactive)
                if trailing:
                    data[buf_key] = trailing
                    if len(data) > 64:
                        oldest_key = next(iter(data))
                        if oldest_key != buf_key:
                            data.pop(oldest_key, None)
                else:
                    data.pop(buf_key, None)
                atomic_write_json(buf_file, data)
        except (OSError, TimeoutError):
            cmd_res = _eval_shell_command_string(raw_chunk)
            if cmd_res is not None:
                return cmd_res
            return {
                "decision": "force_ask",
                "reason": "[Harness Bash Guard] Interactive input buffer lock unavailable; human confirmation required.",
            }
        return {"decision": "allow"}

    # 3. Subagent delegation (`invoke_subagent`): enforce Rule 12 & Model & Effort Gate on customization/governance delegation (GEMINI.md Rule 17)
    if tool_name == "invoke_subagent":
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
            ledger_ok, conv_entry, _ = _swarm_ledger_context(payload, conv_id)
            if not ledger_ok:
                return {
                    "decision": "force_ask",
                    "reason": "[Harness Model & Effort Gate] Could not verify `swarm_workers.json`; human confirmation required.",
                }
            if isinstance(conv_entry, dict):
                custom_registered = type_name in [
                    str(x).lower() for x in (conv_entry.get("custom_subagents") or []) if isinstance(x, str)
                ]
        targets_cust = (type_name not in _READONLY_SUBAGENT_TYPES) and (
            custom_registered
            or _text_targets_customization(
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

    # 3b. Native swarm & delegation/messaging/schedule gates (GEMINI.md Rules 12, 15f & 17)
    if tool_name == "swarm":
        return _handle_swarm_pre_tool_use(payload, args, workspaces, workspace, effective_cwd=effective_cwd)
    if tool_name == "post_message":
        return _handle_post_message_pre_tool_use(payload, args, workspaces, workspace, effective_cwd=effective_cwd)
    if tool_name == "send_message":
        return _handle_send_message_pre_tool_use(payload, args, workspaces, workspace, effective_cwd=effective_cwd)
    if tool_name == "define_subagent":
        return _handle_define_subagent_pre_tool_use(payload, args, workspaces, workspace, effective_cwd=effective_cwd)
    if tool_name == "schedule":
        return _handle_schedule_pre_tool_use(payload, args, workspaces, workspace, effective_cwd=effective_cwd)

    # 4. Dynamic Python orchestration workflows (`run_workflow`): enforce Workflow Shield (GEMINI.md Rule 15e & Rule 17)
    if tool_name == "run_workflow":
        script_sources, arg_strings, workflow_cwd, script_paths_meta, err_reason = _extract_workflow_sources_ex(
            args, workspace
        )
        if err_reason:
            return {"decision": "deny", "reason": err_reason}
        if workflow_cwd is not None and _targets_governance_dir(str(workflow_cwd)):
            return {
                "decision": "deny",
                "reason": (
                    f"[Harness Governance Shield] Executing `run_workflow` with `Cwd` inside a protected "
                    f"governance tree (`{workflow_cwd}`) is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                ),
            }
        for arg_text in arg_strings:
            masked_arg = _mask_quoted_operators(arg_text)
            if _GUARD_ADMIN_RE.search(masked_arg) or _GUARD_INLINE_PY_RE.search(arg_text):
                return {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Human-only `agy-guard` administration commands are "
                        "prohibited inside `run_workflow` `Args` (GEMINI.md Rule 12)."
                    ),
                }
            if _WORKFLOW_INSTALL_EXEC_RE.search(masked_arg):
                return {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Executing `install.py` inside `run_workflow` `Args` is "
                        "prohibited (GEMINI.md Rule 12)."
                    ),
                }
            if _GIT_HOOK_BYPASS_RE.search(masked_arg):
                return {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Git hook bypass flags (`--no-verify`, `commit -n`, "
                        "`core.hooksPath`, `HUSKY=0`) are prohibited inside `run_workflow` `Args`."
                    ),
                }
        pending_flight_writes: List[Tuple[str, str]] = []
        pending_force_ask: Optional[Dict[str, Any]] = None
        swarm_overlay: Dict[str, Any] = {}
        pending_swarm_ops: List[Dict[str, Any]] = []
        for sp_path, sp_mode in script_paths_meta:
            in_ws = any(is_within(sp_path, ws) for ws in workspaces)
            if (sp_mode & stat.S_IWOTH) or (workspaces and not in_ws) or (not workspaces and (sp_mode & 0o222)):
                pending_force_ask = {
                    "decision": "force_ask",
                    "reason": (
                        f"[Harness Workflow Shield] `run_workflow` `ScriptPath` (`{sp_path}`) resides outside "
                        "the active workspace or is world-writable (TOCTOU risk); explicit human confirmation "
                        "is required (GEMINI.md Rule 12 & Rule 15e)."
                    ),
                }
                break
        wf_owner_ws = (
            _workspace_for_target(str(workflow_cwd), workspaces, fallback=workspace)
            if workflow_cwd is not None
            else workspace
        )
        for src in script_sources:
            res, fw = _inspect_workflow_script(
                src,
                arg_strings,
                payload,
                wf_owner_ws,
                workflow_cwd=workflow_cwd,
                swarm_overlay=swarm_overlay,
                pending_swarm_ops=pending_swarm_ops,
            )
            if res.get("decision") == "deny":
                return res
            if res.get("decision") == "force_ask" and pending_force_ask is None:
                pending_force_ask = res
            pending_flight_writes.extend(fw)
        if pending_swarm_ops:
            if bool(payload.get("_workflowDryCheck")) and isinstance(payload.get("_pendingSwarmOps"), list):
                payload["_pendingSwarmOps"].extend(pending_swarm_ops)
            elif not bool(payload.get("_workflowDryCheck")):
                if not _facade_attr("_batch_update_swarm_workers_ledger", _batch_update_swarm_workers_ledger)(pending_swarm_ops):
                    flush_err = "[Harness Swarm Guard] Failed to persist `run_workflow` swarm worker ledger; confirm execution."
                    if pending_force_ask is None:
                        pending_force_ask = {
                            "decision": "force_ask",
                            "reason": flush_err,
                        }
                    elif flush_err not in str(pending_force_ask.get("reason") or ""):
                        pending_force_ask = {
                            "decision": "force_ask",
                            "reason": f"{pending_force_ask.get('reason')} ({flush_err})",
                        }
        if pending_force_ask is not None:
            return pending_force_ask
        for inner_tool, target in pending_flight_writes:
            fw_ws = _workspace_for_target(target, workspaces, fallback=wf_owner_ws)
            _record_flight_pre_write(payload, fw_ws, inner_tool, target)
        return {"decision": "allow"}

    # Normal pass-through in Antigravity 2.0 PreToolUse requires explicit {"decision": "allow"}
    return {"decision": "allow"}

_HANDOFF_COMPLETE_STATUS_RE = _LazyRegex(
    r"(?im)^[^\S\r\n]*(?:[-*•][^\S\r\n]+)?(?:\*\*Status:\*\*|\*\*Status\*\*:|Status:)[^\S\r\n]*`?\[COMPLETE\]`?[^\S\r\n]*$"
)
_HANDOFF_ANY_STATUS_RE = _LazyRegex(
    r"(?im)^[^\S\r\n]*(?:[-*•][^\S\r\n]+)?(?:\*\*Status:\*\*|\*\*Status\*\*:|Status:)[^\S\r\n]*(\S.*?)[^\S\r\n]*$"
)
_AUTH_HTML_COMMENT_RE = _LazyRegex(r"(?s)<!--.*?-->")
_EDIT_TARGET_KEYS: Tuple[str, ...] = (
    "TargetContent",
    "Target",
    "old_string",
    "old_str",
    "oldText",
    "old_text",
)
_EDIT_REPLACEMENT_KEYS: Tuple[str, ...] = (
    "ReplacementContent",
    "Replacement",
    "new_string",
    "new_str",
    "newText",
    "new_text",
)


def _handoff_file_allows_stale_reset(handoff_path: Path) -> bool:
    if not os.path.lexists(handoff_path):
        return True
    try:
        if handoff_path.is_symlink():
            return False
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(handoff_path, flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > 512 * 1024:
                return False
            chunks: List[bytes] = []
            rem = 512 * 1024 + 1
            while rem > 0:
                buf = os.read(fd, min(65536, rem))
                if not buf:
                    break
                chunks.append(buf)
                rem -= len(buf)
            raw_bytes = b"".join(chunks)
            if len(raw_bytes) > 512 * 1024:
                return False
        finally:
            os.close(fd)
    except OSError:
        return False
    raw_handoff = _normalize_markdown_newlines(raw_bytes.decode("utf-8", errors="replace"))
    htext = _FENCE_RE.sub(" ", raw_handoff)
    statuses = _HANDOFF_ANY_STATUS_RE.findall(htext)
    if not statuses or not _HANDOFF_COMPLETE_STATUS_RE.search(htext):
        return False
    return all(bool(_HANDOFF_COMPLETE_STATUS_RE.match(f"Status: {val}")) for val in statuses)


def _old_auth_has_only_parsed_entries(old_text: str, old_auth: set[str], tb_cls: Any) -> bool:
    empty_tokens = ("", "none", "yok", "n/a", "na", "null", "nil", "false", "hayir", "hayır")
    norm_src = _normalize_markdown_newlines(old_text)
    saw_heading = False
    for match in _AUTH_HEADING_RE.finditer(norm_src):
        saw_heading = True
        inline_tail = (match.group(1) or "").strip()
        if inline_tail:
            cleaned_tail = re.sub(r"[-*•\[\]\s.`_:;()]+", "", inline_tail.lower())
            if cleaned_tail not in empty_tokens:
                for part in inline_tail.split(","):
                    seg = part.strip()
                    if seg and tb_cls._extract_authorized_path(seg) not in old_auth:
                        return False
        body = _AUTH_HTML_COMMENT_RE.sub("", match.group(2) or "")
        for raw_line in body.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue
            cleaned_line = re.sub(r"[-*•\[\]\s.`_:;()]+", "", stripped.lower())
            if cleaned_line in empty_tokens:
                continue
            if not stripped.startswith(("-", "*", "•", "[")):
                return False
            if tb_cls._extract_authorized_path(raw_line) not in old_auth:
                return False
    return saw_heading


def _check_worktree_paths_clean_for_reset(
    wt_root: Path,
    sorted_paths: List[str],
    tb_cls: Any,
    *,
    conv_id: str = "",
) -> bool:
    for rel_p in sorted_paths:
        cur = wt_root
        parts = [seg for seg in rel_p.split("/") if seg]
        for idx, seg in enumerate(parts):
            cur = cur / seg
            try:
                if cur.is_symlink():
                    return False
                if idx < len(parts) - 1 and (cur / ".git").exists():
                    return False
            except OSError:
                return False
    try:
        tbg = tb_cls(workspace_dir=wt_root)
        snap_src = tbg._snapshot_source(None)
        if os.path.lexists(snap_src) and not tbg.verify(mode="tdd", authorized_modifications=set()).is_intact:
            return False
    except Exception:
        return False
    try:
        head_proc = subprocess.run(
            ["git", "--literal-pathspecs", "-C", str(wt_root), "rev-parse", "--verify", "HEAD"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        head_oid = head_proc.stdout.strip().lower()
        if head_proc.returncode != 0 or not head_oid:
            return False
        status_proc = subprocess.run(
            [
                "git",
                "--literal-pathspecs",
                "-C",
                str(wt_root),
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--ignored=matching",
                "--",
                *sorted_paths,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if status_proc.returncode != 0 or status_proc.stdout.strip() != "":
            return False
        ls_proc = subprocess.run(
            [
                "git",
                "--literal-pathspecs",
                "-C",
                str(wt_root),
                "ls-files",
                "-v",
                "-z",
                "--",
                *sorted_paths,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if ls_proc.returncode != 0:
            return False
        for entry in ls_proc.stdout.split("\0"):
            if entry and not entry.startswith("H "):
                return False
        flight_file = _flight_recorder_file()
        if conv_id and flight_file.is_file():
            wt_key = str(wt_root.resolve())
            ledger = _read_ledger_safe(flight_file)
            rec = ledger.get(wt_key)
            if isinstance(rec, dict) and str(rec.get("conversation_id") or "") == conv_id:
                rec_base = str(rec.get("base_head") or "").strip().lower()
                if rec_base and rec_base != head_oid:
                    diff_proc = subprocess.run(
                        [
                            "git",
                            "--literal-pathspecs",
                            "-C",
                            str(wt_root),
                            "diff",
                            "--diff-filter=MDCR",
                            "--name-only",
                            rec_base,
                            "HEAD",
                            "--",
                            *sorted_paths,
                        ],
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    if diff_proc.returncode != 0 or diff_proc.stdout.strip() != "":
                        return False
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def _is_safe_stale_auth_reset(
    disk_path: Optional[Path],
    old_text: str,
    new_text: str,
    *,
    conv_id: str = "",
) -> bool:
    if disk_path is None or _extract_normalized_auth_section(new_text) != "":
        return False
    try:
        from guard.test_boundary import TestBoundaryGuard
    except Exception:
        return False
    if TestBoundaryGuard.parse_authorized_tasks_text(new_text) != set():
        return False
    old_auth = TestBoundaryGuard.parse_authorized_tasks_text(old_text)
    if not old_auth or not _old_auth_has_only_parsed_entries(old_text, old_auth, TestBoundaryGuard):
        return False
    ws_dir = disk_path.parent
    try:
        if not ws_dir.is_dir() or not (ws_dir / ".git").exists() or not _is_git_repo_workspace(ws_dir):
            return False
        ws_resolved = ws_dir.resolve()
    except (OSError, RuntimeError):
        return False
    if not _handoff_file_allows_stale_reset(ws_dir / "HANDOFF.md"):
        return False
    main_root = TestBoundaryGuard.resolve_linked_worktree_root(ws_dir)
    if main_root is not None and not _handoff_file_allows_stale_reset(main_root / "HANDOFF.md"):
        return False
    sorted_paths = sorted(old_auth)
    for rel_p in sorted_paths:
        if rel_p.startswith(("-", ":")) or any(ord(ch) < 32 for ch in rel_p):
            return False
    if not _check_worktree_paths_clean_for_reset(ws_dir, sorted_paths, TestBoundaryGuard, conv_id=conv_id):
        return False
    try:
        has_worktrees_dir = (ws_dir / ".git" / "worktrees").is_dir()
    except OSError:
        return False
    if has_worktrees_dir:
        try:
            wt_proc = subprocess.run(
                ["git", "-C", str(ws_dir), "worktree", "list", "--porcelain"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if wt_proc.returncode != 0:
                return False
            for raw_wt_line in wt_proc.stdout.splitlines():
                if raw_wt_line.startswith("worktree "):
                    cand_wt = Path(raw_wt_line[len("worktree "):].strip())
                    try:
                        if not cand_wt.is_dir() or cand_wt.resolve() == ws_resolved:
                            continue
                    except (OSError, RuntimeError):
                        return False
                    if not _handoff_file_allows_stale_reset(cand_wt / "HANDOFF.md"):
                        return False
                    if not _check_worktree_paths_clean_for_reset(
                        cand_wt, sorted_paths, TestBoundaryGuard, conv_id=conv_id
                    ):
                        return False
        except (OSError, subprocess.SubprocessError):
            return False
    return True


def _auth_sections_differ(
    old_text: str,
    new_text: str,
    *,
    disk_path: Optional[Path] = None,
    conv_id: str = "",
) -> bool:
    differ = _extract_normalized_auth_section(new_text) != _extract_normalized_auth_section(old_text)
    if not differ:
        try:
            from guard.test_boundary import TestBoundaryGuard

            if TestBoundaryGuard.parse_authorized_tasks_text(new_text) != TestBoundaryGuard.parse_authorized_tasks_text(old_text):
                differ = True
        except Exception:
            differ = True
    if not differ:
        return False
    if _is_safe_stale_auth_reset(disk_path, old_text, new_text, conv_id=conv_id):
        return False
    return True


def _extract_edit_pair(mapping: Dict[str, Any]) -> Tuple[bool, Optional[Tuple[str, str]]]:
    has_t = any(k in mapping for k in _EDIT_TARGET_KEYS)
    has_r = any(k in mapping for k in _EDIT_REPLACEMENT_KEYS)
    if not has_t and not has_r:
        return False, None
    t_val = next((mapping[k] for k in _EDIT_TARGET_KEYS if k in mapping and mapping[k] is not None), None)
    r_val = next((mapping[k] for k in _EDIT_REPLACEMENT_KEYS if k in mapping and mapping[k] is not None), None)
    if not isinstance(t_val, str) or not isinstance(r_val, str) or t_val == "":
        return True, None
    return True, (_normalize_markdown_newlines(t_val), _normalize_markdown_newlines(r_val))


def _write_mutates_authorized_test_section(
    target: str,
    args: Dict[str, Any],
    base_dir: Optional[Path],
    *,
    allow_stale_reset: bool = True,
    conv_id: str = "",
) -> bool:
    raw_s = target.strip()
    if raw_s.lower().startswith("file:"):
        parsed_uri = _parse_file_uri(raw_s)
        if parsed_uri is None:
            return "tasks" in urllib.parse.unquote(raw_s).lower()
        norm_target = parsed_uri.replace("\\", "/").strip()
    else:
        norm_target = raw_s.replace("\\", "/").strip()
    if Path(norm_target).name.lower() != "tasks.md":
        return False
    raw_disk_path = Path(os.path.expanduser(norm_target))
    if not raw_disk_path.is_absolute():
        raw_disk_path = (base_dir or _repo_root()) / raw_disk_path
    is_target_symlink = False
    try:
        is_target_symlink = raw_disk_path.is_symlink()
        disk_path = raw_disk_path.resolve()
    except (OSError, RuntimeError):
        is_target_symlink = True
        disk_path = raw_disk_path
    reset_disk_path: Optional[Path] = disk_path if (allow_stale_reset and not is_target_symlink) else None
    old_text = ""
    try:
        if disk_path.is_file():
            old_text = disk_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        old_text = ""
    norm_old = _normalize_markdown_newlines(old_text)
    evaluated_any = False

    # 1. Inspect every present full-file or append content key (`SBV-03`)
    for content_key in ("Content", "FileContent", "CodeContent", "content", "file_text"):
        if content_key in args and args.get(content_key) is not None:
            raw_body = args.get(content_key)
            if not isinstance(raw_body, str):
                return True
            evaluated_any = True
            body = _normalize_markdown_newlines(raw_body)
            is_append = bool(args.get("Append") or args.get("append"))
            sim_text = (norm_old + body) if is_append else body
            if _auth_sections_differ(norm_old, sim_text, disk_path=reset_disk_path, conv_id=conv_id):
                return True

    # 2. Inspect every present chunk-list key and top-level replacement key (`SBV-01`, `SBV-02`, `SBV-03`)
    pair_groups: List[List[Tuple[str, str]]] = []
    for chunk_key in ("ReplacementChunks", "edits", "chunks"):
        if chunk_key in args and args.get(chunk_key) is not None:
            chunks = args.get(chunk_key)
            if not isinstance(chunks, list) or not chunks:
                return True
            group: List[Tuple[str, str]] = []
            for ch in chunks:
                if not isinstance(ch, dict):
                    return True
                has_keys, extracted_pair = _extract_edit_pair(ch)
                if not has_keys or extracted_pair is None:
                    return True
                group.append(extracted_pair)
            pair_groups.append(group)

    has_top_edit, top_pair = _extract_edit_pair(args)
    if has_top_edit:
        if top_pair is None:
            return True
        pair_groups.append([top_pair])

    has_existing_heading = bool(_AUTH_HEADING_RE.search(norm_old))
    for pairs in pair_groups:
        evaluated_any = True
        if len(pairs) == 1:
            t_s, r_s = pairs[0]
            if norm_old and t_s in norm_old:
                sim_text = norm_old.replace(t_s, r_s)
                if _auth_sections_differ(norm_old, sim_text, disk_path=reset_disk_path, conv_id=conv_id):
                    return True
            else:
                if has_existing_heading or re.search(
                    r"Authorized\s+Test\s+Modifications", f"{t_s}\n{r_s}", re.IGNORECASE
                ):
                    return True
        else:
            if not norm_old:
                return True
            spans: List[Tuple[int, int, str]] = []
            ambiguous_or_missing = False
            for t_s, r_s in pairs:
                pos = 0
                found_for_pair = 0
                while True:
                    idx = norm_old.find(t_s, pos)
                    if idx == -1:
                        break
                    spans.append((idx, idx + len(t_s), r_s))
                    found_for_pair += 1
                    pos = idx + len(t_s)
                if found_for_pair == 0:
                    ambiguous_or_missing = True
                    break
            if not ambiguous_or_missing:
                spans.sort(key=lambda item: (item[0], item[1]))
                for idx in range(1, len(spans)):
                    if spans[idx - 1][1] > spans[idx][0]:
                        ambiguous_or_missing = True
                        break
            if ambiguous_or_missing:
                return True
            out_parts: List[str] = []
            cursor = 0
            for s_start, s_end, r_s in spans:
                out_parts.append(norm_old[cursor:s_start])
                out_parts.append(r_s)
                cursor = s_end
            out_parts.append(norm_old[cursor:])
            sim_text = "".join(out_parts)
            if _auth_sections_differ(norm_old, sim_text, disk_path=reset_disk_path, conv_id=conv_id):
                return True

    if not evaluated_any:
        return True
    return False
