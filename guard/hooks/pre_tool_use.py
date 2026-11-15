"""
guard/hooks/pre_tool_use.py — PreToolUse bashguard, governance/customization shield, workflow AST & swarm gate (ADR-0008).
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import ast
import os
import re
import stat
import sys
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
    _is_harness_repo_root,
    _iter_jsonl_tail_entries,
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

_GUARD_ADMIN_RE = re.compile(rf"(?:^|[;&|()\n`])\s*{_GUARD_ADMIN_BODY}", re.IGNORECASE)

_DELEGATION_GUARD_ADMIN_RE = re.compile(rf"(?:^|[\s;|&()\n`'\"]){_GUARD_ADMIN_BODY}", re.IGNORECASE)

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
_GUARD_INLINE_PY_RE = re.compile(
    r"(?:"
    rf"\bpython3?(?:\.\d+)?\b[^\n;|&`]*(?:\s-[A-Za-z0-9]*c\b|<<-?\s*['\"]?[A-Za-z0-9_]+['\"]?)[\s\S]*?{_GUARD_API_TOKEN_PAT}|"
    rf"{_GUARD_API_TOKEN_PAT}[\s\S]*?\|\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?python3?(?:\.\d+)?\b"
    r")",
    re.IGNORECASE,
)

# Direct execution of install.py without --dry-run or --help (GEMINI.md Rule 12).
# Anchored to the start of a simple command (or interpreter invocation) so passing `install.py`
# as a path argument to read-only commands (`git diff ... install.py`, `grep ... install.py`) is allowed.
_INSTALL_PY_RE = re.compile(
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

_WORKFLOW_INSTALL_EXEC_RE = re.compile(rf"(?:^|[;&|()\n`])\s*{_WORKFLOW_INSTALL_EXEC_BODY}", re.IGNORECASE)

_DELEGATION_INSTALL_EXEC_RE = re.compile(rf"(?:^|[\s;|&()\n`'\"]){_WORKFLOW_INSTALL_EXEC_BODY}", re.IGNORECASE)

_QUOTED_SPAN_RE = re.compile(r"'[^']*'|\"(?:\\.|[^\"\\])*\"")

_BACKTICK_SPAN_RE = re.compile(r"`((?:\\.|[^`\\])+)`")

_SHELL_C_EXTRACT_RE = re.compile(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}"
    r"(?:(?:[^\s;|&`]*/)?(?:ba|z|da|k)?sh\b[^\n;|&`]*?\s-(?:[A-Za-z0-9]+\s+)*[A-Za-z0-9]*c[A-Za-z0-9]*|eval)\s+"
    r"(?:'([^']*)'|\"((?:\\.|[^\"\\])*)\")",
    re.IGNORECASE,
)

_SCRIPT_C_EXTRACT_RE = re.compile(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?script\b[^\n;|&`]*?"
    r"(?:\s-(?:[A-Za-z0-9]+\s+)*[A-Za-z0-9]*c\s*|\s--command(?:=|\s+))"
    r"(?:'([^']*)'|\"((?:\\.|[^\"\\])*)\"|([^\s;|&`'\"]+))",
    re.IGNORECASE,
)

_PIPE_TO_SH_EXTRACT_RE = re.compile(
    rf"(?:^|[;&|()\n`])\s*(?:echo|printf)\b(?:\s+-[neE]+)*\s+"
    r"(?:'([^']*)'|\"((?:\\.|[^\"\\])*)\")\s*\|\s*"
    rf"{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?(?:ba|z|da|k)?sh\b",
    re.IGNORECASE,
)

_FIND_EXEC_EXTRACT_RE = re.compile(
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
_TERMINAL_MUX_SEGMENT_RE = re.compile(
    r"(?:^|[;&|()\n`])\s*(?:[^\s;|&`]*/)?(?:tmux|screen|byobu|tmate|dtach|abduco|zellij)\b([^\n;|&`]*)",
    re.IGNORECASE,
)

# Keystroke or buffer injection into a multiplexer runs arbitrary commands outside `PreToolUse` inspection.
_TERMINAL_INJECTION_RE = re.compile(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?(?:"
    r"(?:tmux|byobu|tmate)\b[^\n;|&`]*\s(?:send-keys|send|paste-buffer|pasteb|load-buffer|loadb|set-buffer|setb)\b|"
    r"screen\b[^\n;|&`]*\s-X\s+(?:stuff|paste|readbuf|register)\b|"
    r"zellij\b[^\n;|&`]*\s(?:write-chars|write)\b"
    r")",
    re.IGNORECASE,
)

# Exec-like calls whose argv is a string list/tuple (`pty.spawn(['agy-guard', 'unlock'])`,
# `subprocess.run(("python3", "install.py"))`) or a single command string (`os.system('...')`).
_EXEC_CALL_ARGV_RE = re.compile(
    r"\b(?:system|popen|run|call|check_call|check_output|getoutput|getstatusoutput|Popen|spawn|spawnSync|"
    r"execSync|execFile|execFileSync|exec[lv]p?e?|spawn[lv]p?e?)\s*\(\s*"
    r"(?:[\[(]\s*((?:'[^'\n]*'|\"[^\"\n]*\")(?:\s*,\s*(?:'[^'\n]*'|\"[^\"\n]*\"))*)\s*,?\s*[\])]"
    r"|('[^'\n]*'|\"[^\"\n]*\"))"
)

_STR_ARGV_TOKEN_RE = re.compile(r"'([^'\n]*)'|\"([^\"\n]*)\"")

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

_QUOTED_ARG_TOKEN_RE = re.compile(r"'([^']*)'|\"((?:\\.|[^\"\\])*)\"|([^\s'\"]+)")

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
    parts: List[str] = []
    last = 0
    for m in _QUOTED_SPAN_RE.finditer(cmd):
        outside = cmd[last : m.start()]
        parts.append(re.sub(r"\\([A-Za-z0-9_./~-])", r"\1", outside))
        span = m.group(0)
        inner = span[1:-1]
        if inner == "":
            adjacent = (m.start() > 0 and not cmd[m.start() - 1].isspace()) or (
                m.end() < len(cmd) and not cmd[m.end()].isspace()
            )
            parts.append("" if adjacent else span)
        elif not re.search(r"[\s\\;|&()<>`]", inner):
            parts.append(inner)
        else:
            parts.append(span)
        last = m.end()
    parts.append(re.sub(r"\\([A-Za-z0-9_./~-])", r"\1", cmd[last:]))
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
            r"(?:/(?:\s|$|[;&|])|~(?:/|\s|$|[;&|])|\$HOME\b|\.\.(?:/|\s|$|[;&|])|\*(?:\s|$|[;&|]))"
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
    allowed_roots: List[Path] = [Path("/tmp"), Path("/var/tmp")]
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
        for tok in raw_tokens:
            if not tok or re.match(r"^\d*>{1,2}", tok) or tok in ("2>&1", ">/dev/null", "2>/dev/null"):
                continue
            if not after_ddash and tok == "--":
                after_ddash = True
                continue
            if not after_ddash and tok.startswith("-") and len(tok) > 1:
                if tok == "--recursive" or (not tok.startswith("--") and ("r" in tok[1:] or "R" in tok[1:])):
                    is_recursive_rm = True
                continue
            pos_args.append(tok)

        if verb == "rm" and not is_recursive_rm:
            continue
        if not pos_args:
            continue

        for arg in pos_args:
            norm_arg = arg.replace("${HOME}", home_str).replace("$HOME", home_str)
            if norm_arg == "~" or norm_arg.startswith("~/"):
                norm_arg = home_str + norm_arg[1:]
            if norm_arg.startswith("$"):
                continue
            if norm_arg in ("/dev/null",):
                continue
            if not norm_arg.startswith("/") and ".." not in norm_arg.split("/"):
                continue
            cand_raw = Path(norm_arg) if norm_arg.startswith("/") else (base_dir / norm_arg)
            cand_abs = Path(os.path.abspath(cand_raw))
            if not any(is_within(cand_abs, root) for root in allowed_roots):
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

_URI_SCHEME_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def _targets_governance_dir(target_path_str: str, base_dir: Optional[Path] = None) -> bool:
    if not target_path_str:
        return False
    cleaned = target_path_str.split("\x00", 1)[0].strip()
    if not cleaned:
        return False
    if _URI_SCHEME_PREFIX_RE.match(cleaned):
        if not cleaned.lower().startswith("file://"):
            return False
        parsed_uri = urllib.parse.urlparse(cleaned)
        if parsed_uri.netloc and parsed_uri.netloc.lower() != "localhost":
            return False
        uri_path = urllib.parse.unquote(parsed_uri.path or "")
        if re.match(r"^/[A-Za-z]:/", uri_path):
            uri_path = uri_path[1:]
        cleaned = uri_path.split("\x00", 1)[0].strip()
        if not cleaned:
            return False
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
    norm = cmd.replace("${HOME}", "$HOME")
    norm = re.sub(r"(?<!:)/{2,}", "/", norm)
    for _ in range(16):
        collapsed_dot = re.sub(r"/\.(?=/|\s|$|[;&|'\"()])", "", norm)
        if collapsed_dot == norm:
            break
        norm = collapsed_dot
    for _ in range(32):
        collapsed = re.sub(
            r"/(?!\.\.?(?:/|\s|$|[;&|'\"()]))[^/\s;|&'\"()]+/\.\.(?=/|\s|$|[;&|'\"()])",
            "",
            norm,
        )
        if collapsed == norm:
            break
        norm = collapsed
    norm = re.sub(r"(?<!:)/{2,}", "/", norm)
    return norm

_SIMPLE_VAR_ASSIGN_RE = re.compile(
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

_SHELL_MUTATION_INDICATOR_RE = re.compile(
    r"(?:"
    r">{1,2}\|?|"
    r"\b(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip)\b|"
    r"\bfind\b[^\n;|&]*\s-(?:delete|exec|execdir|ok)\b|"
    r"\bsed\b[^\n;|&]*\s-(?:[A-Za-z]*i\S*|-in-place(?:=\S*)?)\b|"
    r"\b(?:curl|wget)\b[^\n;|&]*\s-(?:o|O)\b|"
    r"\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*(?:\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*)\b|<<)"
    r")"
)

_SHELL_DOTDOT_TOKEN_RE = re.compile(r"(?:^|[\s/'\"=])\.\.(?:$|[\s/'\";&|()])")

def _command_mutates_governance(cmd: str) -> bool:
    """Detects shell commands that write, copy, move, delete, or chmod inside protected governance or Guard state/runtime trees."""
    unquoted_expanded = _normalize_governance_globs(_unquote_single_tokens(_expand_simple_shell_vars(cmd)))
    norm_cmd = _normalize_shell_paths(unquoted_expanded)
    has_dotdot_escape = bool(_SHELL_DOTDOT_TOKEN_RE.search(norm_cmd))

    # Catch inline/heredoc/piped interpreter scripts constructing home-relative governance paths (`Path.home() / '.gemini' / 'config'`)
    if re.search(
        r"(?:\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*(?:\s-(?:[A-Za-z0-9]*c|e)\b|<<)|\|\s*(?:[A-Za-z0-9_./-]*\s+)*(?:python3?(?:\.\d+)?|node|ruby|perl)\b)",
        cmd,
    ):
        inline_cmd = cmd
        if not has_dotdot_escape and "symlink" not in cmd:
            inline_cmd = re.sub(
                r"(?:['\"]\.local['\"]\s*/\s*['\"]state['\"]\s*/\s*['\"]antigravity-(?:harness|guard)['\"]\s*/\s*['\"]staging['\"]|"
                rf"(?:~|\$HOME|{re.escape(str(state_dir()))}|[^\s'\"/]+/\.local/state)/antigravity-(?:harness|guard)/staging(?=/|['\"\s,)]))",
                "__RUNTIME_STAGING__",
                inline_cmd,
            )
        if re.search(
            r"(?:['\"]\.gemini['\"]\s*(?:/|,)\s*['\"](?:config|GEMINI\.md|AGENTS\.md)['\"]|"
            r"\.gemini/(?:config|GEMINI\.md|AGENTS\.md)|"
            r"(?:\.local/(?:state|share)|/usr/(?:lib|share))/antigravity-(?:harness|guard)|"
            r"['\"](?:state|share|lib)['\"]\s*(?:/|,)\s*['\"]antigravity-(?:harness|guard)['\"]|"
            r"['\"]\.local['\"]\s*(?:/|,)\s*['\"]bin['\"]\s*(?:/|,)\s*['\"]agy-|"
            r"\.local/bin/agy-)",
            inline_cmd,
            re.IGNORECASE,
        ) and re.search(
            r"(?:write_text|write_bytes|\.write\s*\(|\bopen\s*\([^)]*['\"][wa+x]|unlink|remove|rmtree|rename|replace|chmod|symlink|shutil\.(?:copy|move|rmtree))",
            cmd,
        ):
            return True

    home = Path.home()
    cfg_roots = list(
        dict.fromkeys(
            [*(str(p) for p in _config_root_candidates()), "~/.gemini/config", "$HOME/.gemini/config"]
        )
    )
    gemini_top_files = [
        str(home / ".gemini" / "GEMINI.md"),
        str(home / ".gemini" / "AGENTS.md"),
        "~/.gemini/GEMINI.md",
        "$HOME/.gemini/GEMINI.md",
        "~/.gemini/AGENTS.md",
        "$HOME/.gemini/AGENTS.md",
    ]
    for cfg_cand in _config_root_candidates():
        if cfg_cand.name == "config" and cfg_cand.parent.name == ".gemini":
            gemini_top_files.append(str(cfg_cand.parent / "GEMINI.md"))
            gemini_top_files.append(str(cfg_cand.parent / "AGENTS.md"))
    state_roots = list(
        dict.fromkeys(
            [
                *(str(p) for p in _state_root_candidates()),
                "~/.local/state/antigravity-harness",
                "$HOME/.local/state/antigravity-harness",
                "~/.local/state/antigravity-guard",
                "$HOME/.local/state/antigravity-guard",
            ]
        )
    )
    custom_root_tokens: List[str] = []
    for c_root in _custom_enforced_governance_roots():
        custom_root_tokens.append(str(c_root))
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
                str(data_dir()),
                str(data_dir() / "runtime"),
                str(data_dir() / "snapshots"),
                "~/.local/share/antigravity-harness",
                "$HOME/.local/share/antigravity-harness",
                "~/.local/share/antigravity-guard",
                "$HOME/.local/share/antigravity-guard",
                str(home / ".local" / "bin" / "agy-guard"),
                str(home / ".local" / "bin" / "agy-porter"),
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
                        str(home / ".local" / "bin" / "porter"),
                        "~/.local/bin/porter",
                        "$HOME/.local/bin/porter",
                    ]
                    if (home / ".local" / "bin" / "porter") in _governance_roots()
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
    # ONLY when no `..` traversal, link creation (`ln`), or archive extraction (`tar`/`unzip`) is present.
    scrubbed = norm_cmd
    has_dotdot_escape = bool(_SHELL_DOTDOT_TOKEN_RE.search(norm_cmd))
    if not has_dotdot_escape and not re.search(r"\b(?:ln|tar|unzip)\b", scrubbed):
        for root in cfg_roots:
            esc_root = re.escape(root)
            for sub in _RUNTIME_CONFIG_SUBDIRS:
                if sub == "plugins":
                    scrubbed = re.sub(
                        rf"{esc_root}/plugins(?=/|\s|$|[;&|'\"()])(?![^\s;|&'\"]*(?:/(?:skills|agents|rules|hooks|scripts|bin|hooks\.json|mcp_config\.json|\.mcp\.json)\b|\.(?:mdc?|py[cow]?|m?js|cjs|tsx?|jsx|sh|bash|zsh|fish|ksh|pl|rb|php|ps1|bat|cmd|so|dylib|dll|exe|wasm)\b))",
                        "__RUNTIME_SUBDIR__",
                        scrubbed,
                        flags=re.IGNORECASE,
                    )
                else:
                    scrubbed = re.sub(
                        rf"{esc_root}/{re.escape(sub)}(?=/|\s|$|[;&|'\"()])",
                        "__RUNTIME_SUBDIR__",
                        scrubbed,
                    )
        for st_root in state_roots:
            esc_st = re.escape(st_root)
            scrubbed = re.sub(
                rf"{esc_st}/staging(?=/|\s|$|[;&|'\"()])",
                "__RUNTIME_SUBDIR__",
                scrubbed,
            )
    if not any(tok in scrubbed for tok in roots):
        return False
    # Read-only commands are permitted only when not redirecting or running mutating flags/interpreters
    for root in roots:
        escaped = re.escape(root)
        if re.search(rf">{{1,2}}\|?\s*['\"]?{escaped}", scrubbed):
            return True
        if re.search(rf"\b(?:cd|pushd)\s+['\"]?{escaped}", scrubbed) and _SHELL_MUTATION_INDICATOR_RE.search(scrubbed):
            return True
        if re.search(
            rf"\b(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip)\b[^\n;|&]*{escaped}",
            scrubbed,
        ):
            return True
        if re.search(
            rf"{escaped}[^\n;&]*\|\s*(?:{_CMD_WRAPPER_PREFIX})*xargs\b[^\n;&]*\b(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip|sed|python3?(?:\.\d+)?|node|ruby|perl|(?:ba|z|da|k)?sh)\b",
            scrubbed,
        ):
            return True
        if re.search(rf"\bfind\b[^\n;|&]*{escaped}[^\n;|&]*\s-(?:delete|exec|execdir|ok)\b", scrubbed):
            return True
        if re.search(
            rf"\bsed\b[^\n;|&]*(?:\s-(?:[A-Za-z]*i\S*|-in-place(?:=\S*)?)\b[^\n;|&]*{escaped}|{escaped}[^\n;|&]*\s-(?:[A-Za-z]*i\S*|-in-place(?:=\S*)?)\b)",
            scrubbed,
        ):
            return True
        if re.search(rf"\b(?:curl|wget)\b[^\n;|&]*\s-(?:o|O)\b[^\n;|&]*{escaped}", scrubbed):
            return True
        if re.search(
            rf"(?:\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*)\b[^\n;|&]*{escaped}|{escaped}[^\n;|&]*\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*)\b)",
            scrubbed,
        ):
            return True
        if re.search(r"\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*<<", scrubbed) and re.search(
            r"(?:write|open\s*\(|unlink|remove|rmtree|rename|replace|chmod|symlink|shutil|fs\.)",
            scrubbed,
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

_SETTINGS_MODEL_RE = re.compile(
    r"changed\s+setting\s+`?Model\s+Selection`?\s+from\s+[^\n]+?\s+to\s+([^\n]+?)\.(?=\s|$)",
    re.IGNORECASE,
)

_SETTINGS_EFFORT_RE = re.compile(
    r"changed\s+setting\s+`?(?:Effort(?:\s+Level)?|Thinking\s+Level|Reasoning\s+Effort)`?\s+from\s+[^\n]+?\s+to\s+([^\n]+?)\.(?=\s|$)",
    re.IGNORECASE,
)

_SETTINGS_KV_MODEL_RE = re.compile(
    r"(?:^|[\n,{])\s*['\"`]?(?:modelName|model_name|model|Model\s+Selection)['\"`]?\s*:\s*['\"`]?([^\n,\"'`\}]+)",
    re.IGNORECASE,
)

_SETTINGS_KV_EFFORT_RE = re.compile(
    r"(?:^|[\n,{])\s*['\"`]?(?:effort|effortLevel|effort_level|thinkingLevel|thinking_level|reasoningEffort|Effort(?:\s+Level)?)['\"`]?\s*:\s*['\"`]?([^\n,\"'`\}]+)",
    re.IGNORECASE,
)

_MODEL_EMBEDDED_EFFORT_RE = re.compile(
    r"(?:(?:\(\s*|(?:,|\s+-\s+)\s*)(xhigh|extra(?:\s*-\s*high|\s+high)?|high|max|maximum|medium|med|low|minimal|min)\s*\)\s*$|"
    r"-(xhigh|extra-high|extra|high|max|maximum|medium|low|minimal)$)",
    re.IGNORECASE,
)

_USER_REQUEST_BLOCK_RE = re.compile(r"(?is)<USER_REQUEST\b[^<>]*>.*?</USER_REQUEST\s*>")

_USER_SETTINGS_BLOCK_RE = re.compile(r"(?is)<USER_SETTINGS_CHANGE\b[^<>]*>(.*?)</USER_SETTINGS_CHANGE\s*>")

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
    norm_cmd = _normalize_shell_paths(_unquote_single_tokens(_expand_simple_shell_vars(cmd)))
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
        rf"(?:\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*)\b[^\n;|&]*{target_pat}|{target_pat}[^\n;|&]*\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*)\b)",
        norm_cmd,
    ):
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
                    seed_pbtxt = str(data.get("last_pbtxt_model") or "").strip()
                    seed_model = str(data.get("last_audited_model") or "").strip()
                    if seed_pbtxt and seed_pbtxt.upper() == target_up and seed_model:
                        return f"matches seed `last_pbtxt_model` -> `{seed_model}`, {eff_note}"
        except (OSError, ValueError):
            continue
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

_WORKFLOW_READONLY_MODE_RE = re.compile(r"^[rtbU]+$")

_WORKFLOW_ARCHIVE_READONLY_MODE_RE = re.compile(r"^(?:r(?::[a-z0-9*]*)?|[rtb]+)$")

_PEP263_ENCODING_RE = re.compile(r"coding[:=]\s*([-\w.]+)")

_FORBIDDEN_WORKFLOW_MODULES = frozenset({
    "subprocess",
    "pty",
    "popen2",
    "commands",
    "multiprocessing",
    "_posixsubprocess",
    "_winapi",
    "msvcrt",
    "posix",
    "nt",
    "os2",
    "ce",
    "_io",
    "_pyio",
    "fileinput",
    "ctypes",
    "cffi",
    "importlib",
    "runpy",
    "code",
    "codeop",
    "builtins",
    "operator",
    "gc",
    "inspect",
    "pdb",
    "bdb",
    "py_compile",
    "compileall",
    "zipapp",
    "signal",
    "fcntl",
    "resource",
    "tempfile",
    "sqlite3",
    "dbm",
    "shelve",
    "marshal",
    "pickle",
    "urllib",
    "http",
    "socket",
    "ssl",
    "ftplib",
    "poplib",
    "imaplib",
    "smtplib",
    "telnetlib",
    "xmlrpc",
    "logging",
    "xml",
    "webbrowser",
})

_FORBIDDEN_CHILD_PROC_MODULES = frozenset({
    "subprocess",
    "pty",
    "popen2",
    "commands",
    "multiprocessing",
    "_posixsubprocess",
    "_winapi",
})

_FORBIDDEN_OS_EXEC_NAMES = frozenset({
    "system",
    "startfile",
    "popen",
    "fdopen",
    "openpty",
    "login_tty",
    "pidfd_open",
    "putenv",
    "unsetenv",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "fork",
    "forkpty",
    "posix_spawn",
    "posix_spawnp",
    "kill",
    "killpg",
})

_FORBIDDEN_OS_FS_NAMES = frozenset({
    "open",
    "write",
    "pwrite",
    "writev",
    "pwritev",
    "remove",
    "unlink",
    "rmdir",
    "removedirs",
    "rename",
    "renames",
    "replace",
    "chdir",
    "fchdir",
    "chroot",
    "chmod",
    "fchmod",
    "lchmod",
    "chown",
    "fchown",
    "lchown",
    "symlink",
    "link",
    "truncate",
    "ftruncate",
    "posix_fallocate",
    "sendfile",
    "copy_file_range",
    "splice",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "memfd_create",
    "mkdir",
    "makedirs",
    "mknod",
    "mkfifo",
    "utime",
})

_FORBIDDEN_ASYNCIO_EXEC_NAMES = frozenset({
    "create_subprocess_exec",
    "create_subprocess_shell",
    "open_connection",
    "open_unix_connection",
    "start_server",
    "start_unix_server",
    "create_connection",
    "create_unix_connection",
    "create_server",
    "create_unix_server",
    "create_datagram_endpoint",
    "connect_write_pipe",
    "connect_read_pipe",
    "sock_connect",
    "sock_sendall",
    "sock_sendfile",
    "run_in_executor",
    "to_thread",
})

_FORBIDDEN_EXEC_ATTRS = (
    _FORBIDDEN_OS_EXEC_NAMES
    | _FORBIDDEN_ASYNCIO_EXEC_NAMES
    | frozenset({"subprocess_exec", "subprocess_shell", "Popen", "check_call", "check_output"})
)

_FORBIDDEN_DIRECT_FS_ATTRS = frozenset({
    "write",
    "writelines",
    "pwrite",
    "writev",
    "pwritev",
    "write_text",
    "write_bytes",
    "touch",
    "mkdir",
    "makedirs",
    "unlink",
    "rmdir",
    "removedirs",
    "rename",
    "renames",
    "chdir",
    "fchdir",
    "chroot",
    "chmod",
    "fchmod",
    "lchmod",
    "chown",
    "fchown",
    "lchown",
    "symlink",
    "symlink_to",
    "hardlink_to",
    "truncate",
    "ftruncate",
    "posix_fallocate",
    "sendfile",
    "copy_file_range",
    "splice",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "memfd_create",
    "utime",
    "mknod",
    "mkfifo",
    "move",
    "move_into",
    "copy_into",
    "copy2",
    "copyfile",
    "copyfileobj",
    "copymode",
    "copystat",
    "copytree",
    "unpack_archive",
    "make_archive",
    "extract",
    "extractall",
    "writestr",
    "FileType",
    "open_code",
    "bltn_open",
    "BufferedWriter",
    "BufferedRandom",
})

_NON_ALIASABLE_FS_ATTRS = (
    _FORBIDDEN_DIRECT_FS_ATTRS
    | _FORBIDDEN_OS_FS_NAMES
    | frozenset({
        "rmtree",
        "open",
        "FileIO",
        "ZipFile",
        "PyZipFile",
        "TarFile",
        "GzipFile",
        "BZ2File",
        "LZMAFile",
        "copy",
        "write",
        "writelines",
    })
)

_STDLIB_MODULES: frozenset[str] = frozenset(getattr(sys, "stdlib_module_names", ()))

_ALLOWED_STDLIB_WORKFLOW_MODULES = frozenset({
    "__future__",
    "abc",
    "argparse",
    "ast",
    "asyncio",
    "base64",
    "bisect",
    "bz2",
    "calendar",
    "codecs",
    "collections",
    "contextlib",
    "copy",
    "csv",
    "dataclasses",
    "datetime",
    "decimal",
    "difflib",
    "enum",
    "errno",
    "fnmatch",
    "fractions",
    "functools",
    "glob",
    "gzip",
    "hashlib",
    "heapq",
    "hmac",
    "html",
    "io",
    "ipaddress",
    "itertools",
    "json",
    "keyword",
    "lzma",
    "math",
    "numbers",
    "os",
    "pathlib",
    "posixpath",
    "pprint",
    "queue",
    "random",
    "re",
    "secrets",
    "shlex",
    "shutil",
    "stat",
    "statistics",
    "struct",
    "sys",
    "tarfile",
    "textwrap",
    "time",
    "tomllib",
    "typing",
    "unicodedata",
    "uuid",
    "zipfile",
    "zlib",
})

_FORBIDDEN_DUNDER_NAMES = frozenset({
    "__builtins__",
    "__import__",
    "__subclasses__",
    "__globals__",
    "__code__",
    "__loader__",
    "__spec__",
    "__dict__",
    "__class__",
    "__bases__",
    "__mro__",
    "__closure__",
    "__func__",
    "__self__",
    "__wrapped__",
    "__traceback__",
    "__cause__",
    "__context__",
    "__suppress_context__",
    "__objclass__",
    "__getattribute__",
    "__getattr__",
    "__setattr__",
    "__delattr__",
    "__match_args__",
    "__instancecheck__",
    "__subclasscheck__",
    "__init_subclass__",
    "__class_getitem__",
    "__prepare__",
    "__set_name__",
    "__reduce__",
    "__reduce_ex__",
    "__getstate__",
    "__setstate__",
})

_FORBIDDEN_FRAME_ATTRS = frozenset({
    "gi_frame",
    "gi_code",
    "gi_yieldfrom",
    "gi_running",
    "gi_suspended",
    "cr_frame",
    "cr_code",
    "cr_origin",
    "cr_await",
    "cr_running",
    "cr_suspended",
    "ag_frame",
    "ag_code",
    "ag_await",
    "ag_running",
    "ag_suspended",
    "tb_frame",
    "tb_next",
    "tb_lasti",
    "tb_lineno",
    "f_builtins",
    "f_globals",
    "f_locals",
    "f_back",
    "f_code",
    "f_trace",
    "f_trace_lines",
    "f_trace_opcodes",
    "f_lasti",
    "f_lineno",
})

_FORBIDDEN_CALLABLE_BUILTINS = frozenset({
    "eval",
    "exec",
    "compile",
    "__import__",
    "breakpoint",
    "help",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
    "input",
    "type",
})

_FORBIDDEN_REFLECTIVE_ATTRS = frozenset({
    "exec",
    "eval",
    "__import__",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
    "breakpoint",
    "help",
    "import_module",
    "exec_module",
    "load_module",
    "run_path",
    "run_module",
    "attrgetter",
    "methodcaller",
    "MethodType",
    "capture_call_graph",
    "format",
    "format_map",
    "vformat",
    "get_field",
    "get_value",
    "Formatter",
    "Template",
})

_SAFE_WORKFLOW_HOST_CALLABLES = frozenset({
    "parallel",
    "pipeline",
    "phase",
    "trajectory",
    "log",
    "print",
})

_SAFE_WORKFLOW_BUILTINS = frozenset({
    "abs",
    "aiter",
    "all",
    "anext",
    "any",
    "ascii",
    "bin",
    "bool",
    "bytearray",
    "bytes",
    "callable",
    "chr",
    "classmethod",
    "complex",
    "dict",
    "divmod",
    "enumerate",
    "filter",
    "float",
    "frozenset",
    "hash",
    "hex",
    "id",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "list",
    "map",
    "max",
    "memoryview",
    "min",
    "next",
    "object",
    "oct",
    "ord",
    "pow",
    "property",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "slice",
    "sorted",
    "staticmethod",
    "str",
    "sum",
    "super",
    "tuple",
    "zip",
    "BaseException",
    "Exception",
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "BlockingIOError",
    "BrokenPipeError",
    "BufferError",
    "ChildProcessError",
    "ConnectionError",
    "EOFError",
    "FileExistsError",
    "FileNotFoundError",
    "FloatingPointError",
    "GeneratorExit",
    "ImportError",
    "IndexError",
    "InterruptedError",
    "IsADirectoryError",
    "KeyError",
    "KeyboardInterrupt",
    "LookupError",
    "MemoryError",
    "ModuleNotFoundError",
    "NameError",
    "NotADirectoryError",
    "NotImplementedError",
    "OSError",
    "OverflowError",
    "PermissionError",
    "ProcessLookupError",
    "RecursionError",
    "ReferenceError",
    "RuntimeError",
    "StopAsyncIteration",
    "StopIteration",
    "SyntaxError",
    "SystemError",
    "SystemExit",
    "TimeoutError",
    "TypeError",
    "UnboundLocalError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "UnicodeError",
    "UnicodeTranslateError",
    "ValueError",
    "ZeroDivisionError",
})

_SAFE_ENVIRON_READ_METHODS = frozenset({"get", "keys", "values", "items", "copy"})

_PROTECTED_HOST_PRIMITIVES = frozenset({
    "open",
    "call_tool",
    "agent",
    "parallel",
    "pipeline",
    "trajectory",
    "log",
    "phase",
    "args",
})

_NON_ALIASABLE_WORKFLOW_NAMES = _FORBIDDEN_CALLABLE_BUILTINS | frozenset({
    "open",
    "call_tool",
    "agent",
    "parallel",
    "pipeline",
    "trajectory",
})

_UNCONDITIONAL_FORBIDDEN_SYS_ATTRS = frozenset({
    "meta_path",
    "path_hooks",
    "path_importer_cache",
    "addaudithook",
    "settrace",
    "gettrace",
    "setprofile",
    "getprofile",
    "monitoring",
    "exc_info",
    "last_traceback",
    "last_exc",
    "last_value",
    "last_type",
    "_getframe",
    "_getframemodulename",
    "_current_frames",
    "_current_exceptions",
    "breakpointhook",
    "excepthook",
    "unraisablehook",
    "displayhook",
    "remote_exec",
    "call_tracing",
})

_FORBIDDEN_SYS_ATTRS = _UNCONDITIONAL_FORBIDDEN_SYS_ATTRS | frozenset({
    "modules",
    "path",
    "audit",
    "exception",
    "setdlopenflags",
})

_FORBIDDEN_REEXPORT_ATTRS = (
    (_FORBIDDEN_WORKFLOW_MODULES - frozenset({"code"}))
    | _FORBIDDEN_CHILD_PROC_MODULES
    | frozenset({
        "builtins",
        "bltns",
        "os",
        "posix",
        "nt",
        "sys",
        "shutil",
        "io",
        "codecs",
        "tarfile",
        "zipfile",
        "gzip",
        "bz2",
        "lzma",
        "types",
        "concurrent",
        "threading",
        "importlib",
        "annotationlib",
        "copyreg",
        "weakref",
        "pwd",
        "grp",
        "pathlib",
        "posixpath",
        "ntpath",
        "genericpath",
        "linecache",
        "tokenize",
        "subprocess",
        "base_subprocess",
        "unix_events",
        "selector_events",
        "proactor_events",
        "windows_events",
        "windows_utils",
        "base_events",
        "base_futures",
        "base_tasks",
        "events",
        "tasks",
        "coroutines",
        "futures",
        "locks",
        "queues",
        "protocols",
        "threads",
        "timeouts",
        "staggered",
        "constants",
        "exceptions",
        "format_helpers",
        "mixins",
        "taskgroups",
        "tools",
        "graph",
        "runners",
        "streams",
        "sslproto",
        "trsock",
        "transports",
    })
)

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
    if depth > _WORKFLOW_MAX_ARG_DEPTH:
        return "[Harness Workflow Shield] `run_workflow` `Args` exceeds maximum nesting depth (32)."
    if isinstance(value, str):
        if "\x00" in value:
            return "[Harness Workflow Shield] Null bytes are prohibited inside `run_workflow` `Args`."
        if value:
            out.append(value)
        return None
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                if "\x00" in k:
                    return "[Harness Workflow Shield] Null bytes are prohibited inside `run_workflow` `Args`."
                if k:
                    out.append(k)
            err = _collect_workflow_arg_strings(v, out, depth + 1)
            if err:
                return err
        return None
    if isinstance(value, (list, tuple)):
        for elt in value:
            if isinstance(elt, str) and "\x00" in elt:
                return "[Harness Workflow Shield] Null bytes are prohibited inside `run_workflow` `Args`."
        str_parts = [elt for elt in value if isinstance(elt, str) and elt]
        if len(str_parts) >= 2:
            out.append(" ".join(str_parts))
        for elt in value:
            err = _collect_workflow_arg_strings(elt, out, depth + 1)
            if err:
                return err
        return None
    return None

def _extract_workflow_sources_ex(
    args: Dict[str, Any], workspace: Optional[Path]
) -> Tuple[List[str], List[str], Optional[Path], List[Tuple[Path, int]], Optional[str]]:
    """
    Extracts `(script_sources, arg_strings, workflow_cwd, script_paths_meta, error_reason)` from `run_workflow`.
    `script_paths_meta` records `(resolved_path, st_mode)` for every `ScriptPath` file read so TOCTOU
    risk on external/world-writable `ScriptPath` targets can require confirmation (`I-01`).
    """
    try:
        base_dir: Optional[Path] = workspace if workspace is not None else Path.cwd()
    except OSError:
        base_dir = workspace

    cwd_values: List[str] = []
    for ck in ("Cwd", "cwd"):
        if ck not in args:
            continue
        cwd_raw = args.get(ck)
        if cwd_raw is None:
            continue
        if not isinstance(cwd_raw, str):
            return [], [], base_dir, [], f"[Harness Workflow Shield] `run_workflow` `{ck}` argument must be a string."
        if "\x00" in cwd_raw:
            return [], [], base_dir, [], f"[Harness Workflow Shield] Null bytes are prohibited inside `run_workflow` `{ck}`."
        if cwd_raw != cwd_raw.strip():
            return (
                [],
                [],
                base_dir,
                [],
                f"[Harness Workflow Shield] `run_workflow` `{ck}` must not contain leading or trailing whitespace.",
            )
        if cwd_raw:
            cwd_values.append(cwd_raw)
    if len(set(cwd_values)) > 1:
        return [], [], base_dir, [], "[Harness Workflow Shield] Conflicting `Cwd`/`cwd` arguments in `run_workflow`."
    if cwd_values:
        cwd_path = Path(os.path.expanduser(cwd_values[0]))
        if not cwd_path.is_absolute():
            if base_dir is None:
                return [], [], None, [], "[Harness Workflow Shield] Cannot resolve relative `Cwd` without a working directory."
            base_dir = base_dir / cwd_path
        else:
            base_dir = cwd_path

    script_sources: List[str] = []
    script_paths_meta: List[Tuple[Path, int]] = []
    for sk in ("Script", "script"):
        if sk not in args:
            continue
        inline = args.get(sk)
        if inline is None:
            continue
        if not isinstance(inline, str):
            return [], [], base_dir, [], f"[Harness Workflow Shield] `run_workflow` `{sk}` argument must be a string."
        if "\x00" in inline:
            return [], [], base_dir, [], f"[Harness Workflow Shield] Null bytes are prohibited inside `run_workflow` `{sk}`."
        if inline.strip():
            if len(inline.encode("utf-8", errors="replace")) > _WORKFLOW_MAX_BYTES:
                return [], [], base_dir, [], "[Harness Workflow Shield] `run_workflow` inline `Script` exceeds 1 MB inspection limit."
            cookie_err = _check_pep263_cookie(inline)
            if cookie_err:
                return [], [], base_dir, [], cookie_err
            script_sources.append(inline)

    for sp_key in ("ScriptPath", "scriptPath", "script_path"):
        if sp_key not in args:
            continue
        sp_raw = args.get(sp_key)
        if sp_raw is None:
            continue
        if not isinstance(sp_raw, str):
            return [], [], base_dir, [], f"[Harness Workflow Shield] `run_workflow` `{sp_key}` argument must be a string."
        if "\x00" in sp_raw:
            return [], [], base_dir, [], f"[Harness Workflow Shield] Null bytes are prohibited inside `run_workflow` `{sp_key}`."
        if sp_raw != sp_raw.strip():
            return (
                [],
                [],
                base_dir,
                [],
                f"[Harness Workflow Shield] `run_workflow` `{sp_key}` must not contain leading or trailing whitespace.",
            )
        if not sp_raw:
            continue
        sp = Path(os.path.expanduser(sp_raw))
        if not sp.is_absolute():
            if base_dir is None:
                return [], [], None, [], f"[Harness Workflow Shield] Cannot resolve relative `{sp_key}` without a working directory."
            sp = base_dir / sp
        try:
            if sp.is_symlink():
                return [], [], base_dir, [], "[Harness Workflow Shield] `run_workflow` `ScriptPath` must not be a symbolic link."
            open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            fd = os.open(str(sp), open_flags)
        except (OSError, ValueError) as exc:
            return [], [], base_dir, [], f"[Harness Workflow Shield] Cannot inspect `run_workflow` `ScriptPath` (`{sp}`): {exc}"
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return [], [], base_dir, [], f"[Harness Workflow Shield] `run_workflow` `ScriptPath` (`{sp}`) must be a regular file."
            if st.st_size > _WORKFLOW_MAX_BYTES:
                return [], [], base_dir, [], "[Harness Workflow Shield] `run_workflow` `ScriptPath` exceeds 1 MB inspection limit."
            chunks_b: List[bytes] = []
            total_b = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total_b += len(chunk)
                if total_b > _WORKFLOW_MAX_BYTES:
                    return [], [], base_dir, [], "[Harness Workflow Shield] `run_workflow` `ScriptPath` exceeds 1 MB inspection limit."
                chunks_b.append(chunk)
            raw_bytes = b"".join(chunks_b)
            file_mode = int(st.st_mode)
        except OSError as exc:
            return [], [], base_dir, [], f"[Harness Workflow Shield] Failed reading `run_workflow` `ScriptPath` (`{sp}`): {exc}"
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        if b"\x00" in raw_bytes:
            return [], [], base_dir, [], f"[Harness Workflow Shield] Null bytes are prohibited inside `ScriptPath` (`{sp}`)."
        try:
            decoded_src = raw_bytes.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as exc:
            return [], [], base_dir, [], f"[Harness Workflow Shield] `run_workflow` `ScriptPath` (`{sp}`) must be valid UTF-8: {exc}"
        cookie_err = _check_pep263_cookie(decoded_src)
        if cookie_err:
            return [], [], base_dir, [], cookie_err
        if decoded_src.strip():
            script_sources.append(decoded_src)
            script_paths_meta.append((sp, file_mode))

    if not script_sources:
        return [], [], base_dir, [], "[Harness Workflow Shield] `run_workflow` requires a non-empty `Script` or `ScriptPath`."

    arg_strings: List[str] = []
    for ak in ("Args", "args"):
        if ak not in args:
            continue
        wf_args = args.get(ak)
        if wf_args is not None:
            err = _collect_workflow_arg_strings(wf_args, arg_strings)
            if err:
                return [], [], base_dir, [], err

    return script_sources, arg_strings, base_dir, script_paths_meta, None

def _extract_workflow_sources(
    args: Dict[str, Any], workspace: Optional[Path]
) -> Tuple[List[str], List[str], Optional[Path], Optional[str]]:
    sources, arg_strings, base_dir, _sp_meta, err = _extract_workflow_sources_ex(args, workspace)
    return sources, arg_strings, base_dir, err

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

def _extract_partial_text_and_dynamic(
    node: Optional[ast.AST],
    const_vars: Dict[str, str],
    depth: int = 0,
    memo: Optional[Dict[int, Tuple[str, bool]]] = None,
) -> Tuple[str, bool]:
    """Extracts static text fragments from an AST string/f-string expression and flags dynamic holes."""
    if node is None or depth > 24:
        return "", False
    if memo is None:
        memo = {}
    nid = id(node)
    if nid in memo:
        return memo[nid]
    exact = _eval_workflow_str_expr(node, const_vars, depth)
    if exact is not None:
        res = (exact, False)
        memo[nid] = res
        return res
    if isinstance(node, ast.JoinedStr):
        frags: List[str] = []
        has_dyn = False
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                frags.append(val.value)
            elif isinstance(val, ast.FormattedValue):
                sub_txt, sub_dyn = _extract_partial_text_and_dynamic(val.value, const_vars, depth + 1, memo)
                if sub_txt:
                    frags.append(sub_txt)
                has_dyn = True or sub_dyn
            else:
                has_dyn = True
        res = (" ".join(frags)[:_WORKFLOW_MAX_FOLDED_LEN], has_dyn)
        memo[nid] = res
        return res
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        l_txt, l_dyn = _extract_partial_text_and_dynamic(node.left, const_vars, depth + 1, memo)
        r_txt, r_dyn = _extract_partial_text_and_dynamic(node.right, const_vars, depth + 1, memo)
        res = (f"{l_txt}{r_txt}"[:_WORKFLOW_MAX_FOLDED_LEN], (l_dyn or r_dyn))
        memo[nid] = res
        return res
    memo[nid] = ("", True)
    return "", True

def _eval_workflow_path_expr(node: Optional[ast.AST], const_vars: Dict[str, str], depth: int = 0) -> Optional[str]:
    if node is None or depth > 24:
        return None
    as_str = _eval_workflow_str_expr(node, const_vars, depth)
    if as_str is not None:
        return as_str
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
        if isinstance(node.func, ast.Name) and node.func.id in ("Path", "PurePath", "PosixPath"):
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

def _eval_workflow_const_value(
    node: Optional[ast.AST], const_vars: Dict[str, str], depth: int = 0
) -> Tuple[Any, bool]:
    if node is None or depth > 24:
        return None, False
    folded_str = _eval_workflow_path_expr(node, const_vars, depth)
    if folded_str is not None:
        return folded_str, True
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float, bool, type(None))):
        if isinstance(node.value, str) and len(node.value) > _WORKFLOW_MAX_FOLDED_LEN:
            return None, False
        return node.value, True
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, (ast.USub, ast.UAdd))
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, (int, float))
        and not isinstance(node.operand.value, bool)
    ):
        return (-node.operand.value if isinstance(node.op, ast.USub) else +node.operand.value), True
    if isinstance(node, (ast.List, ast.Tuple)):
        if len(node.elts) > 256:
            return None, False
        items: List[Any] = []
        for elt in node.elts:
            if isinstance(elt, ast.Starred):
                return None, False
            val, ok = _eval_workflow_const_value(elt, const_vars, depth + 1)
            if not ok:
                return None, False
            items.append(val)
        return (items if isinstance(node, ast.List) else tuple(items)), True
    if isinstance(node, ast.Dict):
        if len(node.keys) > 256:
            return None, False
        out_dict: Dict[Any, Any] = {}
        for k_node, v_node in zip(node.keys, node.values):
            if k_node is None:
                return None, False
            k_val, k_ok = _eval_workflow_const_value(k_node, const_vars, depth + 1)
            if not k_ok or not isinstance(k_val, (str, int, float, bool, type(None))):
                return None, False
            v_val, v_ok = _eval_workflow_const_value(v_node, const_vars, depth + 1)
            if not v_ok:
                return None, False
            out_dict[k_val] = v_val
        return out_dict, True
    return None, False

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
    """
    Statically inspects a `run_workflow` Python script and its `Args` strings for:
      - Human-only `agy-guard` admin commands, `install.py`, and git hook bypasses (`Rule 12`)
      - Child-process / dynamic-eval / FFI / aliasing escapes (`subprocess`, `os.system`, `eval`, `ctypes` — `Rule 15e`)
      - Direct Python filesystem writes/mutations bypassing `call_tool` & Flight Recorder (`Rule 12`, `15a`, `15e`)
      - Static `call_tool(...)` invocations targeting governance, customization, or destructive commands
      - Delegated `agent(...)` model downgrades (`model='flash' | 'flash_lite'`) on customization files (`Rule 17`)
    """
    eff_cwd = workflow_cwd if workflow_cwd is not None else workspace
    local_swarm_ops: List[Dict[str, Any]] = []
    if swarm_overlay is None:
        swarm_overlay = {}

    def _path_hits_gov(cand: str, resolve_rel: bool = False) -> bool:
        return _targets_governance_dir(cand, base_dir=(eff_cwd if resolve_rel else None))

    def _path_hits_cust(cand: str, resolve_rel: bool = False) -> bool:
        if not cand or not cand.strip() or "\x00" in cand:
            return False
        ws_ctx = workspace if workspace is not None else eff_cwd
        if resolve_rel and eff_cwd is not None:
            exp = Path(os.path.expanduser(cand.strip()))
            if not exp.is_absolute():
                return _targets_customization_structure(str(eff_cwd / exp), workspace=ws_ctx)
        return _targets_customization_structure(cand, workspace=ws_ctx)

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as exc:
        return (
            {
                "decision": "deny",
                "reason": (
                    f"[Harness Workflow Shield] Failed to parse Python `run_workflow` script "
                    f"({type(exc).__name__}): {exc}"
                ),
            },
            [],
        )

    # Single-assignment constant propagation plus bounded multi-assignment candidate tracking (`P09`):
    # variables bound more than once are excluded from `const_vars`, while all candidate values are
    # tracked in `multi_var_values` so reassignment (`p = ''; p = 'GEM' + 'INI.md'`) cannot mask targets.
    bind_counts: Dict[str, int] = {}
    store_counts: Dict[str, int] = {}
    single_rhs: Dict[str, ast.AST] = {}
    multi_rhs: Dict[str, List[ast.AST]] = {}
    local_callable_defs: Dict[str, int] = {}
    rebound_host_primitive: Optional[str] = None
    forbidden_dunder_def: Optional[str] = None
    for stmt in ast.walk(tree):
        if isinstance(stmt, ast.Name) and isinstance(stmt.ctx, (ast.Store, ast.Del)):
            bind_counts[stmt.id] = bind_counts.get(stmt.id, 0) + 1
            if isinstance(stmt.ctx, ast.Store):
                store_counts[stmt.id] = store_counts.get(stmt.id, 0) + 1
            if stmt.id in _PROTECTED_HOST_PRIMITIVES:
                rebound_host_primitive = stmt.id
        elif isinstance(stmt, ast.arg):
            bind_counts[stmt.arg] = bind_counts.get(stmt.arg, 0) + 1
            store_counts[stmt.arg] = store_counts.get(stmt.arg, 0) + 1
            if stmt.arg in _PROTECTED_HOST_PRIMITIVES:
                rebound_host_primitive = stmt.arg
        elif isinstance(stmt, ast.ExceptHandler) and stmt.name:
            bind_counts[stmt.name] = bind_counts.get(stmt.name, 0) + 1
            store_counts[stmt.name] = store_counts.get(stmt.name, 0) + 1
            if stmt.name in _PROTECTED_HOST_PRIMITIVES:
                rebound_host_primitive = stmt.name
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bind_counts[stmt.name] = bind_counts.get(stmt.name, 0) + 1
            store_counts[stmt.name] = store_counts.get(stmt.name, 0) + 1
            local_callable_defs[stmt.name] = local_callable_defs.get(stmt.name, 0) + 1
            if stmt.name in _PROTECTED_HOST_PRIMITIVES:
                rebound_host_primitive = stmt.name
            if stmt.name in _FORBIDDEN_DUNDER_NAMES:
                forbidden_dunder_def = stmt.name
        elif isinstance(stmt, (ast.MatchAs, ast.MatchStar)) and stmt.name:
            bind_counts[stmt.name] = bind_counts.get(stmt.name, 0) + 1
            store_counts[stmt.name] = store_counts.get(stmt.name, 0) + 1
            if stmt.name in _PROTECTED_HOST_PRIMITIVES:
                rebound_host_primitive = stmt.name
        elif isinstance(stmt, ast.MatchMapping) and stmt.rest:
            bind_counts[stmt.rest] = bind_counts.get(stmt.rest, 0) + 1
            store_counts[stmt.rest] = store_counts.get(stmt.rest, 0) + 1
            if stmt.rest in _PROTECTED_HOST_PRIMITIVES:
                rebound_host_primitive = stmt.rest
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for al in stmt.names:
                bname = al.asname or al.name.split(".", 1)[0]
                bind_counts[bname] = bind_counts.get(bname, 0) + 1
                store_counts[bname] = store_counts.get(bname, 0) + 1
                if bname in _PROTECTED_HOST_PRIMITIVES:
                    rebound_host_primitive = bname
        if isinstance(stmt, ast.Assign):
            if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                single_rhs[stmt.targets[0].id] = stmt.value
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name):
                    multi_rhs.setdefault(tgt.id, []).append(stmt.value)
                elif isinstance(tgt, (ast.Tuple, ast.List)) and isinstance(stmt.value, (ast.Tuple, ast.List)):
                    if len(tgt.elts) == len(stmt.value.elts):
                        for sub_t, sub_v in zip(tgt.elts, stmt.value.elts):
                            if isinstance(sub_t, ast.Name):
                                multi_rhs.setdefault(sub_t.id, []).append(sub_v)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            single_rhs[stmt.target.id] = stmt.value
            multi_rhs.setdefault(stmt.target.id, []).append(stmt.value)
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            multi_rhs.setdefault(stmt.target.id, []).append(
                ast.BinOp(left=ast.Name(id=stmt.target.id, ctx=ast.Load()), op=stmt.op, right=stmt.value)
            )
        elif isinstance(stmt, ast.NamedExpr) and isinstance(stmt.target, ast.Name):
            single_rhs[stmt.target.id] = stmt.value
            multi_rhs.setdefault(stmt.target.id, []).append(stmt.value)

    const_vars: Dict[str, str] = {}
    for _ in range(8):
        progressed = False
        for vname, rhs in single_rhs.items():
            if bind_counts.get(vname, 0) != 1 or vname in const_vars:
                continue
            folded = _eval_workflow_path_expr(rhs, const_vars)
            if folded is not None:
                const_vars[vname] = folded
                progressed = True
        if not progressed:
            break

    def _eval_multi_candidates(
        expr: Optional[ast.AST], env_map: Dict[str, List[str]], depth: int = 0
    ) -> List[str]:
        if expr is None or depth > 16:
            return []
        direct = _eval_workflow_path_expr(expr, const_vars)
        if direct is not None:
            return [direct]
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return [expr.value] if len(expr.value) <= _WORKFLOW_MAX_FOLDED_LEN else []
        if isinstance(expr, ast.Name):
            return list(env_map.get(expr.id, ()))[:8]
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            lefts = _eval_multi_candidates(expr.left, env_map, depth + 1)
            rights = _eval_multi_candidates(expr.right, env_map, depth + 1)
            out_add: List[str] = []
            for l_s in lefts[:6]:
                for r_s in rights[:6]:
                    if len(l_s) + len(r_s) <= _WORKFLOW_MAX_FOLDED_LEN:
                        comb = l_s + r_s
                        if comb not in out_add:
                            out_add.append(comb)
                        if len(out_add) >= 12:
                            return out_add
            return out_add
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
            lefts = _eval_multi_candidates(expr.left, env_map, depth + 1)
            rights = _eval_multi_candidates(expr.right, env_map, depth + 1)
            out_div: List[str] = []
            for l_s in lefts[:6]:
                for r_s in rights[:6]:
                    comb = f"{l_s.rstrip('/')}/{r_s.lstrip('/')}"
                    if len(comb) <= _WORKFLOW_MAX_FOLDED_LEN and comb not in out_div:
                        out_div.append(comb)
                        if len(out_div) >= 12:
                            return out_div
            return out_div
        if isinstance(expr, ast.JoinedStr):
            acc = [""]
            for val in expr.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    step_vals = [val.value]
                elif isinstance(val, ast.FormattedValue):
                    step_vals = _eval_multi_candidates(val.value, env_map, depth + 1)
                    if not step_vals:
                        return []
                else:
                    return []
                next_acc: List[str] = []
                for prefix in acc[:8]:
                    for sv in step_vals[:6]:
                        if len(prefix) + len(sv) <= _WORKFLOW_MAX_FOLDED_LEN:
                            joined_s = prefix + sv
                            if joined_s not in next_acc:
                                next_acc.append(joined_s)
                            if len(next_acc) >= 12:
                                break
                    if len(next_acc) >= 12:
                        break
                acc = next_acc
                if not acc:
                    return []
            return acc
        return []

    multi_var_values: Dict[str, List[str]] = {k: [v] for k, v in const_vars.items()}
    for _ in range(4):
        progressed_m = False
        for vname, rhs_list in multi_rhs.items():
            existing = multi_var_values.setdefault(vname, [])
            for rhs_expr in rhs_list[:8]:
                for cand_s in _eval_multi_candidates(rhs_expr, multi_var_values):
                    if cand_s not in existing and len(existing) < 16:
                        existing.append(cand_s)
                        progressed_m = True
        if not progressed_m:
            break

    # Map persistent `var = agent(...)` bindings (across Assign, AnnAssign, NamedExpr, and reassignments)
    # and chained `agent(...)(prompt, ...)` calls BEFORE collecting benign prose node IDs.
    persistent_agents: Dict[str, List[ast.Call]] = {}
    persistent_agent_turn_nodes: Dict[str, List[ast.AST]] = {}
    chained_agent_turns: Dict[int, List[ast.AST]] = {}

    def _unwrap_agent_call(expr: Optional[ast.AST], allow_await: bool = True) -> Optional[ast.Call]:
        inner = expr.value if (allow_await and isinstance(expr, ast.Await)) else expr
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name) and inner.func.id == "agent":
            return inner
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            ag_val = _unwrap_agent_call(node.value, allow_await=False)
            if ag_val is not None:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        persistent_agents.setdefault(tgt.id, []).append(ag_val)
                        persistent_agent_turn_nodes.setdefault(tgt.id, [])
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            ag_val = _unwrap_agent_call(node.value, allow_await=False)
            if ag_val is not None:
                persistent_agents.setdefault(node.target.id, []).append(ag_val)
                persistent_agent_turn_nodes.setdefault(node.target.id, [])
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            ag_val = _unwrap_agent_call(node.value, allow_await=False)
            if ag_val is not None:
                persistent_agents.setdefault(node.target.id, []).append(ag_val)
                persistent_agent_turn_nodes.setdefault(node.target.id, [])

    # Track non-executing UI/prompt string node ids so prose in `log(...)`, `phase(...)`, `agent(...)`,
    # persistent `var(prompt, ...)`, or chained `agent(...)(prompt, ...)` does not trigger shell regex false positives.
    benign_prose_node_ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            if node.func.id in ("log", "phase"):
                for sub in ast.walk(node):
                    benign_prose_node_ids.add(id(sub))
            elif node.func.id == "agent":
                for arg_node in node.args[:3]:
                    for sub in ast.walk(arg_node):
                        benign_prose_node_ids.add(id(sub))
                for kw in node.keywords:
                    if kw.arg in ("prompt", "role", "schema"):
                        for sub in ast.walk(kw.value):
                            benign_prose_node_ids.add(id(sub))
            elif node.func.id in persistent_agents:
                for arg_node in node.args[:2]:
                    for sub in ast.walk(arg_node):
                        benign_prose_node_ids.add(id(sub))
                for kw in node.keywords:
                    if kw.arg in ("prompt", "schema"):
                        for sub in ast.walk(kw.value):
                            benign_prose_node_ids.add(id(sub))
        else:
            chained_ag = _unwrap_agent_call(node.func, allow_await=True)
            if chained_ag is not None:
                turns = chained_agent_turns.setdefault(id(chained_ag), [])
                if node.args:
                    turns.append(node.args[0])
                for arg_node in node.args[:2]:
                    for sub in ast.walk(arg_node):
                        benign_prose_node_ids.add(id(sub))
                for kw in node.keywords:
                    if kw.arg == "prompt":
                        turns.append(kw.value)
                    if kw.arg in ("prompt", "schema"):
                        for sub in ast.walk(kw.value):
                            benign_prose_node_ids.add(id(sub))

    all_literals: List[str] = []
    cmd_candidates: List[str] = list(arg_strings)
    for vals in multi_var_values.values():
        for mv in vals:
            if mv and mv not in all_literals:
                all_literals.append(mv)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value:
            all_literals.append(node.value)
            if id(node) not in benign_prose_node_ids:
                cmd_candidates.append(node.value)
        elif isinstance(node, (ast.BinOp, ast.JoinedStr)) or (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
        ):
            for folded_s in _eval_multi_candidates(node, multi_var_values):
                if folded_s:
                    all_literals.append(folded_s)
                    if id(node) not in benign_prose_node_ids:
                        cmd_candidates.append(folded_s)
        elif isinstance(node, (ast.List, ast.Tuple)):
            parts = [
                elt_str
                for elt in node.elts
                for elt_str in [_eval_workflow_str_expr(elt, const_vars)]
                if elt_str
            ]
            if len(parts) >= 2:
                joined = " ".join(parts)
                all_literals.append(joined)
                if id(node) not in benign_prose_node_ids:
                    cmd_candidates.append(joined)

    def _gov_deny_or(default_reason: str) -> Tuple[Dict[str, Any], List[Tuple[str, str]]]:
        for cand in [*const_vars.values(), *arg_strings, *all_literals]:
            if _path_hits_gov(cand, resolve_rel=False):
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            f"[Harness Governance Shield] Protected governance path (`{cand}`) targeted via "
                            f"prohibited `run_workflow` construct: {default_reason}"
                        ),
                    },
                    [],
                )
        return {"decision": "deny", "reason": default_reason}, []

    if rebound_host_primitive is not None:
        return _gov_deny_or(
            f"[Harness Workflow Shield] Rebinding or redefining host primitive `{rebound_host_primitive}` "
            "inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
        )
    if forbidden_dunder_def is not None:
        return _gov_deny_or(
            f"[Harness Workflow Shield] Defining reflective dunder hook `{forbidden_dunder_def}` inside "
            "`run_workflow` is prohibited (GEMINI.md Rule 15e)."
        )

    # 1. Human-only Guard admin, install.py, and git hook bypasses across workflow Args & non-prose candidates
    for text in cmd_candidates:
        masked_text = _mask_quoted_operators(text)
        if _GUARD_ADMIN_RE.search(masked_text) or _GUARD_INLINE_PY_RE.search(text):
            return (
                {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Human-only `agy-guard` administration commands are "
                        "prohibited inside `run_workflow` (GEMINI.md Rule 12)."
                    ),
                },
                [],
            )
        if _WORKFLOW_INSTALL_EXEC_RE.search(masked_text):
            return (
                {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Executing `install.py` inside `run_workflow` is "
                        "prohibited (GEMINI.md Rule 12)."
                    ),
                },
                [],
            )
        if _GIT_HOOK_BYPASS_RE.search(masked_text):
            return (
                {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Git hook bypass flags (`--no-verify`, `commit -n`, "
                        "`core.hooksPath`, `HUSKY=0`) are prohibited inside `run_workflow`."
                    ),
                },
                [],
            )

    # 2. Collect module aliases, imported callables, dunder/frame/MatchClass escapes, and anti-aliasing structural sets
    os_aliases: set[str] = set()
    environ_aliases: set[str] = set()
    shutil_aliases: set[str] = set()
    io_open_aliases: set[str] = set()
    archive_aliases: set[str] = set()
    sys_aliases: set[str] = set()
    copy_mod_aliases: set[str] = set()
    json_mod_aliases: set[str] = set()
    collections_mod_aliases: set[str] = set()
    namedtuple_factory_names: set[str] = set()
    imported_module_names: set[str] = set()
    safe_imported_callables: Dict[str, int] = {}
    pathlib_names: set[str] = {
        "Path",
        "PurePath",
        "PosixPath",
        "WindowsPath",
        "PurePosixPath",
        "PureWindowsPath",
    }
    imported_os_fs_funcs: set[str] = set()
    imported_shutil_fs_funcs: set[str] = set()
    imported_io_open_funcs: set[str] = set()
    imported_archive_open_funcs: set[str] = set()
    rmtree_funcs: set[str] = set()
    forbidden_child_exec_reason: Optional[str] = None
    forbidden_runtime_escape_reason: Optional[str] = None
    direct_fs_mutation_detected = False
    direct_fs_candidate_paths: List[str] = []

    call_func_node_ids: set[int] = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    attr_value_node_ids: set[int] = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Attribute)}

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in _FORBIDDEN_DUNDER_NAMES:
            forbidden_runtime_escape_reason = (
                f"[Harness Workflow Shield] Introspective/dunder escape (`{node.id}`) inside `run_workflow` "
                "is prohibited (GEMINI.md Rule 15e)."
            )
        elif isinstance(node, ast.Attribute) and (
            node.attr in _FORBIDDEN_DUNDER_NAMES or node.attr in _FORBIDDEN_FRAME_ATTRS
        ):
            forbidden_runtime_escape_reason = (
                f"[Harness Workflow Shield] Introspective/frame/dunder attribute (`{node.attr}`) inside `run_workflow` "
                "is prohibited (GEMINI.md Rule 15e)."
            )
        elif isinstance(node, ast.MatchClass):
            for kwd_attr in node.kwd_attrs:
                if (
                    kwd_attr.startswith("_")
                    or kwd_attr in _FORBIDDEN_DUNDER_NAMES
                    or kwd_attr in _FORBIDDEN_FRAME_ATTRS
                    or kwd_attr in _FORBIDDEN_EXEC_ATTRS
                    or kwd_attr in _FORBIDDEN_REFLECTIVE_ATTRS
                    or kwd_attr in _NON_ALIASABLE_WORKFLOW_NAMES
                    or kwd_attr in _NON_ALIASABLE_FS_ATTRS
                    or kwd_attr in _FORBIDDEN_REEXPORT_ATTRS
                    or kwd_attr in _FORBIDDEN_SYS_ATTRS
                ):
                    forbidden_runtime_escape_reason = (
                        f"[Harness Workflow Shield] `match` class attribute extraction (`{kwd_attr}=`) "
                        "inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                    )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                segments = alias.name.split(".")
                root_mod = segments[0]
                bound = alias.asname or root_mod
                imported_module_names.add(bound)
                if alias.asname is None:
                    imported_module_names.add(root_mod)
                if any(seg in _FORBIDDEN_CHILD_PROC_MODULES for seg in segments) or (
                    root_mod == "asyncio" and len(segments) > 1
                ):
                    forbidden_child_exec_reason = (
                        f"[Harness Workflow Shield] Direct child-process/event-loop submodule (`{alias.name}`) inside "
                        "`run_workflow` scripts bypasses tool-level safety gates; use `call_tool('run_command', ...)` "
                        "or delegated `agent(...)` turns (GEMINI.md Rule 15e)."
                    )
                elif (
                    (root_mod.startswith("_") and root_mod != "__future__")
                    or any(seg.startswith("_") for seg in segments[1:])
                    or any(seg in _FORBIDDEN_WORKFLOW_MODULES for seg in segments)
                    or (root_mod != "__future__" and root_mod not in _ALLOWED_STDLIB_WORKFLOW_MODULES)
                    or (len(segments) > 1 and alias.name != "os.path")
                ):
                    forbidden_runtime_escape_reason = (
                        f"[Harness Workflow Shield] Module `{alias.name}` is prohibited inside `run_workflow` "
                        "orchestration scripts; use `call_tool(...)` or `agent(...)` (GEMINI.md Rule 15e)."
                    )
                elif root_mod == "os":
                    if alias.name == "os":
                        os_aliases.add(bound)
                    elif alias.asname is None:
                        os_aliases.add("os")
                elif root_mod == "shutil":
                    shutil_aliases.add(bound if alias.name == "shutil" else "shutil")
                elif root_mod in ("io", "codecs"):
                    io_open_aliases.add(bound if alias.name == root_mod else root_mod)
                elif root_mod in ("tarfile", "zipfile", "gzip", "bz2", "lzma"):
                    archive_aliases.add(bound if alias.name == root_mod else root_mod)
                elif root_mod == "sys":
                    sys_aliases.add(bound if alias.name == "sys" else "sys")
                elif root_mod == "copy":
                    copy_mod_aliases.add(bound if alias.name == "copy" else "copy")
                elif root_mod == "json":
                    json_mod_aliases.add(bound if alias.name == "json" else "json")
                elif root_mod == "collections":
                    collections_mod_aliases.add(bound if alias.name == "collections" else "collections")
        elif isinstance(node, ast.ImportFrom):
            mod_str = node.module or ""
            segments = mod_str.split(".") if mod_str else []
            root_mod = segments[0] if segments else ""
            if (node.level or 0) > 0:
                forbidden_runtime_escape_reason = (
                    "[Harness Workflow Shield] Relative imports inside `run_workflow` scripts are prohibited (GEMINI.md Rule 15e)."
                )
            elif any(seg in _FORBIDDEN_CHILD_PROC_MODULES for seg in segments) or (
                root_mod == "asyncio" and len(segments) > 1
            ):
                forbidden_child_exec_reason = (
                    f"[Harness Workflow Shield] Direct child-process/event-loop import (`from {mod_str} import ...`) "
                    "inside `run_workflow` bypasses tool-level safety gates; use `call_tool('run_command', ...)` "
                    "or `agent(...)` (GEMINI.md Rule 15e)."
                )
            elif (
                (root_mod.startswith("_") and root_mod != "__future__")
                or any(seg.startswith("_") for seg in segments[1:])
                or any(seg in _FORBIDDEN_WORKFLOW_MODULES for seg in segments)
                or (root_mod != "__future__" and root_mod not in _ALLOWED_STDLIB_WORKFLOW_MODULES)
                or (len(segments) > 1 and mod_str != "os.path")
            ):
                forbidden_runtime_escape_reason = (
                    f"[Harness Workflow Shield] Importing from `{mod_str}` is prohibited inside "
                    "`run_workflow` orchestration scripts (GEMINI.md Rule 15e)."
                )
            else:
                for alias in node.names:
                    local = alias.asname or alias.name
                    if alias.name == "*":
                        forbidden_runtime_escape_reason = (
                            f"[Harness Workflow Shield] Wildcard `from {mod_str} import *` is prohibited inside `run_workflow`."
                        )
                    elif alias.name.startswith("_"):
                        forbidden_runtime_escape_reason = (
                            f"[Harness Workflow Shield] Importing private attribute `{mod_str}.{alias.name}` "
                            "inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                        )
                    elif alias.name in _FORBIDDEN_EXEC_ATTRS:
                        forbidden_child_exec_reason = (
                            f"[Harness Workflow Shield] Direct process/socket primitive (`{mod_str}.{alias.name}`) "
                            "inside `run_workflow` is prohibited; use `call_tool('run_command', ...)` (GEMINI.md Rule 15e)."
                        )
                    elif (
                        alias.name in _FORBIDDEN_DUNDER_NAMES
                        or alias.name in _FORBIDDEN_CALLABLE_BUILTINS
                        or alias.name in _FORBIDDEN_REFLECTIVE_ATTRS
                        or alias.name in _FORBIDDEN_REEXPORT_ATTRS
                        or (root_mod == "json" and alias.name == "tool")
                        or (root_mod == "asyncio" and alias.name == "log")
                        or (root_mod == "functools" and alias.name in ("partial", "partialmethod", "reduce"))
                    ):
                        forbidden_runtime_escape_reason = (
                            f"[Harness Workflow Shield] Importing re-exported/reflective symbol `{mod_str}.{alias.name}` "
                            "inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                        )
                    elif root_mod == "sys" and alias.name in _FORBIDDEN_SYS_ATTRS:
                        forbidden_runtime_escape_reason = (
                            f"[Harness Workflow Shield] Importing `sys.{alias.name}` inside `run_workflow` "
                            "is prohibited (GEMINI.md Rule 15e)."
                        )
                    elif root_mod == "os" and alias.name in ("environ", "environb"):
                        environ_aliases.add(local)
                    elif alias.name == "rmtree":
                        rmtree_funcs.add(local)
                    elif alias.name in ("ZipFile", "PyZipFile", "TarFile", "GzipFile", "BZ2File", "LZMAFile") or (
                        root_mod in ("tarfile", "zipfile", "gzip", "bz2", "lzma") and alias.name == "open"
                    ):
                        imported_archive_open_funcs.add(local)
                    elif alias.name in ("open", "FileIO"):
                        imported_io_open_funcs.add(local)
                    elif alias.name in _FORBIDDEN_DIRECT_FS_ATTRS or alias.name in _FORBIDDEN_OS_FS_NAMES:
                        imported_os_fs_funcs.add(local)
                    elif root_mod == "shutil":
                        imported_shutil_fs_funcs.add(local)
                    elif root_mod == "pathlib" or (root_mod == "zipfile" and alias.name == "Path"):
                        pathlib_names.add(local)
                        safe_imported_callables[local] = safe_imported_callables.get(local, 0) + 1
                    elif mod_str == "os" and alias.name == "path":
                        imported_module_names.add(local)
                    else:
                        safe_imported_callables[local] = safe_imported_callables.get(local, 0) + 1
                        if (root_mod == "collections" and alias.name == "namedtuple") or (
                            root_mod == "typing" and alias.name == "NamedTuple"
                        ):
                            namedtuple_factory_names.add(local)

    if forbidden_child_exec_reason:
        return _gov_deny_or(forbidden_child_exec_reason)
    if forbidden_runtime_escape_reason:
        return _gov_deny_or(forbidden_runtime_escape_reason)

    def _is_environ_expr(expr: ast.AST) -> bool:
        if isinstance(expr, ast.Attribute) and expr.attr in ("environ", "environb"):
            return True
        if isinstance(expr, ast.Name) and expr.id in environ_aliases:
            return True
        return False

    safe_environ_node_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load) and _is_environ_expr(node.value):
            safe_environ_node_ids.add(id(node.value))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _SAFE_ENVIRON_READ_METHODS
            and _is_environ_expr(node.func.value)
        ):
            safe_environ_node_ids.add(id(node.func.value))
        elif isinstance(node, ast.Compare) and all(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
            for comp in node.comparators:
                if _is_environ_expr(comp):
                    safe_environ_node_ids.add(id(comp))

    guarded_imported_funcs = (
        rmtree_funcs
        | imported_os_fs_funcs
        | imported_shutil_fs_funcs
        | imported_io_open_funcs
        | imported_archive_open_funcs
    )
    guarded_module_aliases = (
        imported_module_names
        | os_aliases
        | shutil_aliases
        | io_open_aliases
        | archive_aliases
        | sys_aliases
        | copy_mod_aliases
        | json_mod_aliases
    )

    for node in ast.walk(tree):
        if _is_environ_expr(node) and id(node) not in safe_environ_node_ids:
            return _gov_deny_or(
                "[Harness Workflow Shield] Mutating or aliasing `os.environ` inside `run_workflow` "
                "is prohibited (GEMINI.md Rule 15e)."
            )
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in _PROTECTED_HOST_PRIMITIVES:
                return _gov_deny_or(
                    f"[Harness Workflow Shield] Rebinding host primitive `{node.id}` inside "
                    "`run_workflow` is prohibited (GEMINI.md Rule 15e)."
                )
            if isinstance(node.ctx, ast.Load):
                if (
                    node.id in _NON_ALIASABLE_WORKFLOW_NAMES
                    or node.id in guarded_imported_funcs
                    or node.id in persistent_agents
                ) and (id(node) not in call_func_node_ids):
                    return _gov_deny_or(
                        f"[Harness Workflow Shield] Aliasing or passing primitive `{node.id}` as a "
                        "first-class value inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                    )
                if node.id in guarded_module_aliases and id(node) not in attr_value_node_ids:
                    return _gov_deny_or(
                        f"[Harness Workflow Shield] Aliasing or passing module `{node.id}` as a "
                        "first-class value inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                    )
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if isinstance(node.value, ast.Attribute) and node.value.attr in ("environ", "environb"):
                return _gov_deny_or(
                    "[Harness Workflow Shield] Mutating `os.environ` inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                )
        elif isinstance(node, ast.Attribute):
            if node.attr in _FORBIDDEN_EXEC_ATTRS:
                return _gov_deny_or(
                    f"[Harness Workflow Shield] Direct child-process primitive (`.{node.attr}`) inside "
                    "`run_workflow` bypasses tool-level safety gates; use `call_tool('run_command', ...)` "
                    "or delegated `agent(...)` turns (GEMINI.md Rule 15e)."
                )
            if node.attr in _FORBIDDEN_REFLECTIVE_ATTRS:
                return _gov_deny_or(
                    f"[Harness Workflow Shield] Reflective/dynamic execution attribute (`.{node.attr}`) "
                    "inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                )
            if (
                node.attr in _FORBIDDEN_REEXPORT_ATTRS
                or (
                    node.attr.startswith("_")
                    and node.attr not in ("_asdict", "_replace", "_fields", "_field_defaults")
                )
                or (
                    node.attr == "tool"
                    and isinstance(node.value, ast.Name)
                    and node.value.id in json_mod_aliases
                )
            ):
                return _gov_deny_or(
                    f"[Harness Workflow Shield] Re-exported or private module attribute traversal (`.{node.attr}`) "
                    "inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                )
            if node.attr in _UNCONDITIONAL_FORBIDDEN_SYS_ATTRS or (
                isinstance(node.value, ast.Name)
                and node.value.id in sys_aliases
                and node.attr in _FORBIDDEN_SYS_ATTRS
            ):
                return _gov_deny_or(
                    f"[Harness Workflow Shield] Accessing `sys.{node.attr}` inside `run_workflow` "
                    "is prohibited (GEMINI.md Rule 15e)."
                )
            if (
                isinstance(node.ctx, ast.Load)
                and id(node) not in call_func_node_ids
                and node.attr in _NON_ALIASABLE_FS_ATTRS
            ):
                return _gov_deny_or(
                    f"[Harness Workflow Shield] Aliasing or referencing filesystem/I/O method (`.{node.attr}`) "
                    "without a direct call inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                )

    flight_writes: List[Tuple[str, str]] = []
    force_ask_reasons: List[str] = []
    rmtree_calls: List[ast.Call] = []
    indirect_call_reason: Optional[str] = None

    # 3. Inspect all AST calls for child-process escapes, direct Python writes, `rmtree`, `call_tool`, and `agent`
    raw_agent_call_nodes: List[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not isinstance(node.func, (ast.Name, ast.Attribute)) and _unwrap_agent_call(node.func, allow_await=True) is None:
            for arg_node in node.args[:2]:
                p = _eval_workflow_path_expr(arg_node, const_vars)
                if p:
                    direct_fs_candidate_paths.append(p)
            indirect_call_reason = (
                "[Harness Workflow Shield] Indirect/computed call targets (such as container indexing or "
                "factory chaining) inside `run_workflow` are prohibited so safety gates can inspect every call "
                "(GEMINI.md Rule 15e)."
            )
            continue

        if isinstance(node.func, ast.Name):
            fn = node.func.id
            if fn in _FORBIDDEN_CALLABLE_BUILTINS:
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            f"[Harness Workflow Shield] Dynamic/reflective builtin `{fn}()` is prohibited "
                            "inside `run_workflow` (GEMINI.md Rule 15e)."
                        ),
                    },
                    [],
                )
            if fn in rmtree_funcs:
                rmtree_calls.append(node)
                continue
            if fn in imported_os_fs_funcs or fn in imported_shutil_fs_funcs:
                direct_fs_mutation_detected = True
                for arg_node in node.args[:2]:
                    p = _eval_workflow_path_expr(arg_node, const_vars)
                    if p:
                        direct_fs_candidate_paths.append(p)
                continue
            if fn in imported_io_open_funcs or fn == "open":
                if not _is_readonly_open_call(node, 1, const_vars):
                    direct_fs_mutation_detected = True
                    if node.args:
                        p = _eval_workflow_path_expr(node.args[0], const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                    for kw in node.keywords:
                        if kw.arg == "file":
                            p = _eval_workflow_path_expr(kw.value, const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                continue
            if fn in imported_archive_open_funcs:
                if not _is_readonly_open_call(node, 1, const_vars, archive=True):
                    direct_fs_mutation_detected = True
                    if node.args:
                        p = _eval_workflow_path_expr(node.args[0], const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                continue
            if fn == "call_tool":
                if len(node.args) != 1 or isinstance(node.args[0], ast.Starred):
                    return (
                        {
                            "decision": "deny",
                            "reason": (
                                "[Harness Workflow Shield] `call_tool()` inside `run_workflow` requires "
                                "exactly one positional tool-name string and static keyword arguments."
                            ),
                        },
                        [],
                    )
                inner_name = _eval_workflow_str_expr(node.args[0], const_vars)
                if not inner_name or not inner_name.strip():
                    return (
                        {
                            "decision": "deny",
                            "reason": (
                                "[Harness Workflow Shield] `call_tool()` inside `run_workflow` must specify a "
                                "static string tool name so safety gates can inspect it."
                            ),
                        },
                        [],
                    )
                inner_tool = inner_name.strip().lower().rsplit(":", 1)[-1]
                if inner_tool == "run_workflow":
                    return (
                        {
                            "decision": "deny",
                            "reason": (
                                "[Harness Workflow Shield] Nested `call_tool('run_workflow', ...)` inside "
                                "`run_workflow` is prohibited."
                            ),
                        },
                        [],
                    )
                static_kwargs: Dict[str, Any] = {}
                has_dynamic_kw = False
                for kw in node.keywords:
                    if kw.arg is None:
                        has_dynamic_kw = True
                        continue
                    const_val, const_ok = _eval_workflow_const_value(kw.value, const_vars)
                    if const_ok:
                        static_kwargs[kw.arg] = const_val
                    else:
                        has_dynamic_kw = True

                if inner_tool in WRITE_TOOL_NAMES:
                    targets = _extract_write_targets(static_kwargs)
                    if not targets or has_dynamic_kw:
                        for cand in [*targets, *arg_strings, *all_literals]:
                            if _path_hits_gov(cand, resolve_rel=(cand in targets)):
                                return (
                                    {
                                        "decision": "deny",
                                        "reason": (
                                            "[Harness Governance Shield] Direct write to the protected governance tree "
                                            f"(`{cand}`) inside `run_workflow` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                                        ),
                                    },
                                    [],
                                )
                        return (
                            {
                                "decision": "deny",
                                "reason": (
                                    f"[Harness Workflow Shield] `call_tool('{inner_name}', ...)` inside `run_workflow` "
                                    "must pass static arguments (including `Path`) so Governance Shield and Flight Recorder can verify the write."
                                ),
                            },
                            [],
                        )
                    for target in targets:
                        if "\x00" in target:
                            return (
                                {
                                    "decision": "deny",
                                    "reason": "[Harness Workflow Shield] Null bytes in `call_tool` target paths are prohibited.",
                                },
                                [],
                            )
                        if _path_hits_gov(target, resolve_rel=True):
                            return (
                                {
                                    "decision": "deny",
                                    "reason": (
                                        "[Harness Governance Shield] Direct write to the protected governance tree "
                                        f"(`{target}`) inside `run_workflow` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                                    ),
                                },
                                [],
                            )
                    if any(_path_hits_cust(target, resolve_rel=True) for target in targets):
                        mod_eval = _evaluate_customization_model_and_effort(payload)
                        if mod_eval is not None:
                            if mod_eval[0] == "deny":
                                return {"decision": "deny", "reason": mod_eval[1]}, []
                            force_ask_reasons.append(mod_eval[1])
                    for target in targets:
                        if _write_mutates_authorized_test_section(target, static_kwargs, eff_cwd):
                            force_ask_reasons.append(
                                "[Harness Test Boundary] Modifying `## Authorized Test Modifications` in `tasks.md` "
                                "requires explicit human confirmation (GEMINI.md Rule 9)."
                            )
                        exp_t = Path(os.path.expanduser(target.strip()))
                        rec_t = str(eff_cwd / exp_t) if (not exp_t.is_absolute() and eff_cwd is not None) else target
                        flight_writes.append((inner_tool, rec_t))
                elif inner_tool in COMMAND_TOOL_NAMES:
                    if has_dynamic_kw:
                        return (
                            {
                                "decision": "deny",
                                "reason": (
                                    f"[Harness Workflow Shield] `call_tool('{inner_name}', ...)` inside `run_workflow` "
                                    "must pass static command arguments or delegate to `agent(...)`."
                                ),
                            },
                            [],
                        )
                    if inner_tool == "manage_task":
                        mt_act = str(static_kwargs.get("Action") or static_kwargs.get("action") or "").strip().lower()
                        mt_inp = str(static_kwargs.get("Input") or static_kwargs.get("input") or "").strip()
                        if mt_act not in ("list", "status", "kill") and not mt_inp:
                            return (
                                {
                                    "decision": "deny",
                                    "reason": (
                                        "[Harness Workflow Shield] `call_tool('manage_task', ...)` inside `run_workflow` "
                                        "requires an explicit `Action` (`list`/`status`/`kill` or non-empty `send_input`)."
                                    ),
                                },
                                [],
                            )
                    elif inner_tool == "send_command_input":
                        sci_inp = str(
                            static_kwargs.get("Input")
                            or static_kwargs.get("input")
                            or static_kwargs.get("CommandLine")
                            or static_kwargs.get("command")
                            or ""
                        ).strip()
                        if not sci_inp:
                            return (
                                {
                                    "decision": "deny",
                                    "reason": (
                                        "[Harness Workflow Shield] `call_tool('send_command_input', ...)` inside "
                                        "`run_workflow` requires a non-empty static `Input` string."
                                    ),
                                },
                                [],
                            )
                    else:
                        rc_cmd = str(static_kwargs.get("CommandLine") or static_kwargs.get("command") or "").strip()
                        if not rc_cmd:
                            return (
                                {
                                    "decision": "deny",
                                    "reason": (
                                        f"[Harness Workflow Shield] `call_tool('{inner_name}', ...)` inside "
                                        "`run_workflow` requires a non-empty static `CommandLine` string."
                                    ),
                                },
                                [],
                            )
                    inner_payload = {
                        **payload,
                        "_workflowDryCheck": True,
                        **({"cwd": str(eff_cwd)} if eff_cwd is not None else {}),
                        "toolCall": {"name": inner_tool, "args": static_kwargs},
                    }
                    inner_res = _facade_attr("handle_pre_tool_use", handle_pre_tool_use)(inner_payload)
                    if inner_res.get("decision") == "deny":
                        return inner_res, []
                    if inner_res.get("decision") == "force_ask":
                        force_ask_reasons.append(str(inner_res.get("reason") or "Confirmation required."))
                elif inner_tool in ("invoke_subagent", "swarm", "post_message", "send_message", "define_subagent", "schedule"):
                    if has_dynamic_kw:
                        return (
                            {
                                "decision": "deny",
                                "reason": (
                                    f"[Harness Workflow Shield] `call_tool('{inner_name}', ...)` inside "
                                    "`run_workflow` must pass static arguments."
                                ),
                            },
                            [],
                        )
                    inner_payload: Dict[str, Any] = {
                        **payload,
                        "_workflowDryCheck": True,
                        **({"cwd": str(eff_cwd)} if eff_cwd is not None else {}),
                        "toolCall": {"name": inner_tool, "args": static_kwargs},
                    }
                    if inner_tool in ("swarm", "post_message", "send_message", "define_subagent", "invoke_subagent"):
                        inner_payload["_swarmOverlay"] = swarm_overlay
                        inner_payload["_pendingSwarmOps"] = local_swarm_ops
                    inner_res = _facade_attr("handle_pre_tool_use", handle_pre_tool_use)(inner_payload)
                    if inner_res.get("decision") == "deny":
                        return inner_res, []
                    if inner_res.get("decision") == "force_ask":
                        force_ask_reasons.append(str(inner_res.get("reason") or "Confirmation required."))
                elif inner_tool == "call_mcp_tool" or inner_tool.startswith("mcp_"):
                    if has_dynamic_kw:
                        return (
                            {
                                "decision": "deny",
                                "reason": (
                                    f"[Harness Workflow Shield] `call_tool('{inner_name}', ...)` inside "
                                    "`run_workflow` must pass static arguments so MCP safety gates can inspect it."
                                ),
                            },
                            [],
                        )
                    inner_res = _facade_attr("handle_pre_tool_use", handle_pre_tool_use)(
                        {
                            **payload,
                            "_workflowDryCheck": True,
                            **({"cwd": str(eff_cwd)} if eff_cwd is not None else {}),
                            "toolCall": {"name": inner_tool, "args": static_kwargs},
                        }
                    )
                    if inner_res.get("decision") == "deny":
                        return inner_res, []
                    if inner_res.get("decision") == "force_ask":
                        force_ask_reasons.append(str(inner_res.get("reason") or "Confirmation required."))
                    mcp_nested = (
                        static_kwargs.get("Arguments")
                        if isinstance(static_kwargs.get("Arguments"), dict)
                        else (
                            static_kwargs.get("arguments")
                            if isinstance(static_kwargs.get("arguments"), dict)
                            else static_kwargs
                        )
                    )
                    for mcp_t in _extract_mcp_target_paths(mcp_nested):
                        exp_mt = Path(os.path.expanduser(mcp_t.strip()))
                        rec_mt = str(eff_cwd / exp_mt) if (not exp_mt.is_absolute() and eff_cwd is not None) else mcp_t
                        flight_writes.append((inner_tool, rec_mt))
                continue
            if fn == "agent":
                raw_agent_call_nodes.append(node)
                continue
            if fn in persistent_agents and len(persistent_agents[fn]) == store_counts.get(fn, 0):
                if node.args:
                    persistent_agent_turn_nodes[fn].append(node.args[0])
                for kw in node.keywords:
                    if kw.arg == "prompt":
                        persistent_agent_turn_nodes[fn].append(kw.value)
                continue

            is_namedtuple_ctor = False
            if store_counts.get(fn, 0) == 1 and isinstance(single_rhs.get(fn), ast.Call):
                rhs_call = single_rhs[fn]
                assert isinstance(rhs_call, ast.Call)
                if (
                    isinstance(rhs_call.func, ast.Name)
                    and rhs_call.func.id in namedtuple_factory_names
                    and store_counts.get(rhs_call.func.id, 0) == 1
                ) or (
                    isinstance(rhs_call.func, ast.Attribute)
                    and rhs_call.func.attr == "namedtuple"
                    and isinstance(rhs_call.func.value, ast.Name)
                    and rhs_call.func.value.id in collections_mod_aliases
                    and store_counts.get(rhs_call.func.value.id, 0) == 1
                ):
                    is_namedtuple_ctor = True

            is_verified_name_call = (
                (fn in _SAFE_WORKFLOW_HOST_CALLABLES and bind_counts.get(fn, 0) == 0)
                or (fn in _SAFE_WORKFLOW_BUILTINS and bind_counts.get(fn, 0) == 0)
                or (fn in local_callable_defs and local_callable_defs[fn] == store_counts.get(fn, 0))
                or (fn in safe_imported_callables and safe_imported_callables[fn] == store_counts.get(fn, 0))
                or is_namedtuple_ctor
            )
            if not is_verified_name_call:
                return _gov_deny_or(
                    f"[Harness Workflow Shield] Calling dynamically bound or unverified symbol `{fn}()` "
                    "inside `run_workflow` is prohibited so safety gates can inspect every call (GEMINI.md Rule 15e)."
                )
            continue

        elif isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            recv = node.func.value
            recv_name = recv.id if isinstance(recv, ast.Name) else ""

            if attr in _FORBIDDEN_EXEC_ATTRS:
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            f"[Harness Workflow Shield] Direct child-process execution (`.{attr}()`) inside "
                            "`run_workflow` bypasses tool-level safety gates; use `call_tool('run_command', ...)` "
                            "or delegated `agent(...)` turns (GEMINI.md Rule 15e)."
                        ),
                    },
                    [],
                )
            if attr == "rmtree":
                rmtree_calls.append(node)
                continue
            if attr in _FORBIDDEN_DIRECT_FS_ATTRS:
                direct_fs_mutation_detected = True
                recv_path = _eval_workflow_path_expr(recv, const_vars)
                if recv_path:
                    direct_fs_candidate_paths.append(recv_path)
                for arg_node in node.args[:2]:
                    p = _eval_workflow_path_expr(arg_node, const_vars)
                    if p:
                        direct_fs_candidate_paths.append(p)
                for kw in node.keywords:
                    if kw.arg in ("src", "dst", "target", "target_dir", "path"):
                        p = _eval_workflow_path_expr(kw.value, const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                continue
            if attr == "replace":
                has_star = any(isinstance(a, ast.Starred) for a in node.args) or any(
                    kw.arg is None for kw in node.keywords
                )
                is_path_replace = (
                    recv_name in pathlib_names
                    or (isinstance(recv, ast.Attribute) and recv.attr in pathlib_names)
                    or (len(node.args) == 1 and not node.keywords)
                    or (len(node.args) == 0 and any(kw.arg == "target" for kw in node.keywords))
                    or has_star
                )
                if recv_name in os_aliases or is_path_replace:
                    direct_fs_mutation_detected = True
                    recv_path = _eval_workflow_path_expr(recv, const_vars)
                    if recv_path:
                        direct_fs_candidate_paths.append(recv_path)
                    for arg_node in node.args[:2]:
                        p = _eval_workflow_path_expr(arg_node, const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                    for kw in node.keywords:
                        if kw.arg in ("target", "dst"):
                            p = _eval_workflow_path_expr(kw.value, const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                continue
            if attr in ("remove", "truncate", "ftruncate", "link", "utime") and recv_name in os_aliases:
                direct_fs_mutation_detected = True
                for arg_node in node.args[:2]:
                    p = _eval_workflow_path_expr(arg_node, const_vars)
                    if p:
                        direct_fs_candidate_paths.append(p)
                continue
            if attr == "copy" and (
                recv_name in shutil_aliases
                or len(node.args) >= 2
                or ((bool(node.args) or bool(node.keywords)) and recv_name not in copy_mod_aliases)
            ):
                direct_fs_mutation_detected = True
                recv_path = _eval_workflow_path_expr(recv, const_vars)
                if recv_path:
                    direct_fs_candidate_paths.append(recv_path)
                for arg_node in node.args[:2]:
                    p = _eval_workflow_path_expr(arg_node, const_vars)
                    if p:
                        direct_fs_candidate_paths.append(p)
                for kw in node.keywords:
                    if kw.arg in ("src", "dst", "target"):
                        p = _eval_workflow_path_expr(kw.value, const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                continue
            if attr == "FileIO":
                if not _is_readonly_open_call(node, 1, const_vars):
                    direct_fs_mutation_detected = True
                    if node.args:
                        p = _eval_workflow_path_expr(node.args[0], const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                    for kw in node.keywords:
                        if kw.arg == "file":
                            p = _eval_workflow_path_expr(kw.value, const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                continue
            if attr in ("ZipFile", "PyZipFile", "TarFile", "GzipFile", "BZ2File", "LZMAFile"):
                if not _is_readonly_open_call(node, 1, const_vars, archive=True):
                    direct_fs_mutation_detected = True
                    if node.args:
                        p = _eval_workflow_path_expr(node.args[0], const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                    for kw in node.keywords:
                        if kw.arg in ("file", "name"):
                            p = _eval_workflow_path_expr(kw.value, const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                continue
            if attr == "open":
                is_unbound_path_open = recv_name in pathlib_names or (
                    isinstance(recv, ast.Attribute) and recv.attr in pathlib_names
                )
                if recv_name in os_aliases:
                    direct_fs_mutation_detected = True
                    if node.args:
                        p = _eval_workflow_path_expr(node.args[0], const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                    for kw in node.keywords:
                        if kw.arg in ("path", "file"):
                            p = _eval_workflow_path_expr(kw.value, const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                elif recv_name in io_open_aliases:
                    if not _is_readonly_open_call(node, 1, const_vars):
                        direct_fs_mutation_detected = True
                        if node.args:
                            p = _eval_workflow_path_expr(node.args[0], const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                elif recv_name in archive_aliases:
                    if not _is_readonly_open_call(node, 1, const_vars, archive=True):
                        direct_fs_mutation_detected = True
                        if node.args:
                            p = _eval_workflow_path_expr(node.args[0], const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                elif is_unbound_path_open:
                    if not _is_readonly_open_call(node, 1, const_vars):
                        direct_fs_mutation_detected = True
                        if node.args:
                            p = _eval_workflow_path_expr(node.args[0], const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                else:
                    # Bound `Path(...).open(mode='r', ...)` has `mode` at positional index 0
                    if not _is_readonly_open_call(node, 0, const_vars):
                        direct_fs_mutation_detected = True
                        recv_path = _eval_workflow_path_expr(recv, const_vars)
                        if recv_path:
                            direct_fs_candidate_paths.append(recv_path)
                continue

    if direct_fs_mutation_detected:
        for cand in [*direct_fs_candidate_paths, *const_vars.values()]:
            if _path_hits_gov(cand, resolve_rel=True):
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            "[Harness Governance Shield] Direct Python mutation of protected governance path "
                            f"(`{cand}`) inside `run_workflow` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                        ),
                    },
                    [],
                )
        for cand in [*arg_strings, *all_literals]:
            if _path_hits_gov(cand, resolve_rel=False):
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            "[Harness Governance Shield] Direct Python mutation of protected governance path "
                            f"(`{cand}`) inside `run_workflow` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                        ),
                    },
                    [],
                )
        return (
            {
                "decision": "deny",
                "reason": (
                    "[Harness Workflow Shield] Direct Python filesystem writes/mutations inside `run_workflow` "
                    "bypass tool-level safety and Flight Recorder gates; use `call_tool('write_file', ...)` "
                    "or `agent(...)` instead (GEMINI.md Rule 15e)."
                ),
            },
            [],
        )

    if indirect_call_reason:
        return _gov_deny_or(indirect_call_reason)

    for rmtree_node in rmtree_calls:
        if any(isinstance(a, ast.Starred) for a in rmtree_node.args) or any(
            kw.arg is None for kw in rmtree_node.keywords
        ):
            resolved_rm = None
        else:
            target_arg = rmtree_node.args[0] if rmtree_node.args else None
            if target_arg is None:
                for kw in rmtree_node.keywords:
                    if kw.arg == "path":
                        target_arg = kw.value
                        break
            resolved_rm = _eval_workflow_path_expr(target_arg, const_vars)
        if resolved_rm is None:
            if eff_cwd is not None and _targets_governance_dir(str(eff_cwd)):
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            "[Harness Governance Shield] Recursive deletion inside protected governance Cwd "
                            f"(`{eff_cwd}`) inside `run_workflow` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                        ),
                    },
                    [],
                )
            for cand in [*const_vars.values(), *arg_strings, *all_literals]:
                if _path_hits_gov(cand, resolve_rel=False):
                    return (
                        {
                            "decision": "deny",
                            "reason": (
                                "[Harness Governance Shield] Recursive deletion targeting protected governance path "
                                f"(`{cand}`) inside `run_workflow` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                            ),
                        },
                        [],
                    )
            return (
                {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] `shutil.rmtree()` inside `run_workflow` requires a static "
                        "path literal so Governance Shield can verify the target (GEMINI.md Rule 12 & Rule 15e)."
                    ),
                },
                [],
            )
        if _path_hits_gov(resolved_rm, resolve_rel=True):
            return (
                {
                    "decision": "deny",
                    "reason": (
                        "[Harness Governance Shield] Recursive deletion of protected governance path "
                        f"(`{resolved_rm}`) inside `run_workflow` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                    ),
                },
                [],
            )
        if _path_hits_cust(resolved_rm, resolve_rel=True):
            mod_eval = _evaluate_customization_model_and_effort(payload)
            if mod_eval is not None:
                if mod_eval[0] == "deny":
                    return {"decision": "deny", "reason": mod_eval[1]}, []
                force_ask_reasons.append(mod_eval[1])
        force_ask_reasons.append(
            "[Harness Workflow Shield] Recursive directory deletion (`shutil.rmtree`) inside `run_workflow` "
            "requires explicit human confirmation (GEMINI.md Rule 12)."
        )

    # 4. Enforce Customization Model Gate on one-shot, persistent (`var = agent(...)`), and chained `agent(...)(...)` calls
    def _agent_has_oneshot_prompt(ag_call: ast.Call) -> bool:
        if any(isinstance(a, ast.Starred) for a in ag_call.args) or any(k.arg is None for k in ag_call.keywords):
            return False
        prompt_arg: Optional[ast.AST] = ag_call.args[0] if ag_call.args else None
        if prompt_arg is None:
            for k in ag_call.keywords:
                if k.arg == "prompt":
                    prompt_arg = k.value
                    break
        if prompt_arg is None:
            return False
        folded_prompt = _eval_workflow_str_expr(prompt_arg, const_vars)
        if folded_prompt is not None:
            return bool(folded_prompt.strip())
        if isinstance(prompt_arg, ast.JoinedStr):
            return True
        if isinstance(prompt_arg, ast.BinOp) and isinstance(prompt_arg.op, ast.Add):
            frag, _ = _extract_partial_text_and_dynamic(prompt_arg, const_vars)
            return bool(frag.strip())
        return False

    def _direct_parallel_agent_calls(par_call: ast.Call) -> List[ast.Call]:
        found: List[ast.Call] = []
        for par_arg in par_call.args:
            cand = _unwrap_agent_call(par_arg, allow_await=True)
            if cand is not None:
                found.append(cand)
            elif isinstance(par_arg, ast.Lambda):
                lam_cand = _unwrap_agent_call(par_arg.body, allow_await=True)
                if lam_cand is not None:
                    found.append(lam_cand)
            elif isinstance(par_arg, (ast.List, ast.Tuple)):
                for elt in par_arg.elts:
                    elt_cand = _unwrap_agent_call(elt, allow_await=True)
                    if elt_cand is not None:
                        found.append(elt_cand)
                    elif isinstance(elt, ast.Lambda):
                        lam_cand = _unwrap_agent_call(elt.body, allow_await=True)
                        if lam_cand is not None:
                            found.append(lam_cand)
            elif isinstance(par_arg, (ast.ListComp, ast.GeneratorExp)):
                comp_cand = _unwrap_agent_call(par_arg.elt, allow_await=True)
                if comp_cand is not None:
                    found.append(comp_cand)
                elif isinstance(par_arg.elt, ast.Lambda):
                    lam_cand = _unwrap_agent_call(par_arg.elt.body, allow_await=True)
                    if lam_cand is not None:
                        found.append(lam_cand)
        return found

    call_to_vars: Dict[int, List[str]] = {}
    allowed_agent_call_ids: set[int] = set(chained_agent_turns.keys())
    for var_name, ag_list in persistent_agents.items():
        for ag_c in ag_list:
            call_to_vars.setdefault(id(ag_c), []).append(var_name)
            allowed_agent_call_ids.add(id(ag_c))
    for n in ast.walk(tree):
        if isinstance(n, ast.Await):
            aw_ag = _unwrap_agent_call(n.value, allow_await=False)
            if aw_ag is not None and _agent_has_oneshot_prompt(aw_ag):
                allowed_agent_call_ids.add(id(aw_ag))
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("parallel", "pipeline"):
            for sub in _direct_parallel_agent_calls(n):
                if _agent_has_oneshot_prompt(sub):
                    allowed_agent_call_ids.add(id(sub))

    for ag_node in raw_agent_call_nodes:
        if id(ag_node) not in allowed_agent_call_ids:
            return (
                {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Persistent `agent()` handles inside `run_workflow` must be "
                        "bound directly to a variable name (`var = agent(...)`) or awaited directly so safety "
                        "gates can inspect every turn (GEMINI.md Rule 15e & Rule 17)."
                    ),
                },
                [],
            )
        extra_prompt_nodes: List[ast.AST] = list(chained_agent_turns.get(id(ag_node), []))
        for var_name in call_to_vars.get(id(ag_node), ()):
            extra_prompt_nodes.extend(persistent_agent_turn_nodes.get(var_name, []))

        # Signature: agent(prompt=None, schema=None, role=None, type_name="self", workspace="inherit", model=None)
        model_node: Optional[ast.AST] = ag_node.args[5] if len(ag_node.args) >= 6 else None
        type_node: Optional[ast.AST] = ag_node.args[3] if len(ag_node.args) >= 4 else None
        prompt_nodes: List[ast.AST] = list(extra_prompt_nodes)
        if ag_node.args:
            prompt_nodes.append(ag_node.args[0])
        if len(ag_node.args) >= 3:
            prompt_nodes.append(ag_node.args[2])
        has_star_kw = any(isinstance(a, ast.Starred) for a in ag_node.args)
        for kw in ag_node.keywords:
            if kw.arg is None:
                has_star_kw = True
            elif kw.arg == "model":
                model_node = kw.value
            elif kw.arg == "type_name":
                type_node = kw.value
            elif kw.arg in ("prompt", "role"):
                prompt_nodes.append(kw.value)

        model_dynamic = has_star_kw
        if model_node is None or (isinstance(model_node, ast.Constant) and model_node.value is None):
            model_tier = "inherit"
        else:
            eval_m = _eval_workflow_str_expr(model_node, const_vars)
            if eval_m is None:
                model_tier = ""
                model_dynamic = True
            else:
                model_tier = eval_m.strip().lower()

        if type_node is None or (isinstance(type_node, ast.Constant) and type_node.value is None):
            agent_type = "self"
        else:
            type_val = _eval_workflow_str_expr(type_node, const_vars)
            agent_type = type_val.strip().lower() if type_val is not None else "__dynamic__"
        if has_star_kw and type_node is None:
            agent_type = "__dynamic__"

        prompt_fragments: List[str] = []
        prompt_has_dynamic = False
        for p_node in prompt_nodes:
            frag, is_dyn = _extract_partial_text_and_dynamic(p_node, const_vars)
            if frag:
                prompt_fragments.append(frag)
            for multi_frag in _eval_multi_candidates(p_node, multi_var_values):
                if multi_frag and multi_frag not in prompt_fragments:
                    prompt_fragments.append(multi_frag)
            for sub_p in ast.walk(p_node):
                if isinstance(sub_p, ast.Name) and sub_p.id in multi_var_values:
                    for mv_cand in multi_var_values[sub_p.id]:
                        if mv_cand and mv_cand not in prompt_fragments:
                            prompt_fragments.append(mv_cand)
            if is_dyn:
                prompt_has_dynamic = True

        parent_cust_eval = _evaluate_customization_model_and_effort(payload) if agent_type != "research" else None
        parent_model_fails_cust = parent_cust_eval is not None
        agent_fails_cust_gate = (
            model_dynamic
            or model_tier in ("flash", "flash_lite")
            or (agent_type != "research" and model_tier not in ("", "none", "inherit"))
            or parent_model_fails_cust
        )

        haystacks = list(prompt_fragments)
        if prompt_has_dynamic or model_dynamic:
            haystacks.extend(arg_strings)
            if agent_fails_cust_gate:
                haystacks.extend(all_literals)

        wf_workspaces = _workspaces_from_payload(payload)
        ws_ctx = eff_cwd if eff_cwd is not None else workspace
        combined_prompt = " ".join(haystacks)
        targets_cust = (
            _text_targets_customization(
                combined_prompt,
                wf_workspaces,
                fallback_ws=workspace,
                effective_cwd=eff_cwd,
                extra_tokens=haystacks,
            )
            or (
                eff_cwd is not None
                and (
                    _targets_governance_dir(str(eff_cwd))
                    or _targets_customization_structure(str(eff_cwd), workspace=ws_ctx)
                )
            )
        )
        if targets_cust and agent_type != "research":
            if model_dynamic:
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            "[Harness Customization Model Gate] `run_workflow` `agent()` targeting "
                            "customization or governance files must specify literal `model='inherit'` "
                            "(GEMINI.md Rule 15e & Rule 17)."
                        ),
                    },
                    [],
                )
            if model_tier in ("flash", "flash_lite") or model_tier not in ("", "none", "inherit"):
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            "[Harness Customization Model Gate] `run_workflow` cannot delegate "
                            f"customization or governance modifications to downgraded model tier `{model_tier}` "
                            "(GEMINI.md Rule 15e & Rule 17)."
                        ),
                    },
                    [],
                )
            if parent_cust_eval is not None:
                if parent_cust_eval[0] == "deny":
                    return {"decision": "deny", "reason": parent_cust_eval[1]}, []
                force_ask_reasons.append(parent_cust_eval[1])

    # 5. Prompt (`force_ask`) on destructive shell patterns, unpinned remote packages, or `shutil.rmtree`
    for text in cmd_candidates:
        unquoted_t = _unquote_single_tokens(text)
        for pattern, reason in _DESTRUCTIVE_CMD_PATTERNS:
            if pattern.search(unquoted_t):
                force_ask_reasons.append(f"[Harness Workflow Shield] {reason}")
                break
        unpinned_reason = _detect_unpinned_package_exec(unquoted_t)
        if unpinned_reason:
            force_ask_reasons.append(f"[Harness Workflow Shield] {unpinned_reason}")

    if force_ask_reasons:
        if pending_swarm_ops is not None and local_swarm_ops:
            pending_swarm_ops.extend(local_swarm_ops)
        return {"decision": "force_ask", "reason": force_ask_reasons[0]}, []

    if pending_swarm_ops is not None and local_swarm_ops:
        pending_swarm_ops.extend(local_swarm_ops)
    return {"decision": "allow"}, flight_writes

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
        inner = m_q.group(0)[1:-1].strip()
        if inner and "\n" not in inner and ("/" in inner or inner.endswith(".md") or inner.endswith(".py") or inner.endswith(".json")):
            out.append(inner)
    return out

def _shell_has_unquoted_mutation(sub_cmd: str) -> bool:
    expanded = _unquote_single_tokens(_strip_unquoted_shell_comments(sub_cmd))
    scrubbed = _QUOTED_SPAN_RE.sub('"__QUOTED__"', expanded)
    return bool(_SHELL_MUTATION_INDICATOR_RE.search(scrubbed))

_CD_SEG_RE = re.compile(
    r"^\s*\(*\s*(?:builtin\s+|command\s+)?(?P<verb>cd|pushd|popd)(?:\s+(?P<rest>.*))?$"
)

_INLINE_DIR_FLAG_RE = re.compile(
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
    for seg, seg_cwd in _iter_shell_segments_with_cwd(sub_cmd, effective_cwd):
        if seg_cwd is None or not _shell_has_unquoted_mutation(seg):
            continue
        tokens = _extract_shell_path_tokens(seg)
        for tok in tokens:
            if _targets_governance_dir(tok, base_dir=seg_cwd):
                return True
        if _targets_governance_dir(str(seg_cwd)):
            rel_tokens = [t for t in tokens if not Path(os.path.expanduser(t)).is_absolute()]
            if not tokens or any(_targets_governance_dir(t, base_dir=seg_cwd) for t in rel_tokens):
                return True
    return False

def _command_mutates_customization_in_cwd(
    sub_cmd: str, effective_cwd: Optional[Path], workspaces: Sequence[Path], fallback_ws: Optional[Path]
) -> bool:
    for seg, seg_cwd in _iter_shell_segments_with_cwd(sub_cmd, effective_cwd):
        is_interp = bool(
            re.search(r"\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*\s-(?:[A-Za-z0-9]*[ceip])", seg)
        )
        if not _shell_has_unquoted_mutation(seg) and not is_interp:
            continue
        base_cwd = seg_cwd if seg_cwd is not None else fallback_ws
        ws_root = (
            _workspace_for_target(str(base_cwd), workspaces, fallback=(fallback_ws or base_cwd))
            if base_cwd is not None
            else None
        )
        tokens = list(_extract_shell_path_tokens(seg))
        if is_interp:
            tokens.extend(re.findall(r"['\"]([^'\"]*[/\\][^'\"]+)['\"]", seg))
        for tok in tokens:
            exp = Path(os.path.expanduser(tok))
            if not exp.is_absolute() and base_cwd is None:
                continue
            resolved_str = str(base_cwd / exp) if (not exp.is_absolute() and base_cwd is not None) else str(exp)
            tok_ws = _workspace_for_target(resolved_str, workspaces, fallback=(ws_root or base_cwd))
            if _targets_customization_structure(resolved_str, workspace=tok_ws):
                return True
        if not is_interp and base_cwd is not None and _targets_customization_structure(str(base_cwd), workspace=ws_root):
            if not tokens or any(not Path(os.path.expanduser(t)).is_absolute() for t in tokens):
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

_INTERP_SCRIPT_SEG_RE = re.compile(
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

_STR_LIST_SEQ_RE = re.compile(
    r"[\[(]\s*(?:['\"][^'\"\n]+['\"]\s*,\s*)+['\"][^'\"\n]*['\"]\s*,?\s*[\])]"
)

_QUOTED_ITEM_RE = re.compile(r"'([^'\\\n]*)'|\"([^\"\\\n]*)\"")

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

_MCP_DEBUGGER_ESCAPE_RE = re.compile(r"^\s*(?:!+|\.!|#!(?:pipe|python3?|ba?sh)\s+|(?:shell|system)\s+)", re.IGNORECASE)

_MCP_MUTATING_TOOL_HINT_RE = re.compile(
    r"(?:write|edit|create|delete|remove|unlink|mv|move|rename|copy|chmod|chown|push|install|uninstall|"
    r"extract|save|exec|command|console|frida|script|gdb|rizin|cutter|adb|patch|modify|update|set_|put)",
    re.IGNORECASE,
)

def _collect_mcp_strings(value: Any, out: List[str], depth: int = 0) -> Optional[str]:
    if depth > _WORKFLOW_MAX_ARG_DEPTH:
        return "[Harness MCP Shield] MCP `Arguments` exceed maximum nesting depth (failing closed)."
    if isinstance(value, str):
        if "\x00" in value:
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
        parsed = urllib.parse.urlparse(s)
        return urllib.parse.unquote(parsed.path or "")
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
            if _write_mutates_authorized_test_section(t_raw, mcp_args, effective_cwd or t_ws):
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

_DELEGATION_MUTATION_VERB_RE = re.compile(
    r"\b(?:edit|write|modify|overwrite|replace|update|patch|append|create|delete|remove|rm|unlink|"
    r"chmod|chown|unlock|rebaseline|copy|cp|mv|move|symlink|ln)\b",
    re.IGNORECASE,
)

_DELEGATION_PATH_TOKEN_RE = re.compile(r"(?:~|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[A-Za-z]:)?[^\s'\"`<>|;&(),]+")

_SWARM_MENTION_RE = re.compile(r"(?<![A-Za-z0-9._-])@([a-z0-9][a-z0-9_-]*)", re.IGNORECASE)

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
            if "\x00" in target:
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
            if _write_mutates_authorized_test_section(target, args, effective_cwd or t_ws):
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
                    segs_with_cwd = _iter_shell_segments_with_cwd(
                        sub_cmd, effective_cwd if effective_cwd is not None else workspace
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
                if (
                    re.search(r"(?:^|[\s/'\"=])(?:\.agents?|_agents?)/hooks\.json\b", unquoted_sub, re.IGNORECASE)
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
                    if pattern.search(unquoted_sub):
                        if pending_cmd_force_ask is None:
                            pending_cmd_force_ask = {
                                "decision": "force_ask",
                                "reason": f"[Harness Bash Guard] {reason}",
                            }
                        break

                out_ws_msg = _detect_out_of_workspace_rm_or_mv(unquoted_sub, workspaces, effective_cwd)
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

def _auth_sections_differ(old_text: str, new_text: str) -> bool:
    if _extract_normalized_auth_section(new_text) != _extract_normalized_auth_section(old_text):
        return True
    try:
        from guard.test_boundary import TestBoundaryGuard

        if TestBoundaryGuard.parse_authorized_tasks_text(new_text) != TestBoundaryGuard.parse_authorized_tasks_text(old_text):
            return True
    except Exception:
        pass
    return False

def _write_mutates_authorized_test_section(target: str, args: Dict[str, Any], base_dir: Optional[Path]) -> bool:
    norm_target = target.replace("\\", "/").strip()
    if Path(norm_target).name.lower() != "tasks.md":
        return False
    disk_path = Path(os.path.expanduser(norm_target))
    if not disk_path.is_absolute():
        disk_path = (base_dir or _repo_root()) / disk_path
    try:
        disk_path = disk_path.resolve()
    except (OSError, RuntimeError):
        pass
    old_text = ""
    try:
        if disk_path.is_file():
            old_text = disk_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        old_text = ""
    norm_old = old_text.replace("\r\n", "\n").replace("\r", "\n")

    # Full-file or append write (`write_file`, `write_to_file`, `create_file`, `write`)
    for content_key in ("Content", "FileContent", "CodeContent", "content", "file_text"):
        if content_key in args and isinstance(args.get(content_key), str):
            body = args[content_key].replace("\r\n", "\n").replace("\r", "\n")
            is_append = bool(args.get("Append") or args.get("append"))
            sim_text = (norm_old + body) if is_append else body
            return _auth_sections_differ(norm_old, sim_text)

    # Targeted replacement (`edit_file`, `replace_file_content`, `multi_replace_file_content`, `edit`, `multiedit`)
    pairs: List[Tuple[str, str]] = []
    chunks = args.get("ReplacementChunks") or args.get("edits") or args.get("chunks")
    if isinstance(chunks, list):
        for ch in chunks:
            if isinstance(ch, dict):
                t_s = (
                    ch.get("TargetContent")
                    or ch.get("Target")
                    or ch.get("old_string")
                    or ch.get("old_str")
                    or ch.get("oldText")
                )
                r_s = (
                    ch.get("ReplacementContent")
                    if "ReplacementContent" in ch
                    else (
                        ch.get("Replacement")
                        if "Replacement" in ch
                        else (
                            ch.get("new_string")
                            if "new_string" in ch
                            else (ch.get("new_str") if "new_str" in ch else ch.get("newText"))
                        )
                    )
                )
                if isinstance(t_s, str) and isinstance(r_s, str):
                    pairs.append(
                        (
                            t_s.replace("\r\n", "\n").replace("\r", "\n"),
                            r_s.replace("\r\n", "\n").replace("\r", "\n"),
                        )
                    )
    else:
        t_s = (
            args.get("Target")
            or args.get("TargetContent")
            or args.get("old_string")
            or args.get("old_str")
            or args.get("oldText")
        )
        r_s = (
            args.get("Replacement")
            if "Replacement" in args
            else (
                args.get("ReplacementContent")
                if "ReplacementContent" in args
                else (
                    args.get("new_string")
                    if "new_string" in args
                    else (args.get("new_str") if "new_str" in args else args.get("newText"))
                )
            )
        )
        if isinstance(t_s, str) and isinstance(r_s, str):
            pairs.append(
                (
                    t_s.replace("\r\n", "\n").replace("\r", "\n"),
                    r_s.replace("\r\n", "\n").replace("\r", "\n"),
                )
            )

    if pairs:
        if norm_old and all(t_s in norm_old for t_s, _ in pairs):
            sim_text = norm_old
            for t_s, r_s in pairs:
                sim_text = sim_text.replace(t_s, r_s)
            return _auth_sections_differ(norm_old, sim_text)
        has_existing_heading = bool(_AUTH_HEADING_RE.search(norm_old))
        for t_s, r_s in pairs:
            if re.search(r"Authorized\s+Test\s+Modifications", f"{t_s}\n{r_s}", re.IGNORECASE):
                return True
            if has_existing_heading:
                return True
    return False
