"""
guard/hooks/_shell_guard.py — Lazy PreToolUse shell/bash, Python-AST scrubber & workflow entrypoint guard (ADR-0013).
Part of Plumbwork (https://github.com/hadbilen/plumbwork)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import ast
import functools
import os
import re
import stat
import textwrap
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from guard.paths import HOOK_LOCK_TIMEOUT, is_within, share_dir_candidates, windows_launcher_dir

from . import pre_tool_use as _ptu
from .pre_tool_use import _normalize_shell_paths
from .common import (
    _HARNESS_PLUGIN_NAMES,
    _LazyRegex,
    _conversation_id,
    _facade_attr,
    _read_ledger_checked,
    _read_ledger_safe,
    _repo_root,
    atomic_write_json,
    data_dir,
    file_lock,
    json,
)

_PY_INTERP_OPTS = r"(?:-(?![A-Za-z0-9]*[mc]\b)(?:[WXx]\s+\S+|\d+(?:\.\d+)?(?:-\d+)?|[A-Za-z0-9]+(?:=\S+)?)\s+)*"

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

# Human-only Guard administration subcommands & root-redirect env overrides (GEMINI.md Rule 12)
_GUARD_ADMIN_BODY = (
    rf"{_CMD_WRAPPER_PREFIX}"
    r"(?:"
    rf"(?:(?:[^\s;|&`]*[/\\])?(?:python3?(?:\.\d+)?|py)(?:\.exe)?\s+{_PY_INTERP_OPTS}(?:-[A-Za-z0-9]*m\s+guard(?:\.cli)?\b|(?:[^\s;|&`]*[/\\])?(?:guard\.py|guard[/\\]cli\.py))|(?:[^\s;|&`]*[/\\])?(?:guard\.py|guard[/\\]cli\.py|plumb-guard(?:\.(?:exe|cmd|bat|ps1))?))\s+"
    r"(?:--?[A-Za-z0-9_-]+(?:=\S+|\s+(?!unlock\b|rebaseline\b|test-boundary\b|provenance\b|verify-invariants\b|snapshot\b|porter\b|env\b|startup\b|notify\b|doctor\b|init\b)[^\s;|&`]+)?\s+)*"
    r"(?:"
    r"unlock\b|"
    r"rebaseline\b|"
    rf"test-boundary{_SUBPARSER_OPTS}\s+snapshot\b|"
    r"test-boundary\b[^\n;|&`]*\s--auth[a-z-]*(?:\b|=)|"
    r"provenance\b[^\n;|&`]*\s--auth[a-z-]*(?:\b|=)|"
    r"verify-invariants\b[^\n;|&`]*\s--auth[a-z-]*(?:\b|=)|"
    rf"snapshot{_SUBPARSER_OPTS}\s+(?:restore|prune)\b|"
    rf"porter{_SUBPARSER_OPTS}\s+(?:stage\b|import\b[^\n;|&`]*\s--force\b)|"
    rf"env{_SUBPARSER_OPTS}\s+remove\b|"
    rf"env{_SUBPARSER_OPTS}\s+add\b[^\n;|&`]*--policy(?:=|\s+)(?!enforced\b)\S+|"
    rf"env{_SUBPARSER_OPTS}\s+policy\b(?!(?![^\n;|&`]*\b(?:monitored|disabled|relaxed)\b)(?:[^\n;|&`]*\s+\S+\s+enforced\s*(?:$|[;&|()\n`])|[^\n;|&`]*--policy-val(?:=|\s+)enforced\b))|"
    rf"startup{_SUBPARSER_OPTS}\s+(?:enable|disable)\b|"
    rf"notify{_SUBPARSER_OPTS}\s+disable\b|"
    r"doctor\b[^\n;|&`]*\s--(?:fix|rec[a-z-]*)\b|"
    r"init\b(?!(?![^\n;|&`]*--uninst[a-z-]*\b)[^\n;|&`]*(?:--dry-run\b|--help\b|-h\b))"
    r")|"
    rf"(?:(?:[^\s;|&`]*[/\\])?(?:python3?(?:\.\d+)?|py)(?:\.exe)?\s+{_PY_INTERP_OPTS}(?:-[A-Za-z0-9]*m\s+porter\b|(?:[^\s;|&`]*[/\\])?porter\.py)|(?:[^\s;|&`]*[/\\])?(?:porter\.py|(?:plumb-)?porter(?:\.(?:exe|cmd|bat|ps1))?)){_SUBPARSER_OPTS}\s+(?:stage\b|import\b[^\n;|&`]*\s--force\b)|"
    rf"(?:(?:[^\s;|&`]*[/\\])?(?:python3?(?:\.\d+)?|py)(?:\.exe)?\s+{_PY_INTERP_OPTS}(?:-[A-Za-z0-9]*m\s+scripts\.verify_invariants\b|(?:[^\s;|&`]*[/\\])?verify_invariants\.py)|(?:[^\s;|&`]*[/\\])?verify_invariants\.py)\b[^\n;|&`]*\s--auth[a-z-]*(?:\b|=)|"
    r"(?:export\s+|env\s+(?:-[A-Za-z0-9-]+\s+)*)?(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*"
    r"(?:PLUMBWORK_SHARE_DIR|PLUMB_GUARD_DATA_DIR|PLUMB_GUARD_STATE_DIR|ANTIGRAVITY_CONFIG_DIR|XDG_DATA_HOME|XDG_STATE_HOME)=\S+(?:[^\n`]*?(?:[\s;&|()]+))"
    r"(?:"
    rf"(?:[^\s;|&`]*[/\\])?(?:python3?(?:\.\d+)?|py)(?:\.exe)?\s+{_PY_INTERP_OPTS}(?:-[A-Za-z0-9]*m\s+(?:guard(?:\.cli)?|porter)\b|(?:[^\s;|&`]*[/\\])?(?:guard\.py|guard[/\\]cli\.py|porter\.py)\b)|"
    r"(?:[^\s;|&`]*[/\\])?(?:guard\.py|guard[/\\]cli\.py|porter\.py|plumb-guard(?:\.(?:exe|cmd|bat|ps1))?|plumb-porter(?:\.(?:exe|cmd|bat|ps1))?)\b"
    r")"
    r")"
)

_GUARD_ADMIN_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*{_GUARD_ADMIN_BODY}",
    re.IGNORECASE,
    any_tokens=("guard", "porter", "verify_invariants"),
)

_DELEGATION_GUARD_ADMIN_RE = _LazyRegex(
    rf"(?:^|[\s;|&()\n`'\"]){_GUARD_ADMIN_BODY}",
    re.IGNORECASE,
    any_tokens=("guard", "porter", "verify_invariants"),
)

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
    rf"\b(?:python3?(?:\.\d+)?|py)(?:\.exe)?\b[^\n;|&`]*(?:\s-[A-Za-z0-9]*c\b|<<-?\s*['\"]?[A-Za-z0-9_]+['\"]?)[\s\S]*?{_GUARD_API_TOKEN_PAT}|"
    rf"{_GUARD_API_TOKEN_PAT}[\s\S]*?\|\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*[/\\])?(?:python3?(?:\.\d+)?|py)(?:\.exe)?\b"
    r")",
    re.IGNORECASE,
    any_tokens=(
        "osprotectionadapter",
        "porterbridge",
        "installer",
        "guard.",
        "install.main",
        "authorized_modifications",
        ".unlock",
        ".save_baseline",
        ".snapshot",
        ".restore_snapshot",
        ".prune_snapshots",
        ".stage_and_ingest",
        ".set_policy",
        ".register_environment",
        ".unregister_environment",
        ".remove_environment",
    ),
)

# Direct execution of install.py without --dry-run or --help (GEMINI.md Rule 12).
# Anchored to the start of a simple command (or interpreter invocation) so passing `install.py`
# as a path argument to read-only commands (`git diff ... install.py`, `grep ... install.py`) is allowed.
_INSTALL_PY_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}"
    r"(?:(?:[^\s;|&`]*/)?(?:python3?(?:\.\d+)?|py|(?:ba|z|da|k)?sh)\s+(?:-[^\s;|&`]+\s+)*(?:[^\s;|&`]*/)?|(?:[^\s;|&`]*/)?)"
    r"install\.py\b(?![^\n;|&`]*(?:--dry-run|--help|-h\b))",
    re.IGNORECASE,
    any_tokens=("install.py",),
)

_WORKFLOW_INSTALL_EXEC_BODY = (
    rf"{_CMD_WRAPPER_PREFIX}"
    r"(?:(?:[^\s;|&`]*/)?(?:python3?(?:\.\d+)?|py|(?:ba|z|da|k)?sh)\s+(?:-[^\s;|&`]+\s+)*(?:[^\s;|&`]*/)?|(?:\./|/[^\s;|&`]*/))"
    r"install\.py\b(?![^\n;|&`]*(?:--dry-run|--help|-h\b))"
)

_WORKFLOW_INSTALL_EXEC_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*{_WORKFLOW_INSTALL_EXEC_BODY}",
    re.IGNORECASE,
    any_tokens=("install.py",),
)

_DELEGATION_INSTALL_EXEC_RE = _LazyRegex(
    rf"(?:^|[\s;|&()\n`'\"]){_WORKFLOW_INSTALL_EXEC_BODY}",
    re.IGNORECASE,
    any_tokens=("install.py",),
)

_QUOTED_SPAN_RE = _LazyRegex(r"\$'(?:\\.|[^'\\])*'|'[^']*'|\"(?:\\.|[^\"\\])*\"", any_tokens=("'", '"'))

_BACKTICK_SPAN_RE = _LazyRegex(r"`((?:\\.|[^`\\])+)`", any_tokens=("`",))

_SHELL_C_EXTRACT_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}"
    r"(?:(?:[^\s;|&`]*/)?(?:ba|z|da|k)?sh\b[^\n;|&`]*?\s-(?:[A-Za-z0-9]+\s+)*[A-Za-z0-9]*c[A-Za-z0-9]*|eval)\s+"
    r"(?:'([^']*)'|\"((?:\\.|[^\"\\])*)\")",
    re.IGNORECASE,
    any_tokens=("sh", "eval"),
)

_SCRIPT_C_EXTRACT_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?script\b[^\n;|&`]*?"
    r"(?:\s-(?:[A-Za-z0-9]+\s+)*[A-Za-z0-9]*c\s*|\s--command(?:=|\s+))"
    r"(?:'([^']*)'|\"((?:\\.|[^\"\\])*)\"|([^\s;|&`'\"]+))",
    re.IGNORECASE,
    any_tokens=("script",),
)

_PIPE_TO_SH_EXTRACT_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*(?:echo|printf)\b(?:\s+-[neE]+)*\s+"
    r"(?:'([^']*)'|\"((?:\\.|[^\"\\])*)\")\s*\|\s*"
    rf"{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?(?:ba|z|da|k)?sh\b",
    re.IGNORECASE,
    any_tokens=("|",),
)

_FIND_EXEC_EXTRACT_RE = _LazyRegex(
    r"\bfind\b[^\n;|&]*?\s-(?:exec|execdir|ok|okdir)\s+([^\n;|]+?)(?:\s+(?:\\;|;|\+))?(?=$|[;&|\n])",
    re.IGNORECASE,
    any_tokens=("find",),
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
    any_tokens=("tmux", "screen", "byobu", "tmate", "dtach", "abduco", "zellij"),
)

# Keystroke or buffer injection into a multiplexer runs arbitrary commands outside `PreToolUse` inspection.
_TERMINAL_INJECTION_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?(?:"
    r"(?:tmux|byobu|tmate)\b[^\n;|&`]*\s(?:send-keys|send|paste-buffer|pasteb|load-buffer|loadb|set-buffer|setb)\b|"
    r"screen\b[^\n;|&`]*\s-X\s+(?:stuff|paste|readbuf|register)\b|"
    r"zellij\b[^\n;|&`]*\s(?:write-chars|write)\b"
    r")",
    re.IGNORECASE,
    any_tokens=("tmux", "byobu", "tmate", "screen", "zellij"),
)

# Exec-like calls whose argv is a string list/tuple (`pty.spawn(['plumb-guard', 'unlock'])`,
# `subprocess.run(("python3", "install.py"))`) or a single command string (`os.system('...')`).
_EXEC_CALL_ARGV_RE = _LazyRegex(
    r"\b(?:system|popen|run|call|check_call|check_output|getoutput|getstatusoutput|Popen|spawn|spawnSync|"
    r"execSync|execFile|execFileSync|exec[lv]p?e?|spawn[lv]p?e?)\s*\(\s*"
    r"(?:[\[(]\s*((?:'[^'\n]*'|\"[^\"\n]*\")(?:\s*,\s*(?:'[^'\n]*'|\"[^\"\n]*\"))*)\s*,?\s*[\])]"
    r"|('[^'\n]*'|\"[^\"\n]*\"))",
    any_tokens=("(",),
)

_STR_ARGV_TOKEN_RE = _LazyRegex(r"'([^'\n]*)'|\"([^\"\n]*)\"")

def _blank_quoted_spans(cmd: str) -> str:
    """Returns `cmd` with every quoted span's interior replaced by spaces (same length, quotes kept)."""
    def _repl(m: re.Match) -> str:
        s = m.group(0)
        if s.startswith("$'"):
            return "$'" + " " * max(0, len(s) - 3) + "'"
        return s[0] + " " * max(0, len(s) - 2) + s[-1]
    return _QUOTED_SPAN_RE.sub(_repl, cmd)

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
        # Every token suffix is a candidate command line (`new-window plumb-guard unlock` -> `plumb-guard unlock`).
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
    in_ansic = False
    i = 0
    n = len(cmd)
    while i < n:
        ch = cmd[i]
        if in_ansic:
            if ch == "\\" and i + 1 < n:
                out.append(cmd[i : i + 2])
                i += 2
                continue
            out.append(ch)
            if ch == "'":
                in_ansic = False
            i += 1
            continue
        if in_sq:
            out.append(ch)
            if ch == "'":
                in_sq = False
            i += 1
            continue
        if ch == "$" and i + 1 < n and cmd[i + 1] == "'":
            in_ansic = True
            out.append("$'")
            i += 2
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
    in_ansic = False
    in_dq = False
    i = 0
    n = len(cmd)
    while i < n:
        ch = cmd[i]
        if in_ansic:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "'":
                in_ansic = False
            i += 1
            continue
        if in_sq:
            if ch == "'":
                in_sq = False
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if not in_dq and ch == "$" and i + 1 < n and cmd[i + 1] == "'":
            in_ansic = True
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
            sub_ansic = False
            sub_dq = False
            while j < n and depth > 0:
                cj = cmd[j]
                if sub_ansic:
                    if cj == "\\" and j + 1 < n:
                        j += 2
                        continue
                    if cj == "'":
                        sub_ansic = False
                    j += 1
                    continue
                if sub_sq:
                    if cj == "'":
                        sub_sq = False
                    j += 1
                    continue
                if cj == "\\" and j + 1 < n:
                    j += 2
                    continue
                if not sub_dq and cj == "$" and j + 1 < n and cmd[j + 1] == "'":
                    sub_ansic = True
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
    in_ansic = False
    in_dq = False
    i = 0
    n = len(cmd)
    while i < n:
        ch = cmd[i]
        if in_ansic:
            if ch == "\\" and i + 1 < n:
                out.append(cmd[i : i + 2])
                i += 2
                continue
            out.append(ch)
            if ch == "'":
                in_ansic = False
            i += 1
            continue
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
        if ch == "$" and i + 1 < n and cmd[i + 1] == "'":
            in_ansic = True
            out.append("$'")
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
    """Unquotes whitespace-free quoted tokens (`"plumb-guard"`, `plumb-""guard`, `'--no-verify'`) while preserving multi-word quoted prose."""
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
        if span.startswith("$'"):
            raw_pieces.append((True, span))
            last = m.end()
            continue
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
    r")",
    any_tokens=("git", "HUSKY", "LEFTHOOK"),
)

_REMOTE_INTERPRETER_PAT = (
    r"(?:(?:[^\s;|&]*/)?(?:(?:ba|z|da|k|tc|c|fi)?sh|python3?(?:\.\d+)?|py|node|nodejs|deno|bun|perl|ruby|php))"
)

# Destructive shell/git operations that require explicit human confirmation (force_ask)
_DESTRUCTIVE_CMD_PATTERNS: Tuple[Tuple[Any, str], ...] = (
    (
        _LazyRegex(rf"\bgit{_GIT_GLOBAL_OPTS}\s+reset\b[^\n;|&]*--hard\b", any_tokens=("--hard",)),
        "Destructive git operation (`git reset --hard`) discards uncommitted work (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            rf"\bgit{_GIT_GLOBAL_OPTS}\s+(?:checkout\s+(?:--\s+)?\.|restore\s+(?:(?:--worktree|--staged|-[sSW]+)\s+)*(?:--\s+)?\.)(?:\s|$|[;&|])",
            any_tokens=("checkout", "restore"),
        ),
        "Destructive git operation discards workspace modifications across the tree (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(rf"\bgit{_GIT_GLOBAL_OPTS}\s+clean\b[^\n;|&]*(?:--force\b|\s-(?!-)[a-zA-Z]*f)", any_tokens=("clean",)),
        "Destructive git operation (`git clean -f`) permanently deletes untracked files (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            rf"\bgit{_GIT_GLOBAL_OPTS}\s+push\b[^\n;|&]*(?:\s--force(?![-a-zA-Z])|\s-(?!-)[a-zA-Z]*f[a-zA-Z]*\b|\s['\"]?\+[A-Za-z0-9_./:-]+)",
            any_tokens=("push",),
        ),
        "Force-pushing (`git push --force` / `+refspec`) rewrites remote history (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            rf"\bgit{_GIT_GLOBAL_OPTS}\s+branch\b[^\n;|&]*(?:\s-(?!-)[a-zA-Z]*D[a-zA-Z]*\b|"
            r"(?=[^\n;|&]*--delete\b)(?=[^\n;|&]*(?:--force\b|\s-(?!-)[a-zA-Z]*f)))",
            any_tokens=("branch",),
        ),
        "Force-deleting a git branch (`git branch -D` / `--delete --force`) may discard unmerged commits (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(rf"\bgit{_GIT_GLOBAL_OPTS}\s+stash\s+(?:drop|clear)\b", any_tokens=("stash",)),
        "Dropping or clearing git stashes (`git stash drop` / `git stash clear`) permanently discards stashed work (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            r"\brm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r|--recursive)\b\s+"
            r"(?:/(?:\s|$|[;&|])|~(?:[/\\]|\s|$|[;&|])|\$HOME\b|\.\.(?:[/\\]|\s|$|[;&|])|\*(?:\s|$|[;&|]))",
            any_tokens=("rm",),
        ),
        "High-risk recursive deletion (`rm -rf` on root, home, parent, or wildcard) requires confirmation (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            r"\bfind\b[^\n;|&]*(?:\s-delete\b|\s-(?:exec|execdir|ok)\s+(?:[^\s;|&]*/)?rm\b)",
            any_tokens=("find",),
        ),
        "Bulk file deletion via `find -delete` or `find -exec rm` requires explicit human confirmation (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            r"(?:\bdropdb\b|"
            r"\b(?:DROP\s+(?:DATABASE|TABLE|SCHEMA)|TRUNCATE\s+TABLE)\b|"
            r"\bDELETE\s+FROM\s+[A-Za-z0-9_.`\"']+\s*(?:;|$|['\"]))",
            re.IGNORECASE,
            any_tokens=("drop", "truncate", "delete"),
        ),
        "Destructive database operation (`dropdb`, `DROP TABLE/DATABASE/SCHEMA`, `TRUNCATE TABLE`, or unconditional `DELETE FROM`) requires explicit human confirmation (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            r"\b(?:docker|podman)\s+(?:system|volume|builder|image|container)\s+prune\b[^\n;|&]*(?:\s--all\b|\s--volumes\b|\s-(?!-)[a-zA-Z]*a[a-zA-Z]*\b)",
            any_tokens=("prune",),
        ),
        "Pruning all container/volume/builder caches (`docker/podman ... prune -a/--all/--volumes`) requires explicit human confirmation (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(
            r"\bchmod\b[^\n;|&]*(?:\s--recursive\b|\s-(?!-)[a-zA-Z]*R[a-zA-Z]*\b)[^\n;|&]*\b(?:0?777|a\+rwx)\b",
            any_tokens=("chmod",),
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
            any_tokens=("curl", "wget"),
        ),
        "Executing remote scripts directly via a shell or language interpreter is forbidden by supply-chain policy (GEMINI.md Rule 12).",
    ),
    (
        _LazyRegex(r"\b(?:npx|bunx|pnpm\s+dlx|uvx)\b[^\n;|&]*@latest\b", any_tokens=("@latest",)),
        "Executing unpinned `@latest` packages (`npx/bunx/uvx @latest`) violates supply-chain pinning rules (GEMINI.md Rule 12).",
    ),
)

_RM_OR_MV_SEGMENT_RE = _LazyRegex(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?(?P<verb>rm|mv)\b(?P<rest>[^\n;|&`]*)",
    any_tokens=("rm", "mv"),
)


def _detect_out_of_workspace_rm_or_mv(
    cmd: str,
    workspaces: Sequence[Path],
    effective_cwd: Optional[Path],
    artifact_dir: Optional[Path] = None,
) -> Optional[str]:
    """Detects recursive `rm` (`-r`/`-rf`/`--recursive`) or `mv` targeting paths outside active workspaces, `/tmp`, or active conversation `artifactDirectoryPath` (`mv` only)."""
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

    allowed_resolved_roots: List[Path] = []
    for r in allowed_roots:
        allowed_resolved_roots.append(r)
        try:
            rr = r.resolve()
            if rr not in allowed_resolved_roots:
                allowed_resolved_roots.append(rr)
        except (OSError, RuntimeError):
            pass

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
            unresolved_tilde = False
            if norm_arg == "~" or norm_arg.startswith(("~/", "~\\")):
                norm_arg = home_str + norm_arg[1:]
            elif norm_arg.startswith("~"):
                expanded_u = os.path.expanduser(norm_arg)
                if expanded_u.startswith("~"):
                    unresolved_tilde = True
                else:
                    norm_arg = expanded_u
            if norm_arg.startswith("$") or (norm_arg.startswith("%") and norm_arg.endswith("%")):
                continue
            if norm_arg in ("/dev/null", "NUL", "nul"):
                continue
            if unresolved_tilde:
                within_allowed = False
            else:
                norm_slashes = norm_arg.replace("\\", "/")
                is_win_drive = bool(re.match(r"^[A-Za-z]:/", norm_slashes))
                is_abs_like = norm_slashes.startswith("/") or is_win_drive or Path(norm_arg).is_absolute()
                if is_win_drive and os.name != "nt":
                    within_allowed = False
                else:
                    cand_raw = Path(norm_slashes) if is_abs_like else (base_dir / norm_slashes)
                    cand_abs = Path(os.path.abspath(cand_raw))
                    try:
                        cand_res = cand_abs.resolve()
                    except (OSError, RuntimeError):
                        cand_res = cand_abs
                    if not is_abs_like and ".." not in norm_slashes.split("/"):
                        within_allowed = any(is_within(cand_res, root) for root in allowed_resolved_roots)
                    else:
                        within_allowed = any(is_within(cand_abs, root) for root in allowed_roots) and any(
                            is_within(cand_res, root) for root in allowed_resolved_roots
                        )
                    if not within_allowed and verb == "mv" and artifact_dir is not None:
                        within_allowed = _ptu._is_path_strictly_within_dir(norm_arg, artifact_dir, base_dir=base_dir)
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
    any_tokens=("npx", "bunx", "pnpm", "uvx", "pipx"),
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

_SIMPLE_VAR_ASSIGN_RE = _LazyRegex(
    r"(?:^|[;&|()\n\s])([A-Za-z_][A-Za-z0-9_]*)=(?:'([^']*)'|\"([^\"\\]*)\"|([^\s;|&'\"()]+))",
    any_tokens=("=",),
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

def _normalize_governance_globs(
    cmd: str,
    *,
    return_variants: bool = False,
    admin_variants: bool = False,
) -> Any:
    """
    Canonicalizes wildcard-obfuscated governance path prefixes, Guard/Porter launchers, and root installer globs.
    Returns `str` by default; `return_variants=True` returns all multi-match glob candidates;
    `admin_variants=True` returns `[masked, *expanded_glob_variants]` for Rule 12 checks.
    """
    if admin_variants:
        masked = _mask_quoted_operators(cmd)
        out_variants: List[str] = [masked]
        expanded = _normalize_shell_paths(_unquote_single_tokens(_expand_simple_shell_vars(masked)))
        for v in _normalize_governance_globs(expanded, return_variants=True):
            if v not in out_variants:
                out_variants.append(v)
        return out_variants

    out = re.sub(r"(?:~|\$HOME|\$\{HOME\})/\.gem[^\s;|&'\"/]*/conf[^\s;|&'\"/]*", "~/.gemini/config", cmd)
    out = re.sub(
        r"(?:~|\$HOME|\$\{HOME\})/\.gem[^\s;|&'\"/]*/(GEMINI|AGENTS)\.md\b",
        r"~/.gemini/\1.md",
        out,
        flags=re.IGNORECASE,
    )
    out = re.sub(
        r"(?:~|\$HOME|\$\{HOME\})/\.local/(state|share)/plumb[^\s;|&'\"/]*",
        r"~/.local/\1/plumbwork",
        out,
    )
    out = re.sub(r"(?:~|\$HOME|\$\{HOME\})/\.local/bin/plumb-p[^\s;|&'\"/]*", "~/.local/bin/plumb-porter", out)
    out = re.sub(r"(?:~|\$HOME|\$\{HOME\})/\.local/bin/plumb-g[^\s;|&'\"/]*", "~/.local/bin/plumb-guard", out)
    out = re.sub(r"(?:~|\$HOME|\$\{HOME\})/\.local/bin/por\?ter|(?:~|\$HOME|\$\{HOME\})/\.local/bin/por\*[^\s;|&'\"/]*", "~/.local/bin/porter", out)
    out = re.sub(r"/usr/bin/plumb-p[^\s;|&'\"/]*", "/usr/bin/plumb-porter", out)
    out = re.sub(r"/usr/bin/plumb-g[^\s;|&'\"/]*", "/usr/bin/plumb-guard", out)
    out = re.sub(r"/usr/share/plumb[^\s;|&'\"/]*", "/usr/share/plumbwork", out)
    out = re.sub(r"/usr/lib/plumb[^\s;|&'\"/]*", "/usr/lib/plumb-guard", out)

    if not any(ch in out for ch in "*?["):
        return [out] if return_variants else out

    import fnmatch

    match_fn = fnmatch.fnmatch if os.name == "nt" else fnmatch.fnmatchcase
    home_str = Path.home().as_posix().rstrip("/")
    raw_targets: List[str] = [
        "~/.gemini/config",
        "~/.gemini/GEMINI.md",
        "~/.gemini/AGENTS.md",
        "~/.local/state/plumbwork",
        "~/.local/share/plumbwork",
        "~/.local/bin/plumb-guard",
        "~/.local/bin/plumb-porter",
        "~/.local/bin/porter",
        "/usr/bin/plumb-guard",
        "/usr/bin/plumb-porter",
        "/usr/lib/plumb-guard",
        "install.py",
        "./install.py",
    ]
    if home_str:
        raw_targets.extend([
            f"{home_str}/.gemini/config",
            f"{home_str}/.gemini/GEMINI.md",
            f"{home_str}/.gemini/AGENTS.md",
            f"{home_str}/.local/state/plumbwork",
            f"{home_str}/.local/share/plumbwork",
            f"{home_str}/.local/bin/plumb-guard",
            f"{home_str}/.local/bin/plumb-porter",
            f"{home_str}/.local/bin/porter",
        ])
    for dyn in (
        *_ptu._config_root_candidates(),
        *_ptu._state_root_candidates(),
        data_dir(),
        *share_dir_candidates(),
        windows_launcher_dir(),
        *_ptu._custom_enforced_governance_roots(),
    ):
        s_posix = Path(dyn).as_posix().rstrip("/")
        if s_posix:
            raw_targets.append(s_posix)
    concrete_targets = list(dict.fromkeys(raw_targets))

    _prefix_re = re.compile(r"^((?:[0-9&]?>>?\|?|<)|[A-Za-z_][A-Za-z0-9_]*=)(.+)$")
    alt_variants: List[str] = []

    def _match_token_candidates(tok: str) -> List[str]:
        if not any(ch in tok for ch in "*?["):
            return [tok]
        prefix = ""
        body = tok
        pm = _prefix_re.match(body)
        if pm:
            prefix, body = pm.group(1), pm.group(2)
            if not any(ch in body for ch in "*?["):
                return [tok]
        norm_tok = re.sub(r"^(?:\$\{HOME\}|\$HOME)(?=[/\\]|$)", "~", body).replace("\\", "/")
        parts = norm_tok.split("/")
        matches: List[str] = []
        for cand in concrete_targets:
            c_parts = cand.split("/")
            if len(parts) < len(c_parts):
                continue
            if all(match_fn(cp, tp) for cp, tp in zip(c_parts, parts[: len(c_parts)])):
                tail = parts[len(c_parts) :]
                rewritten = prefix + cand + ("/" + "/".join(tail) if tail else "")
                if rewritten not in matches:
                    matches.append(rewritten)
        return matches or [tok]

    token_matches: List[Tuple[int, int, List[str]]] = []
    for m in re.finditer(r"[^\s;|&'\"()]+", out):
        cands = _match_token_candidates(m.group(0))
        if cands[0] != m.group(0) or len(cands) > 1:
            token_matches.append((m.start(), m.end(), cands))

    if not token_matches:
        return [out] if return_variants else out

    def _apply_choice(choice_fn: Callable[[int, List[str]], str]) -> str:
        pieces: List[str] = []
        cursor = 0
        for idx, (s_pos, e_pos, cands) in enumerate(token_matches):
            pieces.append(out[cursor:s_pos])
            pieces.append(choice_fn(idx, cands))
            cursor = e_pos
        pieces.append(out[cursor:])
        return "".join(pieces)

    primary = _apply_choice(lambda _i, cands: cands[0])
    if not return_variants:
        return primary
    alt_variants.append(primary)
    for idx, (_s, _e, cands) in enumerate(token_matches):
        if len(cands) <= 1:
            continue
        for alt in cands[1:4]:
            v = _apply_choice(lambda j, cs, target_idx=idx, target_val=alt: target_val if j == target_idx else cs[0])
            if v not in alt_variants:
                alt_variants.append(v)
            if len(alt_variants) >= 6:
                break
        if len(alt_variants) >= 6:
            break
    return alt_variants

_SHELL_MUTATION_INDICATOR_RE = _LazyRegex(
    r"(?:"
    r">{1,2}\|?|"
    r"\b(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip)\b|"
    rf"\bgit{_GIT_GLOBAL_OPTS}\s+clone\b|"
    r"\bfind\b[^\n;|&]*\s-(?:delete|exec|execdir|ok)\b|"
    r"\bsed\b[^\n;|&]*\s-(?:[A-Za-z]*i\S*|-in-place(?:=\S*)?)\b|"
    r"\b(?:curl|wget)\b[^\n;|&]*\s-(?:o|O)\b|"
    r"\b(?:python3?(?:\.\d+)?|py|node|nodejs|deno|bun|ruby|perl|php|lua)\b[^\n;|&]*(?:\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*|m\s+(?!(?:unittest|pytest|py_compile|mypy|ruff|flake8|doctest|cprofile|profile|ast|tokenize|dis)\b)\S+)\b|<<)|"
    r"\|\s*(?:[A-Za-z0-9_.=/-]+\s+)*(?:python3?(?:\.\d+)?|py|node|nodejs|deno|bun|ruby|perl|php|lua)\b"
    r")"
)

_BENIGN_FD_NULL_AT_SEP_RE = _LazyRegex(
    r"(?:[012]?>{1,2}\|?\s*(?:/dev/null|'/dev/null'|\"/dev/null\")"
    r"|&>{1,2}\s*(?:/dev/null|'/dev/null'|\"/dev/null\")"
    r"|[012]?>&\s*[012-]"
    r"|[012]?<&\s*[012-])"
    r"(?=$|[\s;&|()<>])"
)

_BENIGN_FD_NULL_AT_BARE_RE = _LazyRegex(
    r"(?:>{1,2}\|?\s*(?:/dev/null|'/dev/null'|\"/dev/null\")"
    r"|&>{1,2}\s*(?:/dev/null|'/dev/null'|\"/dev/null\")"
    r"|>&\s*[012-]"
    r"|<&\s*[012-])"
    r"(?=$|[\s;&|()<>])"
)

def _strip_benign_fd_null_redirections(text: str) -> str:
    """
    Removes unquoted harmless FD/null-sink redirections (`2>/dev/null`, `>/dev/null`, `1>/dev/null`,
    `&>/dev/null`, `2>&1`, `1>&2`, `>&2`, `<&0`) outside quotes while preserving real file
    redirections (`> file`, `>> file`, `2> file`, `>| file`) and quoted strings intact.
    """
    if not text or (">" not in text and "<" not in text):
        return text
    out: List[str] = []
    n = len(text)
    i = 0
    mode = ""
    while i < n:
        ch = text[i]
        if not mode:
            if ch == "\\" and i + 1 < n:
                out.append(text[i : i + 2])
                i += 2
                continue
            if ch in ("0", "1", "2", ">", "<", "&"):
                prev = text[i - 1] if i > 0 else ""
                m = None
                if i == 0 or prev in " \t\n\r;&|()":
                    m = _BENIGN_FD_NULL_AT_SEP_RE.match(text, i)
                elif ch in (">", "<", "&") and prev not in "><0123456789&":
                    m = _BENIGN_FD_NULL_AT_BARE_RE.match(text, i)
                if m is not None:
                    out.append(" ")
                    i = m.end()
                    continue
            if ch == "$" and i + 1 < n and text[i + 1] == "'":
                mode = "$'"
                out.append("$'")
                i += 2
                continue
            if ch in ("'", '"'):
                mode = ch
            out.append(ch)
            i += 1
        elif mode == "$'":
            if ch == "\\" and i + 1 < n:
                out.append(text[i : i + 2])
                i += 2
                continue
            out.append(ch)
            if ch == "'":
                mode = ""
            i += 1
        elif mode == "'":
            out.append(ch)
            if ch == "'":
                mode = ""
            i += 1
        else:
            if ch == "\\" and i + 1 < n:
                out.append(text[i : i + 2])
                i += 2
                continue
            out.append(ch)
            if ch == '"':
                mode = ""
            i += 1
    return "".join(out)

_SHELL_DOTDOT_TOKEN_RE = _LazyRegex(r"(?:^|[\s/'\"=])\.\.(?:$|[\s/'\";&|()])", any_tokens=("..",))

@functools.lru_cache(maxsize=256)
def _compiled_cfg_subdir_patterns(root: str) -> Tuple[Tuple[re.Pattern[str], str], ...]:
    sep = r"(?:[/\\]|\\\\)+"
    seg_end = r"(?=[/\\]|\\\\|[\s;|&'\"(),]|$)"
    gov_segs = "|".join(re.escape(seg) for seg in sorted(_ptu._PLUGIN_GOVERNANCE_SEGMENTS, key=len, reverse=True))
    exec_sfxs = "|".join(
        re.escape(sfx.lstrip(".")) for sfx in sorted(_ptu._PLUGIN_EXEC_SUFFIXES, key=len, reverse=True)
    )
    plugin_gov_tail = rf"(?:{sep}(?:{gov_segs}){seg_end}|\.(?:{exec_sfxs}){seg_end})"
    harness_packs = "|".join(re.escape(pack) for pack in sorted(_HARNESS_PLUGIN_NAMES, key=len, reverse=True))
    esc_root = re.escape(root)
    pats: List[Tuple[re.Pattern[str], str]] = []
    for sub in _ptu._RUNTIME_CONFIG_SUBDIRS:
        if sub == "plugins":
            pats.append(
                (
                    re.compile(
                        rf"(['\"]){esc_root}{sep}plugins(?![^'\"\n]*{plugin_gov_tail}){sep}"
                        rf"(?!(?:{harness_packs})[. ]*(?=[/\\]|\\\\|['\"\n]|$))"
                        rf"[^./\\'\"\n*?\[\]{{}}$`!@+()<>][^/\\'\"\n*?\[\]{{}}$`!@+()<>]*"
                        rf"(?:(?=[/\\]|\\\\)[^'\"\n`$]*|(?=\1))\1",
                        re.IGNORECASE,
                    ),
                    r"\1__RUNTIME_SUBDIR__\1",
                )
            )
            pats.append(
                (
                    re.compile(
                        rf"(?<!['\"]){esc_root}{sep}plugins(?![^\s;|&'\"]*{plugin_gov_tail}){sep}"
                        rf"(?!(?:{harness_packs})[. ]*(?=[/\\]|\\\\|[\s;|&'\"),]|$))"
                        rf"[^./\\\s;|&'\"(),*?\[\]{{}}$`!@+<>][^/\\\s;|&'\"(),*?\[\]{{}}$`!@+<>]*"
                        rf"(?:(?=[/\\]|\\\\)[^\s;|&'\"`$]*|(?=[\s;|&'\"),]|$))",
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
                if cand and _ptu._targets_governance_dir(cand, base_dir=base_dir):
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
    """Returns True if `seg` contains unquoted `>`, `<(`, `>(`, `$(`, backticks, or `$'...'` ANSI-C quotes (ignoring benign FD/null redirections)."""
    seg = _strip_benign_fd_null_redirections(seg)
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
    seg = _strip_benign_fd_null_redirections(seg)

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
    any_tokens=("node", "deno", "bun", "ruby", "perl", "php", "lua", "py"),
)

_ANY_PYTHON_INLINE_OR_HEREDOC_RE = _LazyRegex(
    r"\bpython3?(?:\.\d+)?\b[^\n;|&]*(?:\s-(?:[A-Za-z0-9]*[cmi])\b|<<)",
    re.IGNORECASE,
    any_tokens=("python",),
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
            rf"(?:\b(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip)\b|\bgit{_GIT_GLOBAL_OPTS}\s+clone\b)(?:[^\n;|&]*|\s*\$\([\s\S]*?){escaped}"
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
    unquoted_expanded = _normalize_shell_paths(_unquote_single_tokens(_expand_simple_shell_vars(ro_scrubbed_cmd)))
    glob_rewritten = _normalize_governance_globs(unquoted_expanded)
    had_glob_rewrite = glob_rewritten != unquoted_expanded
    norm_cmd = _normalize_shell_paths(glob_rewritten)
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
            st_variants = "|".join(re.escape(s) for s in _path_spellings(_ptu.state_dir()))
            inline_cmd = re.sub(
                r"(?:['\"]\.local['\"]\s*/\s*['\"]state['\"]\s*/\s*['\"]plumb(?:work|-guard)['\"]\s*/\s*['\"]staging['\"]|"
                rf"(?:{st_variants})(?:[/\\]|\\\\)+staging(?=[/\\]|['\"\s,)])|"
                r"(?:~|\$HOME|[^\s'\"]+)(?:[/\\]|\\\\)+\.local(?:[/\\]|\\\\)+state(?:[/\\]|\\\\)+plumb(?:work|-guard)(?:[/\\]|\\\\)+staging(?=[/\\]|['\"\s,)]))",
                "__RUNTIME_STAGING__",
                inline_cmd,
            )
        if re.search(
            r"(?:['\"]\.gemini['\"]\s*(?:/|,)\s*['\"](?:config|GEMINI\.md|AGENTS\.md)['\"]|"
            r"\.gemini(?:[/\\]|\\\\)+(?:config|GEMINI\.md|AGENTS\.md)|"
            r"(?:\.local(?:[/\\]|\\\\)+(?:state|share)|/usr/(?:bin|lib|share))(?:[/\\]|\\\\)+plumb(?:work|-guard|-porter)|"
            r"Programs(?:[/\\]|\\\\)+plumb-guard|"
            r"['\"](?:state|share|lib|bin|Programs)['\"]\s*(?:/|,)\s*['\"]plumb(?:work|-guard|-porter)['\"]|"
            r"['\"]\.local['\"]\s*(?:/|,)\s*['\"]bin['\"]\s*(?:/|,)\s*['\"]plumb-|"
            r"\.local(?:[/\\]|\\\\)+bin(?:[/\\]|\\\\)+plumb-|"
            r"\b(?:ANTIGRAVITY_CONFIG_DIR|PLUMB_GUARD_STATE_DIR|ANTIGRAVITY_STATE_DIR|PLUMB_GUARD_DATA_DIR|PLUMBWORK_SHARE_DIR)\b)",
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
                *(sp for p in _ptu._config_root_candidates() for sp in _path_spellings(p)),
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
    for cfg_cand in _ptu._config_root_candidates():
        if cfg_cand.name == "config" and cfg_cand.parent.name == ".gemini":
            gemini_top_files.extend(_path_spellings(cfg_cand.parent / "GEMINI.md"))
            gemini_top_files.extend(_path_spellings(cfg_cand.parent / "AGENTS.md"))
    state_roots = list(
        dict.fromkeys(
            [
                *(sp for p in _ptu._state_root_candidates() for sp in _path_spellings(p)),
                "~/.local/state/plumbwork",
                "$HOME/.local/state/plumbwork",
                "~/.local/state/plumb-guard",
                "$HOME/.local/state/plumb-guard",
            ]
        )
    )
    custom_root_tokens: List[str] = []
    for c_root in _ptu._custom_enforced_governance_roots():
        custom_root_tokens.extend(_path_spellings(c_root))
        try:
            rel_home = c_root.relative_to(home).as_posix()
            if rel_home and rel_home != ".":
                custom_root_tokens.append(f"~/{rel_home}")
                custom_root_tokens.append(f"$HOME/{rel_home}")
        except ValueError:
            pass
    share_tokens = [sp for sh in share_dir_candidates() for sp in _path_spellings(sh)]
    guard_roots = list(
        dict.fromkeys(
            state_roots
            + gemini_top_files
            + [
                *_path_spellings(data_dir()),
                *_path_spellings(data_dir() / "runtime"),
                *_path_spellings(data_dir() / "snapshots"),
                "~/.local/share/plumbwork",
                "$HOME/.local/share/plumbwork",
                "~/.local/share/plumb-guard",
                "$HOME/.local/share/plumb-guard",
                *_path_spellings(home / ".local" / "bin" / "plumb-guard"),
                *_path_spellings(home / ".local" / "bin" / "plumb-porter"),
                "~/.local/bin/plumb-guard",
                "$HOME/.local/bin/plumb-guard",
                "~/.local/bin/plumb-porter",
                "$HOME/.local/bin/plumb-porter",
                "/usr/bin/plumb-guard",
                "/usr/bin/plumb-porter",
                "/usr/lib/plumb-guard",
                *share_tokens,
                *(
                    [
                        *_path_spellings(home / ".local" / "bin" / "porter"),
                        "~/.local/bin/porter",
                        "$HOME/.local/bin/porter",
                    ]
                    if (home / ".local" / "bin" / "porter") in _ptu._governance_roots()
                    else []
                ),
                *(
                    _path_spellings(windows_launcher_dir())
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
    # ONLY when no `..`/`.parent` traversal, link creation (`ln`), archive extraction (`tar`/`unzip`),
    # or wildcard-obfuscated `plugins/` path rewrite is present.
    scrubbed = norm_cmd
    skip_plugin_scrub = had_glob_rewrite and "/plugins/" in norm_cmd
    if not has_parent_escape and not skip_plugin_scrub and not re.search(r"\b(?:ln|tar|unzip)\b", scrubbed):
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
                has_mut_ind = bool(_SHELL_MUTATION_INDICATOR_RE.search(_strip_benign_fd_null_redirections(scrubbed)))
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

def _command_mutates_customization_structure(cmd: str, *, harness_scope: bool = True) -> bool:
    """Detects shell commands that write, overwrite, move, delete, or regenerate customization/governance files."""
    if not harness_scope:
        return False
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
    norm_cmd = _normalize_governance_globs(_normalize_shell_paths(_unquote_single_tokens(_expand_simple_shell_vars(ro_cmd))))
    masked_cmd = _mask_quoted_operators(norm_cmd)
    has_subshell_c = bool(re.search(r"\b(?:ba|z|da|k)?sh\s+-(?:[A-Za-z]*c)\b", norm_cmd))
    verb_haystack = norm_cmd if has_subshell_c else masked_cmd
    target_pat = _ptu._CUST_CMD_TARGET_PAT if harness_scope else _ptu._CUST_CMD_UNIVERSAL_TARGET_PAT
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
    ) and _SHELL_MUTATION_INDICATOR_RE.search(_strip_benign_fd_null_redirections(norm_cmd)):
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
    if any(
        re.search(
            rf"(?:\b(?:plumb-porter|porter(?:\.py)?)|(?:python3?(?:\.\d+)?|py)(?:\.exe)?\s+{_PY_INTERP_OPTS}-[A-Za-z0-9]*m\s+porter){_SUBPARSER_OPTS}\s+manifest\b(?![^\n;|&]*--check)",
            cand_v,
        )
        for cand_v in _normalize_governance_globs(norm_cmd, return_variants=True)
    ):
        return True
    return False

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
            if trimmed in ("", "."):
                parent_out = ".."
            elif trimmed == ".." or trimmed.endswith(("/..", "\\..")):
                parent_out = f"{trimmed}/.."
            else:
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
        if isinstance(node.func, ast.Name) and node.func.id == "getcwd" and not node.args:
            return "."
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
            if node.func.attr in ("cwd", "getcwd") and not node.args:
                return "."
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
                    "PLUMB_GUARD_STATE_DIR",
                    "ANTIGRAVITY_STATE_DIR",
                    "PLUMB_GUARD_DATA_DIR",
                    "PLUMBWORK_SHARE_DIR",
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
    buf_file = _ptu.state_dir() / "cmd_input_buffers.json"
    buf_ok, data = _read_ledger_checked(buf_file)
    if not buf_ok or not isinstance(data, dict):
        return buf_key, ""
    val = data.get(buf_key)
    return buf_key, (val if isinstance(val, str) else "")

def _save_cmd_input_prefix(buf_key: str, combined_input: str) -> None:
    trailing = _compute_trailing_cmd_buffer(combined_input)
    buf_file = _ptu.state_dir() / "cmd_input_buffers.json"
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
    raw_no_comments = _strip_unquoted_shell_comments(_expand_simple_shell_vars(sub_cmd))
    expanded = _unquote_single_tokens(raw_no_comments)
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
    for win_rel in re.findall(r"(?:^|(?<=[\s;|&()<>]))(\.\.?\\[^\s;|&()<>'\"`]+)", raw_no_comments):
        norm_rel = win_rel.replace("\\", "/")
        if win_rel not in out:
            out.append(win_rel)
        if norm_rel not in out:
            out.append(norm_rel)
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
    scrubbed = _QUOTED_SPAN_RE.sub('"__QUOTED__"', _strip_benign_fd_null_redirections(expanded))
    if "$'" in scrubbed:
        return True
    if not _SHELL_MUTATION_INDICATOR_RE.search(scrubbed):
        return False
    if "python" in sub_cmd.lower():
        ro_scrubbed, _unverified, _mut_srcs = _scrub_verified_readonly_python_invocations(sub_cmd)
        if ro_scrubbed != sub_cmd:
            exp_ro = _unquote_single_tokens(_strip_unquoted_shell_comments(ro_scrubbed))
            scrubbed_ro = _QUOTED_SPAN_RE.sub('"__QUOTED__"', _strip_benign_fd_null_redirections(exp_ro))
            if "$'" in scrubbed_ro:
                return True
            return bool(_SHELL_MUTATION_INDICATOR_RE.search(scrubbed_ro))
    return True

_CD_SEG_RE = _LazyRegex(
    r"^\s*\(*\s*(?:builtin\s+|command\s+)?(?P<verb>cd|pushd|popd)(?:\s+(?P<rest>.*))?$",
    any_tokens=("cd", "pushd", "popd"),
)

_INLINE_DIR_FLAG_RE = _LazyRegex(
    r"(?:^|\s)(?:-C\s+(?P<c_arg>'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+)|--(?:directory|chdir)(?:=(?P<eq_arg>'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+)|\s+(?P<sp_arg>'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+)))",
    any_tokens=("-C", "--directory", "--chdir"),
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
            if _ptu._targets_governance_dir(tok, base_dir=seg_cwd):
                return True
        if seg_cwd is not None and _ptu._targets_governance_dir(str(seg_cwd)):
            rel_tokens = [t for t in tokens if not Path(os.path.expanduser(t)).is_absolute()]
            if not tokens or any(_ptu._targets_governance_dir(t, base_dir=seg_cwd) for t in rel_tokens):
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
        t_ws = _ptu._workspace_for_target(res_c, workspaces, fallback=(fallback_ws or base_dir))
        return _ptu._targets_customization_structure(res_c, workspace=t_ws)

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
            _ptu._workspace_for_target(str(base_cwd), workspaces, fallback=(fallback_ws or base_cwd))
            if base_cwd is not None
            else None
        )
        tokens = list(_extract_shell_path_tokens(seg))
        if is_interp:
            tokens.extend(re.findall(r"['\"]([^'\"]*[/\\][^'\"]+)['\"]", seg))
        for tok in tokens:
            if _matches_cust_target(tok, base_cwd):
                return True
        if not is_interp and base_cwd is not None and _ptu._targets_customization_structure(str(base_cwd), workspace=ws_root):
            if not tokens or any(not Path(os.path.expanduser(t)).is_absolute() for t in tokens):
                return True

    if saw_unv_c:
        in_h_scope = _ptu._workspaces_in_harness_scope(workspaces, effective_cwd)

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
    any_tokens=("py", "sh", "node", "ruby", "perl", "source", "."),
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

def _extract_code_map_trace_target(rem_tokens: Sequence[str], *, all_targets: bool = False) -> Any:
    if not rem_tokens:
        return [] if all_targets else None
    sub_idx = 0
    while sub_idx < len(rem_tokens) and rem_tokens[sub_idx].startswith("-"):
        sub_idx += 1
    if sub_idx >= len(rem_tokens) or rem_tokens[sub_idx] != "trace":
        return [] if all_targets else None
    targets: List[str] = []
    j = sub_idx + 1
    skip_val_flags = {"--timeout", "--max-events", "--limit", "--format", "-o", "--output", "--root"}
    after_dd = False
    while j < len(rem_tokens):
        t = rem_tokens[j]
        if not after_dd and t == "--":
            after_dd = True
            j += 1
            continue
        if not after_dd and t in skip_val_flags and j + 1 < len(rem_tokens):
            j += 2
            continue
        if not after_dd and t.startswith("-"):
            j += 1
            continue
        if t and t not in targets:
            targets.append(t)
        j += 1
    if all_targets:
        return targets
    return targets[0] if targets else None

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
        _ptu.config_dir() / "skills",
        _ptu.configured_config_dir() / "skills",
        *(
            cfg_base / "plugins" / pack / "skills"
            for cfg_base in (_ptu.config_dir(), _ptu.configured_config_dir())
            for pack in sorted(_HARNESS_PLUGIN_NAMES)
        ),
        data_dir() / "runtime" / "scripts",
        data_dir() / "runtime" / "skills",
        *(sh_dir / "skills" for sh_dir in share_dir_candidates()),
        Path("/usr/lib/plumb-guard/scripts"),
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

    def _extract_guard_code_map_targets(rem_tokens: Sequence[str]) -> List[str]:
        for k, tk in enumerate(rem_tokens):
            if tk == "code-map":
                return _extract_code_map_trace_target(rem_tokens[k + 1 :], all_targets=True)
        return []

    bin_res = getattr(_inspect_external_script_command, "_bin_res", None)
    if bin_res is None:
        bin_res = (
            _LazyRegex(
                rf"^\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`'\"()]*[/\\])?(?:plumb-guard(?:\.(?:exe|cmd|bat|ps1))?|guard\.py|guard[/\\]cli\.py)\s+(?P<rest>.+)$",
                re.IGNORECASE,
                any_tokens=("guard",),
            ),
            _LazyRegex(
                rf"^\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`'\"()]*[/\\])?code_map\.py\s+(?P<rest>.+)$",
                re.IGNORECASE,
                any_tokens=("code_map.py",),
            ),
        )
        setattr(_inspect_external_script_command, "_bin_res", bin_res)
    _guard_bin_re, _codemap_bin_re = bin_res

    for seg in segments:
        m = _INTERP_SCRIPT_SEG_RE.match(seg)
        candidate_script_args: List[str] = []
        skip_seg = False
        if not m:
            gm = _guard_bin_re.match(seg)
            if gm:
                g_tokens = [t.strip("'\"") for t in re.findall(r"'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+", gm.group("rest"))]
                cm_targets = _extract_guard_code_map_targets(g_tokens)
                if not cm_targets:
                    continue
                candidate_script_args.extend(cm_targets)
            else:
                cm_m = _codemap_bin_re.match(seg)
                if not cm_m:
                    continue
                cm_tokens = [t.strip("'\"") for t in re.findall(r"'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+", cm_m.group("rest"))]
                cm_targets = _extract_code_map_trace_target(cm_tokens, all_targets=True)
                if not cm_targets:
                    continue
                candidate_script_args.extend(cm_targets)
        else:
            interp_base = Path(m.group("interp")).name.lower()
            is_py_interp = interp_base == "py" or interp_base.startswith("python")
            tokens = [t.strip("'\"") for t in re.findall(r"'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+", m.group("rest"))]
            idx = 0
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
                                candidate_script_args.extend(
                                    _extract_code_map_trace_target(tokens[idx + 2 :], all_targets=True)
                                )
                            elif mod_lower in ("guard", "guard.cli"):
                                candidate_script_args.extend(_extract_guard_code_map_targets(tokens[idx + 2 :]))
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
                    candidate_script_args.extend(
                        _extract_code_map_trace_target(tokens[idx + 1 :], all_targets=True)
                    )
                elif Path(tok).name in ("guard.py", "cli.py"):
                    candidate_script_args.extend(_extract_guard_code_map_targets(tokens[idx + 1 :]))
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
                    if in_gate_set and _ptu._targets_customization_structure(str(check_target), workspace=h_root):
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
                            plug_script_hit = _detect_harness_plugin_cli_mutation(non_comment)
                            if plug_script_hit is None:
                                for sc in synth_list_cmds:
                                    plug_script_hit = _detect_harness_plugin_cli_mutation(sc)
                                    if plug_script_hit is not None:
                                        break
                            if plug_script_hit is not None:
                                plug_verb, plug_pack = plug_script_hit
                                is_h_pack = plug_pack in _HARNESS_PLUGIN_NAMES or plug_pack == "harness-plugin"
                                target_desc = (
                                    f"harness-managed plugin pack `{plug_pack}`" if is_h_pack else f"plugin `{plug_pack}`"
                                )
                                return {
                                    "decision": "force_ask",
                                    "reason": _ptu._format_force_ask_reason(
                                        f"[Harness Plugin Gate] Script `{script_arg}` invokes official CLI command "
                                        f"`agy plugin {plug_verb}` targeting {target_desc} (GEMINI.md Rule 12).",
                                        what_changes=(
                                            f"Executes `{script_arg}` running `agy plugin {plug_verb}` on `{plug_pack}`"
                                        ),
                                        if_approved=(
                                            f"Permits `{script_arg}` to modify or install `{plug_pack}` plugin state"
                                        ),
                                        if_denied=(
                                            f"Cancels `{script_arg}` and leaves `{plug_pack}` unchanged"
                                        ),
                                    ),
                                }
                            drop_script_hit = _detect_plugin_directory_drop(non_comment, effective_cwd)
                            if drop_script_hit is None:
                                for sc in synth_list_cmds:
                                    drop_script_hit = _detect_plugin_directory_drop(sc, effective_cwd)
                                    if drop_script_hit is not None:
                                        break
                            if drop_script_hit is not None:
                                drop_op, drop_pack = drop_script_hit
                                return {
                                    "decision": "force_ask",
                                    "reason": _ptu._format_force_ask_reason(
                                        f"[Harness Plugin Gate] Script `{script_arg}` runs `{drop_op}` into "
                                        f"`~/.gemini/config/plugins/{drop_pack}` (GEMINI.md Rule 12).",
                                        what_changes=(
                                            f"Executes `{script_arg}` dropping plugin files into `plugins/{drop_pack}` via `{drop_op}`"
                                        ),
                                        if_approved=(
                                            f"Permits `{script_arg}` to write or extract plugin directory `plugins/{drop_pack}`"
                                        ),
                                        if_denied=(
                                            f"Cancels `{script_arg}` and leaves `plugins/{drop_pack}` unchanged"
                                        ),
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


_WRAPPER_VAL_FLAGS: Dict[str, frozenset[str]] = {
    "env": frozenset({"-u", "--unset", "-C", "--chdir"}),
    "exec": frozenset({"-a"}),
    "sudo": frozenset({"-u", "-U", "-g", "-C", "-p", "--user", "--group", "--chdir", "--other-user"}),
    "doas": frozenset({"-u", "-C"}),
    "stdbuf": frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}),
    "timeout": frozenset({"-k", "-s", "--signal", "--kill-after"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "-n", "-p", "-t"}),
    "taskset": frozenset({"-c", "--cpu-list"}),
    "xargs": frozenset({
        "-I", "-i", "-n", "-L", "-l", "-P", "-d", "-E", "-e", "-s", "-a",
        "--arg-file", "--delimiter", "--eof", "--max-args", "--max-lines", "--max-procs", "--replace",
    }),
}


def _unwrap_shell_command_tokens(seg_tokens: Sequence[str]) -> Tuple[Optional[int], bool, List[str]]:
    """Strips leading env assignments and command wrappers; returns `(cmd_idx, via_xargs, expanded_tokens)`."""
    import shlex

    idx = 0
    toks = list(seg_tokens)
    in_wrapper: Optional[str] = None
    via_xargs = False
    skip_next = False
    while idx < len(toks):
        tok = toks[idx]
        if skip_next:
            skip_next = False
            idx += 1
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tok, re.DOTALL):
            idx += 1
            continue
        if in_wrapper is not None:
            if tok == "--":
                in_wrapper = None
                idx += 1
                continue
            if in_wrapper == "env" and tok in ("-S", "--split-string") and idx + 1 < len(toks):
                try:
                    spliced = shlex.split(toks[idx + 1])
                except ValueError:
                    spliced = toks[idx + 1].split()
                toks[idx : idx + 2] = spliced
                in_wrapper = None
                continue
            if in_wrapper == "env" and (tok.startswith("--split-string=") or (tok.startswith("-S") and len(tok) > 2)):
                raw_s = tok.split("=", 1)[1] if tok.startswith("--split-string=") else tok[2:]
                try:
                    spliced = shlex.split(raw_s)
                except ValueError:
                    spliced = raw_s.split()
                toks[idx : idx + 1] = spliced
                in_wrapper = None
                continue
            if in_wrapper == "command" and re.fullmatch(r"-[A-Za-z]*[vV][A-Za-z]*", tok):
                return None, via_xargs, toks
            if tok.startswith("-"):
                if tok in _WRAPPER_VAL_FLAGS.get(in_wrapper, frozenset()):
                    skip_next = True
                idx += 1
                continue
            if in_wrapper == "timeout" and re.fullmatch(r"\d+(?:\.\d+)?[smhd]?", tok):
                in_wrapper = None
                idx += 1
                continue
            if in_wrapper in ("taskset", "chrt") and re.fullmatch(r"[0-9a-fA-Fx,-]+", tok):
                in_wrapper = None
                idx += 1
                continue
        base = tok.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if base in _C_FLAG_LAUNCH_WRAPPERS or base == "xargs":
            in_wrapper = base
            if base == "xargs":
                via_xargs = True
            idx += 1
            continue
        return idx, via_xargs, toks
    return None, via_xargs, toks


def _detect_harness_plugin_cli_mutation(sub_cmd: str) -> Optional[Tuple[str, str]]:
    """Detects `agy plugin (install|import)` (any target) and `agy plugin (disable|uninstall)` targeting harness packs."""
    import fnmatch
    import posixpath
    import shlex

    mutating_verbs = frozenset({"disable", "uninstall", "install", "import"})
    agy_bins = frozenset({"agy", "agy.exe", "agy.cmd", "agy.bat", "agy.ps1"})

    def _expand_braces(text_item: str, max_items: int = 32) -> List[str]:
        work = [text_item]
        for _ in range(4):
            next_work: List[str] = []
            changed = False
            for cand in work:
                m_brace = re.search(r"\{([^{}]+)\}", cand)
                if not m_brace:
                    next_work.append(cand)
                    continue
                changed = True
                prefix = cand[: m_brace.start()]
                suffix = cand[m_brace.end() :]
                for alt in m_brace.group(1).split(","):
                    next_work.append(f"{prefix}{alt.strip()}{suffix}")
                    if len(next_work) >= max_items:
                        break
                if len(next_work) >= max_items:
                    break
            work = next_work
            if not changed:
                break
        return work

    def _match_target(raw_token: str) -> Optional[str]:
        tok = raw_token.strip().strip("'\"")
        if not tok:
            return None
        if any(ch in tok for ch in ("$", "`")):
            return "harness-plugin"
        norm_raw = tok.replace("\\", "/")
        norm = posixpath.normpath(norm_raw)
        if norm in (".", "..", "/"):
            return "harness-plugin"
        parts_path = [p for p in norm.split("/") if p and p != "."]
        if not parts_path:
            return "harness-plugin"
        base = parts_path[-1].lower()
        candidates: List[str] = [base]
        if base == "plugin.json" and len(parts_path) >= 2:
            candidates.append(parts_path[-2].lower())
        expanded: List[str] = []
        for cand in candidates:
            expanded.extend(_expand_braces(cand))
        sorted_packs = sorted(_HARNESS_PLUGIN_NAMES)
        for item in expanded:
            if "{" in item or "}" in item:
                return "harness-plugin"
            clean_item = item.rstrip(". ")
            if clean_item in _HARNESS_PLUGIN_NAMES:
                return clean_item
            for pack in sorted_packs:
                if (
                    clean_item in (f"{pack}.zip", f"{pack}.tar.gz", f"{pack}.tgz")
                    or clean_item.startswith((f"{pack}-", f"{pack}_", f"{pack}.", f"{pack}@"))
                ):
                    return pack
            if any(ch in clean_item for ch in "*?["):
                from guard import __version__ as _guard_ver

                _ver_low = str(_guard_ver).lower()
                _stem = re.sub(r"(?:\.(?:zip|tar\.gz|tgz))$", "", clean_item)
                _stem_nover = re.sub(r"[-_@]v?[\d.*?\[\]!]+(?:[.-][\da-z.*?\[\]!]+)*$", "", _stem)
                _prefix_delim = re.split(r"(?:[-_.]v(?=[0-9*?\[\]!])|@)", _stem, maxsplit=1)[0]
                for pack in sorted_packs:
                    if (
                        fnmatch.fnmatchcase(pack, clean_item)
                        or (_stem != clean_item and fnmatch.fnmatchcase(pack, _stem))
                        or (_stem_nover != clean_item and fnmatch.fnmatchcase(pack, _stem_nover))
                        or (_prefix_delim and _prefix_delim != clean_item and fnmatch.fnmatchcase(pack, _prefix_delim))
                        or fnmatch.fnmatchcase(f"{pack}.zip", clean_item)
                        or fnmatch.fnmatchcase(f"{pack}.tar.gz", clean_item)
                        or fnmatch.fnmatchcase(f"{pack}.tgz", clean_item)
                        or fnmatch.fnmatchcase(f"{pack}-v{_ver_low}.zip", clean_item)
                        or fnmatch.fnmatchcase(f"{pack}-v0.0.0.zip", clean_item)
                        or fnmatch.fnmatchcase(f"{pack}-v2.4.0.zip", clean_item)
                        or fnmatch.fnmatchcase(f"{pack}-v{_ver_low}.tar.gz", clean_item)
                        or fnmatch.fnmatchcase(f"{pack}-v0.0.0.tar.gz", clean_item)
                        or fnmatch.fnmatchcase(f"{pack}-v{_ver_low}.tgz", clean_item)
                        or fnmatch.fnmatchcase(f"{pack}-v0.0.0.tgz", clean_item)
                        or fnmatch.fnmatchcase(f"{pack}-{_ver_low}.zip", clean_item)
                        or fnmatch.fnmatchcase(f"{pack}-0.0.0.zip", clean_item)
                        or fnmatch.fnmatchcase(f"{pack}@latest", clean_item)
                    ):
                        return pack
        return None

    cleaned = _strip_unquoted_shell_comments(_join_shell_line_continuations(sub_cmd))
    if not any(ch in cleaned for ch in "\"'\\$`"):
        low_clean = cleaned.lower()
        if "agy" not in low_clean or "plugin" not in low_clean:
            return None
    expanded_vars = _expand_simple_shell_vars(cleaned)
    text = _normalize_governance_globs(re.sub(r"\$'", "'", expanded_vars))
    # Inspect unquoted `echo/printf ... | sh` pipelines as well.
    m_pipe_sh = re.search(
        r"(?:^|[;&|()\n`])\s*(?:echo|printf)\b(?:\s+-[neE]+)*\s+([^\n|;&]+?)\s*\|\s*"
        r"(?:[^\s;|&`]*/)?(?:env\s+)?(?:ba|z|da|k)?sh\b",
        text,
        re.IGNORECASE,
    )
    if m_pipe_sh:
        piped_payload = m_pipe_sh.group(1).strip()
        if piped_payload and piped_payload != sub_cmd:
            nested = _detect_harness_plugin_cli_mutation(piped_payload)
            if nested is not None:
                return nested

    # Keep `$(...)` and backtick command substitutions attached to their target token during splitting.
    punct_chars = ";&|\n"
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=punct_chars)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        tokens = [
            t.strip("'\"")
            for t in re.findall(r"'[^']*'|\"(?:\\.|[^\"\\])*\"|[;&|\n]|\S+", _unquote_single_tokens(text))
        ]

    segments: List[List[str]] = []
    cur_seg: List[str] = []
    for tok in tokens:
        if tok and set(tok) <= set(punct_chars):
            if cur_seg:
                segments.append(cur_seg)
                cur_seg = []
        else:
            cur_seg.append(tok)
    if cur_seg:
        segments.append(cur_seg)

    for seg_tokens in segments:
        cmd_idx, via_xargs, toks = _unwrap_shell_command_tokens(seg_tokens)
        if cmd_idx is None:
            continue
        cmd_base = toks[cmd_idx].replace("\\", "/").rsplit("/", 1)[-1].lower()
        if cmd_base not in agy_bins:
            continue

        rest = toks[cmd_idx + 1 :]
        try:
            plugin_idx = next(i for i, t in enumerate(rest) if t.lower() == "plugin")
        except StopIteration:
            continue
        after_plugin = rest[plugin_idx + 1 :]
        verb_idx: Optional[int] = None
        verb = ""
        for i, t in enumerate(after_plugin):
            low = t.lower()
            if low in ("-h", "--help"):
                verb_idx = None
                break
            if low in mutating_verbs:
                verb_idx = i
                verb = low
                break
        if verb_idx is None:
            continue

        target_args = after_plugin[verb_idx + 1 :]
        after_dd = False
        candidates_to_check: List[str] = []
        bulk_flag_hit = False
        is_help = False
        for t in target_args:
            if not after_dd and t == "--":
                after_dd = True
                continue
            if not after_dd and t.lower() in ("-h", "--help"):
                is_help = True
                candidates_to_check = []
                bulk_flag_hit = False
                break
            if not after_dd and t.startswith("-"):
                if t.lower() in ("--all", "-a"):
                    bulk_flag_hit = True
                elif "=" in t:
                    candidates_to_check.append(t.split("=", 1)[1])
                continue
            candidates_to_check.append(t)

        if is_help:
            continue
        if bulk_flag_hit or (via_xargs and not candidates_to_check):
            return verb, "harness-plugin"
        for cand in candidates_to_check:
            matched_pack = _match_target(cand)
            if matched_pack is not None:
                return verb, matched_pack
        if verb in ("install", "import"):
            target_label = candidates_to_check[0] if candidates_to_check else "plugin"
            return verb, target_label
    return None


def _detect_plugin_directory_drop(
    sub_cmd: str, effective_cwd: Optional[Path] = None
) -> Optional[Tuple[str, str]]:
    """Detects directory-copy/clone/move/extract commands targeting `~/.gemini/config/plugins/<any>`."""
    import shlex

    cleaned = _strip_unquoted_shell_comments(_join_shell_line_continuations(sub_cmd))
    if not cleaned.strip():
        return None

    plugin_roots: List[Path] = []
    cfg_roots_abs: List[Path] = []
    for cfg_cand in _ptu._config_root_candidates():
        c_abs = Path(os.path.abspath(cfg_cand))
        if c_abs not in cfg_roots_abs:
            cfg_roots_abs.append(c_abs)
        p_abs = Path(os.path.abspath(cfg_cand / "plugins"))
        if p_abs not in plugin_roots:
            plugin_roots.append(p_abs)
        try:
            p_res = (cfg_cand / "plugins").resolve()
            if p_res not in plugin_roots:
                plugin_roots.append(p_res)
        except OSError:
            pass

    cwd_under_cfg = False
    if effective_cwd is not None:
        cwd_abs = Path(os.path.abspath(effective_cwd))
        for cr in cfg_roots_abs:
            try:
                cwd_abs.relative_to(cr)
                cwd_under_cfg = True
                break
            except ValueError:
                continue

    low_clean = cleaned.lower()
    if (
        not cwd_under_cfg
        and "plugins" not in low_clean
        and not any(ch in cleaned for ch in "\"'\\$`*?[")
    ):
        return None
    if not any(ch in cleaned for ch in "\"'\\$`") and not any(
        verb in low_clean for verb in ("cp", "rsync", "git", "mv", "tar", "unzip")
    ):
        return None

    expanded_vars = _expand_simple_shell_vars(cleaned)
    text = _normalize_governance_globs(re.sub(r"\$'", "'", expanded_vars))

    m_pipe_sh = re.search(
        r"(?:^|[;&|()\n`])\s*(?:echo|printf)\b(?:\s+-[neE]+)*\s+([^\n|;&]+?)\s*\|\s*"
        r"(?:[^\s;|&`]*/)?(?:env\s+)?(?:ba|z|da|k)?sh\b",
        text,
        re.IGNORECASE,
    )
    if m_pipe_sh:
        piped_payload = m_pipe_sh.group(1).strip()
        if piped_payload and piped_payload != sub_cmd:
            nested = _detect_plugin_directory_drop(piped_payload, effective_cwd)
            if nested is not None:
                return nested

    cfg_dir_str = str(_ptu.configured_config_dir())

    def _match_plugin_dest(raw_dest: Optional[str], base_cwd: Optional[Path]) -> Optional[str]:
        if raw_dest is None:
            return None
        tok = raw_dest.strip().strip("'\"")
        if not tok:
            return None
        tok = tok.replace("${ANTIGRAVITY_CONFIG_DIR}", cfg_dir_str)
        tok = re.sub(r"\$ANTIGRAVITY_CONFIG_DIR(?![A-Za-z0-9_])", lambda _m: cfg_dir_str, tok)
        resolved = _resolve_shell_dir_token(tok, base_cwd)
        cand_paths: List[Path] = []
        if resolved is not None:
            cand_paths.append(resolved)
            try:
                res_real = resolved.resolve()
                if res_real != resolved:
                    cand_paths.append(res_real)
            except OSError:
                pass
        for cp_cand in cand_paths:
            for p_root in plugin_roots:
                try:
                    rel = cp_cand.relative_to(p_root)
                except ValueError:
                    continue
                if not rel.parts:
                    return "plugins"
                return rel.parts[0]
        return None

    _RSYNC_VAL_FLAGS = frozenset({
        "-e", "--rsh", "-f", "--filter", "--exclude", "--include", "--exclude-from", "--include-from",
        "--files-from", "--compare-dest", "--copy-dest", "--link-dest", "--backup-dir", "--suffix",
        "--chmod", "--chown", "--bwlimit", "--log-file", "--temp-dir", "-T", "--out-format",
        "--port", "--password-file", "--address", "--sockopts", "--timeout", "--contimeout",
        "--max-size", "--min-size", "--modify-window", "--block-size", "-B", "--compress-level",
        "--skip-compress", "--iconv", "--usermap", "--groupmap", "--info", "--debug",
    })
    _GIT_GLOBAL_VAL_FLAGS = frozenset({
        "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--list-cmds",
    })
    _GIT_CLONE_VAL_FLAGS = frozenset({
        "-b", "--branch", "--depth", "-o", "--origin", "-u", "--upload-pack", "--reference",
        "--reference-if-able", "--separate-git-dir", "-c", "--config", "--filter", "-j", "--jobs",
        "--template", "--shallow-since", "--shallow-exclude", "--server-option", "--bundle-uri",
    })
    _TAR_VAL_FLAGS = frozenset({
        "-f", "--file", "-T", "--files-from", "-X", "--exclude-from", "--exclude", "-I",
        "--use-compress-program", "-L", "--tape-length", "-V", "--label", "-b", "--blocking-factor",
        "-H", "--format", "--transform", "--strip-components",
    })

    for seg, seg_cwd in _iter_shell_segments_with_cwd(text, effective_cwd):
        try:
            lexer = shlex.shlex(seg, posix=True, punctuation_chars="|")
            lexer.whitespace_split = True
            seg_toks = list(lexer)
        except ValueError:
            seg_toks = [
                t.strip("'\"")
                for t in re.findall(r"'[^']*'|\"(?:\\.|[^\"\\])*\"|\||\S+", _unquote_single_tokens(seg))
            ]

        pipe_stages: List[List[str]] = []
        cur_stage: List[str] = []
        for t in seg_toks:
            if t == "|":
                if cur_stage:
                    pipe_stages.append(cur_stage)
                    cur_stage = []
            else:
                cur_stage.append(t)
        if cur_stage:
            pipe_stages.append(cur_stage)

        for stage in pipe_stages:
            cmd_idx, via_xargs, toks = _unwrap_shell_command_tokens(stage)
            if cmd_idx is None:
                continue
            cmd_base = toks[cmd_idx].replace("\\", "/").rsplit("/", 1)[-1].lower()
            rest = toks[cmd_idx + 1 :]

            if cmd_base in ("cp", "gcp"):
                is_dir_copy = False
                target_dir: Optional[str] = None
                positionals: List[str] = []
                after_dd = False
                expect_target = False
                skip_next = False
                for t in rest:
                    if expect_target:
                        target_dir = t
                        expect_target = False
                        continue
                    if skip_next:
                        skip_next = False
                        continue
                    if not after_dd and t == "--":
                        after_dd = True
                        continue
                    if not after_dd and t in ("-t", "--target-directory"):
                        expect_target = True
                        continue
                    if not after_dd and t.startswith("--target-directory="):
                        target_dir = t.split("=", 1)[1]
                        continue
                    if not after_dd and t.startswith("-t") and len(t) > 2:
                        target_dir = t[2:]
                        continue
                    if not after_dd and t in ("--recursive", "--archive"):
                        is_dir_copy = True
                        continue
                    if not after_dd and t.startswith("-") and not t.startswith("--") and len(t) > 1:
                        flags_str = t[1:]
                        if any(ch in flags_str for ch in ("r", "R", "a")):
                            is_dir_copy = True
                        if flags_str.endswith("t"):
                            expect_target = True
                        elif flags_str.endswith("S"):
                            skip_next = True
                        continue
                    if not after_dd and t.startswith("--"):
                        if t == "--suffix":
                            skip_next = True
                        continue
                    positionals.append(t)
                if is_dir_copy:
                    dests: List[Optional[str]] = (
                        [target_dir]
                        if target_dir is not None
                        else ([positionals[-1]] if len(positionals) >= 2 else ([str(seg_cwd)] if via_xargs and seg_cwd is not None else []))
                    )
                    for d in dests:
                        hit = _match_plugin_dest(d, seg_cwd)
                        if hit is not None:
                            return "cp -r", hit

            elif cmd_base in ("mv", "gmv"):
                target_dir = None
                positionals = []
                after_dd = False
                expect_target = False
                skip_next = False
                for t in rest:
                    if expect_target:
                        target_dir = t
                        expect_target = False
                        continue
                    if skip_next:
                        skip_next = False
                        continue
                    if not after_dd and t == "--":
                        after_dd = True
                        continue
                    if not after_dd and t in ("-t", "--target-directory"):
                        expect_target = True
                        continue
                    if not after_dd and t.startswith("--target-directory="):
                        target_dir = t.split("=", 1)[1]
                        continue
                    if not after_dd and t.startswith("-t") and len(t) > 2:
                        target_dir = t[2:]
                        continue
                    if not after_dd and t.startswith("-") and not t.startswith("--") and len(t) > 1:
                        if t[1:].endswith("t"):
                            expect_target = True
                        elif t[1:].endswith("S"):
                            skip_next = True
                        continue
                    if not after_dd and t.startswith("--"):
                        if t == "--suffix":
                            skip_next = True
                        continue
                    positionals.append(t)
                dests = (
                    [target_dir]
                    if target_dir is not None
                    else ([positionals[-1]] if len(positionals) >= 2 else ([str(seg_cwd)] if via_xargs and seg_cwd is not None else []))
                )
                for d in dests:
                    hit = _match_plugin_dest(d, seg_cwd)
                    if hit is not None:
                        return "mv", hit

            elif cmd_base in ("rsync", "rsync.exe"):
                positionals = []
                after_dd = False
                skip_next = False
                for t in rest:
                    if skip_next:
                        skip_next = False
                        continue
                    if not after_dd and t == "--":
                        after_dd = True
                        continue
                    if not after_dd and t.startswith("-"):
                        if t in _RSYNC_VAL_FLAGS:
                            skip_next = True
                        continue
                    positionals.append(t)
                if len(positionals) >= 2:
                    hit = _match_plugin_dest(positionals[-1], seg_cwd)
                    if hit is not None:
                        return "rsync", hit

            elif cmd_base in ("git", "git.exe"):
                git_cwd = seg_cwd
                g_idx = 0
                subcmd = ""
                while g_idx < len(rest):
                    gt = rest[g_idx]
                    if gt == "-C" and g_idx + 1 < len(rest):
                        git_cwd = _resolve_shell_dir_token(rest[g_idx + 1], git_cwd)
                        g_idx += 2
                        continue
                    if gt.startswith("-C") and len(gt) > 2:
                        git_cwd = _resolve_shell_dir_token(gt[2:], git_cwd)
                        g_idx += 1
                        continue
                    if gt in _GIT_GLOBAL_VAL_FLAGS and g_idx + 1 < len(rest):
                        g_idx += 2
                        continue
                    if gt.startswith("-"):
                        g_idx += 1
                        continue
                    subcmd = gt.lower()
                    g_idx += 1
                    break
                if subcmd == "clone":
                    clone_args = rest[g_idx:]
                    positionals = []
                    after_dd = False
                    skip_next = False
                    for ct in clone_args:
                        if skip_next:
                            skip_next = False
                            continue
                        if not after_dd and ct == "--":
                            after_dd = True
                            continue
                        if not after_dd and ct.startswith("-"):
                            if ct in _GIT_CLONE_VAL_FLAGS:
                                skip_next = True
                            continue
                        positionals.append(ct)
                    dest_cand: Optional[str] = None
                    if len(positionals) >= 2:
                        dest_cand = positionals[1]
                    elif (len(positionals) == 1 or via_xargs) and git_cwd is not None:
                        dest_cand = str(git_cwd)
                    hit = _match_plugin_dest(dest_cand, git_cwd)
                    if hit is not None:
                        return "git clone", hit

            elif cmd_base in ("tar", "gtar", "bsdtar", "tar.exe"):
                is_extract = False
                target_dir = None
                expect_dir = False
                skip_next = False
                for t_idx, t in enumerate(rest):
                    if expect_dir:
                        target_dir = t
                        expect_dir = False
                        continue
                    if skip_next:
                        skip_next = False
                        continue
                    if t in ("-C", "--directory"):
                        expect_dir = True
                        continue
                    if t.startswith("--directory="):
                        target_dir = t.split("=", 1)[1]
                        continue
                    if t.startswith("-C") and len(t) > 2:
                        target_dir = t[2:]
                        continue
                    if t in ("--extract", "--get"):
                        is_extract = True
                        continue
                    if t.startswith("-f") and len(t) > 2:
                        continue
                    if t in _TAR_VAL_FLAGS:
                        skip_next = True
                        continue
                    if t.startswith("-") and not t.startswith("--") and len(t) > 1:
                        flags_str = t[1:]
                        if "x" in flags_str:
                            is_extract = True
                        if flags_str.endswith("f"):
                            skip_next = True
                        elif flags_str.endswith("C"):
                            expect_dir = True
                        continue
                    if t_idx == 0 and re.fullmatch(r"[A-Za-z0-9]+", t):
                        if "x" in t:
                            is_extract = True
                        if "f" in t:
                            skip_next = True
                        continue
                if is_extract:
                    dest_cand = target_dir if target_dir is not None else (str(seg_cwd) if seg_cwd is not None else None)
                    hit = _match_plugin_dest(dest_cand, seg_cwd)
                    if hit is not None:
                        return "tar -x", hit

            elif cmd_base in ("unzip", "unzip.exe"):
                is_readonly = False
                target_dir = None
                expect_dir = False
                skip_next = False
                for t in rest:
                    if expect_dir:
                        target_dir = t
                        expect_dir = False
                        continue
                    if skip_next:
                        skip_next = False
                        continue
                    if t == "-d":
                        expect_dir = True
                        continue
                    if t.startswith("-d") and len(t) > 2:
                        target_dir = t[2:]
                        continue
                    if t in ("-P", "-O", "-I"):
                        skip_next = True
                        continue
                    if t.startswith("-") and not t.startswith("--") and len(t) > 1:
                        if any(ch in t[1:] for ch in ("l", "t", "Z", "p", "c")):
                            is_readonly = True
                        continue
                if not is_readonly:
                    dest_cand = target_dir if target_dir is not None else (str(seg_cwd) if seg_cwd is not None else None)
                    hit = _match_plugin_dest(dest_cand, seg_cwd)
                    if hit is not None:
                        return "unzip", hit

    return None


def _handle_command_pre_tool_use(
    tool_name: str,
    payload: Dict[str, Any],
    args: Dict[str, Any],
    workspaces: Sequence[Path],
    workspace: Optional[Path],
    effective_cwd: Optional[Path],
) -> Dict[str, Any]:
    def _eval_shell_command_string(raw_cmd_str: str) -> Optional[Dict[str, Any]]:
        joined_top = _join_shell_line_continuations(raw_cmd_str).strip()
        if not joined_top:
            return {"decision": "allow"}
        candidate_cmds: List[Tuple[str, Optional[Path]]] = [(joined_top, effective_cwd)]
        seen_cands: set[Tuple[str, Optional[Path]]] = {(joined_top, effective_cwd)}
        if raw_cmd_str.strip() != joined_top:
            pair = (raw_cmd_str.strip(), effective_cwd)
            candidate_cmds.append(pair)
            seen_cands.add(pair)
        top_segs = _iter_shell_segments_with_cwd(
            joined_top, effective_cwd if effective_cwd is not None else workspace
        )
        for seg, seg_cwd in top_segs:
            for ext_sub in _extract_shell_c_payloads(seg):
                pair = (ext_sub, seg_cwd if seg_cwd is not None else effective_cwd)
                if pair not in seen_cands:
                    candidate_cmds.append(pair)
                    seen_cands.add(pair)
        extracted_seen_texts = {c for c, _ in candidate_cmds}
        for ext_sub in _extract_shell_c_payloads(raw_cmd_str):
            if ext_sub not in extracted_seen_texts:
                pair = (ext_sub, effective_cwd)
                candidate_cmds.append(pair)
                seen_cands.add(pair)
                extracted_seen_texts.add(ext_sub)

        pending_cmd_force_ask: Optional[Dict[str, Any]] = None
        for sub_cmd, sub_cwd in candidate_cmds:
            cur_cwd = sub_cwd if sub_cwd is not None else effective_cwd
            admin_variants = _normalize_governance_globs(sub_cmd, admin_variants=True)
            masked_cmd = admin_variants[0]

            if (
                any(_GUARD_ADMIN_RE.search(v) for v in admin_variants)
                or _GUARD_INLINE_PY_RE.search(sub_cmd)
            ):
                return {
                    "decision": "deny",
                    "reason": (
                        "[Harness Governance Shield] Guard administration commands (`plumb-guard unlock`, "
                        "`rebaseline`, `test-boundary snapshot`, `--authorize`, `snapshot restore/prune`, `porter stage`, `porter import --force`, "
                        "`env policy/add/remove`, `startup enable/disable`, `notify disable`, `doctor --fix/--recover`, `init`, or Guard root env overrides) are reserved exclusively "
                        "for the human operator (GEMINI.md Rule 12). You may only run `plumb-guard request-unlock` "
                        "or read-only status/verify/`--dry-run` commands."
                    ),
                }

            if any(_INSTALL_PY_RE.search(v) for v in admin_variants):
                return {
                    "decision": "deny",
                    "reason": (
                        "[Harness Governance Shield] Running `install.py` (without `--dry-run`) is reserved "
                        "for the human operator (GEMINI.md Rule 12)."
                    ),
                }

            cmd_gov_bases: List[Optional[Path]] = []
            for _cb in (cur_cwd, effective_cwd, workspace, *workspaces):
                if _cb is not None and _cb not in cmd_gov_bases:
                    cmd_gov_bases.append(_cb)
            if not cmd_gov_bases:
                cmd_gov_bases.append(None)
            if _command_mutates_governance(sub_cmd) or any(
                _command_mutates_governance_in_cwd(sub_cmd, _cb) for _cb in cmd_gov_bases
            ):
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

            plug_cli_hit = _detect_harness_plugin_cli_mutation(sub_cmd)
            if plug_cli_hit is not None and pending_cmd_force_ask is None:
                plug_verb, plug_pack = plug_cli_hit
                is_h_pack = plug_pack in _HARNESS_PLUGIN_NAMES or plug_pack == "harness-plugin"
                target_desc = (
                    f"harness-managed plugin pack `{plug_pack}`" if is_h_pack else f"plugin `{plug_pack}`"
                )
                pending_cmd_force_ask = {
                    "decision": "force_ask",
                    "reason": _ptu._format_force_ask_reason(
                        f"[Harness Plugin Gate] Official CLI command `agy plugin {plug_verb}` targets "
                        f"{target_desc} (GEMINI.md Rule 12).",
                        what_changes=(
                            f"Runs `agy plugin {plug_verb}` targeting {target_desc}"
                        ),
                        if_approved=(
                            f"Permits `agy plugin {plug_verb}` to modify or install `{plug_pack}` plugin state"
                        ),
                        if_denied=(
                            f"Cancels `agy plugin {plug_verb}` and leaves `{plug_pack}` unchanged"
                        ),
                    ),
                }

            plug_drop_hit = _detect_plugin_directory_drop(sub_cmd, cur_cwd)
            if plug_drop_hit is not None and pending_cmd_force_ask is None:
                drop_op, drop_pack = plug_drop_hit
                pending_cmd_force_ask = {
                    "decision": "force_ask",
                    "reason": _ptu._format_force_ask_reason(
                        f"[Harness Plugin Gate] Shell command `{drop_op}` drops or extracts plugin content into "
                        f"`~/.gemini/config/plugins/{drop_pack}` (GEMINI.md Rule 12).",
                        what_changes=(
                            f"Runs `{drop_op}` into `~/.gemini/config/plugins/{drop_pack}`"
                        ),
                        if_approved=(
                            f"Permits `{drop_op}` to write or extract files into `plugins/{drop_pack}`"
                        ),
                        if_denied=(
                            f"Cancels `{drop_op}` and leaves `plugins/{drop_pack}` unchanged"
                        ),
                    ),
                }

            in_harness_scope = _ptu._workspaces_in_harness_scope(workspaces, cur_cwd)
            cmd_cust_hit = _command_mutates_customization_in_cwd(
                sub_cmd, cur_cwd, workspaces, workspace
            )
            if not cmd_cust_hit:
                ro_cust_sub = (
                    _scrub_verified_readonly_python_invocations(sub_cmd)[0]
                    if "python" in sub_cmd.lower()
                    else sub_cmd
                )
                segs_with_cwd = _iter_shell_segments_with_cwd(
                    ro_cust_sub, cur_cwd if cur_cwd is not None else workspace
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
                            seg, harness_scope=(_ptu._find_harness_repo_root(sc) is not None)
                        )
                        for seg, sc in segs_with_cwd
                        if sc is not None
                    )
                else:
                    seg_harness_scope = in_harness_scope or any(
                        _ptu._find_harness_repo_root(sc) is not None
                        for _, sc in segs_with_cwd
                        if sc is not None
                    )
                    cmd_cust_hit = _command_mutates_customization_structure(
                        sub_cmd, harness_scope=seg_harness_scope
                    )
            if cmd_cust_hit:
                mod_eval = _ptu._evaluate_customization_model_and_effort(payload)
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

            active_art_dir = _ptu._active_artifact_dir(payload)
            out_ws_msg = _detect_out_of_workspace_rm_or_mv(
                unquoted_sub, workspaces, effective_cwd, artifact_dir=active_art_dir
            )
            if out_ws_msg is None and "\\" in sub_cmd:
                out_ws_msg = _detect_out_of_workspace_rm_or_mv(
                    sub_cmd, workspaces, effective_cwd, artifact_dir=active_art_dir
                )
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

    raw_chunk = ""
    if tool_name == "manage_task":
        action = str(args.get("Action") or args.get("action") or "").strip().lower()
        if action == "send_input":
            raw_chunk = str(args.get("Input") if args.get("Input") is not None else (args.get("input") or ""))
        else:
            return {"decision": "allow"}
    elif tool_name == "send_command_input":
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
            cmd_ws = _ptu._workspace_for_target(
                str(effective_cwd) if effective_cwd is not None else "",
                workspaces,
                fallback=(effective_cwd if effective_cwd is not None else workspace),
            )
            if cmd_ws is not None:
                _ptu._record_flight_pre_write(payload, cmd_ws, tool_name, f"<shell:{tool_name}>")
        return {"decision": "allow"}

    buf_key = _cmd_input_buffer_key(payload, args)
    buf_file = _ptu.state_dir() / "cmd_input_buffers.json"
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



def _handle_workflow_pre_tool_use(
    payload: Dict[str, Any],
    args: Dict[str, Any],
    workspaces: Sequence[Path],
    workspace: Optional[Path],
    effective_cwd: Optional[Path],
) -> Dict[str, Any]:
    script_sources, arg_strings, workflow_cwd, script_paths_meta, err_reason = _extract_workflow_sources_ex(
        args, effective_cwd if effective_cwd is not None else workspace
    )
    if err_reason:
        return {"decision": "deny", "reason": err_reason}
    if workflow_cwd is not None and _ptu._targets_governance_dir(str(workflow_cwd)):
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
                    "[Harness Workflow Shield] Human-only `plumb-guard` administration commands are "
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
    active_art_dir = _ptu._active_artifact_dir(payload)
    active_scratch_dir = (active_art_dir / "scratch") if active_art_dir is not None else None
    for sp_path, sp_mode in script_paths_meta:
        in_ws = any(_ptu._is_path_strictly_within_dir(str(sp_path), ws) for ws in workspaces)
        in_active_scratch = (
            active_scratch_dir is not None
            and _ptu._is_path_strictly_within_dir(str(sp_path), active_scratch_dir)
        )
        if (
            (os.name != "nt" and bool(sp_mode & stat.S_IWOTH))
            or (workspaces and not in_ws and not in_active_scratch)
            or (not workspaces and not in_active_scratch and (sp_mode & 0o222))
        ):
            pending_force_ask = {
                "decision": "force_ask",
                "reason": (
                    f"[Harness Workflow Shield] `run_workflow` `ScriptPath` (`{sp_path}`) resides outside "
                    "the active workspace and conversation `scratch/` directory or is world-writable "
                    "(TOCTOU risk); explicit human confirmation is required (GEMINI.md Rule 12 & Rule 15e)."
                ),
            }
            break
    wf_owner_ws = (
        _ptu._workspace_for_target(str(workflow_cwd), workspaces, fallback=workspace)
        if workflow_cwd is not None
        else workspace
    )
    for src in script_sources:
        res, fw = _ptu._inspect_workflow_script(
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
            from ._swarm_guard import _batch_update_swarm_workers_ledger as _default_batch_swarm
            if not _facade_attr("_batch_update_swarm_workers_ledger", _default_batch_swarm)(pending_swarm_ops):
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
        fw_ws = _ptu._workspace_for_target(target, workspaces, fallback=wf_owner_ws)
        _ptu._record_flight_pre_write(payload, fw_ws, inner_tool, target)
    return {"decision": "allow"}

