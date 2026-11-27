"""
guard/hooks/_workflow_ast.py — Static AST sandbox & delegation verifier for `run_workflow` (ADR-0010).
Part of Plumbwork (https://github.com/tozhax/plumbwork)
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
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .common import _facade_attr, _workspaces_from_payload
from .pre_tool_use import (
    COMMAND_TOOL_NAMES,
    WRITE_TOOL_NAMES,
    _DESTRUCTIVE_CMD_PATTERNS,
    _GIT_HOOK_BYPASS_RE,
    _GUARD_ADMIN_RE,
    _GUARD_INLINE_PY_RE,
    _SAFE_ENVIRON_READ_METHODS,
    _WORKFLOW_INSTALL_EXEC_RE,
    _WORKFLOW_MAX_ARG_DEPTH,
    _WORKFLOW_MAX_BYTES,
    _WORKFLOW_MAX_FOLDED_LEN,
    _WRITE_TARGET_ARG_KEYS,
    _canonicalize_check_path,
    _check_pep263_cookie,
    _detect_unpinned_package_exec,
    _eval_workflow_path_expr,
    _eval_workflow_str_expr,
    _evaluate_customization_model_and_effort,
    _extract_mcp_target_paths,
    _extract_write_targets,
    _is_readonly_open_call,
    _mask_quoted_operators,
    _parse_file_uri,
    _targets_customization_structure,
    _targets_governance_dir,
    _text_targets_customization,
    _unquote_single_tokens,
    _workspaces_in_harness_scope,
    _write_mutates_authorized_test_section,
    handle_pre_tool_use,
)


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
    def _expand_wf_path_token(raw_tok: str) -> str:
        s = raw_tok
        if os.name != "nt" and re.match(r"^(?:~|\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})|%[A-Za-z_][A-Za-z0-9_]*%|[A-Za-z]:)\\", s, re.IGNORECASE):
            s = s.replace("\\\\", "/").replace("\\", "/")
        s = re.sub(
            r"^(?:\$HOME|\$\{HOME\}|%USERPROFILE%|\$USERPROFILE)(?=[/\\]|$)",
            lambda _m: str(Path.home()),
            s,
            flags=re.IGNORECASE,
        )
        if os.name != "nt" and re.match(r"^[A-Za-z]:\\", s):
            s = s.replace("\\\\", "/").replace("\\", "/")
        return os.path.expanduser(s)

    base_dir: Optional[Path] = workspace

    cwd_values: List[str] = []
    for ck in ("Cwd", "cwd", "workingDirectory", "working_directory"):
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
        exp_cwd_str = _expand_wf_path_token(cwd_values[0])
        if re.match(r"^(?:\$|\$\{|%[A-Za-z_])", exp_cwd_str):
            return [], [], base_dir, [], "[Harness Workflow Shield] Unexpanded shell variable in `run_workflow` `Cwd` (failing closed)."
        cwd_path = Path(exp_cwd_str)
        if not cwd_path.is_absolute() and not re.match(r"^[A-Za-z]:[/\\]", exp_cwd_str) and not exp_cwd_str.startswith("\\\\"):
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
        exp_sp_str = _expand_wf_path_token(sp_raw)
        if re.match(r"^(?:\$|\$\{|%[A-Za-z_])", exp_sp_str):
            return [], [], base_dir, [], f"[Harness Workflow Shield] Unexpanded shell variable in `run_workflow` `{sp_key}` (failing closed)."
        sp = Path(exp_sp_str)
        if not sp.is_absolute() and not re.match(r"^[A-Za-z]:[/\\]", exp_sp_str) and not exp_sp_str.startswith("\\\\"):
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
      - Human-only `plumb-guard` admin commands, `install.py`, and git hook bypasses (`Rule 12`)
      - Child-process / dynamic-eval / FFI / aliasing escapes (`subprocess`, `os.system`, `eval`, `ctypes` — `Rule 15e`)
      - Direct Python filesystem writes/mutations bypassing `call_tool` & Flight Recorder (`Rule 12`, `15a`, `15e`)
      - Static `call_tool(...)` invocations targeting governance, customization, or destructive commands
      - Delegated `agent(...)` model downgrades (`model='flash' | 'flash_lite'`) on customization files (`Rule 17`)
    """
    eff_cwd = workflow_cwd if workflow_cwd is not None else workspace
    wf_all_workspaces = _workspaces_from_payload(payload) if isinstance(payload, dict) else []
    wf_rel_bases: List[Path] = []
    for _wb in (eff_cwd, workspace, *wf_all_workspaces):
        if _wb is not None and _wb not in wf_rel_bases:
            wf_rel_bases.append(_wb)
    local_swarm_ops: List[Dict[str, Any]] = []
    if swarm_overlay is None:
        swarm_overlay = {}

    def _path_hits_gov(cand: str, resolve_rel: bool = False) -> bool:
        if _targets_governance_dir(cand):
            return True
        if resolve_rel:
            return any(_targets_governance_dir(cand, base_dir=b) for b in wf_rel_bases)
        return False

    def _path_hits_cust(cand: str, resolve_rel: bool = False) -> bool:
        if not cand or not cand.strip():
            return False
        raw_c = cand.strip()
        if "\x00" in raw_c or (raw_c.lower().startswith("file:") and "%00" in raw_c.lower()):
            return True
        if raw_c.lower().startswith("file:"):
            parsed_c = _parse_file_uri(raw_c)
            if parsed_c is None:
                return _targets_customization_structure(raw_c, workspace=(workspace if workspace is not None else eff_cwd))
            raw_c = parsed_c
        ws_ctx = workspace if workspace is not None else eff_cwd
        if resolve_rel and wf_rel_bases:
            exp = Path(os.path.expanduser(raw_c))
            if not exp.is_absolute():
                return any(_targets_customization_structure(str(b / exp), workspace=b) for b in wf_rel_bases)
        return _targets_customization_structure(raw_c, workspace=ws_ctx) or any(
            _targets_customization_structure(raw_c, workspace=b) for b in wf_rel_bases if b != ws_ctx
        )

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
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
    local_func_defs: Dict[str, Any] = {}
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
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                local_func_defs[stmt.name] = stmt
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
    closed_multi_vars: Dict[str, List[str]] = {k: [v] for k, v in const_vars.items()}

    def _eval_static_str_seq(expr: Optional[ast.AST]) -> Optional[List[str]]:
        if expr is None:
            return None
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            items: List[str] = []
            for elt in expr.elts:
                val = _eval_workflow_path_expr(elt, const_vars)
                if val is None:
                    return None
                if val not in items:
                    items.append(val)
            return items[:24] if items else None
        if isinstance(expr, ast.Name) and expr.id in seq_var_elements:
            return list(seq_var_elements[expr.id])
        return None

    seq_var_elements: Dict[str, List[str]] = {}
    for vname, rhs in single_rhs.items():
        if bind_counts.get(vname, 0) != 1:
            continue
        seq_vals = _eval_static_str_seq(rhs)
        if seq_vals:
            seq_var_elements[vname] = seq_vals

    # Bind static string sequence elements into `for` loops, comprehensions, and `parallel`/`pipeline` lambda params.
    iter_bound_values: Dict[str, List[str]] = {}
    iter_bound_unclosed: set[str] = set()
    for nd in ast.walk(tree):
        if isinstance(nd, (ast.For, ast.AsyncFor, ast.comprehension)):
            if isinstance(nd.target, ast.Name):
                tname = nd.target.id
                sv = _eval_static_str_seq(nd.iter)
                if sv:
                    bucket = iter_bound_values.setdefault(tname, [])
                    for item in sv:
                        if item not in bucket and len(bucket) < 24:
                            bucket.append(item)
                else:
                    iter_bound_unclosed.add(tname)
        elif isinstance(nd, ast.Call) and isinstance(nd.func, ast.Name) and nd.func.id in ("parallel", "pipeline"):
            if len(nd.args) >= 2:
                sv = _eval_static_str_seq(nd.args[0])
                fn_arg = nd.args[1]
                if isinstance(fn_arg, ast.Lambda):
                    lam_params = [a.arg for a in fn_arg.args.posonlyargs] + [a.arg for a in fn_arg.args.args]
                    if lam_params:
                        p0 = lam_params[0]
                        if sv:
                            bucket = iter_bound_values.setdefault(p0, [])
                            for item in sv:
                                if item not in bucket and len(bucket) < 24:
                                    bucket.append(item)
                        else:
                            iter_bound_unclosed.add(p0)

    for vname, vals in iter_bound_values.items():
        if vals:
            existing = multi_var_values.setdefault(vname, [])
            for v in vals:
                if v not in existing and len(existing) < 24:
                    existing.append(v)
            if vname not in iter_bound_unclosed and vname not in multi_rhs:
                closed_multi_vars[vname] = list(vals)

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

    for _ in range(4):
        progressed_c = False
        for vname, rhs_list in multi_rhs.items():
            if vname in closed_multi_vars or vname in iter_bound_unclosed:
                continue
            if not rhs_list or len(rhs_list) > 8:
                continue
            all_resolved = True
            collected: List[str] = []
            for rhs_expr in rhs_list:
                cands = _eval_multi_candidates(rhs_expr, closed_multi_vars)
                if not cands:
                    all_resolved = False
                    break
                for cand_s in cands:
                    if cand_s not in collected and len(collected) < 16:
                        collected.append(cand_s)
            if all_resolved and collected:
                closed_multi_vars[vname] = collected
                progressed_c = True
        if not progressed_c:
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

    def _expr_is_nonempty_prompt(
        expr: ast.AST,
        depth: int = 0,
        param_names: frozenset[str] = frozenset(),
    ) -> bool:
        if depth > 4:
            return False
        folded_prompt = _eval_workflow_str_expr(expr, const_vars)
        if folded_prompt is not None:
            return bool(folded_prompt.strip())
        if isinstance(expr, ast.JoinedStr):
            return True
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            frag, _ = _extract_partial_text_and_dynamic(expr, const_vars)
            return bool(frag.strip())
        if isinstance(expr, ast.Name):
            if expr.id in param_names:
                return True
            if bind_counts.get(expr.id, 0) == 1 and expr.id in single_rhs:
                return _expr_is_nonempty_prompt(single_rhs[expr.id], depth + 1, param_names=param_names)
        return False

    def _agent_has_oneshot_prompt(ag_call: ast.Call, param_names: frozenset[str] = frozenset()) -> bool:
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
        return _expr_is_nonempty_prompt(prompt_arg, param_names=param_names)

    def _walk_own_func_nodes(fdef: Any) -> List[ast.AST]:
        """Walks statements/expressions inside `fdef.body` without descending into nested def/class bodies."""
        visited: List[ast.AST] = []
        stack: List[ast.AST] = list(fdef.body)
        while stack:
            cur = stack.pop()
            visited.append(cur)
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            stack.extend(ast.iter_child_nodes(cur))
        return visited

    # Single-definition local helper functions (`def`/`async def`) eligible for `agent()` return/param calibration (`A2`).
    verified_local_funcs: Dict[str, Any] = {
        fname: fdef
        for fname, fdef in local_func_defs.items()
        if local_callable_defs.get(fname, 0) == 1 and store_counts.get(fname, 0) == 1
    }
    call_func_node_ids_pre: set[int] = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}

    # Pass A: Helper functions returning `agent(...)` (both one-shot helpers and persistent-agent factories).
    helper_allowed_agent_call_ids: set[int] = set()
    helper_extra_prompt_nodes: Dict[int, List[ast.AST]] = {}
    helper_owned_agent_ids: Dict[str, List[int]] = {}
    persistent_factory_agents: Dict[str, List[ast.Call]] = {}
    dynamic_turn_agent_ids: set[int] = set()
    dynamic_turn_persistent_vars: set[str] = set()

    for fname, fdef in verified_local_funcs.items():
        own_nodes = _walk_own_func_nodes(fdef)
        f_explicit_params = frozenset(
            a.arg for a in (list(fdef.args.posonlyargs) + list(fdef.args.args) + list(fdef.args.kwonlyargs))
        )
        for nd in own_nodes:
            if isinstance(nd, ast.Call) and isinstance(nd.func, ast.Name) and nd.func.id == "agent":
                helper_owned_agent_ids.setdefault(fname, []).append(id(nd))
            if isinstance(nd, ast.Return) and nd.value is not None:
                ret_ag = _unwrap_agent_call(nd.value, allow_await=True)
                if ret_ag is None:
                    continue
                if _agent_has_oneshot_prompt(ret_ag, param_names=f_explicit_params):
                    helper_allowed_agent_call_ids.add(id(ret_ag))
                elif not isinstance(nd.value, ast.Await):
                    persistent_factory_agents.setdefault(fname, []).append(ret_ag)

    # Validate persistent-agent factories: every reference to `fname` must be a direct call whose result
    # is bound to a variable (`var = fname(...)`) or immediately chained (`fname(...)(prompt)`).
    if persistent_factory_agents:
        verified_factory_chained_ids: set[int] = set()
        factory_bound_call_ids: Dict[str, Dict[int, List[str]]] = {}
        factory_chained_calls: Dict[str, Dict[int, List[ast.AST]]] = {}
        factory_chained_has_star: Dict[int, bool] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
                fn = node.value.func.id
                if fn in persistent_factory_agents:
                    tgts = [t.id for t in node.targets if isinstance(t, ast.Name)]
                    if tgts and len(tgts) == len(node.targets):
                        factory_bound_call_ids.setdefault(fn, {})[id(node.value)] = tgts
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id in persistent_factory_agents
            ):
                factory_bound_call_ids.setdefault(node.value.func.id, {})[id(node.value)] = [node.target.id]
            elif (
                isinstance(node, ast.NamedExpr)
                and isinstance(node.target, ast.Name)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id in persistent_factory_agents
            ):
                factory_bound_call_ids.setdefault(node.value.func.id, {})[id(node.value)] = [node.target.id]
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Call) and isinstance(node.func.func, ast.Name):
                fn = node.func.func.id
                if fn in persistent_factory_agents:
                    turns_f = factory_chained_calls.setdefault(fn, {}).setdefault(id(node.func), [])
                    for a_arg in node.args:
                        if isinstance(a_arg, ast.Starred):
                            turns_f.append(a_arg.value)
                            factory_chained_has_star[id(node.func)] = True
                    if node.args and not isinstance(node.args[0], ast.Starred):
                        turns_f.append(node.args[0])
                    for kw in node.keywords:
                        if kw.arg is None:
                            turns_f.append(kw.value)
                            factory_chained_has_star[id(node.func)] = True
                        elif kw.arg == "prompt":
                            turns_f.append(kw.value)

        for fname, ag_list in persistent_factory_agents.items():
            # Reject factory if `fname` is passed as a bare value anywhere or called without binding/chaining
            factory_safe = True
            for nd in ast.walk(tree):
                if isinstance(nd, ast.Name) and isinstance(nd.ctx, ast.Load) and nd.id == fname:
                    if id(nd) not in call_func_node_ids_pre:
                        factory_safe = False
                        break
                elif isinstance(nd, ast.Call) and isinstance(nd.func, ast.Name) and nd.func.id == fname:
                    if (
                        id(nd) not in factory_bound_call_ids.get(fname, {})
                        and id(nd) not in factory_chained_calls.get(fname, {})
                    ):
                        factory_safe = False
                        break
            if not factory_safe:
                continue
            for ag_c in ag_list:
                helper_allowed_agent_call_ids.add(id(ag_c))
                for _call_id, tgt_vars in factory_bound_call_ids.get(fname, {}).items():
                    for tv in tgt_vars:
                        persistent_agents.setdefault(tv, []).append(ag_c)
                        persistent_agent_turn_nodes.setdefault(tv, [])
                for _call_id, ch_turns in factory_chained_calls.get(fname, {}).items():
                    verified_factory_chained_ids.add(_call_id)
                    chained_agent_turns.setdefault(id(ag_c), []).extend(ch_turns)
                    if factory_chained_has_star.get(_call_id):
                        dynamic_turn_agent_ids.add(id(ag_c))
    else:
        verified_factory_chained_ids = set()

    # Propagate call-site args and `parallel(items, fn)` / `pipeline(items, fn)` inputs onto helper-owned `agent()` calls.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        fn = node.func.id
        if fn in helper_owned_agent_ids:
            site_args: List[ast.AST] = list(node.args) + [kw.value for kw in node.keywords]
            if site_args:
                for ag_id in helper_owned_agent_ids[fn]:
                    helper_extra_prompt_nodes.setdefault(ag_id, []).extend(site_args)
        elif fn in ("parallel", "pipeline"):
            fn_refs = [
                a.id
                for a in node.args
                if isinstance(a, ast.Name) and a.id in helper_owned_agent_ids
            ]
            if fn_refs:
                other_args = [a for a in node.args if not (isinstance(a, ast.Name) and a.id in fn_refs)] + [
                    kw.value for kw in node.keywords
                ]
                for ref_name in fn_refs:
                    for ag_id in helper_owned_agent_ids[ref_name]:
                        helper_extra_prompt_nodes.setdefault(ag_id, []).extend(other_args)

    # Pass B: Passing a persistent agent handle into a verified local helper function (`check_file(reviewer, path)`).
    allowed_persistent_agent_load_ids: set[int] = set()
    verified_agent_param_call_ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        fn = node.func.id
        if fn not in verified_local_funcs:
            continue
        if any(isinstance(a, ast.Starred) for a in node.args) or any(kw.arg is None for kw in node.keywords):
            continue
        fdef = verified_local_funcs[fn]
        if fdef.args.vararg is not None or fdef.args.kwarg is not None:
            continue
        pos_params = [a.arg for a in fdef.args.posonlyargs] + [a.arg for a in fdef.args.args]
        kw_params = {a.arg for a in fdef.args.args} | {a.arg for a in fdef.args.kwonlyargs}

        bound_pairs: List[Tuple[str, ast.AST]] = []
        for idx_a, a_node in enumerate(node.args):
            if idx_a < len(pos_params):
                bound_pairs.append((pos_params[idx_a], a_node))
        for kw in node.keywords:
            if kw.arg and kw.arg in kw_params:
                bound_pairs.append((kw.arg, kw.value))

        other_site_args: List[ast.AST] = []
        agent_bindings: List[Tuple[str, ast.Name, List[ast.Call]]] = []
        for pname, aval in bound_pairs:
            if (
                isinstance(aval, ast.Name)
                and aval.id in persistent_agents
                and len(persistent_agents[aval.id]) == store_counts.get(aval.id, 0)
            ):
                agent_bindings.append((pname, aval, persistent_agents[aval.id]))
            else:
                other_site_args.append(aval)

        if not agent_bindings:
            continue

        own_body_nodes = _walk_own_func_nodes(fdef)
        # Check for nested defs/lambdas referencing the agent parameter ambiguously
        all_body_nodes = [nd for stmt in fdef.body for nd in ast.walk(stmt)]
        for pname, aval, ag_calls in agent_bindings:
            param_safe = True
            param_turn_calls: List[ast.Call] = []
            for nd in all_body_nodes:
                if isinstance(nd, ast.Name) and nd.id == pname:
                    if isinstance(nd.ctx, (ast.Store, ast.Del)):
                        param_safe = False
                        break
                    if isinstance(nd.ctx, ast.Load) and id(nd) not in call_func_node_ids_pre:
                        param_safe = False
                        break
                elif isinstance(nd, ast.arg) and nd.arg == pname:
                    param_safe = False
                    break
            if not param_safe:
                continue
            for nd in own_body_nodes:
                if isinstance(nd, ast.Call) and isinstance(nd.func, ast.Name) and nd.func.id == pname:
                    param_turn_calls.append(nd)
            allowed_persistent_agent_load_ids.add(id(aval))
            for tc in param_turn_calls:
                verified_agent_param_call_ids.add(id(tc))
                turn_exprs: List[ast.AST] = []
                tc_has_star = False
                for a_arg in tc.args:
                    if isinstance(a_arg, ast.Starred):
                        turn_exprs.append(a_arg.value)
                        tc_has_star = True
                if tc.args and not isinstance(tc.args[0], ast.Starred):
                    turn_exprs.append(tc.args[0])
                for tkw in tc.keywords:
                    if tkw.arg is None:
                        turn_exprs.append(tkw.value)
                        tc_has_star = True
                    elif tkw.arg == "prompt":
                        turn_exprs.append(tkw.value)
                for ag_c in ag_calls:
                    helper_extra_prompt_nodes.setdefault(id(ag_c), []).extend(turn_exprs)
                    helper_extra_prompt_nodes.setdefault(id(ag_c), []).extend(other_site_args)
                    if tc_has_star:
                        dynamic_turn_agent_ids.add(id(ag_c))
            if not param_turn_calls and other_site_args:
                for ag_c in ag_calls:
                    helper_extra_prompt_nodes.setdefault(id(ag_c), []).extend(other_site_args)

    # Track non-executing UI/prompt string node ids so prose in `log(...)`, `phase(...)`, `agent(...)`,
    # persistent `var(prompt, ...)`, helper agent-param turns, or chained `agent(...)(prompt, ...)` does not trigger shell regex false positives.
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
            elif node.func.id in persistent_agents or id(node) in verified_agent_param_call_ids:
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
                for a_arg in node.args:
                    if isinstance(a_arg, ast.Starred):
                        turns.append(a_arg.value)
                        dynamic_turn_agent_ids.add(id(chained_ag))
                if node.args and not isinstance(node.args[0], ast.Starred):
                    turns.append(node.args[0])
                for arg_node in node.args[:2]:
                    for sub in ast.walk(arg_node):
                        benign_prose_node_ids.add(id(sub))
                for kw in node.keywords:
                    if kw.arg is None:
                        turns.append(kw.value)
                        dynamic_turn_agent_ids.add(id(chained_ag))
                    elif kw.arg == "prompt":
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

    # 1. Human-only Guard admin, env-override, install.py, and git hook bypasses across workflow Args & non-prose candidates
    from ._shell_guard import _normalize_governance_globs

    for text in cmd_candidates:
        admin_variants = _normalize_governance_globs(text, admin_variants=True)
        masked_text = admin_variants[0]
        if any(_GUARD_ADMIN_RE.search(v) for v in admin_variants) or _GUARD_INLINE_PY_RE.search(text):
            return (
                {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Human-only `plumb-guard` administration commands are "
                        "prohibited inside `run_workflow` (GEMINI.md Rule 12)."
                    ),
                },
                [],
            )
        if any(_WORKFLOW_INSTALL_EXEC_RE.search(v) for v in admin_variants):
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
    for mod_alias in sorted(guarded_module_aliases | collections_mod_aliases):
        if bind_counts.get(mod_alias, 0) > 1:
            return _gov_deny_or(
                f"[Harness Workflow Shield] Rebinding imported module alias `{mod_alias}` inside "
                "`run_workflow` is prohibited (GEMINI.md Rule 15e)."
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
                    (node.id in _NON_ALIASABLE_WORKFLOW_NAMES or node.id in guarded_imported_funcs)
                    and (id(node) not in call_func_node_ids)
                ) or (
                    node.id in persistent_agents
                    and id(node) not in call_func_node_ids
                    and id(node) not in allowed_persistent_agent_load_ids
                ):
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
    tasks_md_write_count = 0
    tasks_md_rely_on_stale_reset = False
    has_command_or_mcp_mutation = False

    # 3. Inspect all AST calls for child-process escapes, direct Python writes, `rmtree`, `call_tool`, and `agent`
    raw_agent_call_nodes: List[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if (
            not isinstance(node.func, (ast.Name, ast.Attribute))
            and _unwrap_agent_call(node.func, allow_await=True) is None
            and id(node.func) not in verified_factory_chained_ids
        ):
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
                                "exactly one positional tool-name string and explicit keyword arguments."
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
                dynamic_kw_nodes: Dict[str, ast.AST] = {}
                has_double_star_kw = False
                for kw in node.keywords:
                    if kw.arg is None:
                        has_double_star_kw = True
                        continue
                    const_val, const_ok = _eval_workflow_const_value(kw.value, const_vars)
                    if const_ok:
                        static_kwargs[kw.arg] = const_val
                    else:
                        dynamic_kw_nodes[kw.arg] = kw.value

                if has_double_star_kw:
                    return (
                        {
                            "decision": "deny",
                            "reason": (
                                f"[Harness Workflow Shield] `call_tool('{inner_name}', **kwargs)` unpacking inside "
                                "`run_workflow` is prohibited; pass explicit keyword arguments."
                            ),
                        },
                        [],
                    )

                has_dynamic_kw = bool(dynamic_kw_nodes)
                all_kw_names = set(static_kwargs.keys()) | set(dynamic_kw_nodes.keys())

                def _collect_kw_expr_fragments(expr: ast.AST) -> List[str]:
                    frags: List[str] = []
                    folded_p = _eval_workflow_path_expr(expr, const_vars)
                    if folded_p:
                        frags.append(folded_p)
                    part_txt, _ = _extract_partial_text_and_dynamic(expr, const_vars)
                    if part_txt and part_txt not in frags:
                        frags.append(part_txt)
                    for mc in _eval_multi_candidates(expr, multi_var_values):
                        if mc and mc not in frags:
                            frags.append(mc)
                    refs_args = False
                    for sub in ast.walk(expr):
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and sub.value:
                            if sub.value not in frags:
                                frags.append(sub.value)
                        elif isinstance(sub, ast.Name):
                            if sub.id == "args":
                                refs_args = True
                            for mv in multi_var_values.get(sub.id, ()):
                                if mv and mv not in frags:
                                    frags.append(mv)
                    if refs_args:
                        for astr in arg_strings:
                            if astr and astr not in frags:
                                frags.append(astr)
                    return frags[:24]

                def _synth_value_for_dyn_kw(expr: ast.AST) -> Tuple[Any, bool]:
                    if isinstance(expr, ast.Dict):
                        synth_d: Dict[str, Any] = {}
                        all_ok = True
                        for k_nd, v_nd in zip(expr.keys, expr.values):
                            if k_nd is None:
                                all_ok = False
                                continue
                            k_s = _eval_workflow_str_expr(k_nd, const_vars)
                            if not k_s:
                                all_ok = False
                                continue
                            v_c, v_ok = _eval_workflow_const_value(v_nd, const_vars)
                            if v_ok:
                                synth_d[k_s] = v_c
                            else:
                                sv, sv_ok = _synth_value_for_dyn_kw(v_nd)
                                synth_d[k_s] = sv
                                if not sv_ok:
                                    all_ok = False
                        return synth_d, all_ok
                    if isinstance(expr, (ast.List, ast.Tuple)):
                        items: List[Any] = []
                        all_ok = True
                        for elt in expr.elts:
                            e_c, e_ok = _eval_workflow_const_value(elt, const_vars)
                            if e_ok:
                                items.append(e_c)
                            else:
                                sv, sv_ok = _synth_value_for_dyn_kw(elt)
                                items.append(sv)
                                if not sv_ok:
                                    all_ok = False
                        return items, all_ok
                    closed_cands = _eval_multi_candidates(expr, closed_multi_vars)
                    if closed_cands:
                        return " ".join(closed_cands), True
                    frags = _collect_kw_expr_fragments(expr)
                    return (" ".join(frags) if frags else "<dynamic>"), False

                if inner_tool in WRITE_TOOL_NAMES:
                    targets = _extract_write_targets(static_kwargs)
                    dyn_target_keys = [k for k in dynamic_kw_nodes if k in _WRITE_TARGET_ARG_KEYS]
                    if not targets and not dyn_target_keys:
                        return (
                            {
                                "decision": "deny",
                                "reason": (
                                    f"[Harness Workflow Shield] `call_tool('{inner_name}', ...)` inside `run_workflow` "
                                    "must specify a write target keyword argument (e.g. `Path` or `TargetFile`)."
                                ),
                            },
                            [],
                        )
                    dyn_target_cands: List[str] = []
                    for dk in dyn_target_keys:
                        closed_t = _eval_multi_candidates(dynamic_kw_nodes[dk], closed_multi_vars)
                        if not closed_t:
                            return (
                                {
                                    "decision": "deny",
                                    "reason": (
                                        f"[Harness Workflow Shield] Dynamic write target `{dk}` in "
                                        f"`call_tool('{inner_name}', ...)` cannot be statically resolved to a "
                                        "finite constant set (failing closed; GEMINI.md Rule 12 & Rule 15e)."
                                    ),
                                },
                                [],
                            )
                        for ct in closed_t:
                            if ct not in dyn_target_cands:
                                dyn_target_cands.append(ct)
                    all_write_cands = [*targets, *dyn_target_cands]
                    for target in all_write_cands:
                        if "\x00" in target or (target.strip().lower().startswith("file:") and "%00" in target.lower()):
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
                    if any(_path_hits_cust(target, resolve_rel=True) for target in all_write_cands):
                        mod_eval = _evaluate_customization_model_and_effort(payload)
                        if mod_eval is not None:
                            if mod_eval[0] == "deny":
                                return {"decision": "deny", "reason": mod_eval[1]}, []
                            force_ask_reasons.append(mod_eval[1])
                    for target in targets:
                        raw_wf_t = target.strip()
                        unparsed_wf_uri = False
                        if raw_wf_t.lower().startswith("file:"):
                            parsed_wf_t = _parse_file_uri(raw_wf_t)
                            if parsed_wf_t is not None:
                                raw_wf_t = parsed_wf_t
                            else:
                                unparsed_wf_uri = True
                        exp_t = Path(os.path.expanduser(raw_wf_t))
                        rec_t = (
                            str(eff_cwd / exp_t)
                            if (not unparsed_wf_uri and not exp_t.is_absolute() and eff_cwd is not None)
                            else raw_wf_t
                        )
                        canon_wf_t = _canonicalize_check_path(rec_t)
                        if re.search(r"(?:^|/)(?:\.agents?|_agents?)/hooks\.json$", canon_wf_t, re.IGNORECASE):
                            wf_workspaces = _workspaces_from_payload(payload)
                            if bool(wf_workspaces) or not _workspaces_in_harness_scope(wf_workspaces, eff_cwd or workspace):
                                force_ask_reasons.append(
                                    "[Harness Governance Shield] Modifying workspace `.agents/hooks.json` inside "
                                    "`run_workflow` can shadow or disable global lifecycle hooks and requires explicit "
                                    "human confirmation (GEMINI.md Rule 12 & Rule 15a)."
                                )
                        if Path(canon_wf_t).name.lower() == "tasks.md":
                            tasks_md_write_count += 1
                            if has_dynamic_kw:
                                force_ask_reasons.append(
                                    "[Harness Test Boundary] Writing dynamic content to `tasks.md` inside `run_workflow` "
                                    "could alter `## Authorized Test Modifications` and requires explicit human confirmation (GEMINI.md Rule 9)."
                                )
                        if not has_dynamic_kw:
                            if _write_mutates_authorized_test_section(target, static_kwargs, eff_cwd):
                                force_ask_reasons.append(
                                    "[Harness Test Boundary] Modifying `## Authorized Test Modifications` in `tasks.md` "
                                    "requires explicit human confirmation (GEMINI.md Rule 9)."
                                )
                            elif _write_mutates_authorized_test_section(
                                target, static_kwargs, eff_cwd, allow_stale_reset=False
                            ):
                                tasks_md_rely_on_stale_reset = True
                        flight_writes.append((inner_tool, rec_t))
                    if dyn_target_keys:
                        for dt in dyn_target_cands:
                            canon_dt = _canonicalize_check_path(dt)
                            if re.search(r"(?:^|/)(?:\.agents?|_agents?)/hooks\.json$", canon_dt, re.IGNORECASE):
                                force_ask_reasons.append(
                                    "[Harness Governance Shield] Modifying workspace `.agents/hooks.json` inside "
                                    "`run_workflow` requires explicit human confirmation (GEMINI.md Rule 12 & Rule 15a)."
                                )
                            if Path(canon_dt).name.lower() == "tasks.md":
                                tasks_md_write_count += 1
                                force_ask_reasons.append(
                                    "[Harness Test Boundary] Writing dynamically to `tasks.md` inside `run_workflow` "
                                    "requires explicit human confirmation (GEMINI.md Rule 9)."
                                )
                        flight_writes.append((inner_tool, f"<workflow:{inner_tool}>"))
                elif inner_tool in COMMAND_TOOL_NAMES:
                    has_command_or_mcp_mutation = True
                    if inner_tool == "manage_task":
                        has_act_key = bool(all_kw_names & {"Action", "action"})
                        mt_act = str(static_kwargs.get("Action") or static_kwargs.get("action") or "").strip().lower()
                        has_inp_key = bool(all_kw_names & {"Input", "input"})
                        mt_inp = str(static_kwargs.get("Input") or static_kwargs.get("input") or "").strip()
                        if not has_act_key or (
                            "Action" not in dynamic_kw_nodes
                            and "action" not in dynamic_kw_nodes
                            and mt_act not in ("list", "status", "kill")
                            and (not has_inp_key or (not mt_inp and not ({"Input", "input"} & set(dynamic_kw_nodes))))
                        ):
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
                        inp_keys = ("Input", "input", "CommandLine", "command")
                        has_any_inp = any(k in all_kw_names for k in inp_keys)
                        has_dyn_inp = any(k in dynamic_kw_nodes for k in inp_keys)
                        sci_inp = str(
                            static_kwargs.get("Input")
                            or static_kwargs.get("input")
                            or static_kwargs.get("CommandLine")
                            or static_kwargs.get("command")
                            or ""
                        ).strip()
                        if not has_any_inp or (not has_dyn_inp and not sci_inp):
                            return (
                                {
                                    "decision": "deny",
                                    "reason": (
                                        "[Harness Workflow Shield] `call_tool('send_command_input', ...)` inside "
                                        "`run_workflow` requires a non-empty `Input` string."
                                    ),
                                },
                                [],
                            )
                    else:
                        has_cmd_key = bool(all_kw_names & {"CommandLine", "command"})
                        has_dyn_cmd = bool(set(dynamic_kw_nodes) & {"CommandLine", "command"})
                        rc_cmd = str(static_kwargs.get("CommandLine") or static_kwargs.get("command") or "").strip()
                        if not has_cmd_key or (not has_dyn_cmd and not rc_cmd):
                            return (
                                {
                                    "decision": "deny",
                                    "reason": (
                                        f"[Harness Workflow Shield] `call_tool('{inner_name}', ...)` inside "
                                        "`run_workflow` requires a non-empty `CommandLine` string."
                                    ),
                                },
                                [],
                            )
                    check_arg_dicts: List[Dict[str, Any]] = []
                    if not has_dynamic_kw:
                        check_arg_dicts.append(static_kwargs)
                    else:
                        crit_cmd_keys = ("CommandLine", "command", "Input", "input", "Action", "action", "Cwd", "cwd")
                        resolved_crit: Dict[str, List[str]] = {}
                        for ck in crit_cmd_keys:
                            if ck in dynamic_kw_nodes:
                                cands_c = _eval_multi_candidates(dynamic_kw_nodes[ck], closed_multi_vars)
                                if not cands_c:
                                    return (
                                        {
                                            "decision": "deny",
                                            "reason": (
                                                f"[Harness Workflow Shield] Dynamic command argument `{ck}` in "
                                                f"`call_tool('{inner_name}', ...)` cannot be statically resolved "
                                                "to a finite constant set (failing closed; GEMINI.md Rule 12 & Rule 15e)."
                                            ),
                                        },
                                        [],
                                    )
                                resolved_crit[ck] = cands_c
                        synth_cmd_kw = dict(static_kwargs)
                        for dk, dnode in dynamic_kw_nodes.items():
                            if dk in resolved_crit:
                                synth_cmd_kw[dk] = resolved_crit[dk][0]
                            else:
                                synth_cmd_kw[dk], _ = _synth_value_for_dyn_kw(dnode)
                        check_arg_dicts.append(synth_cmd_kw)
                        for ck, cands_c in resolved_crit.items():
                            for mc in cands_c[1:]:
                                cand_d = dict(synth_cmd_kw)
                                cand_d[ck] = mc
                                check_arg_dicts.append(cand_d)
                    for cand_kwargs in check_arg_dicts:
                        inner_payload = {
                            **payload,
                            "_workflowDryCheck": True,
                            **({"cwd": str(eff_cwd)} if eff_cwd is not None else {}),
                            "toolCall": {"name": inner_tool, "args": cand_kwargs},
                        }
                        inner_res = _facade_attr("handle_pre_tool_use", handle_pre_tool_use)(inner_payload)
                        if inner_res.get("decision") == "deny":
                            return inner_res, []
                        if inner_res.get("decision") == "force_ask":
                            force_ask_reasons.append(str(inner_res.get("reason") or "Confirmation required."))
                    flight_writes.append((inner_tool, f"<workflow:{inner_tool}>"))
                elif inner_tool in ("invoke_subagent", "swarm", "post_message", "send_message", "define_subagent", "schedule"):
                    eff_kwargs = dict(static_kwargs)
                    check_orch_dicts: List[Dict[str, Any]] = []
                    if has_dynamic_kw:
                        ctrl_keys = (
                            "action", "op", "subaction", "channel_action", "operation",
                            "model", "Model", "TypeName", "type_name", "Recipient", "recipient",
                            "channel", "name", "members", "workers", "member", "worker",
                        )
                        resolved_ctrl: Dict[str, List[str]] = {}
                        for ck in ctrl_keys:
                            if ck in dynamic_kw_nodes:
                                cands_o = _eval_multi_candidates(dynamic_kw_nodes[ck], closed_multi_vars)
                                if not cands_o:
                                    return (
                                        {
                                            "decision": "deny",
                                            "reason": (
                                                f"[Harness Workflow Shield] Dynamic orchestration control argument `{ck}` "
                                                f"in `call_tool('{inner_name}', ...)` cannot be statically resolved "
                                                "(failing closed; GEMINI.md Rule 15e & Rule 17)."
                                            ),
                                        },
                                        [],
                                    )
                                resolved_ctrl[ck] = cands_o
                        for dk, dnode in dynamic_kw_nodes.items():
                            if dk in resolved_ctrl:
                                eff_kwargs[dk] = resolved_ctrl[dk][0]
                            else:
                                sv, sv_ok = _synth_value_for_dyn_kw(dnode)
                                if not sv_ok and isinstance(sv, str) and (all_literals or arg_strings):
                                    extra_ctx = " ".join([*all_literals[:24], *arg_strings[:16]])
                                    sv = f"{sv} {extra_ctx}".strip()
                                eff_kwargs[dk] = sv
                        check_orch_dicts.append(eff_kwargs)
                        for ck, cands_o in resolved_ctrl.items():
                            for mc in cands_o[1:]:
                                cand_o = dict(eff_kwargs)
                                cand_o[ck] = mc
                                check_orch_dicts.append(cand_o)
                    else:
                        check_orch_dicts.append(eff_kwargs)
                    for cand_orch in check_orch_dicts:
                        inner_payload = {
                            **payload,
                            "_workflowDryCheck": True,
                            **({"cwd": str(eff_cwd)} if eff_cwd is not None else {}),
                            "toolCall": {"name": inner_tool, "args": cand_orch},
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
                    eff_mcp_kwargs = dict(static_kwargs)
                    check_mcp_dicts: List[Dict[str, Any]] = []
                    unresolved_mcp_args = False
                    if has_dynamic_kw:
                        mcp_id_keys = ("ToolName", "tool_name", "toolName", "ServerName", "server_name", "serverName")
                        resolved_mcp_ids: Dict[str, List[str]] = {}
                        for mk in mcp_id_keys:
                            if mk in dynamic_kw_nodes:
                                cands_m = _eval_multi_candidates(dynamic_kw_nodes[mk], closed_multi_vars)
                                if not cands_m:
                                    return (
                                        {
                                            "decision": "deny",
                                            "reason": (
                                                f"[Harness Workflow Shield] Dynamic MCP identifier `{mk}` in "
                                                f"`call_tool('{inner_name}', ...)` cannot be statically resolved "
                                                "(failing closed; GEMINI.md Rule 12 & Rule 15e)."
                                            ),
                                        },
                                        [],
                                    )
                                resolved_mcp_ids[mk] = cands_m
                        for dk, dnode in dynamic_kw_nodes.items():
                            if dk in resolved_mcp_ids:
                                eff_mcp_kwargs[dk] = resolved_mcp_ids[dk][0]
                            else:
                                sv, sv_ok = _synth_value_for_dyn_kw(dnode)
                                eff_mcp_kwargs[dk] = sv
                                if not sv_ok:
                                    unresolved_mcp_args = True
                        check_mcp_dicts.append(eff_mcp_kwargs)
                        for mk, cands_m in resolved_mcp_ids.items():
                            for mc in cands_m[1:]:
                                cand_m = dict(eff_mcp_kwargs)
                                cand_m[mk] = mc
                                check_mcp_dicts.append(cand_m)
                    else:
                        check_mcp_dicts.append(eff_mcp_kwargs)
                    if unresolved_mcp_args:
                        from ._mcp_guard import _READONLY_MCP_ALLOWLIST

                        for cand_m in check_mcp_dicts:
                            raw_tn = (
                                str(cand_m.get("ToolName") or cand_m.get("tool_name") or cand_m.get("toolName") or "")
                                if inner_tool == "call_mcp_tool"
                                else inner_tool
                            ).strip().lower()
                            norm_tn = raw_tn.rsplit(":", 1)[-1]
                            if norm_tn not in _READONLY_MCP_ALLOWLIST:
                                return (
                                    {
                                        "decision": "deny",
                                        "reason": (
                                            f"[Harness Workflow Shield] Unresolvable dynamic arguments for non-readonly "
                                            f"MCP tool `{raw_tn or inner_name}` inside `run_workflow` are prohibited "
                                            "(failing closed; GEMINI.md Rule 12 & Rule 15e)."
                                        ),
                                    },
                                    [],
                                )
                    for cand_m in check_mcp_dicts:
                        inner_res = _facade_attr("handle_pre_tool_use", handle_pre_tool_use)(
                            {
                                **payload,
                                "_workflowDryCheck": True,
                                **({"cwd": str(eff_cwd)} if eff_cwd is not None else {}),
                                "toolCall": {"name": inner_tool, "args": cand_m},
                            }
                        )
                        if inner_res.get("decision") == "deny":
                            return inner_res, []
                        if inner_res.get("decision") == "force_ask":
                            force_ask_reasons.append(str(inner_res.get("reason") or "Confirmation required."))
                        mcp_nested = (
                            cand_m.get("Arguments")
                            if isinstance(cand_m.get("Arguments"), dict)
                            else (
                                cand_m.get("arguments")
                                if isinstance(cand_m.get("arguments"), dict)
                                else cand_m
                            )
                        )
                        for mcp_t in _extract_mcp_target_paths(mcp_nested):
                            norm_mcp_t = urllib.parse.unquote(mcp_t.strip()).replace("\\", "/")
                            if Path(norm_mcp_t).name.lower() == "tasks.md":
                                tasks_md_write_count += 1
                                if has_dynamic_kw or _write_mutates_authorized_test_section(
                                    mcp_t, mcp_nested, eff_cwd, allow_stale_reset=False
                                ):
                                    tasks_md_rely_on_stale_reset = True
                            exp_mt = Path(os.path.expanduser(mcp_t.strip()))
                            rec_mt = str(eff_cwd / exp_mt) if (not exp_mt.is_absolute() and eff_cwd is not None) else mcp_t
                            flight_writes.append((inner_tool, rec_mt))
                continue
            if fn == "agent":
                raw_agent_call_nodes.append(node)
                continue
            if id(node) in verified_agent_param_call_ids:
                continue
            if fn in persistent_agents and len(persistent_agents[fn]) == store_counts.get(fn, 0):
                for a_arg in node.args:
                    if isinstance(a_arg, ast.Starred):
                        persistent_agent_turn_nodes[fn].append(a_arg.value)
                        dynamic_turn_persistent_vars.add(fn)
                if node.args and not isinstance(node.args[0], ast.Starred):
                    persistent_agent_turn_nodes[fn].append(node.args[0])
                for kw in node.keywords:
                    if kw.arg is None:
                        persistent_agent_turn_nodes[fn].append(kw.value)
                        dynamic_turn_persistent_vars.add(fn)
                    elif kw.arg == "prompt":
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

    # 4. Enforce Customization Model Gate on one-shot, persistent (`var = agent(...)`), helper-returned, and chained `agent(...)(...)` calls
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
    allowed_agent_call_ids: set[int] = set(chained_agent_turns.keys()) | set(helper_allowed_agent_call_ids)
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
        extra_prompt_nodes.extend(helper_extra_prompt_nodes.get(id(ag_node), []))
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
        prompt_has_dynamic = (
            id(ag_node) in dynamic_turn_agent_ids
            or any(vn in dynamic_turn_persistent_vars for vn in call_to_vars.get(id(ag_node), ()))
        )
        expanded_prompt_nodes: List[ast.AST] = list(prompt_nodes)
        for pn in list(prompt_nodes):
            if isinstance(pn, ast.Name) and bind_counts.get(pn.id, 0) == 1 and pn.id in single_rhs:
                expanded_prompt_nodes.append(single_rhs[pn.id])
        for p_node in expanded_prompt_nodes:
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

    if tasks_md_write_count > 1:
        force_ask_reasons.append(
            "[Harness Test Boundary] Multiple writes targeting `tasks.md` inside `run_workflow` "
            "require explicit human confirmation (GEMINI.md Rule 9)."
        )
    elif tasks_md_rely_on_stale_reset and (
        len(flight_writes) > 1 or has_command_or_mcp_mutation or bool(raw_agent_call_nodes) or bool(rmtree_calls)
    ):
        force_ask_reasons.append(
            "[Harness Test Boundary] Resetting `## Authorized Test Modifications` in `tasks.md` "
            "alongside other workflow operations requires explicit human confirmation (GEMINI.md Rule 9)."
        )

    if force_ask_reasons:
        if pending_swarm_ops is not None and local_swarm_ops:
            pending_swarm_ops.extend(local_swarm_ops)
        return {"decision": "force_ask", "reason": force_ask_reasons[0]}, []

    if pending_swarm_ops is not None and local_swarm_ops:
        pending_swarm_ops.extend(local_swarm_ops)
    return {"decision": "allow"}, flight_writes
