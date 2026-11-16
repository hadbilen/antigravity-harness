"""
guard/hooks/_workflow_ast.py — Static AST sandbox & delegation verifier for `run_workflow` (ADR-0010).
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import ast
import os
import stat
import sys
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
    _check_pep263_cookie,
    _detect_unpinned_package_exec,
    _eval_workflow_path_expr,
    _eval_workflow_str_expr,
    _evaluate_customization_model_and_effort,
    _extract_mcp_target_paths,
    _extract_write_targets,
    _is_readonly_open_call,
    _mask_quoted_operators,
    _targets_customization_structure,
    _targets_governance_dir,
    _text_targets_customization,
    _unquote_single_tokens,
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
