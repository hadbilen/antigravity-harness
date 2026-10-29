#!/usr/bin/env python3
"""
scripts/code_map.py — Zero-Dependency Structural Code Graph, Runtime Tracer & FTS5 Search Engine
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)

Provides deterministic, standard-library-only capabilities for:
  1. `profile`:      Symbol definition(s), signature, docstring, class hierarchy, callers, and callees.
  2. `callers`:      AST-verified call sites (ignores comments and string literals that trip raw `grep`).
  3. `flow`:         Backward dataflow (argument origins in caller) and forward dataflow (return value consumers).
  4. `blast-radius`: Transitive caller closure, affected files/tests, and GEMINI.md Tier 1/2/3 classification.
  5. `gate-syntax`:  Deterministic parse check for .py, .json, .toml, .svg, and .xml files.
  6. `trace`:        Runtime call-edge, argument, and return-value tracer (including comprehensions & lambdas).
  7. `fts-search`:   In-memory SQLite FTS5 (BM25-ranked) passage search for large logs and documentation.
"""

from __future__ import annotations

import argparse
import ast
import io
import json
import os
import re
import runpy
import signal
import sqlite3
import stat
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import deque
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".harness", "export",
    "dist", "build", ".claude", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
}
MAX_CODE_FILE_BYTES = 10 * 1024 * 1024
DEFAULT_TRACE_TIMEOUT_SEC = 30.0

C_CPP_EXTENSIONS = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"}
CODE_EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs"} | C_CPP_EXTENSIONS
TEXT_EXTENSIONS = CODE_EXTENSIONS | {".md", ".txt", ".log", ".json", ".toml", ".yaml", ".yml", ".sql", ".sh"}


@dataclass
class SymbolDef:
    name: str
    qualified_name: str
    kind: str  # "function", "async_function", "method", "class"
    file: str
    line: int
    end_line: int
    signature: str
    docstring: str = ""
    bases: List[str] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)


@dataclass
class CallSite:
    callee: str
    qualified_hint: str
    file: str
    line: int
    enclosing_scope: str
    args: List[str] = field(default_factory=list)
    kwargs: Dict[str, str] = field(default_factory=dict)
    assigned_to: Optional[str] = None
    returned_directly: bool = False
    arg_origins: Dict[str, List[str]] = field(default_factory=dict)
    forward_uses: List[str] = field(default_factory=list)


@dataclass
class CodeIndex:
    definitions: List[SymbolDef] = field(default_factory=list)
    calls: List[CallSite] = field(default_factory=list)
    parse_errors: List[Dict[str, Any]] = field(default_factory=list)


def _iter_files(
    paths: Sequence[Path],
    allowed_suffixes: Optional[Set[str]] = None,
    errors: Optional[List[Dict[str, Any]]] = None,
    base_dir: Optional[Path] = None,
) -> List[Path]:
    collected: List[Path] = []
    seen: Set[Path] = set()

    def _on_walk_error(exc: OSError) -> None:
        if errors is not None:
            bad = Path(exc.filename) if getattr(exc, "filename", None) else Path("<walk>")
            errors.append({
                "file": _rel_path(bad, base_dir) if bad.is_absolute() else bad.as_posix(),
                "line": 1,
                "message": f"{type(exc).__name__}: {exc}",
            })

    resolved_base = base_dir.resolve() if base_dir is not None else None
    for p in paths:
        try:
            is_link = p.is_symlink()
            exists = p.exists()
        except OSError as exc:
            if errors is not None:
                errors.append({
                    "file": _rel_path(p, base_dir) if p.is_absolute() else p.as_posix(),
                    "line": 1,
                    "message": f"{type(exc).__name__}: {exc}",
                })
            continue
        if not exists:
            if errors is not None:
                errors.append({
                    "file": _rel_path(p, base_dir) if p.is_absolute() else p.as_posix(),
                    "line": 1,
                    "message": f"FileNotFoundError: input path does not exist: {p}",
                })
            continue
        if is_link:
            continue
        resolved = p.resolve()
        if resolved.is_file():
            if (allowed_suffixes is None or resolved.suffix.lower() in allowed_suffixes) and resolved not in seen:
                seen.add(resolved)
                collected.append(resolved)
        elif resolved.is_dir():
            walk_boundary = resolved_base if resolved_base is not None else resolved
            for root, dirs, files in os.walk(resolved, onerror=_on_walk_error, followlinks=False):
                root_path = Path(root)
                has_cargo_toml = (root_path / "Cargo.toml").is_file()
                dirs[:] = sorted(
                    d
                    for d in dirs
                    if d not in SKIP_DIRS
                    and not (root_path / d).is_symlink()
                    and not (
                        d == "target"
                        and (has_cargo_toml or (root_path / d / "CACHEDIR.TAG").is_file())
                    )
                )
                for fname in sorted(files):
                    raw_fpath = root_path / fname
                    if raw_fpath.is_symlink():
                        continue
                    if allowed_suffixes is not None and raw_fpath.suffix.lower() not in allowed_suffixes:
                        continue
                    try:
                        st = raw_fpath.stat()
                        fpath = raw_fpath.resolve()
                    except OSError as exc:
                        if errors is not None:
                            errors.append({
                                "file": _rel_path(raw_fpath, base_dir),
                                "line": 1,
                                "message": f"{type(exc).__name__}: {exc}",
                            })
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    if not (fpath == walk_boundary or walk_boundary in fpath.parents):
                        continue
                    if fpath not in seen:
                        seen.add(fpath)
                        collected.append(fpath)
    return collected


def _rel_path(path: Path, base: Optional[Path] = None) -> str:
    anchor = (base or Path.cwd()).resolve()
    try:
        return path.resolve().relative_to(anchor).as_posix()
    except ValueError:
        return path.as_posix()


def _unparse_safe(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    if isinstance(node, ast.Constant):
        val = node.value
        if val is None or isinstance(val, (bool, int)):
            return repr(val)
    try:
        return ast.unparse(node).strip()
    except Exception:
        return "<expr>"


def _iter_load_names(root: ast.AST) -> List[str]:
    stack = [root]
    out: List[str] = []
    while stack:
        curr = stack.pop()
        if isinstance(curr, ast.Name) and isinstance(curr.ctx, ast.Load):
            out.append(curr.id)
        else:
            stack.extend(ast.iter_child_nodes(curr))
    return out


def _iter_all_names(root: ast.AST) -> List[str]:
    stack = [root]
    out: List[str] = []
    while stack:
        curr = stack.pop()
        if isinstance(curr, ast.Name):
            out.append(curr.id)
        else:
            stack.extend(ast.iter_child_nodes(curr))
    return out


def _extract_call_name(func_node: ast.AST) -> Tuple[str, str]:
    """Returns (short_name, dotted_hint)."""
    if isinstance(func_node, ast.Name):
        return func_node.id, func_node.id
    if isinstance(func_node, ast.Attribute):
        dotted = _unparse_safe(func_node)
        return func_node.attr, dotted
    return _unparse_safe(func_node), _unparse_safe(func_node)


def _format_signature(node: ast.AST) -> str:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return ""
    parts: List[str] = []
    args = node.args
    pos_args = list(args.posonlyargs) + list(args.args)
    defaults_offset = len(pos_args) - len(args.defaults)
    for idx, arg in enumerate(pos_args):
        piece = arg.arg
        if arg.annotation:
            piece += f": {_unparse_safe(arg.annotation)}"
        if idx >= defaults_offset:
            default_node = args.defaults[idx - defaults_offset]
            piece += f" = {_unparse_safe(default_node)}"
        parts.append(piece)
    if args.vararg:
        var = f"*{args.vararg.arg}"
        if args.vararg.annotation:
            var += f": {_unparse_safe(args.vararg.annotation)}"
        parts.append(var)
    elif args.kwonlyargs:
        parts.append("*")
    for kw_arg, kw_def in zip(args.kwonlyargs, args.kw_defaults):
        piece = kw_arg.arg
        if kw_arg.annotation:
            piece += f": {_unparse_safe(kw_arg.annotation)}"
        if kw_def is not None:
            piece += f" = {_unparse_safe(kw_def)}"
        parts.append(piece)
    if args.kwarg:
        kw = f"**{args.kwarg.arg}"
        if args.kwarg.annotation:
            kw += f": {_unparse_safe(args.kwarg.annotation)}"
        parts.append(kw)
    ret = f" -> {_unparse_safe(node.returns)}" if node.returns else ""
    prefix = "async def " if isinstance(node, ast.AsyncFunctionDef) else "def "
    return f"{prefix}{node.name}({', '.join(parts)}){ret}"


class _PythonFileVisitor(ast.NodeVisitor):
    def __init__(self, rel_file: str):
        self.rel_file = rel_file
        self.scope_stack: List[str] = []
        self.definitions: List[SymbolDef] = []
        self.calls: List[CallSite] = []
        # scope_name -> var_name -> list of "line N: expr"
        self.scope_assignments: Dict[str, Dict[str, List[str]]] = {"<module>": {}}
        # scope_name -> var_name -> list of "line N: usage"
        self.scope_usages: Dict[str, Dict[str, List[str]]] = {"<module>": {}}
        self._current_assigned_target: Optional[str] = None
        self._in_return: bool = False
        self._func_callees_stack: List[List[str]] = []

    @property
    def current_scope(self) -> str:
        return ".".join(self.scope_stack) if self.scope_stack else "<module>"

    def _record_assignment(self, target_name: str, value_str: str, lineno: int) -> None:
        scope = self.current_scope
        self.scope_assignments.setdefault(scope, {}).setdefault(target_name, []).append(
            f"L{lineno}: {target_name} = {value_str}"
        )

    def _record_usage(self, var_name: str, context_str: str, lineno: int) -> None:
        scope = self.current_scope
        self.scope_usages.setdefault(scope, {}).setdefault(var_name, []).append(
            f"L{lineno}: {context_str}"
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qual = ".".join(self.scope_stack + [node.name])
        bases = [_unparse_safe(b) for b in node.bases]
        raw_doc = ast.get_docstring(node)
        doc = raw_doc.splitlines()[0] if raw_doc else ""
        self.definitions.append(
            SymbolDef(
                name=node.name,
                qualified_name=qual,
                kind="class",
                file=self.rel_file,
                line=node.lineno,
                end_line=getattr(node, "end_lineno", node.lineno),
                signature=f"class {node.name}({', '.join(bases)})" if bases else f"class {node.name}",
                docstring=doc,
                bases=bases,
            )
        )
        self.scope_stack.append(node.name)
        self.scope_assignments.setdefault(self.current_scope, {})
        self.scope_usages.setdefault(self.current_scope, {})
        self.generic_visit(node)
        self.scope_stack.pop()

    def _visit_function(self, node: ast.AST, is_async: bool) -> None:
        assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        parent_is_class = bool(self.scope_stack) and any(
            d.qualified_name == ".".join(self.scope_stack) and d.kind == "class"
            for d in self.definitions
        )
        kind = "method" if parent_is_class else ("async_function" if is_async else "function")
        qual = ".".join(self.scope_stack + [node.name])
        raw_doc = ast.get_docstring(node)
        doc = raw_doc.splitlines()[0] if raw_doc else ""

        callees: List[str] = []
        self.definitions.append(
            SymbolDef(
                name=node.name,
                qualified_name=qual,
                kind=kind,
                file=self.rel_file,
                line=node.lineno,
                end_line=getattr(node, "end_lineno", node.lineno),
                signature=_format_signature(node),
                docstring=doc,
                callees=callees,
            )
        )

        self.scope_stack.append(node.name)
        self._func_callees_stack.append(callees)
        scope = self.current_scope
        self.scope_assignments.setdefault(scope, {})
        self.scope_usages.setdefault(scope, {})
        for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs):
            self.scope_assignments[scope].setdefault(arg.arg, []).append(f"L{node.lineno}: param `{arg.arg}`")
        if node.args.vararg:
            self.scope_assignments[scope].setdefault(node.args.vararg.arg, []).append(
                f"L{node.lineno}: vararg `*{node.args.vararg.arg}`"
            )
        if node.args.kwarg:
            self.scope_assignments[scope].setdefault(node.args.kwarg.arg, []).append(
                f"L{node.lineno}: kwarg `**{node.args.kwarg.arg}`"
            )

        self.generic_visit(node)
        self._func_callees_stack.pop()
        self.scope_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node, is_async=True)

    def visit_Assign(self, node: ast.Assign) -> None:
        primary_target = _unparse_safe(node.targets[0]) if node.targets else None
        assign_names: List[str] = []
        for t in node.targets:
            if isinstance(t, ast.Name):
                assign_names.append(t.id)
            elif isinstance(t, (ast.Tuple, ast.List)):
                for elt in t.elts:
                    if isinstance(elt, ast.Name):
                        assign_names.append(elt.id)
        load_names = _iter_load_names(node.value)
        if assign_names or load_names:
            val_str = _unparse_safe(node.value)
            for name in assign_names:
                self._record_assignment(name, val_str, node.lineno)
            ctx_str = f"{primary_target} = {val_str}"
            for name in load_names:
                self._record_usage(name, ctx_str, node.lineno)
        prev = self._current_assigned_target
        self._current_assigned_target = None
        for t in node.targets:
            self.visit(t)
        self._current_assigned_target = primary_target
        self.visit(node.value)
        self._current_assigned_target = prev

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        target_str = _unparse_safe(node.target)
        if node.value is not None:
            load_names = _iter_load_names(node.value)
            is_name_target = isinstance(node.target, ast.Name)
            if is_name_target or load_names:
                val_str = _unparse_safe(node.value)
                if is_name_target:
                    self._record_assignment(node.target.id, val_str, node.lineno)
                ctx_str = f"{target_str} = {val_str}"
                for name in load_names:
                    self._record_usage(name, ctx_str, node.lineno)
            prev = self._current_assigned_target
            self._current_assigned_target = target_str
            self.visit(node.value)
            self._current_assigned_target = prev

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            load_names = _iter_load_names(node.value)
            if load_names:
                ret_str = _unparse_safe(node.value)
                ctx_str = f"return {ret_str}"
                for name in load_names:
                    self._record_usage(name, ctx_str, node.lineno)
            prev = self._in_return
            self._in_return = True
            self.visit(node.value)
            self._in_return = prev

    def visit_Call(self, node: ast.Call) -> None:
        short_name, dotted_hint = _extract_call_name(node.func)
        for callees_list in self._func_callees_stack:
            if short_name not in callees_list:
                callees_list.append(short_name)
        arg_strs = [_unparse_safe(a) for a in node.args]
        kwarg_strs = {kw.arg or "**": _unparse_safe(kw.value) for kw in node.keywords}

        scope = self.current_scope
        local_assigns = self.scope_assignments.get(scope, {})
        arg_origins: Dict[str, List[str]] = {}
        for arg_node in list(node.args) + [kw.value for kw in node.keywords]:
            if local_assigns:
                for name in _iter_all_names(arg_node):
                    if name in local_assigns:
                        arg_origins[name] = list(local_assigns[name])
            if isinstance(arg_node, ast.Name) and arg_node.id not in self._call_site_names_logged(node):
                self._record_usage(arg_node.id, f"call {dotted_hint}(...)", node.lineno)

        self.calls.append(
            CallSite(
                callee=short_name,
                qualified_hint=dotted_hint,
                file=self.rel_file,
                line=node.lineno,
                enclosing_scope=scope,
                args=arg_strs,
                kwargs=kwarg_strs,
                assigned_to=self._current_assigned_target,
                returned_directly=self._in_return,
                arg_origins=arg_origins,
            )
        )
        # Nested calls inside arguments should not inherit outer assignment/return flags
        prev_target = self._current_assigned_target
        prev_return = self._in_return
        self._current_assigned_target = None
        self._in_return = False
        for a in node.args:
            self.visit(a)
        for kw in node.keywords:
            self.visit(kw.value)
        self.visit(node.func)
        self._current_assigned_target = prev_target
        self._in_return = prev_return

    @staticmethod
    def _call_site_names_logged(node: ast.Call) -> Set[str]:
        return set()

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        target_str = _unparse_safe(node.target)
        load_names = _iter_load_names(node.value)
        is_name_target = isinstance(node.target, ast.Name)
        if is_name_target or load_names:
            val_str = _unparse_safe(node.value)
            if is_name_target:
                self._record_assignment(node.target.id, val_str, node.lineno)
            ctx_str = f"{target_str} := {val_str}"
            for name in load_names:
                self._record_usage(name, ctx_str, node.lineno)
        prev = self._current_assigned_target
        self._current_assigned_target = target_str
        self.visit(node.value)
        self._current_assigned_target = prev

    def finalize_forward_flows(self) -> None:
        for call in self.calls:
            if call.assigned_to:
                lhs = call.assigned_to.split(".")[0].split("[")[0]
                var_names = re.findall(r"[A-Za-z_]\w*", lhs)
                seen_uses: List[str] = []
                for var_name in var_names:
                    usages = self.scope_usages.get(call.enclosing_scope, {}).get(var_name, [])
                    for u in usages:
                        u_line = int(u.split(":", 1)[0].lstrip("L"))
                        if u_line > call.line and u not in seen_uses:
                            seen_uses.append(u)
                call.forward_uses = seen_uses


_COMMENT_STRING_RE = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`",
    re.DOTALL,
)
_C_CLASS_HEAD_RE = re.compile(
    r"\b(?:class|struct)\s+(?:[A-Za-z_]\w*\s+)*([A-Za-z_]\w*)(?:\s+final\b)?\s*(?::(?!:)[^{;(]*)?$",
    re.DOTALL,
)
_C_DECLARATOR_NAME_RE = re.compile(
    r"(?<![A-Za-z0-9_~])(?:([A-Za-z_]\w*)\s*::\s*)?(operator\s*(?:\(\s*\)|\[\s*\]|[+\-*/%^&|~!=<>]{1,3})|~?[A-Za-z_]\w*)\s*$"
)
_C_CALL_RE = re.compile(
    r"(?<![#A-Za-z0-9_])([A-Za-z_]\w*)(?:\s*<[A-Za-z0-9_:,*&\s]*>)?\s*\("
)
_RUST_FN_DECL_RE = re.compile(r"(?<![#A-Za-z0-9_])fn\s+(?:r#)?([A-Za-z_]\w*)")
_RUST_IMPL_HEAD_RE = re.compile(r"(?<![#A-Za-z0-9_])impl\b[^{;]*?(?:\bfor\s+)?(?:r#)?([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*(?:where\b[^{;]*)?$", re.DOTALL)
_RUST_TYPE_DEF_RE = re.compile(r"(?<![#A-Za-z0-9_])(?:struct|enum|trait)\s+(?:r#)?([A-Za-z_]\w*)")
_RUST_CALL_RE = re.compile(
    r"(?<![#A-Za-z0-9_])(?:r#)?([A-Za-z_]\w*)(?:\s*::\s*<[^{};()]*>)?\s*\("
)
_GENERIC_DEF_RE = re.compile(
    r"(?<![#A-Za-z0-9_])(?:function|func|fn|class|def)\s+([A-Za-z_]\w*)",
)
_GENERIC_CALL_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\(",
)
_NON_CALL_KEYWORDS = {
    "if", "for", "while", "switch", "catch", "return", "sizeof", "typeof",
    "alignof", "decltype", "static_assert", "noexcept", "throw", "defined",
    "function", "func", "fn", "class", "def", "match", "unsafe", "loop",
}
_CPP_TRAILING_KW = frozenset({"const", "volatile", "override", "final", "noexcept"})


def _scrub_preserving_newlines(pattern: re.Pattern[str], text: str) -> str:
    return pattern.sub(
        lambda m: "\n" * m.group(0).count("\n") if "\n" in m.group(0) else " " * len(m.group(0)),
        text,
    )


def _blank_slice(buf: List[str], text: str, start: int, stop: int) -> None:
    for idx in range(start, stop):
        buf.append("\n" if text[idx] == "\n" else " ")


def _scrub_c_cpp_source(text: str) -> Tuple[str, List[Tuple[int, str]]]:
    """Single-pass O(N) C/C++ comment, string, char, raw-string, and `#...` preprocessor scrubber."""
    out: List[str] = []
    directives: List[Tuple[int, str]] = []
    n = len(text)
    i = 0
    at_line_start = True

    while i < n:
        ch = text[i]

        if ch == "\n":
            out.append("\n")
            at_line_start = True
            i += 1
            continue

        if ch in (" ", "\t", "\r", "\f", "\v"):
            out.append(" ")
            i += 1
            continue

        # `//` line comment (supporting `\` line-spliced continuations)
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = i + 2
            while j < n:
                if text[j] == "\\" and j + 1 < n and text[j + 1] == "\n":
                    j += 2
                    continue
                if text[j] == "\\" and j + 2 < n and text[j + 1] == "\r" and text[j + 2] == "\n":
                    j += 3
                    continue
                if text[j] == "\n":
                    break
                j += 1
            _blank_slice(out, text, i, j)
            i = j
            continue

        # `/* ... */` block comment
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            stop = n if end == -1 else end + 2
            _blank_slice(out, text, i, stop)
            if "\n" in text[i:stop]:
                at_line_start = True
            i = stop
            continue

        # Preprocessor directive at logical line start (`#define`, `#if*`, `#else`, `#endif`, ...)
        if ch == "#" and at_line_start:
            m_dir = re.match(r"#[ \t]*([A-Za-z_]\w*)", text[i:])
            if m_dir:
                kw = m_dir.group(1)
                if kw in ("if", "ifdef", "ifndef", "elif", "elifdef", "elifndef", "else", "endif"):
                    directives.append((i, kw))
            j = i + 1
            while j < n:
                cj = text[j]
                if cj == "/" and j + 1 < n and text[j + 1] == "*":
                    end = text.find("*/", j + 2)
                    j = n if end == -1 else end + 2
                    continue
                if cj == "/" and j + 1 < n and text[j + 1] == "/":
                    nl = text.find("\n", j + 2)
                    j = n if nl == -1 else nl
                    break
                if cj == '"':
                    j += 1
                    while j < n and text[j] != "\n":
                        if text[j] == "\\" and j + 1 < n:
                            j += 2
                            continue
                        if text[j] == '"':
                            j += 1
                            break
                        j += 1
                    continue
                if cj == "\\":
                    if j + 1 < n and text[j + 1] == "\n":
                        j += 2
                        continue
                    if j + 2 < n and text[j + 1] == "\r" and text[j + 2] == "\n":
                        j += 3
                        continue
                if cj == "\n":
                    break
                j += 1
            _blank_slice(out, text, i, j)
            i = j
            continue

        at_line_start = False

        # C++11 raw string `R"delim(...)delim"` (optionally preceded by `u8`, `u`, `U`, `L`)
        if ch == "R" and i + 1 < n and text[i + 1] == '"':
            valid_raw = False
            prefix_blank = 0
            if i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_"):
                valid_raw = True
            elif text[i - 1] in ("u", "U", "L") and (i == 1 or not (text[i - 2].isalnum() or text[i - 2] == "_")):
                valid_raw = True
                prefix_blank = 1
            elif i >= 2 and text[i - 2 : i] == "u8" and (i == 2 or not (text[i - 3].isalnum() or text[i - 3] == "_")):
                valid_raw = True
                prefix_blank = 2
            if valid_raw:
                d_end = i + 2
                while d_end < n and (d_end - (i + 2)) <= 16 and text[d_end] not in " ()\\\t\v\f\r\n\"":
                    d_end += 1
                if d_end < n and (d_end - (i + 2)) <= 16 and text[d_end] == "(":
                    for k in range(1, prefix_blank + 1):
                        out[-k] = " "
                    closer = ")" + text[i + 2 : d_end] + '"'
                    c_pos = text.find(closer, d_end + 1)
                    stop = n if c_pos == -1 else c_pos + len(closer)
                    _blank_slice(out, text, i, stop)
                    i = stop
                    continue

        # Standard string literal `"..."`
        if ch == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    if j + 2 < n and text[j + 1] == "\r" and text[j + 2] == "\n":
                        j += 3
                    elif j + 1 < n:
                        j += 2
                    else:
                        j += 1
                    continue
                if text[j] == '"':
                    j += 1
                    break
                if text[j] == "\n":
                    break
                j += 1
            _blank_slice(out, text, i, j)
            i = j
            continue

        # Character literal `'...'` vs C++14 numeric digit separator (`100'000`, `0xFF'00`)
        if ch == "'":
            tok_s = i
            while tok_s > 0 and (text[tok_s - 1].isalnum() or text[tok_s - 1] in ("_", "'", ".")):
                tok_s -= 1
            is_digit_sep = (
                tok_s < i
                and (text[tok_s].isdigit() or (text[tok_s] == "." and tok_s + 1 < i and text[tok_s + 1].isdigit()))
                and i + 1 < n
                and text[i + 1].isalnum()
            )
            if is_digit_sep:
                out.append(" ")
                i += 1
                continue
            j = i + 1
            while j < n and text[j] != "\n":
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == "'":
                    j += 1
                    break
                j += 1
            _blank_slice(out, text, i, j)
            i = j
            continue

        out.append(ch)
        i += 1

    return "".join(out), directives


def _scrub_rust_source(text: str) -> str:
    """Single-pass O(N) Rust scrubber for nested `/* */` comments, raw/byte/C strings, char literals, and `#[...]` attributes while preserving `'a` lifetimes."""
    out: List[str] = []
    n = len(text)
    i = 0

    while i < n:
        ch = text[i]

        if ch == "\n":
            out.append("\n")
            i += 1
            continue

        # `//` line comment
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i + 2)
            stop = n if nl == -1 else nl
            _blank_slice(out, text, i, stop)
            i = stop
            continue

        # Nested `/* ... /* ... */ ... */` block comment
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if text[j] == "/" and j + 1 < n and text[j + 1] == "*":
                    depth += 1
                    j += 2
                elif text[j] == "*" and j + 1 < n and text[j + 1] == "/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            _blank_slice(out, text, i, j)
            i = j
            continue

        # Raw string `r#"..."#`, `br#"..."#`, `cr#"..."#`
        if ch == "r" and (
            i == 0
            or not (text[i - 1].isalnum() or text[i - 1] == "_")
            or (text[i - 1] in ("b", "c") and (i == 1 or not (text[i - 2].isalnum() or text[i - 2] == "_")))
        ):
            h_end = i + 1
            while h_end < n and text[h_end] == "#":
                h_end += 1
            if h_end < n and text[h_end] == '"':
                if i > 0 and text[i - 1] in ("b", "c") and (i == 1 or not (text[i - 2].isalnum() or text[i - 2] == "_")):
                    out[-1] = " "
                closer = '"' + ("#" * (h_end - (i + 1)))
                c_pos = text.find(closer, h_end + 1)
                stop = n if c_pos == -1 else c_pos + len(closer)
                _blank_slice(out, text, i, stop)
                i = stop
                continue

        # Normal / byte / C string `"..."`, `b"..."`, `c"..."`
        if ch == '"':
            if i > 0 and text[i - 1] in ("b", "c") and (i == 1 or not (text[i - 2].isalnum() or text[i - 2] == "_")):
                out[-1] = " "
            j = i + 1
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            _blank_slice(out, text, i, j)
            i = j
            continue

        # Character / byte literal `'x'`, `'\''`, `'\u{...}'`, `b'x'` vs lifetime `'a`, `'static`, `'r#lt`
        if ch == "'":
            is_byte_char = i > 0 and text[i - 1] == "b" and (i == 1 or not (text[i - 2].isalnum() or text[i - 2] == "_"))
            can_open_char = is_byte_char or i == 0 or not (text[i - 1].isalnum() or text[i - 1] in ("_", "'"))
            char_end = -1
            if can_open_char and i + 2 < n:
                if text[i + 1] == "\\":
                    k = i + 2
                    if k < n and text[k] == "u" and k + 1 < n and text[k + 1] == "{":
                        rb = text.find("}", k + 2)
                        if rb != -1 and rb - k <= 10 and rb + 1 < n and text[rb + 1] == "'":
                            char_end = rb + 2
                    elif k < n and text[k] == "x" and k + 3 < n and text[k + 3] == "'":
                        char_end = k + 4
                    elif k + 1 < n and text[k] != "\n" and text[k + 1] == "'":
                        char_end = k + 2
                elif text[i + 1] not in ("'", "\\", "\n") and text[i + 2] == "'":
                    char_end = i + 3
            if char_end != -1:
                if is_byte_char:
                    out[-1] = " "
                _blank_slice(out, text, i, char_end)
                i = char_end
                continue
            # Lifetime tick (`'a`, `'static`, `'_`): blank the `'` tick so downstream tokenizers stay clean
            out.append(" ")
            i += 1
            continue

        # Balanced attribute `#[...]` or `#![...]`
        if ch == "#" and i + 1 < n and (text[i + 1] == "[" or (text[i + 1] == "!" and i + 2 < n and text[i + 2] == "[")):
            b_start = i + 1 if text[i + 1] == "[" else i + 2
            depth = 1
            j = b_start + 1
            while j < n and depth > 0:
                if text[j] == "[":
                    depth += 1
                elif text[j] == "]":
                    depth -= 1
                j += 1
            _blank_slice(out, text, i, j)
            i = j
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _strip_c_attributes_linear(chunk: str) -> str:
    """Linear O(N) balanced stripper for `__attribute__((...))`, `__declspec(...)`, `alignas(...)`, and `[[...]]`."""
    if "__attribute__" not in chunk and "__declspec" not in chunk and "alignas" not in chunk and "[[" not in chunk:
        return chunk
    buf = list(chunk)
    n = len(chunk)
    i = 0
    while i < n:
        if chunk[i] == "[" and i + 1 < n and chunk[i + 1] == "[":
            depth = 2
            j = i + 2
            while j < n and depth > 0:
                if chunk[j] == "[":
                    depth += 1
                elif chunk[j] == "]":
                    depth -= 1
                j += 1
            for k in range(i, j):
                if buf[k] != "\n":
                    buf[k] = " "
            i = j
            continue
        if chunk[i] in ("_", "a"):
            m = re.match(r"(?:__attribute__|__declspec|alignas)\b\s*\(", chunk[i:])
            if m and (i == 0 or not (chunk[i - 1].isalnum() or chunk[i - 1] == "_")):
                p_open = i + m.end() - 1
                depth = 1
                j = p_open + 1
                while j < n and depth > 0:
                    if chunk[j] == "(":
                        depth += 1
                    elif chunk[j] == ")":
                        depth -= 1
                    j += 1
                for k in range(i, j):
                    if buf[k] != "\n":
                        buf[k] = " "
                i = j
                continue
        i += 1
    return "".join(buf)


def _mask_leading_templates_linear(chunk: str) -> str:
    """Replaces `template <...>` parameter lists with equal-length spaces so default `= T` never looks like variable assignment."""
    if "template" not in chunk:
        return chunk
    buf = list(chunk)
    n = len(chunk)
    i = 0
    while i < n:
        if chunk[i] == "t" and (i == 0 or not (chunk[i - 1].isalnum() or chunk[i - 1] == "_")):
            m = re.match(r"template\b\s*<", chunk[i:])
            if m:
                lt_pos = i + m.end() - 1
                depth = 1
                j = lt_pos + 1
                p_depth = 0
                while j < n and depth > 0:
                    c = chunk[j]
                    if c == "(":
                        p_depth += 1
                    elif c == ")":
                        p_depth = max(0, p_depth - 1)
                    elif p_depth == 0:
                        if c == "<":
                            depth += 1
                        elif c == ">":
                            depth -= 1
                    j += 1
                for k in range(i, j):
                    if buf[k] != "\n":
                        buf[k] = " "
                i = j
                continue
        i += 1
    return "".join(buf)


def _find_cpp_ctor_colon_offset(chunk: str) -> Optional[int]:
    """Returns offset of a top-level single `:` member-initializer colon after a closed `(...)`, or None."""
    paren_depth = 0
    saw_closed_paren = False
    n = len(chunk)
    i = 0
    while i < n:
        ch = chunk[i]
        if ch == "(":
            paren_depth += 1
        elif ch == ")":
            if paren_depth > 0:
                paren_depth -= 1
                if paren_depth == 0:
                    saw_closed_paren = True
        elif ch == ":" and paren_depth == 0 and saw_closed_paren:
            prev_colon = i > 0 and chunk[i - 1] == ":"
            next_colon = (i + 1 < n) and chunk[i + 1] == ":"
            if not prev_colon and not next_colon:
                after_kw = chunk[i + 1 :].lstrip()
                if not re.match(r"^(?:public|private|protected)\b", after_kw):
                    return i
        i += 1
    return None


def _strip_c_trailing_qualifiers_linear(head: str) -> str:
    """Linear O(N) stripper for C/C++ trailing `-> Ret`, `requires ...`, `noexcept(...)`, `throw(...)`, `&/&&`, and `const/volatile/override/final`."""
    # First truncate at top-level `->` or `requires` following a closed `)` at paren-depth 0
    p_depth = 0
    saw_close = False
    cut = len(head)
    i = 0
    n = len(head)
    while i < n:
        c = head[i]
        if c == "(":
            p_depth += 1
        elif c == ")":
            if p_depth > 0:
                p_depth -= 1
                if p_depth == 0:
                    saw_close = True
        elif p_depth == 0 and saw_close:
            if c == "-" and i + 1 < n and head[i + 1] == ">":
                cut = i
                break
            if c == "r" and (i == 0 or not (head[i - 1].isalnum() or head[i - 1] == "_")) and head.startswith("requires", i):
                end_kw = i + 8
                if end_kw == n or not (head[end_kw].isalnum() or head[end_kw] == "_"):
                    cut = i
                    break
        i += 1

    end = cut
    while end > 0:
        while end > 0 and head[end - 1].isspace():
            end -= 1
        if end == 0:
            break
        # Peel `&` / `&&` ref-qualifiers
        if head[end - 1] == "&":
            end -= 2 if (end >= 2 and head[end - 2] == "&") else 1
            continue
        # Peel balanced `( ... )` ONLY if immediately preceded by `noexcept` or `throw`
        if head[end - 1] == ")":
            depth = 0
            p_open = -1
            for k in range(end - 1, -1, -1):
                if head[k] == ")":
                    depth += 1
                elif head[k] == "(":
                    depth -= 1
                    if depth == 0:
                        p_open = k
                        break
            if p_open > 0:
                pre = p_open
                while pre > 0 and head[pre - 1].isspace():
                    pre -= 1
                w_start = pre
                while w_start > 0 and (head[w_start - 1].isalnum() or head[w_start - 1] == "_"):
                    w_start -= 1
                if head[w_start:pre] in ("noexcept", "throw"):
                    end = w_start
                    continue
            break
        # Peel trailing identifier qualifier (`const`, `volatile`, `override`, `final`, `noexcept`)
        if head[end - 1].isalnum() or head[end - 1] == "_":
            w_start = end
            while w_start > 0 and (head[w_start - 1].isalnum() or head[w_start - 1] == "_"):
                w_start -= 1
            if head[w_start:end] in _CPP_TRAILING_KW:
                end = w_start
                continue
        break
    return head[:end]


def _blank_angle_groups(prefix: str) -> str:
    """Replaces `<...>` template argument groups with equal-length spaces so `Foo<T>::bar` preserves exact byte offsets."""
    if "<" not in prefix:
        return prefix
    buf = list(prefix)
    stack: List[int] = []
    for idx, ch in enumerate(prefix):
        if ch == "<":
            stack.append(idx)
        elif ch == ">" and stack:
            start = stack.pop()
            if not stack:
                for k in range(start, idx + 1):
                    if buf[k] != "\n":
                        buf[k] = " "
    return "".join(buf)


def _has_top_level_assignment(chunk: str) -> bool:
    """Returns True when `=` appears at paren/bracket-depth 0 outside `operator=...` declarations."""
    cleaned = re.sub(r"\boperator\s*(?:==|!=|<=|>=|=)", lambda m: " " * len(m.group(0)), chunk)
    depth = 0
    n = len(cleaned)
    for i, ch in enumerate(cleaned):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        elif ch == "=" and depth == 0:
            prev_ch = cleaned[i - 1] if i > 0 else ""
            next_ch = cleaned[i + 1] if i + 1 < n else ""
            if prev_ch not in ("!", "<", ">", "=") and next_ch != "=":
                return True
    return False


def _index_c_cpp_scrubbed(
    stmt_text: str,
    pp_directives: List[Tuple[int, str]],
    raw_lines: List[str],
    rel_file: str,
    index: CodeIndex,
) -> None:
    from bisect import bisect_right

    line_starts = [0]
    for m_nl in re.finditer(r"\n", stmt_text):
        line_starts.append(m_nl.end())

    def _line_of(offset: int) -> int:
        return bisect_right(line_starts, offset)

    # Stack items: (kind: "container" | "function" | "init_block" | "block", scope_name: Optional[str], sym_def: Optional[SymbolDef], open_offset: int)
    brace_stack: List[Tuple[str, Optional[str], Optional[SymbolDef], int]] = []
    # `#if*` branch snapshots: List[List[Tuple[...]]]
    ifdef_stack: List[List[Tuple[str, Optional[str], Optional[SymbolDef], int]]] = []
    # Function spans: (open_offset, close_offset, scope_name, sym_def)
    func_spans: List[Tuple[int, int, str, SymbolDef]] = []
    # Top-level `=` initializer spans where module-scope calls are valid: (start_offset, end_offset)
    init_spans: List[Tuple[int, int]] = []
    non_call_offsets: Set[int] = set()
    stmt_start = 0
    paren_depth = 0
    ctor_init_brace_depth = 0
    pp_idx = 0
    n_pp = len(pp_directives)

    def _advance_pp(limit_off: int) -> None:
        nonlocal pp_idx, brace_stack
        while pp_idx < n_pp and pp_directives[pp_idx][0] < limit_off:
            pp_off, pp_kw = pp_directives[pp_idx]
            pp_idx += 1
            if pp_kw in ("if", "ifdef", "ifndef"):
                ifdef_stack.append(list(brace_stack))
            elif pp_kw in ("elif", "elifdef", "elifndef", "else"):
                if ifdef_stack:
                    saved = ifdef_stack[-1]
                    saved_defs = {id(item[2]) for item in saved if item[2] is not None}
                    for b_kind, b_scope, b_def, open_off in reversed(brace_stack):
                        if b_kind == "function" and b_scope is not None and b_def is not None and id(b_def) not in saved_defs:
                            b_def.end_line = _line_of(pp_off)
                            func_spans.append((open_off, pp_off, b_scope, b_def))
                    brace_stack = list(saved)
            elif pp_kw == "endif":
                if ifdef_stack:
                    ifdef_stack.pop()

    for tok_match in re.finditer(r"[(){};]", stmt_text):
        tok = tok_match.group(0)
        pos = tok_match.start()
        _advance_pp(pos)
        in_function = any(k == "function" for k, _, _, _ in brace_stack)

        if tok == "(":
            if not in_function and ctor_init_brace_depth == 0:
                paren_depth += 1
            continue

        if tok == ")":
            if not in_function and ctor_init_brace_depth == 0 and paren_depth > 0:
                paren_depth -= 1
            continue

        if paren_depth > 0 and not in_function:
            continue

        if ctor_init_brace_depth > 0:
            if tok == "{":
                ctor_init_brace_depth += 1
            elif tok == "}":
                ctor_init_brace_depth -= 1
            continue

        if tok == ";":
            if not in_function:
                raw_chunk = stmt_text[stmt_start:pos]
                masked_chunk = _mask_leading_templates_linear(_strip_c_attributes_linear(raw_chunk))
                if _has_top_level_assignment(masked_chunk):
                    eq_idx = masked_chunk.find("=")
                    init_spans.append((stmt_start + max(0, eq_idx), pos))
                stmt_start = pos + 1
                paren_depth = 0
            continue

        if tok == "{":
            if in_function:
                brace_stack.append(("block", None, None, pos))
                continue

            enclosing_cls = next((s for k, s, _, _ in reversed(brace_stack) if k == "container" and s), None)
            raw_chunk = stmt_text[stmt_start:pos]
            # Strip standalone access labels (`public:`, `private:`, `protected:`) without O(2^N) backtracking
            access_scrubbed = re.sub(
                r"\b(?:public|private|protected)\s*:(?!:)",
                lambda m: " " * len(m.group(0)),
                raw_chunk,
            )
            attr_scrubbed = _strip_c_attributes_linear(access_scrubbed)
            chunk = _mask_leading_templates_linear(attr_scrubbed)
            chunk_base = stmt_start

            # Detect C++11 brace member-initializers (`: member_{expr}`) before constructor body `{`
            ctor_colon = _find_cpp_ctor_colon_offset(chunk)
            if ctor_colon is not None:
                after_colon = chunk[ctor_colon + 1 :].rstrip()
                if not after_colon.endswith((")", "}")):
                    ctor_init_brace_depth = 1
                    continue

            if _has_top_level_assignment(chunk):
                eq_idx = chunk.find("=")
                brace_stack.append(("init_block", None, None, chunk_base + max(0, eq_idx)))
                stmt_start = pos + 1
                paren_depth = 0
                continue

            cls_match = _C_CLASS_HEAD_RE.search(chunk)
            if cls_match and "(" not in chunk[cls_match.start() :]:
                cls_name = cls_match.group(1)
                name_off = chunk_base + cls_match.start(1)
                cls_line = _line_of(name_off)
                qual_cls = f"{enclosing_cls}.{cls_name}" if enclosing_cls else cls_name
                index.definitions.append(
                    SymbolDef(
                        name=cls_name,
                        qualified_name=qual_cls,
                        kind="class",
                        file=rel_file,
                        line=cls_line,
                        end_line=cls_line,
                        signature=raw_lines[cls_line - 1].strip().rstrip("{").strip() if cls_line <= len(raw_lines) else f"class {cls_name}",
                    )
                )
                brace_stack.append(("container", qual_cls, None, pos))
                stmt_start = pos + 1
                paren_depth = 0
                continue

            if re.match(r"^\s*(?:inline\s+)?namespace\b", chunk) or re.match(r"^\s*extern\b[^{;(]*$", chunk):
                brace_stack.append(("container", enclosing_cls, None, pos))
                stmt_start = pos + 1
                paren_depth = 0
                continue

            if re.search(r"\b(?:enum|union)\b[^{;(]*$", chunk):
                brace_stack.append(("block", None, None, pos))
                stmt_start = pos + 1
                paren_depth = 0
                continue

            head = chunk[:ctor_colon] if ctor_colon is not None else chunk
            head_no_qual = _strip_c_trailing_qualifiers_linear(head)
            if head_no_qual.endswith(")"):
                depth = 0
                open_paren = -1
                for idx in range(len(head_no_qual) - 1, -1, -1):
                    c = head_no_qual[idx]
                    if c == ")":
                        depth += 1
                    elif c == "(":
                        depth -= 1
                        if depth == 0:
                            open_paren = idx
                            break
                if open_paren > 0:
                    prefix_raw = _blank_angle_groups(head_no_qual[:open_paren])
                    # Unwrap simple parenthesized declarators like `int (foo)(int)`
                    stripped_prefix = prefix_raw.rstrip()
                    if stripped_prefix.endswith(")") and "(" in stripped_prefix:
                        p_last = len(stripped_prefix) - 1
                        p_first = stripped_prefix.rfind("(")
                        if p_first >= 0:
                            buf_p = list(prefix_raw)
                            buf_p[p_first] = " "
                            buf_p[p_last] = " "
                            prefix_raw = "".join(buf_p)
                    decl_match = _C_DECLARATOR_NAME_RE.search(prefix_raw)
                    if decl_match:
                        qual_prefix = decl_match.group(1)
                        raw_sym = re.sub(r"\s+", "", decl_match.group(2))
                        clean_sym = raw_sym.lstrip("~")
                        if clean_sym and clean_sym not in _NON_CALL_KEYWORDS:
                            name_off = chunk_base + decl_match.start(2)
                            fn_line = _line_of(name_off)
                            owner = qual_prefix or enclosing_cls
                            qual_name = f"{owner}.{raw_sym}" if owner else raw_sym
                            kind = "method" if owner else "function"
                            sig = (
                                raw_lines[fn_line - 1].strip().rstrip("{").strip()
                                if fn_line <= len(raw_lines)
                                else qual_name
                            )
                            sym_def = SymbolDef(
                                name=raw_sym,
                                qualified_name=qual_name,
                                kind=kind,
                                file=rel_file,
                                line=fn_line,
                                end_line=fn_line,
                                signature=sig,
                            )
                            index.definitions.append(sym_def)
                            non_call_offsets.add(name_off)
                            # Span starts at `chunk_base + open_paren` to capture default-arg and `: member_(call())` calls
                            brace_stack.append(("function", qual_name, sym_def, chunk_base + open_paren))
                            stmt_start = pos + 1
                            paren_depth = 0
                            continue

            brace_stack.append(("block", None, None, pos))
            stmt_start = pos + 1
            paren_depth = 0
            continue

        if tok == "}":
            if brace_stack:
                b_kind, b_scope, b_def, open_off = brace_stack.pop()
                if b_kind == "function" and b_scope is not None and b_def is not None:
                    b_def.end_line = _line_of(pos)
                    func_spans.append((open_off, pos, b_scope, b_def))
                elif b_kind == "init_block" and not any(k in ("function", "init_block") for k, _, _, _ in brace_stack):
                    init_spans.append((open_off, pos))
            stmt_start = pos + 1
            paren_depth = 0

    _advance_pp(len(stmt_text) + 1)
    eof_off = len(stmt_text)
    while brace_stack:
        b_kind, b_scope, b_def, open_off = brace_stack.pop()
        if b_kind == "function" and b_scope is not None and b_def is not None:
            b_def.end_line = _line_of(eof_off)
            func_spans.append((open_off, eof_off, b_scope, b_def))

    func_spans.sort(key=lambda item: item[0])
    init_spans.sort(key=lambda item: item[0])
    f_idx = 0
    i_idx = 0
    n_funcs = len(func_spans)
    n_inits = len(init_spans)

    for call_match in _C_CALL_RE.finditer(stmt_text):
        call_off = call_match.start(1)
        if call_off in non_call_offsets:
            continue
        callee = call_match.group(1)
        if callee in _NON_CALL_KEYWORDS:
            continue

        while f_idx < n_funcs and func_spans[f_idx][1] < call_off:
            f_idx += 1
        if f_idx < n_funcs and func_spans[f_idx][0] < call_off < func_spans[f_idx][1]:
            _, _, fn_scope, fn_def = func_spans[f_idx]
            if callee not in fn_def.callees:
                fn_def.callees.append(callee)
            index.calls.append(
                CallSite(
                    callee=callee,
                    qualified_hint=callee,
                    file=rel_file,
                    line=_line_of(call_off),
                    enclosing_scope=fn_scope,
                )
            )
            continue

        while i_idx < n_inits and init_spans[i_idx][1] < call_off:
            i_idx += 1
        if i_idx < n_inits and init_spans[i_idx][0] <= call_off <= init_spans[i_idx][1]:
            index.calls.append(
                CallSite(
                    callee=callee,
                    qualified_hint=callee,
                    file=rel_file,
                    line=_line_of(call_off),
                    enclosing_scope="<module>",
                )
            )


def _index_rust_scrubbed(scrubbed: str, raw_lines: List[str], rel_file: str, index: CodeIndex) -> None:
    from bisect import bisect_right

    line_starts = [0]
    for m_nl in re.finditer(r"\n", scrubbed):
        line_starts.append(m_nl.end())

    def _line_of(offset: int) -> int:
        return bisect_right(line_starts, offset)

    brace_stack: List[Tuple[str, Optional[str], Optional[SymbolDef], int]] = []
    func_spans: List[Tuple[int, int, str, SymbolDef]] = []
    init_spans: List[Tuple[int, int]] = []
    non_call_offsets: Set[int] = set()
    stmt_start = 0
    paren_depth = 0

    for tok_match in re.finditer(r"[(){};]", scrubbed):
        tok = tok_match.group(0)
        pos = tok_match.start()
        in_fn = any(k == "fn" for k, _, _, _ in brace_stack)

        if tok == "(":
            if not in_fn:
                paren_depth += 1
            continue
        if tok == ")":
            if not in_fn and paren_depth > 0:
                paren_depth -= 1
            continue
        if paren_depth > 0 and not in_fn:
            continue

        if tok == ";":
            if not in_fn:
                semi_chunk = scrubbed[stmt_start:pos]
                proto_m = _RUST_FN_DECL_RE.search(semi_chunk)
                if proto_m:
                    non_call_offsets.add(stmt_start + proto_m.start(1))
                elif re.search(r"(?<![#A-Za-z0-9_])(?:static|const)\b", semi_chunk) and "=" in semi_chunk:
                    init_spans.append((stmt_start + semi_chunk.find("="), pos))
                stmt_start = pos + 1
                paren_depth = 0
            continue

        if tok == "{":
            if in_fn:
                brace_stack.append(("block", None, None, pos))
                continue

            chunk = scrubbed[stmt_start:pos]
            enclosing_impl = next((s for k, s, _, _ in reversed(brace_stack) if k == "impl" and s), None)

            fn_m = _RUST_FN_DECL_RE.search(chunk)
            if fn_m:
                sym = fn_m.group(1)
                name_off = stmt_start + fn_m.start(1)
                fn_line = _line_of(name_off)
                qual_name = f"{enclosing_impl}.{sym}" if enclosing_impl else sym
                kind = "method" if enclosing_impl else "function"
                sig = raw_lines[fn_line - 1].strip().rstrip("{").strip() if fn_line <= len(raw_lines) else qual_name
                sym_def = SymbolDef(
                    name=sym,
                    qualified_name=qual_name,
                    kind=kind,
                    file=rel_file,
                    line=fn_line,
                    end_line=fn_line,
                    signature=sig,
                )
                index.definitions.append(sym_def)
                non_call_offsets.add(name_off)
                brace_stack.append(("fn", qual_name, sym_def, stmt_start + fn_m.end()))
                stmt_start = pos + 1
                paren_depth = 0
                continue

            impl_m = _RUST_IMPL_HEAD_RE.search(chunk)
            if impl_m:
                brace_stack.append(("impl", impl_m.group(1), None, pos))
                stmt_start = pos + 1
                paren_depth = 0
                continue

            type_m = _RUST_TYPE_DEF_RE.search(chunk)
            if type_m:
                t_name = type_m.group(1)
                t_off = stmt_start + type_m.start(1)
                t_line = _line_of(t_off)
                index.definitions.append(
                    SymbolDef(
                        name=t_name,
                        qualified_name=t_name,
                        kind="class",
                        file=rel_file,
                        line=t_line,
                        end_line=t_line,
                        signature=raw_lines[t_line - 1].strip().rstrip("{").strip() if t_line <= len(raw_lines) else t_name,
                    )
                )
                non_call_offsets.add(t_off)
                brace_stack.append(("block", None, None, pos))
                stmt_start = pos + 1
                paren_depth = 0
                continue

            brace_stack.append(("block", None, None, pos))
            stmt_start = pos + 1
            paren_depth = 0
            continue

        if tok == "}":
            if brace_stack:
                b_kind, b_scope, b_def, open_off = brace_stack.pop()
                if b_kind == "fn" and b_scope is not None and b_def is not None:
                    b_def.end_line = _line_of(pos)
                    func_spans.append((open_off, pos, b_scope, b_def))
            stmt_start = pos + 1
            paren_depth = 0

    eof_off = len(scrubbed)
    while brace_stack:
        b_kind, b_scope, b_def, open_off = brace_stack.pop()
        if b_kind == "fn" and b_scope is not None and b_def is not None:
            b_def.end_line = _line_of(eof_off)
            func_spans.append((open_off, eof_off, b_scope, b_def))

    func_spans.sort(key=lambda item: item[0])
    init_spans.sort(key=lambda item: item[0])
    f_idx = 0
    i_idx = 0
    n_funcs = len(func_spans)
    n_inits = len(init_spans)

    for call_match in _RUST_CALL_RE.finditer(scrubbed):
        call_off = call_match.start(1)
        if call_off in non_call_offsets:
            continue
        callee = call_match.group(1)
        if callee in _NON_CALL_KEYWORDS:
            continue

        while f_idx < n_funcs and func_spans[f_idx][1] < call_off:
            f_idx += 1
        if f_idx < n_funcs and func_spans[f_idx][0] <= call_off < func_spans[f_idx][1]:
            _, _, fn_scope, fn_def = func_spans[f_idx]
            if callee not in fn_def.callees:
                fn_def.callees.append(callee)
            index.calls.append(
                CallSite(
                    callee=callee,
                    qualified_hint=callee,
                    file=rel_file,
                    line=_line_of(call_off),
                    enclosing_scope=fn_scope,
                )
            )
            continue

        while i_idx < n_inits and init_spans[i_idx][1] < call_off:
            i_idx += 1
        if i_idx < n_inits and init_spans[i_idx][0] <= call_off <= init_spans[i_idx][1]:
            index.calls.append(
                CallSite(
                    callee=callee,
                    qualified_hint=callee,
                    file=rel_file,
                    line=_line_of(call_off),
                    enclosing_scope="<module>",
                )
            )


def _index_non_python_file(path: Path, rel_file: str, index: CodeIndex) -> None:
    try:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("source path is not a regular file")
        if st.st_size > MAX_CODE_FILE_BYTES:
            raise ValueError(f"source file exceeds {MAX_CODE_FILE_BYTES} byte safety cap")
        raw_bytes = path.read_bytes()
        if b"\x00" in raw_bytes:
            raise ValueError("source code string cannot contain null bytes")
        text = raw_bytes.decode("utf-8-sig")
    except (UnicodeDecodeError, ValueError, OSError) as exc:
        index.parse_errors.append({
            "file": rel_file,
            "line": 1,
            "message": f"{type(exc).__name__}: {exc}",
        })
        return
    suffix = path.suffix.lower()
    if suffix in C_CPP_EXTENSIONS:
        stmt_c, pp_dirs = _scrub_c_cpp_source(text)
        _index_c_cpp_scrubbed(stmt_c, pp_dirs, text.splitlines(), rel_file, index)
        return
    if suffix == ".rs":
        scrubbed_rs = _scrub_rust_source(text)
        _index_rust_scrubbed(scrubbed_rs, text.splitlines(), rel_file, index)
        return
    # Replace comments and string contents with spaces while preserving newlines for exact line numbers
    scrubbed = _scrub_preserving_newlines(_COMMENT_STRING_RE, text)
    current_scope = "<module>"
    current_def: Optional[SymbolDef] = None
    for lineno, line in enumerate(scrubbed.splitlines(), start=1):
        def_match = _GENERIC_DEF_RE.search(line)
        if def_match:
            sym = def_match.group(1)
            current_scope = sym
            current_def = SymbolDef(
                name=sym,
                qualified_name=sym,
                kind="function",
                file=rel_file,
                line=lineno,
                end_line=lineno,
                signature=line.strip().rstrip("{").strip(),
            )
            index.definitions.append(current_def)
        for call_match in _GENERIC_CALL_RE.finditer(line):
            callee = call_match.group(1)
            if callee in _NON_CALL_KEYWORDS:
                continue
            if def_match and callee == def_match.group(1):
                continue
            if current_def is not None and callee not in current_def.callees:
                current_def.callees.append(callee)
            index.calls.append(
                CallSite(
                    callee=callee,
                    qualified_hint=callee,
                    file=rel_file,
                    line=lineno,
                    enclosing_scope=current_scope,
                )
            )


_PYTHON_FILE_INDEX_CACHE: Dict[Tuple[str, str, int, int], Tuple[List[SymbolDef], List[CallSite]]] = {}


def build_code_index(paths: Sequence[Path], base_dir: Optional[Path] = None) -> CodeIndex:
    index = CodeIndex()
    files = _iter_files(paths, allowed_suffixes=CODE_EXTENSIONS, errors=index.parse_errors, base_dir=base_dir)
    if len(_PYTHON_FILE_INDEX_CACHE) > 2048:
        _PYTHON_FILE_INDEX_CACHE.clear()
    for fpath in files:
        rel_file = _rel_path(fpath, base_dir)
        if fpath.suffix.lower() == ".py":
            cache_key: Optional[Tuple[str, str, int, int]] = None
            st_py: Optional[os.stat_result] = None
            try:
                st_py = fpath.stat()
                cache_key = (str(fpath.resolve()), rel_file, st_py.st_mtime_ns, st_py.st_size)
            except OSError:
                pass
            if st_py is not None and st_py.st_size > MAX_CODE_FILE_BYTES:
                index.parse_errors.append({
                    "file": rel_file,
                    "line": 1,
                    "message": f"ValueError: source file exceeds {MAX_CODE_FILE_BYTES} byte safety cap",
                })
                continue
            if cache_key is not None and cache_key in _PYTHON_FILE_INDEX_CACHE:
                cached_defs, cached_calls = _PYTHON_FILE_INDEX_CACHE[cache_key]
                index.definitions.extend(cached_defs)
                index.calls.extend(cached_calls)
                continue
            try:
                source = fpath.read_text(encoding="utf-8-sig")
                tree = ast.parse(source, filename=rel_file)
            except SyntaxError as exc:
                index.parse_errors.append({
                    "file": rel_file,
                    "line": exc.lineno or 1,
                    "message": f"SyntaxError: {exc.msg}",
                })
                continue
            except (UnicodeDecodeError, ValueError, OSError) as exc:
                index.parse_errors.append({
                    "file": rel_file,
                    "line": 1,
                    "message": f"{type(exc).__name__}: {exc}",
                })
                continue
            visitor = _PythonFileVisitor(rel_file)
            visitor.visit(tree)
            visitor.finalize_forward_flows()
            if cache_key is not None:
                _PYTHON_FILE_INDEX_CACHE[cache_key] = (visitor.definitions, visitor.calls)
            index.definitions.extend(visitor.definitions)
            index.calls.extend(visitor.calls)
        else:
            _index_non_python_file(fpath, rel_file, index)
    return index


def _matches_symbol(candidate_short: str, candidate_qual: str, target: str) -> bool:
    norm_target = target.replace("::", ".")
    if candidate_short == norm_target or candidate_qual == norm_target:
        return True
    if candidate_qual.endswith(f".{norm_target}"):
        return True
    if "." in norm_target and candidate_short == norm_target.split(".")[-1] and candidate_qual == candidate_short:
        return True
    return False


class CallerList(list):
    """List of call-site dicts carrying parse_errors and completeness metadata."""

    def __init__(self, items: Sequence[Dict[str, Any]], parse_errors: Optional[List[Dict[str, Any]]] = None) -> None:
        super().__init__(items)
        self.parse_errors: List[Dict[str, Any]] = list(parse_errors or ())
        self.complete: bool = not self.parse_errors


def find_callers(symbol: str, paths: Sequence[Path], base_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    index = build_code_index(paths, base_dir=base_dir)
    results: List[Dict[str, Any]] = []
    for call in index.calls:
        if _matches_symbol(call.callee, call.qualified_hint, symbol):
            results.append(asdict(call))
    return CallerList(results, parse_errors=index.parse_errors)


def profile_symbol(symbol: str, paths: Sequence[Path], base_dir: Optional[Path] = None) -> Dict[str, Any]:
    index = build_code_index(paths, base_dir=base_dir)
    defs = [
        asdict(d) for d in index.definitions
        if _matches_symbol(d.name, d.qualified_name, symbol)
    ]
    callers = [
        asdict(c) for c in index.calls
        if _matches_symbol(c.callee, c.qualified_hint, symbol)
    ]
    subclasses = [
        {"name": d.qualified_name, "file": d.file, "line": d.line}
        for d in index.definitions
        if d.kind == "class" and any(b == symbol or b.endswith(f".{symbol}") for b in d.bases)
    ]
    return {
        "symbol": symbol,
        "definitions": defs,
        "caller_count": len(callers),
        "callers": callers,
        "subclasses": subclasses,
        "parse_errors": index.parse_errors,
    }


def trace_data_flow(symbol: str, paths: Sequence[Path], base_dir: Optional[Path] = None) -> Dict[str, Any]:
    index = build_code_index(paths, base_dir=base_dir)
    backflow: List[Dict[str, Any]] = []
    forwardflow: List[Dict[str, Any]] = []
    for call in index.calls:
        if not _matches_symbol(call.callee, call.qualified_hint, symbol):
            continue
        backflow.append({
            "file": call.file,
            "line": call.line,
            "enclosing_scope": call.enclosing_scope,
            "args": call.args,
            "kwargs": call.kwargs,
            "arg_origins": call.arg_origins,
        })
        forwardflow.append({
            "file": call.file,
            "line": call.line,
            "enclosing_scope": call.enclosing_scope,
            "assigned_to": call.assigned_to,
            "returned_directly": call.returned_directly,
            "subsequent_uses": call.forward_uses,
        })
    return {
        "symbol": symbol,
        "call_site_count": len(backflow),
        "backflow": backflow,
        "forwardflow": forwardflow,
        "parse_errors": index.parse_errors,
    }


def compute_blast_radius(
    symbol: str,
    paths: Sequence[Path],
    base_dir: Optional[Path] = None,
    max_depth: int = 4,
) -> Dict[str, Any]:
    index = build_code_index(paths, base_dir=base_dir)
    affected_files: Set[str] = set()
    matched_defs = 0
    for d in index.definitions:
        if _matches_symbol(d.name, d.qualified_name, symbol):
            affected_files.add(d.file)
            matched_defs += 1

    calls_by_tail: Dict[str, List[CallSite]] = {}
    has_nonstandard_call = False
    for call in index.calls:
        if call.qualified_hint == call.callee or call.qualified_hint.endswith(f".{call.callee}"):
            calls_by_tail.setdefault(call.callee, []).append(call)
        else:
            has_nonstandard_call = True

    norm_symbol = symbol.replace("::", ".")
    queue: deque[Tuple[str, int]] = deque([(norm_symbol, 0)])
    visited_symbols: Set[str] = {norm_symbol}
    transitive_callers: List[Dict[str, Any]] = []

    while queue:
        current_sym, depth = queue.popleft()
        if depth >= max_depth:
            continue
        candidate_calls = (
            index.calls
            if has_nonstandard_call
            else calls_by_tail.get(current_sym.replace("::", ".").split(".")[-1], ())
        )
        for call in candidate_calls:
            if _matches_symbol(call.callee, call.qualified_hint, current_sym):
                affected_files.add(call.file)
                caller_scope = call.enclosing_scope
                transitive_callers.append({
                    "depth": depth + 1,
                    "callee": current_sym,
                    "caller_scope": caller_scope,
                    "file": call.file,
                    "line": call.line,
                })
                if caller_scope != "<module>" and caller_scope not in visited_symbols:
                    visited_symbols.add(caller_scope)
                    queue.append((caller_scope, depth + 1))

    sorted_files = sorted(affected_files)
    test_files = [
        f for f in sorted_files
        if "test" in Path(f).name.lower() or "/tests/" in f"/{f}/" or "/__tests__/" in f"/{f}/"
    ]
    count = len(sorted_files)
    if count > 8:
        tier = "Tier 3"
    elif index.parse_errors:
        tier = f"INCOMPLETE ({len(index.parse_errors)} parse error(s); escalate past Tier 1)"
    elif count >= 3:
        tier = "Tier 2"
    else:
        tier = "Tier 1"

    return {
        "symbol": symbol,
        "symbol_found": (matched_defs > 0 or len(transitive_callers) > 0),
        "complete": len(index.parse_errors) == 0,
        "affected_file_count": count,
        "affected_files": sorted_files,
        "affected_test_files": test_files,
        "tier_recommendation": tier,
        "transitive_callers": transitive_callers,
        "parse_errors": index.parse_errors,
    }


def gate_syntax(paths: Sequence[Path], base_dir: Optional[Path] = None) -> Dict[str, Any]:
    checked = 0
    errors: List[Dict[str, Any]] = []
    walk_errors: List[Dict[str, Any]] = []
    target_suffixes = {".py", ".json", ".toml", ".svg", ".xml"}
    existing_paths: List[Path] = []
    for p in paths:
        try:
            exists = p.exists()
        except OSError as exc:
            errors.append({"file": str(p), "line": 1, "error": f"{type(exc).__name__}: {exc}"})
            continue
        if not exists:
            errors.append({"file": str(p), "line": 1, "error": "File or directory does not exist"})
        else:
            existing_paths.append(p)
    for fpath in _iter_files(existing_paths, allowed_suffixes=target_suffixes, errors=walk_errors, base_dir=base_dir):
        rel = _rel_path(fpath, base_dir)
        checked += 1
        suffix = fpath.suffix.lower()
        try:
            st = fpath.stat()
            if st.st_size > MAX_CODE_FILE_BYTES:
                errors.append({"file": rel, "line": 1, "error": f"File exceeds {MAX_CODE_FILE_BYTES} byte safety cap"})
                continue
            content = fpath.read_text(encoding="utf-8-sig")
        except Exception as exc:
            errors.append({"file": rel, "line": 1, "error": f"Read error: {exc}"})
            continue

        if suffix == ".py":
            try:
                ast.parse(content, filename=rel)
            except SyntaxError as exc:
                errors.append({"file": rel, "line": exc.lineno or 1, "error": f"SyntaxError: {exc.msg}"})
        elif suffix == ".json":
            try:
                json.loads(content)
            except json.JSONDecodeError as exc:
                errors.append({"file": rel, "line": exc.lineno, "error": f"JSONDecodeError: {exc.msg}"})
        elif suffix == ".toml":
            try:
                import tomllib  # Python 3.11+
                tomllib.loads(content)
            except ImportError:
                errors.append({"file": rel, "line": 1, "error": "Unverified: Python tomllib (3.11+) unavailable"})
            except Exception as exc:
                errors.append({"file": rel, "line": 1, "error": f"TOMLDecodeError: {exc}"})
        elif suffix in (".svg", ".xml"):
            if re.search(r"<!\s*(DOCTYPE|ENTITY)\b", content, re.IGNORECASE):
                errors.append({"file": rel, "line": 1, "error": "Forbidden <!DOCTYPE or <!ENTITY declaration"})
                continue
            try:
                ET.fromstring(content)
            except ET.ParseError as exc:
                line = exc.position[0] if hasattr(exc, "position") and exc.position else 1
                errors.append({"file": rel, "line": line, "error": f"XMLParseError: {exc}"})

    for werr in walk_errors:
        errors.append({
            "file": werr["file"],
            "line": werr.get("line", 1),
            "error": werr.get("error") or werr.get("message", "Directory walk error"),
        })

    if checked == 0 and not errors:
        errors.append({
            "file": "<none>",
            "line": 1,
            "error": f"No supported files ({', '.join(sorted(target_suffixes))}) found in target paths",
        })

    return {
        "passed": len(errors) == 0 and checked > 0,
        "checked_count": checked,
        "errors": errors,
    }


def _safe_repr(val: Any, max_len: int = 80) -> str:
    try:
        text = repr(val)
    except Exception:
        text = f"<{type(val).__name__}>"
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def trace_runtime(
    script_path: Path,
    script_args: Sequence[str] = (),
    root_dir: Optional[Path] = None,
    max_events: int = 500,
    timeout_sec: float = DEFAULT_TRACE_TIMEOUT_SEC,
) -> Dict[str, Any]:
    resolved_script = script_path.resolve()
    scope_root = (root_dir or resolved_script.parent).resolve()
    events: List[Dict[str, Any]] = []
    call_stack: List[str] = ["<entry>"]
    eff_timeout = float(timeout_sec) if timeout_sec > 0 else DEFAULT_TRACE_TIMEOUT_SEC
    deadline = time.monotonic() + eff_timeout

    try:
        st_script = resolved_script.stat()
        if st_script.st_size > MAX_CODE_FILE_BYTES:
            return {
                "script": _rel_path(resolved_script, scope_root),
                "event_count": 0,
                "unique_call_edges": [],
                "events": [],
                "error": f"ValueError: script exceeds {MAX_CODE_FILE_BYTES} byte safety cap",
                "stdout": "",
                "stderr": "",
            }
    except OSError as exc:
        return {
            "script": _rel_path(resolved_script, scope_root),
            "event_count": 0,
            "unique_call_edges": [],
            "events": [],
            "error": f"{type(exc).__name__}: {exc}",
            "stdout": "",
            "stderr": "",
        }

    def _is_in_scope(filename: str) -> bool:
        if not filename or filename.startswith("<"):
            return False
        try:
            f_resolved = Path(filename).resolve()
            return f_resolved == resolved_script or scope_root in f_resolved.parents
        except OSError:
            return False

    def _timeout_only_tracer(frame, event, arg):
        if time.monotonic() > deadline:
            raise TimeoutError(f"Runtime trace exceeded {eff_timeout:.1f}s timeout")
        return _timeout_only_tracer

    def _tracer(frame, event, arg):
        if time.monotonic() > deadline:
            raise TimeoutError(f"Runtime trace exceeded {eff_timeout:.1f}s timeout")
        if len(events) >= max_events:
            return _timeout_only_tracer
        code = frame.f_code
        filename = code.co_filename
        if not _is_in_scope(filename):
            return _timeout_only_tracer
        rel_file = _rel_path(Path(filename), scope_root)
        func_name = code.co_name
        if event == "call":
            caller = call_stack[-1] if call_stack else "<entry>"
            arg_info: Dict[str, str] = {}
            arg_var_count = (
                code.co_argcount
                + code.co_kwonlyargcount
                + bool(code.co_flags & 0x04)
                + bool(code.co_flags & 0x08)
            )
            for var_name in code.co_varnames[:arg_var_count]:
                if var_name in frame.f_locals:
                    arg_info[var_name] = _safe_repr(frame.f_locals[var_name])
            events.append({
                "event": "call",
                "caller": caller,
                "callee": func_name,
                "file": rel_file,
                "line": frame.f_lineno,
                "args": arg_info,
            })
            call_stack.append(func_name)
            return _tracer
        if event == "return":
            if len(call_stack) > 1 and call_stack[-1] == func_name:
                call_stack.pop()
            events.append({
                "event": "return",
                "callee": func_name,
                "file": rel_file,
                "line": frame.f_lineno,
                "return_value": _safe_repr(arg),
            })
        return _tracer

    old_argv = sys.argv[:]
    old_path0 = sys.path[0] if sys.path else None
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    error_msg: Optional[str] = None
    sys.argv = [str(resolved_script)] + list(script_args)
    sys.path.insert(0, str(resolved_script.parent))
    prev_trace = sys.gettrace()
    use_itimer = hasattr(signal, "SIGALRM") and hasattr(signal, "setitimer") and (
        threading.current_thread() is threading.main_thread()
    )
    prev_sigalrm = None

    def _on_sigalrm(_signum, _frame):
        raise TimeoutError(f"Runtime trace exceeded {eff_timeout:.1f}s timeout")

    try:
        if use_itimer:
            prev_sigalrm = signal.getsignal(signal.SIGALRM)
            signal.signal(signal.SIGALRM, _on_sigalrm)
            signal.setitimer(signal.ITIMER_REAL, eff_timeout)
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            sys.settrace(_tracer)
            try:
                runpy.run_path(str(resolved_script), run_name="__main__")
            finally:
                sys.settrace(prev_trace)
    except SystemExit as exc:
        if exc.code not in (0, None):
            error_msg = f"SystemExit({exc.code})"
    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {exc}"
    finally:
        if use_itimer:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            if prev_sigalrm is not None:
                signal.signal(signal.SIGALRM, prev_sigalrm)
        sys.argv = old_argv
        if sys.path and sys.path[0] == str(resolved_script.parent):
            sys.path.pop(0)
        elif old_path0 is not None and (not sys.path or sys.path[0] != old_path0):
            sys.path.insert(0, old_path0)

    call_edges = [
        f"{e['caller']} -> {e['callee']}"
        for e in events
        if e["event"] == "call"
    ]
    return {
        "script": _rel_path(resolved_script, scope_root),
        "event_count": len(events),
        "unique_call_edges": list(dict.fromkeys(call_edges)),
        "events": events,
        "error": error_msg,
        "stdout": stdout_buf.getvalue()[:2000],
        "stderr": stderr_buf.getvalue()[:2000],
    }


def fts_search(
    query: str,
    paths: Sequence[Path],
    base_dir: Optional[Path] = None,
    top_k: int = 5,
    chunk_lines: int = 25,
) -> Dict[str, Any]:
    top_k = max(1, top_k)
    chunk_lines = max(1, chunk_lines)
    parse_errors: List[Dict[str, Any]] = []
    files = _iter_files(paths, allowed_suffixes=TEXT_EXTENSIONS, errors=parse_errors, base_dir=base_dir)
    chunks: List[Tuple[str, int, int, str]] = []
    for fpath in files:
        rel = _rel_path(fpath, base_dir)
        try:
            st = fpath.stat()
            if st.st_size > MAX_CODE_FILE_BYTES:
                parse_errors.append({
                    "file": rel,
                    "line": 1,
                    "message": f"ValueError: file exceeds {MAX_CODE_FILE_BYTES} byte safety cap",
                })
                continue
            lines = fpath.read_text(encoding="utf-8-sig", errors="ignore").splitlines()
        except OSError as exc:
            parse_errors.append({
                "file": rel,
                "line": 1,
                "message": f"{type(exc).__name__}: {exc}",
            })
            continue
        for start in range(0, len(lines), chunk_lines):
            block = "\n".join(lines[start: start + chunk_lines]).strip()
            if block:
                chunks.append((rel, start + 1, min(start + chunk_lines, len(lines)), block))

    tokens = re.findall(r"\w+", query)
    if not tokens or not chunks:
        return {
            "query": query,
            "engine": "fts5",
            "chunk_count": len(chunks),
            "complete": not parse_errors,
            "parse_errors": parse_errors,
            "results": [],
        }

    fts_query = " OR ".join(f'"{t}"' for t in tokens)
    results: List[Dict[str, Any]] = []
    engine_used = "sqlite_fts5"
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE VIRTUAL TABLE chunks USING fts5(file, start_line UNINDEXED, end_line UNINDEXED, content)")
        conn.executemany("INSERT INTO chunks(file, start_line, end_line, content) VALUES (?, ?, ?, ?)", chunks)
        cursor = conn.execute(
            "SELECT file, start_line, end_line, content, bm25(chunks) AS score "
            "FROM chunks WHERE chunks MATCH ? ORDER BY score LIMIT ?",
            (fts_query, top_k),
        )
        for row in cursor.fetchall():
            results.append({
                "file": row[0],
                "start_line": int(row[1]),
                "end_line": int(row[2]),
                "score": round(float(row[4]), 4),
                "snippet": row[3][:600],
            })
    except sqlite3.OperationalError:
        engine_used = "python_fallback"
        lowered_tokens = [t.lower() for t in tokens]
        scored: List[Tuple[int, Tuple[str, int, int, str]]] = []
        for ch in chunks:
            text_low = ch[3].lower()
            hits = sum(text_low.count(tok) for tok in lowered_tokens)
            if hits > 0:
                scored.append((hits, ch))
        scored.sort(key=lambda item: (-item[0], item[1][0], item[1][1]))
        for hits, ch in scored[:top_k]:
            results.append({
                "file": ch[0],
                "start_line": ch[1],
                "end_line": ch[2],
                "score": -float(hits),
                "snippet": ch[3][:600],
            })
    finally:
        conn.close()

    return {
        "query": query,
        "engine": engine_used,
        "chunk_count": len(chunks),
        "complete": not parse_errors,
        "parse_errors": parse_errors,
        "results": results,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="code_map",
        description="Deterministic Structural Code Graph, Runtime Tracer & FTS5 Search Engine",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_prof = sub.add_parser("profile", help="Inspect symbol definitions, callers, callees, and inheritance")
    p_prof.add_argument("symbol", help="Symbol name (e.g. build_manifest or ClassName.method)")
    p_prof.add_argument("paths", nargs="*", default=["."], help="Files or directories to index")
    p_prof.add_argument("--json", action="store_true", help="Output structured JSON")

    p_call = sub.add_parser("callers", help="List AST-verified call sites for a symbol")
    p_call.add_argument("symbol", help="Symbol name to find callers for")
    p_call.add_argument("paths", nargs="*", default=["."], help="Files or directories to index")
    p_call.add_argument("--json", action="store_true", help="Output structured JSON")

    p_flow = sub.add_parser("flow", help="Trace backward argument origins and forward return consumers")
    p_flow.add_argument("symbol", help="Symbol name to trace dataflow for")
    p_flow.add_argument("paths", nargs="*", default=["."], help="Files or directories to index")
    p_flow.add_argument("--json", action="store_true", help="Output structured JSON")

    p_blast = sub.add_parser("blast-radius", help="Compute transitive callers, affected files, and Tier 1/2/3 scope")
    p_blast.add_argument("symbol", help="Symbol name to compute blast radius for")
    p_blast.add_argument("paths", nargs="*", default=["."], help="Files or directories to index")
    p_blast.add_argument("--max-depth", type=int, default=4, help="Maximum transitive caller hops")
    p_blast.add_argument("--json", action="store_true", help="Output structured JSON")

    p_gate = sub.add_parser("gate-syntax", help="Deterministically parse-check .py, .json, .toml, .svg, and .xml files")
    p_gate.add_argument("paths", nargs="+", help="Files or directories to check")
    p_gate.add_argument("--json", action="store_true", help="Output structured JSON")

    p_trace = sub.add_parser("trace", help="Run a Python script under the runtime call and argument tracer")
    p_trace.add_argument("script", help="Path to Python script to execute")
    p_trace.add_argument("script_args", nargs="*", help="Arguments passed to the script")
    p_trace.add_argument("--root", help="Scope directory for traced files (default: script parent)")
    p_trace.add_argument("--max-events", type=int, default=500, help="Maximum trace events to record")
    p_trace.add_argument("--timeout", type=float, default=DEFAULT_TRACE_TIMEOUT_SEC, help="Maximum runtime seconds (default: 30)")
    p_trace.add_argument("--json", action="store_true", help="Output structured JSON")

    p_fts = sub.add_parser("fts-search", help="BM25-ranked SQLite FTS5 search across large logs and docs")
    p_fts.add_argument("query", help="Search terms")
    p_fts.add_argument("paths", nargs="*", default=["."], help="Files or directories to index")
    p_fts.add_argument("--top", type=int, default=5, help="Maximum ranked snippets to return")
    p_fts.add_argument("--chunk-lines", type=int, default=25, help="Lines per indexed passage")
    p_fts.add_argument("--json", action="store_true", help="Output structured JSON")

    return parser


def _report_parse_errors(parse_errors: Sequence[Dict[str, Any]]) -> int:
    if not parse_errors:
        return 0
    print(
        f"[WARN] {len(parse_errors)} file(s) failed to parse; structural graph is incomplete:",
        file=sys.stderr,
    )
    for err in parse_errors[:20]:
        print(f"  - {err['file']}:{err['line']} — {err['message']}", file=sys.stderr)
    return 2


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cmd = args.subcommand

    if cmd == "profile":
        data = profile_symbol(args.symbol, [Path(p) for p in args.paths])
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print(f"Symbol: {data['symbol']} ({len(data['definitions'])} definition(s), {data['caller_count']} caller(s))")
            for d in data["definitions"]:
                print(f"  [DEF] {d['file']}:{d['line']} — {d['signature']}")
            for c in data["callers"]:
                print(f"  [CALL] {c['file']}:{c['line']} in {c['enclosing_scope']} -> {c['qualified_hint']}({', '.join(c['args'])})")
        return _report_parse_errors(data.get("parse_errors", ()))

    if cmd == "callers":
        path_objs = [Path(p) for p in args.paths]
        callers = find_callers(args.symbol, path_objs)
        parse_errors = list(getattr(callers, "parse_errors", ()))
        if args.json:
            if parse_errors:
                print(json.dumps({
                    "symbol": args.symbol,
                    "complete": False,
                    "callers": list(callers),
                    "parse_errors": parse_errors,
                }, indent=2))
            else:
                print(json.dumps(list(callers), indent=2))
        else:
            print(f"Callers of `{args.symbol}` ({len(callers)}):")
            for c in callers:
                print(f"  {c['file']}:{c['line']} [{c['enclosing_scope']}] -> {c['qualified_hint']}({', '.join(c['args'])})")
        return _report_parse_errors(parse_errors)

    if cmd == "flow":
        data = trace_data_flow(args.symbol, [Path(p) for p in args.paths])
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print(f"Dataflow for `{args.symbol}` ({data['call_site_count']} call site(s)):")
            for b, f in zip(data["backflow"], data["forwardflow"]):
                print(f"  {b['file']}:{b['line']} [{b['enclosing_scope']}]")
                print(f"    Backflow (args): {b['args']} | origins: {b['arg_origins']}")
                print(f"    Forwardflow: assigned_to={f['assigned_to']} | returned={f['returned_directly']} | uses={f['subsequent_uses']}")
        return _report_parse_errors(data.get("parse_errors", ()))

    if cmd == "blast-radius":
        data = compute_blast_radius(args.symbol, [Path(p) for p in args.paths], max_depth=args.max_depth)
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print(f"Blast Radius for `{args.symbol}`: {data['affected_file_count']} file(s) -> {data['tier_recommendation']}")
            for f in data["affected_files"]:
                print(f"  - {f}")
        return _report_parse_errors(data.get("parse_errors", ()))

    if cmd == "gate-syntax":
        data = gate_syntax([Path(p) for p in args.paths])
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            status = "PASS" if data["passed"] else "FAIL"
            print(f"[{status}] Syntax gate checked {data['checked_count']} file(s), {len(data['errors'])} error(s).")
            for err in data["errors"]:
                print(f"  {err['file']}:{err['line']} — {err['error']}")
        return 0 if data["passed"] else 1

    if cmd == "trace":
        s_args = list(args.script_args)
        if s_args and s_args[0] == "--":
            s_args = s_args[1:]
        root = Path(args.root) if args.root else None
        data = trace_runtime(
            Path(args.script),
            s_args,
            root_dir=root,
            max_events=args.max_events,
            timeout_sec=args.timeout,
        )
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print(f"Runtime Trace ({data['event_count']} event(s)):")
            for edge in data["unique_call_edges"]:
                print(f"  {edge}")
            if data["error"]:
                print(f"  [ERROR] {data['error']}")
        return 1 if data["error"] else 0

    if cmd == "fts-search":
        data = fts_search(
            args.query,
            [Path(p) for p in args.paths],
            top_k=args.top,
            chunk_lines=args.chunk_lines,
        )
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print(f"FTS5 Search `{args.query}` ({len(data['results'])} result(s) across {data['chunk_count']} chunk(s)):")
            for r in data["results"]:
                print(f"  {r['file']}:L{r['start_line']}-L{r['end_line']} (score={r['score']})")
                for line in r["snippet"].splitlines()[:3]:
                    print(f"    | {line}")
        return _report_parse_errors(data.get("parse_errors", ()))

    return 0


if __name__ == "__main__":
    sys.exit(main())
