"""
guard/test_boundary.py — Test & Configuration Trust Boundary and Reproducibility Gate
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Semantics (aligned with GEMINI.md Rule 9):
- New test files are always permitted (regression tests are encouraged).
- 'bugfix' mode: existing test and runner-config files must stay byte-identical.
- 'tdd' mode: existing test files may be EXTENDED (pure line additions) as long as the
  added lines contain no skip/xfail/disable markers; any removed or changed line blocks.
  Additions that weaken existing tests in other ways also block: runtime skips, early
  returns, process exits, monkeypatched assertions or TestCase machinery and, for Python
  (compared on the syntax tree), redefinitions shadowing an existing class, function or test.
- Runner configuration and fixtures may never change without explicit authorization.
The baseline lives in the per-user state directory or is computed from a git ref.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import os
import re
import subprocess
import sys
import unittest
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union

from guard.paths import atomic_write_json, is_within, path_key, state_dir

TEXT_SNAPSHOT_LIMIT = 256 * 1024

WEAKENING_LINE_PATTERNS = [
    re.compile(r"@pytest\.mark\.(skip|skipif|xfail)\b"),
    re.compile(r"\b(unittest\.)?skip(If|Unless)?\s*\("),
    re.compile(r"\b(it|test|describe)\.(skip|todo)\s*\("),
    re.compile(r"\bx(it|describe|test)\s*\("),
    re.compile(r"\bt\.Skip(Now|f)?\s*\("),
    re.compile(r"@(Disabled|Ignore)\b"),
    re.compile(r"^\s*(#|//)\s*(assert|expect|self\.assert)"),
    # Runtime skips requested from inside a test (unittest and pytest helpers).
    re.compile(r"\bskipTest\s*\("),
    re.compile(r"\bSkipTest\b"),
    re.compile(r"\bpytest\.(skip|xfail|exit|importorskip)\s*\("),
    # Neutralising the unittest base class itself, or ending the process before results are reported.
    re.compile(r"\bTestCase\s*\.\s*\w+\s*=(?!=)"),
    re.compile(r"\bpatch(\.object|\.multiple)?\s*\(\s*['\"]?[\w.]*TestCase\b"),
    re.compile(r"\bos\._exit\s*\("),
]

# Python additions that are ambiguous on a single line (a fake runner may define `run`, a string may
# hold `sys.exit(0)`). For Python test files that parse, the syntax-tree comparison in
# TestBoundaryGuard.python_weakening decides; these patterns apply only when parsing fails.
UNPARSABLE_PYTHON_LINE_PATTERNS = [
    re.compile(r"^\s*return\s*(None\s*)?(#.*)?$"),
    re.compile(r"^\s*[A-Z]\w*(\.\w+)*\.test\w*\s*=(?!=)"),
    re.compile(r"^\s*del\s+[A-Z]\w*(\.\w+)*\.test\w*"),
    re.compile(r"\b(setattr|delattr)\s*\([^,()]+,\s*['\"](test|assert|fail)\w*['\"]"),
    re.compile(r"\b(setattr|delattr)\s*\(\s*(builtins|__builtins__|globals\s*\(\s*\)|locals\s*\(\s*\)|vars\s*\(\s*\))"),
    re.compile(r"\b(globals|locals|vars)\s*\(\s*\)\s*(\.|\[)"),
    re.compile(r"\b(builtins|__builtins__)\s*(\.|\[)"),
    re.compile(r"\.\s*(assert[A-Z_]\w*|fail[A-Z]\w*|fail|failureException)\s*=(?!=)"),
    re.compile(r"\b(self|cls|[A-Z]\w*)\.(run|debug|__call__)\s*=(?!=)"),
    re.compile(r"^\s*(sys\.exit|exit|quit)\s*\("),
    re.compile(r"^\s*raise\s+SystemExit\b"),
]

# unittest.TestCase machinery that a test module must never replace or monkeypatch.
_ASSERTION_NAMES = frozenset(
    {n for n in dir(unittest.TestCase) if n.startswith(("assert", "fail"))}
    | {
        "assertAlmostEqual", "assertCountEqual", "assertDictEqual", "assertEndsWith", "assertEqual", "assertFalse",
        "assertGreater", "assertGreaterEqual", "assertHasAttr", "assertIn", "assertIs", "assertIsInstance",
        "assertIsNone", "assertIsNot", "assertIsNotNone", "assertIsSubclass", "assertLess", "assertLessEqual",
        "assertListEqual", "assertLogs", "assertMultiLineEqual", "assertNoLogs", "assertNotAlmostEqual",
        "assertNotEndsWith", "assertNotEqual", "assertNotHasAttr", "assertNotIn", "assertNotIsInstance",
        "assertNotIsSubclass", "assertNotRegex", "assertNotStartsWith", "assertRaises", "assertRaisesRegex",
        "assertRegex", "assertSequenceEqual", "assertSetEqual", "assertStartsWith", "assertTrue", "assertTupleEqual",
        "assertWarns", "assertWarnsRegex", "fail", "failureException",
        # Deprecated aliases (removed in newer Pythons, still honoured by older ones).
        "assertEquals", "assertNotEquals", "assertAlmostEquals", "assertNotAlmostEquals", "assert_",
        "assertRaisesRegexp", "assertRegexpMatches", "assertNotRegexpMatches", "assertDictContainsSubset",
        "failUnless", "failIf", "failUnlessEqual", "failIfEqual", "failUnlessAlmostEqual", "failIfAlmostEqual",
        "failUnlessRaises",
    }
)
_RUNNER_HOOKS = frozenset({
    "run", "debug", "__call__", "skipTest", "subTest", "doCleanups", "defaultTestResult",
    "_callTestMethod", "_callSetUp", "_callTearDown", "_callCleanup", "_addSkip",
})
_TESTCASE_MACHINERY = _ASSERTION_NAMES | _RUNNER_HOOKS
_EXIT_CALLS = frozenset({"sys.exit", "os._exit", "_exit", "exit", "quit", "pytest.exit"})
_SKIP_CALLS = frozenset({"pytest.skip", "pytest.xfail", "pytest.importorskip", "skip", "xfail", "importorskip"})
_NAMESPACE_FUNCS = frozenset({"globals", "locals", "vars"})
_BUILTIN_NAMES = frozenset({"builtins", "__builtins__"})
_NAMESPACE_DUNDERS = frozenset({"__dict__", "__globals__", "__builtins__"})
_NAMESPACE_MUTATING_METHODS = frozenset({
    "__setitem__", "__delitem__", "update", "pop", "popitem", "clear", "setdefault",
    "__setattr__", "__delattr__",
})
_DYNAMIC_EXEC_CALLS = frozenset({
    "exec", "eval", "builtins.exec", "builtins.eval", "__builtins__.exec", "__builtins__.eval",
})
# "Skip" "Test" is split on purpose: this module's name matches test_*.py, so its own added
# lines are graded by WEAKENING_LINE_PATTERNS too.
_ABORT_EXCEPTIONS = frozenset({"Skip" "Test", "SystemExit"})


def _dotted_name(node: Optional[ast.AST]) -> str:
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _flatten_targets(targets: Sequence[ast.AST]) -> List[ast.AST]:
    flat: List[ast.AST] = []
    for target in targets:
        if isinstance(target, (ast.Tuple, ast.List)):
            flat.extend(_flatten_targets(target.elts))
        elif isinstance(target, ast.Starred):
            flat.extend(_flatten_targets([target.value]))
        else:
            flat.append(target)
    return flat


def _count_returns(body: Sequence[ast.stmt]) -> int:
    """Return statements of a function body, not counting nested functions, lambdas or classes."""
    count = 0
    stack: List[ast.AST] = list(body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Return):
            count += 1
        stack.extend(ast.iter_child_nodes(node))
    return count


def _is_abort_statement(stmt: ast.stmt) -> bool:
    """return / skip / exit as a statement: nothing after it in the test body runs."""
    if isinstance(stmt, ast.Return):
        return True
    if isinstance(stmt, ast.Raise) and stmt.exc is not None:
        exc = stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc
        return _dotted_name(exc).split(".")[-1] in _ABORT_EXCEPTIONS
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        name = _dotted_name(stmt.value.func)
        return name.split(".")[-1] == "skipTest" or name in _EXIT_CALLS or name in _SKIP_CALLS
    return False


def _starts_by_aborting(body: Sequence[ast.stmt]) -> bool:
    for stmt in body:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
            continue  # docstring
        return _is_abort_statement(stmt)
    return False


def _is_test_like_name(name: str) -> bool:
    return name.startswith("Test") or name.endswith(("Test", "Tests", "TestCase"))


class _PythonTestFacts:
    """Structural facts of a Python test module, compared before/after to catch weakening additions."""

    def __init__(self, tree: ast.Module):
        self.defined: Set[str] = set()          # qualified names of classes/functions/methods
        self.test_classes: Set[str] = set()     # classes that are (or derive from) test cases
        self.test_names: Set[str] = set()       # bare names of test functions/methods
        self.bindings: Dict[str, int] = {}      # qualified name -> how often it is (re)bound
        self.local_bindings: Dict[str, int] = {}            # function-local variable bindings
        self.aliases: Dict[Tuple[str, str], int] = {}       # (lhs_name, rhs_dotted) -> count
        self.namespace_aliases: Set[str] = set()            # variables bound to globals()/vars()/builtins/etc.
        self.test_class_aliases: Dict[str, str] = {}        # alias_name -> test class name
        self.returns: Dict[str, int] = {}       # test qualified name -> return statements in its body
        self.aborting: Set[str] = set()         # tests whose first statement returns/skips/exits
        self.overrides: Set[str] = set()        # test-class members replacing TestCase machinery
        self.pytest_hooks: Set[str] = set()     # pytest_* hook functions added to test module
        self.tampering: Dict[str, int] = {}     # "how owner.attr" -> count
        self.exits = 0
        self._scope(tree.body, "", test_class=None)
        self._collect_aliases_and_locals(tree, in_function=False, global_names=frozenset())
        self._scan(tree, in_test_class=False)

    def _bind(self, qualname: str) -> None:
        self.bindings[qualname] = self.bindings.get(qualname, 0) + 1

    def _record_tamper(self, key: str) -> None:
        self.tampering[key] = self.tampering.get(key, 0) + 1

    def _namespace_label(self, expr: Optional[ast.AST]) -> Optional[str]:
        if expr is None:
            return None
        if isinstance(expr, ast.Call):
            fn = _dotted_name(expr.func).split(".")[-1]
            if fn in ("globals", "locals"):
                return f"{fn}()"
            if fn == "vars":
                if not expr.args and not expr.keywords:
                    return "vars()"
                if expr.args:
                    arg0 = _dotted_name(expr.args[0])
                    arg0_leaf = arg0.split(".")[-1] if arg0 else ""
                    if (
                        arg0 in _BUILTIN_NAMES
                        or arg0 in ("self", "cls")
                        or arg0 in self.test_classes
                        or arg0 in self.test_class_aliases
                        or _is_test_like_name(arg0_leaf)
                        or (isinstance(expr.args[0], ast.Subscript) and _dotted_name(expr.args[0].value) == "sys.modules")
                    ):
                        return "vars(...)"
            if (
                fn == "getattr"
                and len(expr.args) >= 2
                and isinstance(expr.args[1], ast.Constant)
                and expr.args[1].value in _NAMESPACE_DUNDERS
            ):
                return f"getattr(..., {expr.args[1].value!r})"
            return None
        if isinstance(expr, ast.Name):
            if expr.id in _BUILTIN_NAMES:
                return expr.id
            if expr.id in self.namespace_aliases:
                return f"alias:{expr.id}"
            return None
        if isinstance(expr, ast.Attribute):
            if expr.attr in _NAMESPACE_DUNDERS:
                owner = _dotted_name(expr.value) or "<expr>"
                return f"{owner}.{expr.attr}"
            dotted = _dotted_name(expr)
            if dotted and dotted.split(".")[0] in _BUILTIN_NAMES:
                return dotted
            return None
        if isinstance(expr, ast.Subscript) and _dotted_name(expr.value) == "sys.modules":
            return "sys.modules[...]"
        return None

    def _collect_direct_globals(self, stmts: Sequence[ast.stmt]) -> Set[str]:
        found: Set[str] = set()
        stack: List[ast.AST] = list(stmts)
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                found.update(node.names)
            stack.extend(ast.iter_child_nodes(node))
        return found

    def _record_local_targets(
        self,
        targets: Sequence[ast.AST],
        value: Optional[ast.AST],
        in_function: bool,
        global_names: frozenset[str],
    ) -> None:
        flat = _flatten_targets(targets)
        for target in flat:
            if isinstance(target, ast.Name):
                lhs = target.id
                if in_function:
                    if lhs in global_names:
                        self._bind(lhs)
                    else:
                        self.local_bindings[lhs] = self.local_bindings.get(lhs, 0) + 1
                if value is not None:
                    if self._namespace_label(value) is not None:
                        self.namespace_aliases.add(lhs)
                    rhs = _dotted_name(value)
                    if rhs:
                        pair = (lhs, rhs)
                        self.aliases[pair] = self.aliases.get(pair, 0) + 1
                        if rhs in self.test_classes:
                            self.test_class_aliases[lhs] = rhs
                        elif rhs in self.test_class_aliases:
                            self.test_class_aliases[lhs] = self.test_class_aliases[rhs]

    def _collect_aliases_and_locals(
        self,
        node: ast.AST,
        in_function: bool,
        global_names: frozenset[str],
    ) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if in_function:
                    if child.name in global_names:
                        self._bind(child.name)
                    else:
                        self.local_bindings[child.name] = self.local_bindings.get(child.name, 0) + 1
                fn_globals = frozenset(self._collect_direct_globals(child.body))
                self._collect_aliases_and_locals(child, in_function=True, global_names=fn_globals)
                continue
            if isinstance(child, ast.ClassDef):
                if in_function:
                    if child.name in global_names:
                        self._bind(child.name)
                    else:
                        self.local_bindings[child.name] = self.local_bindings.get(child.name, 0) + 1
                self._collect_aliases_and_locals(child, in_function=False, global_names=frozenset())
                continue
            if isinstance(child, ast.Assign):
                self._record_local_targets(child.targets, child.value, in_function, global_names)
            elif isinstance(child, ast.AnnAssign) and child.value is not None:
                self._record_local_targets([child.target], child.value, in_function, global_names)
            elif isinstance(child, ast.AugAssign):
                self._record_local_targets([child.target], child.value, in_function, global_names)
            elif isinstance(child, ast.NamedExpr):
                self._record_local_targets([child.target], child.value, in_function, global_names)
            elif isinstance(child, ast.Delete):
                self._record_local_targets(child.targets, None, in_function, global_names)
            elif isinstance(child, (ast.For, ast.AsyncFor)):
                self._record_local_targets([child.target], None, in_function, global_names)
            elif isinstance(child, (ast.With, ast.AsyncWith)):
                opt_targets = [i.optional_vars for i in child.items if i.optional_vars is not None]
                if opt_targets:
                    self._record_local_targets(opt_targets, None, in_function, global_names)
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                for alias in child.names:
                    if alias.name == "*":
                        continue
                    bound = alias.asname or alias.name.split(".")[0]
                    if in_function:
                        if bound in global_names:
                            self._bind(bound)
                        else:
                            self.local_bindings[bound] = self.local_bindings.get(bound, 0) + 1
                    if alias.name.split(".")[0] == "builtins" and bound != "builtins":
                        self.namespace_aliases.add(bound)
            self._collect_aliases_and_locals(child, in_function=in_function, global_names=global_names)

    def _bind_targets(self, targets: Sequence[ast.AST], prefix: str, test_class: Optional[bool]) -> None:
        for target in _flatten_targets(targets):
            if isinstance(target, ast.Name):
                self._bind(prefix + target.id)
                if test_class and target.id in _TESTCASE_MACHINERY:
                    self.overrides.add(prefix + target.id)

    def _scope(self, stmts: Sequence[ast.stmt], prefix: str, test_class: Optional[bool]) -> None:
        """Walks module/class-level statements (not function bodies). test_class is None outside classes."""
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = prefix + stmt.name
                self.defined.add(qualname)
                self._bind(qualname)
                if stmt.name.startswith("pytest_"):
                    self.pytest_hooks.add(qualname)
                if test_class and stmt.name in _TESTCASE_MACHINERY:
                    self.overrides.add(qualname)
                if stmt.name.startswith("test"):
                    self.test_names.add(stmt.name)
                    self.returns[qualname] = self.returns.get(qualname, 0) + _count_returns(stmt.body)
                    if _starts_by_aborting(stmt.body):
                        self.aborting.add(qualname)
            elif isinstance(stmt, ast.ClassDef):
                qualname = prefix + stmt.name
                bases = [_dotted_name(b).split(".")[-1] for b in stmt.bases]
                is_test = _is_test_like_name(stmt.name) or any(
                    _is_test_like_name(b) or b in self.test_classes or b in self.test_class_aliases
                    for b in bases
                )
                if is_test:
                    self.test_classes.add(stmt.name)
                self.defined.add(qualname)
                self._bind(qualname)
                self._scope(stmt.body, qualname + ".", test_class=is_test)
            elif isinstance(stmt, ast.Assign):
                self._bind_targets(stmt.targets, prefix, test_class)
            elif isinstance(stmt, (ast.AugAssign, ast.AnnAssign)):
                if not isinstance(stmt, ast.AnnAssign) or stmt.value is not None:
                    self._bind_targets([stmt.target], prefix, test_class)
            elif isinstance(stmt, ast.Delete):
                self._bind_targets(stmt.targets, prefix, test_class)
            elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
                for alias in stmt.names:
                    if alias.name != "*":
                        self._bind(prefix + (alias.asname or alias.name.split(".")[0]))
            else:
                if isinstance(stmt, (ast.For, ast.AsyncFor)):
                    self._bind_targets([stmt.target], prefix, test_class)
                if isinstance(stmt, (ast.With, ast.AsyncWith)):
                    self._bind_targets([i.optional_vars for i in stmt.items if i.optional_vars is not None],
                                       prefix, test_class)
                for block_name in ("body", "orelse", "finalbody"):
                    block = getattr(stmt, block_name, None)
                    if isinstance(block, list):
                        self._scope(block, prefix, test_class)
                for handler in getattr(stmt, "handlers", None) or []:
                    self._scope(handler.body, prefix, test_class)
                for case in getattr(stmt, "cases", None) or []:
                    self._scope(case.body, prefix, test_class)

    def _tamper(self, how: str, owner_expr: str, attr: str, in_test_class: bool) -> None:
        """Records assignments/patches that replace tests, builtins, or TestCase machinery."""
        owner_root = owner_expr.split(".")[0] if owner_expr else ""
        if owner_root in _BUILTIN_NAMES or owner_root in self.namespace_aliases:
            if how == "patch" and attr in ("open", "input", "print"):
                return
            self._record_tamper(f"{how} {owner_expr or '<expr>'}.{attr}")
            return
        owner = owner_expr.split(".")[-1] if owner_expr else ""
        if owner in self.test_class_aliases:
            on_test_class = True
            replaces_test = attr.startswith("test") or attr in self.test_names
        elif owner in ("self", "cls"):
            on_test_class = in_test_class
            replaces_test = attr in self.test_names       # self.test_dir = ... is just data
        else:
            on_test_class = owner in self.test_classes or _is_test_like_name(owner)
            replaces_test = attr.startswith("test")
        if on_test_class and (attr in _TESTCASE_MACHINERY or replaces_test or attr == "*"):
            self._record_tamper(f"{how} {owner_expr or '<expr>'}.{attr}")

    def _tamper_dotted_string(self, how: str, node: ast.AST, in_test_class: bool) -> None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and "." in node.value:
            owner_expr, attr = node.value.rsplit(".", 1)
            self._tamper(how, owner_expr, attr, in_test_class)

    def _scan(self, node: ast.AST, in_test_class: bool) -> None:
        """Walks every node, tracking whether `self`/`cls` refer to a test class."""
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                self._scan(child, child.name in self.test_classes)
                continue
            self._inspect(child, in_test_class)
            self._scan(child, in_test_class)

    def _inspect(self, node: ast.AST, in_test_class: bool) -> None:
        if isinstance(node, ast.Call):
            name = _dotted_name(node.func)
            last = name.split(".")[-1]
            args = node.args
            if name in _EXIT_CALLS:
                self.exits += 1
            elif name in _DYNAMIC_EXEC_CALLS:
                self._record_tamper(f"call {name}")
            else:
                if isinstance(node.func, ast.Attribute):
                    ns_recv = self._namespace_label(node.func.value)
                    if ns_recv is not None and node.func.attr in _NAMESPACE_MUTATING_METHODS:
                        self._record_tamper(f"namespace.{ns_recv}.{node.func.attr}")
                if last in ("setattr", "delattr", "__setattr__", "__delattr__") and args:
                    ns_target = self._namespace_label(args[0])
                    if ns_target is not None:
                        attr_lbl = (
                            args[1].value
                            if len(args) >= 2 and isinstance(args[1], ast.Constant) and isinstance(args[1].value, str)
                            else "*"
                        )
                        if ns_target == "sys.modules[...]":
                            if (
                                attr_lbl == "*"
                                or attr_lbl.startswith(("test", "pytest_"))
                                or attr_lbl in _TESTCASE_MACHINERY
                                or attr_lbl in self.test_classes
                            ):
                                self._record_tamper(f"{last} sys.modules[...].{attr_lbl}")
                        else:
                            self._record_tamper(f"{last} {ns_target}.{attr_lbl}")
                    elif len(args) >= 2 and isinstance(args[1], ast.Constant) and isinstance(args[1].value, str):
                        self._tamper(last, _dotted_name(args[0]), args[1].value, in_test_class)
                    else:  # monkeypatch.setattr("pkg.Class.attr", value)
                        self._tamper_dotted_string(last, args[0], in_test_class)
                elif last in ("setitem", "delitem", "__setitem__", "__delitem__") and args:
                    ns_target = self._namespace_label(args[0])
                    if ns_target is not None:
                        self._record_tamper(f"{last} {ns_target}[...]")
                elif last == "patch" and args:
                    self._tamper_dotted_string("patch", args[0], in_test_class)
                elif name.endswith("patch.object") and args:
                    ns_target = self._namespace_label(args[0])
                    attr_val = (
                        args[1].value
                        if len(args) >= 2 and isinstance(args[1], ast.Constant) and isinstance(args[1].value, str)
                        else "*"
                    )
                    if ns_target is not None and attr_val not in ("open", "input", "print"):
                        self._record_tamper(f"patch {ns_target}.{attr_val}")
                    elif attr_val != "*":
                        self._tamper("patch", _dotted_name(args[0]), attr_val, in_test_class)
                elif name.endswith("patch.multiple") and args:
                    ns_target = self._namespace_label(args[0])
                    if ns_target is not None:
                        self._record_tamper(f"patch {ns_target}.*")
                    else:
                        self._tamper("patch", _dotted_name(args[0]), "*", in_test_class)
        elif isinstance(node, ast.Raise) and node.exc is not None:
            exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            if _dotted_name(exc).split(".")[-1] == "SystemExit":
                self.exits += 1
        elif isinstance(node, (ast.Assign, ast.Delete, ast.AugAssign, ast.AnnAssign, ast.NamedExpr)):
            if isinstance(node, (ast.Assign, ast.Delete)):
                targets = node.targets
            else:
                targets = [node.target]
            how = "del" if isinstance(node, ast.Delete) else "assignment"
            for target in _flatten_targets(targets):
                if isinstance(target, ast.Attribute):
                    ns_owner = self._namespace_label(target.value)
                    if ns_owner == "sys.modules[...]":
                        if (
                            target.attr.startswith(("test", "pytest_"))
                            or target.attr in _TESTCASE_MACHINERY
                            or target.attr in self.test_classes
                        ):
                            self._record_tamper(f"{how} sys.modules[...].{target.attr}")
                    elif ns_owner is not None:
                        self._record_tamper(f"{how} {ns_owner}.{target.attr}")
                    else:
                        self._tamper(how, _dotted_name(target.value), target.attr, in_test_class)
                elif isinstance(target, ast.Subscript):
                    ns_owner = self._namespace_label(target.value)
                    if ns_owner is not None:
                        self._record_tamper(f"{how} {ns_owner}[...]")


@dataclass
class TestBoundaryReport:
    __test__ = False
    timestamp: str
    workspace_dir: str
    mode: str
    total_files: int
    is_intact: bool
    modified: List[str] = field(default_factory=list)
    added: List[str] = field(default_factory=list)
    deleted: List[str] = field(default_factory=list)
    violations: List[str] = field(default_factory=list)
    fixture_modifications: List[str] = field(default_factory=list)
    extended: List[str] = field(default_factory=list)
    baseline_source: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)

    def summary(self) -> str:
        if self.is_intact:
            extra = f", {len(self.added)} new" if self.added else ""
            extra += f", {len(self.extended)} extended" if self.extended else ""
            return f"[OK] Test & Config Boundary Verified ({self.total_files} files intact in '{self.mode}' mode{extra})."
        reasons = []
        if self.modified:
            reasons.append(f"{len(self.modified)} modified")
        if self.deleted:
            reasons.append(f"{len(self.deleted)} deleted")
        if self.fixture_modifications:
            reasons.append(f"{len(self.fixture_modifications)} fixtures/data altered")
        if not reasons and self.violations:
            reasons.append(self.violations[0])
        return f"[BLOCKED] Test Boundary Violated: {', '.join(reasons)}."


class TestBoundaryGuard:
    """
    Guards test suites and configuration files as an external trust boundary.
    Separates 'agent got exit code 0' from 'implementation satisfied the contract'.
    """
    __test__ = False

    KNOWN_CONFIG_NAMES: Set[str] = {
        "pytest.ini", "setup.cfg", "pyproject.toml", "tox.ini", ".flake8", "tsconfig.json", "package.json",
        "jest.config.js", "jest.config.ts", "jest.config.mjs", "jest.config.cjs", "jest.config.json",
        ".eslintrc", ".eslintrc.json", ".eslintrc.js", ".eslintrc.yaml", ".eslintrc.yml",
        "vitest.config.ts", "vitest.config.js", "Cargo.toml", "go.mod", "pom.xml", "build.gradle",
    }
    TEST_DIR_NAMES: Set[str] = {"tests", "test", "__tests__", "spec", "specs"}
    TEST_FILE_PATTERNS = [
        re.compile(r"^test_.*\.py$"),
        re.compile(r"^.*_test\.py$"),
        re.compile(r"^conftest\.py$"),
        re.compile(r"^.*_test\.go$"),
        re.compile(r"^.*_test\.rs$"),
        re.compile(r"^.*\.(test|spec)\.[cm]?[jt]sx?$"),
        re.compile(r"^.*_spec\.rb$"),
        re.compile(r"^.*Tests?\.(java|kt|cs)$"),
    ]
    EXCLUDED_PATTERNS: Set[str] = {
        "__pycache__", ".git", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules",
        ".harness", ".guard_snapshots", ".DS_Store", ".venv", "venv", "dist", "build",
    }
    FIXTURE_EXTENSIONS: Set[str] = {".json", ".yaml", ".yml", ".csv", ".tsv", ".xml", ".txt", ".sql"}

    def __init__(self, workspace_dir: Optional[Path] = None, state_file: Optional[Path] = None):
        self.workspace_dir = Path(workspace_dir).resolve() if workspace_dir else Path.cwd().resolve()
        self.legacy_state_file = self.workspace_dir / ".harness" / "test_boundary.json"
        if state_file:
            self.state_file = Path(state_file).resolve()
        else:
            self.state_file = state_dir() / "test_boundary" / f"{path_key(self.workspace_dir)}.json"
        self.last_commands: List[str] = []

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def is_test_file(self, rel_path: str) -> bool:
        parts = Path(rel_path).parts
        name = parts[-1] if parts else rel_path
        if any(part in self.TEST_DIR_NAMES for part in parts[:-1]):
            return True
        return any(p.match(name) for p in self.TEST_FILE_PATTERNS)

    def _tracked(self, rel_path: str) -> bool:
        parts = Path(rel_path).parts
        if not parts or any(part in self.EXCLUDED_PATTERNS for part in parts):
            return False
        if len(parts) == 1 and parts[0] in self.KNOWN_CONFIG_NAMES:
            return True
        if parts[-1].startswith(".") or parts[-1].endswith(".pyc"):
            return False
        if any(part.startswith(".") for part in parts[:-1]):
            return False
        return self.is_test_file(rel_path)

    @staticmethod
    def _hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _as_text(data: bytes) -> Optional[str]:
        if len(data) > TEXT_SNAPSHOT_LIMIT:
            return None
        try:
            return data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        except UnicodeDecodeError:
            return None

    @classmethod
    def _normalize_text_and_hash(cls, data: bytes) -> Tuple[str, Optional[str]]:
        try:
            decoded = data.decode("utf-8")
        except UnicodeDecodeError:
            return cls._hash_bytes(data), None
        normalized = decoded.replace("\r\n", "\n").replace("\r", "\n")
        digest = cls._hash_bytes(normalized.encode("utf-8"))
        text = normalized if len(data) <= TEXT_SNAPSHOT_LIMIT else None
        return digest, text

    def _discover(self) -> Tuple[Dict[str, str], Dict[str, str]]:
        hashes: Dict[str, str] = {}
        contents: Dict[str, str] = {}
        ws_root = self.workspace_dir.resolve()
        for root, dirs, files in os.walk(self.workspace_dir, followlinks=False):
            kept_dirs: List[str] = []
            for d in sorted(dirs):
                if d in self.EXCLUDED_PATTERNS or d.startswith("."):
                    continue
                dir_path = Path(root) / d
                if dir_path.is_symlink():
                    continue
                try:
                    if not is_within(dir_path.resolve(), ws_root):
                        continue
                except OSError:
                    continue
                kept_dirs.append(d)
            dirs[:] = kept_dirs
            for f in sorted(files):
                path = Path(root) / f
                if path.is_symlink():
                    continue
                try:
                    resolved = path.resolve()
                except OSError:
                    continue
                if not is_within(resolved, ws_root) or not resolved.is_file():
                    continue
                rel = path.relative_to(self.workspace_dir).as_posix()
                if not self._tracked(rel):
                    continue
                data = resolved.read_bytes()
                digest, text = self._normalize_text_and_hash(data)
                hashes[rel] = digest
                if text is not None:
                    contents[rel] = text
        return hashes, contents

    def discover_files(self) -> Dict[str, str]:
        """Returns relative path -> SHA-256 for tests, fixtures and root runner configs."""
        return self._discover()[0]

    def baseline_from_git_ref(self, ref: str) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Computes the boundary baseline directly from a git ref (e.g. origin/main) — no stored state."""
        listing = subprocess.run(
            ["git", "-C", str(self.workspace_dir), "ls-tree", "-r", "--name-only", ref],
            capture_output=True, text=True, check=True, timeout=15,
        )
        hashes: Dict[str, str] = {}
        contents: Dict[str, str] = {}
        for rel in listing.stdout.splitlines():
            if not self._tracked(rel):
                continue
            blob = subprocess.run(
                ["git", "-C", str(self.workspace_dir), "show", f"{ref}:{rel}"],
                capture_output=True, check=True, timeout=15,
            ).stdout
            digest, text = self._normalize_text_and_hash(blob)
            hashes[rel] = digest
            if text is not None:
                contents[rel] = text
        return hashes, contents

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------
    def snapshot(self, target_path: Optional[Path] = None) -> Tuple[int, Path]:
        """Creates or updates the baseline snapshot of the test/config tree."""
        from guard import __version__

        dest = Path(target_path).resolve() if target_path else self.state_file
        hashes, contents = self._discover()
        payload = {
            "version": __version__,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "workspace": str(self.workspace_dir),
            "total_files": len(hashes),
            "files": hashes,
            "contents": contents,
            "authorized": sorted(self.load_authorized_from_tasks_md(self.workspace_dir)),
        }
        atomic_write_json(dest, payload)
        return len(hashes), dest

    def _snapshot_source(self, target_path: Optional[Path]) -> Path:
        if target_path:
            return Path(target_path).resolve()
        if not self.state_file.exists() and self.legacy_state_file.exists():
            return self.legacy_state_file
        return self.state_file

    def load_snapshot(self, target_path: Optional[Path] = None) -> Optional[Dict[str, str]]:
        data = self._load_payload(target_path)
        return data.get("files", {}) if isinstance(data, dict) else None

    def _load_payload_status(self, target_path: Optional[Path] = None) -> Tuple[Optional[Dict], str]:
        dest = self._snapshot_source(target_path)
        if not os.path.lexists(dest):
            return None, "missing"
        if os.path.islink(dest) or not dest.is_file():
            return None, "corrupt"
        try:
            data = json.loads(dest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None, "corrupt"
        if not isinstance(data, dict):
            return None, "corrupt"
        raw_files = data.get("files")
        if not isinstance(raw_files, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in raw_files.items()
        ):
            return None, "corrupt"
        raw_contents = data.get("contents", {})
        if not isinstance(raw_contents, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in raw_contents.items()
        ):
            return None, "corrupt"
        return data, "ok"

    def _load_payload(self, target_path: Optional[Path] = None) -> Optional[Dict]:
        return self._load_payload_status(target_path)[0]

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------
    @staticmethod
    def _body_lines_after_module_docstring(tree: ast.Module, text: str) -> List[str]:
        lines = text.splitlines()
        if (
            tree.body
            and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)
            and isinstance(tree.body[0].value.value, str)
        ):
            end_ln = getattr(tree.body[0], "end_lineno", 0) or 0
            return lines[end_ln:]
        return lines

    @staticmethod
    def _line_changes(old: str, new: str) -> Tuple[List[str], List[str]]:
        removed, added = [], []
        for line in difflib.ndiff(old.splitlines(), new.splitlines()):
            if line.startswith("- "):
                removed.append(line[2:])
            elif line.startswith("+ "):
                added.append(line[2:])
        return removed, added

    @staticmethod
    def weakening_lines(lines: Sequence[str]) -> List[str]:
        return [l for l in lines if any(p.search(l) for p in WEAKENING_LINE_PATTERNS)]

    @staticmethod
    def python_weakening(old: str, new: str, added_lines: Sequence[str] = ()) -> List[str]:
        """
        Syntax-tree comparison of a Python test file before/after a pure-addition change.
        Reports shadowing redefinitions, tests that now return/skip first, returns added inside
        existing tests, replaced TestCase machinery, monkeypatched tests/assertions and new process
        exits. Falls back to line patterns when either version cannot be parsed.
        """
        try:
            before = _PythonTestFacts(ast.parse(old))
            after = _PythonTestFacts(ast.parse(new))
        except (SyntaxError, ValueError, RecursionError):
            return [l for l in added_lines if any(p.search(l) for p in UNPARSABLE_PYTHON_LINE_PATTERNS)]
        notes: List[str] = []
        for name in sorted(before.defined):
            if after.bindings.get(name, 0) > before.bindings.get(name, 0):
                notes.append(f"redefines existing '{name}' (shadowing)")
        top_level_protected = before.test_classes | {
            n for n in before.defined if "." not in n and (n.startswith("test") or n in before.test_classes)
        }
        for name in sorted(top_level_protected):
            if after.local_bindings.get(name, 0) > before.local_bindings.get(name, 0):
                notes.append(f"rebinds existing test symbol '{name}' in local scope")
        existing_test_defs = {
            n
            for n in before.defined
            if n in before.test_classes
            or n.split(".")[-1].startswith("test")
            or n.split(".")[0] in before.test_classes
        }
        self_cls_tests = {f"self.{t}" for t in before.test_names} | {f"cls.{t}" for t in before.test_names}
        for (lhs, rhs), count in sorted(after.aliases.items()):
            if count > before.aliases.get((lhs, rhs), 0):
                rhs_root = rhs.split(".")[0]
                if rhs in existing_test_defs or rhs_root in before.test_classes or rhs in self_cls_tests:
                    notes.append(f"aliases existing test symbol '{rhs}' as '{lhs}'")
        newly_aborting = after.aborting - before.aborting
        for name in sorted(newly_aborting):
            notes.append(f"test '{name}' returns or skips before running")
        for name, count in sorted(after.returns.items()):
            if name in before.returns and name not in newly_aborting and count > before.returns[name]:
                notes.append(f"'return' added inside existing test '{name}'")
        for name in sorted(after.overrides - before.overrides):
            notes.append(f"replaces unittest machinery '{name}'")
        for name in sorted(after.pytest_hooks - before.pytest_hooks):
            notes.append(f"adds pytest hook '{name}'")
        for key, count in sorted(after.tampering.items()):
            if count > before.tampering.get(key, 0):
                notes.append(f"monkeypatches tests or assertions ({key})")
        if after.exits > before.exits:
            notes.append("adds a process exit (sys.exit / os._exit / SystemExit)")
        return notes

    _AUTH_HEADING_RE = re.compile(
        r"^#{2,4}[\s\u00a0]+Authorized[\s\u00a0]+Test[\s\u00a0]+Modifications(?:[\s\u00a0]*:[\s\u00a0]*(.*))?$",
        re.IGNORECASE,
    )
    _ANY_HEADING_RE = re.compile(r"^#{1,6}[\s\u00a0]+\S")
    _AUTH_ITEM_PATH_RE = re.compile(
        r"^[\s\u00a0]*(?:[-*•][\s\u00a0]+)?(?:\[[ xX]\][\s\u00a0]+)?\[?[\s\u00a0]*"
        r"(?:`([^`]+)`|([\w./\\-]+(?:\.[\w]+)))[\s\u00a0]*(?:[:—\]-]|$)",
        re.UNICODE,
    )
    _DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:")

    @classmethod
    def _normalize_rel_path(cls, raw: str) -> Optional[str]:
        candidate = raw.strip().replace("\\", "/")
        candidate = re.sub(r"/+", "/", candidate)
        while candidate.startswith("./"):
            candidate = candidate[2:]
        candidate = candidate.rstrip("/")
        if (
            not candidate
            or candidate.startswith("/")
            or cls._DRIVE_PREFIX_RE.match(candidate)
            or ".." in candidate.split("/")
        ):
            return None
        return candidate

    @classmethod
    def _extract_authorized_path(cls, text: str) -> Optional[str]:
        m = cls._AUTH_ITEM_PATH_RE.match(text)
        if not m:
            return None
        return cls._normalize_rel_path(m.group(1) or m.group(2) or "")

    @classmethod
    def parse_authorized_tasks_text(cls, text: str = "", content: Optional[str] = None) -> Set[str]:
        source_text = content if content is not None else text
        normalized_text = source_text.replace("\r\n", "\n").replace("\r", "\n")
        authorized: Set[str] = set()
        in_section = False
        for raw_line in normalized_text.splitlines():
            line = raw_line.strip(" \t\r\n\u00a0")
            heading_match = cls._AUTH_HEADING_RE.match(line)
            if heading_match:
                in_section = True
                inline_tail = (heading_match.group(1) or "").strip(" \t\r\n\u00a0")
                if inline_tail:
                    for part in inline_tail.split(","):
                        extracted = cls._extract_authorized_path(part.strip(" \t\r\n\u00a0"))
                        if extracted:
                            authorized.add(extracted)
                continue
            if in_section and cls._ANY_HEADING_RE.match(line):
                in_section = False
                continue
            if not in_section or not line.startswith(("-", "*", "•", "[")):
                continue
            extracted = cls._extract_authorized_path(raw_line)
            if extracted:
                authorized.add(extracted)
        return authorized

    @classmethod
    def load_authorized_from_tasks_md(cls, workspace_dir: Path) -> Set[str]:
        """
        Parses relative file paths listed under `## Authorized Test Modifications`
        in `<workspace_dir>/tasks.md` (supporting both inline `## Authorized Test Modifications: [file: reason]`
        and multi-line bullet lists per skills/harness/SKILL.md and GEMINI.md Rule 9).
        """
        tasks_file = Path(workspace_dir) / "tasks.md"
        if not tasks_file.is_file():
            return set()
        try:
            content = tasks_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return set()
        return cls.parse_authorized_tasks_text(content)

    def verify(
        self,
        mode: str = "bugfix",
        snapshot_path: Optional[Path] = None,
        authorized_modifications: Optional[Set[str]] = None,
        base_ref: Optional[str] = None,
    ) -> TestBoundaryReport:
        """Verifies current test & config files against the stored snapshot or a git ref."""
        timestamp = datetime.now(timezone.utc).isoformat()
        current, current_contents = self._discover()

        if base_ref:
            authorized: Set[str] = set()
            try:
                baseline, baseline_contents = self.baseline_from_git_ref(base_ref)
                source = f"git:{base_ref}"
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
                return TestBoundaryReport(
                    timestamp=timestamp, workspace_dir=str(self.workspace_dir), mode=mode,
                    total_files=len(current), is_intact=False,
                    violations=[f"BASELINE UNAVAILABLE: could not read git ref '{base_ref}' ({e})."],
                )
            try:
                tasks_blob = subprocess.run(
                    ["git", "-C", str(self.workspace_dir), "show", f"{base_ref}:tasks.md"],
                    capture_output=True,
                    check=True,
                    timeout=15,
                ).stdout
                tasks_text = self._as_text(tasks_blob)
                if tasks_text:
                    authorized = self.parse_authorized_tasks_text(tasks_text)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
                pass
        else:
            payload, payload_status = self._load_payload_status(snapshot_path)
            if payload_status == "missing":
                return TestBoundaryReport(
                    timestamp=timestamp, workspace_dir=str(self.workspace_dir), mode=mode,
                    total_files=len(current), is_intact=False,
                    violations=["BASELINE MISSING: No test boundary snapshot found. Run snapshot first."],
                )
            if payload is None or payload_status != "ok":
                return TestBoundaryReport(
                    timestamp=timestamp, workspace_dir=str(self.workspace_dir), mode=mode,
                    total_files=len(current), is_intact=False,
                    violations=[
                        "BASELINE CORRUPT: Test boundary snapshot is malformed or unreadable; "
                        "do not overwrite without human investigation."
                    ],
                )
            baseline = payload.get("files", {})
            baseline_contents = payload.get("contents", {})
            snap_auth = payload.get("authorized")
            if isinstance(snap_auth, list):
                authorized = {
                    norm
                    for raw_p in snap_auth
                    if isinstance(raw_p, str)
                    for norm in [raw_p.strip().replace("\\", "/").lstrip("./")]
                    if norm and ".." not in norm.split("/")
                }
            else:
                authorized = set()
            source = str(self._snapshot_source(snapshot_path))

        if authorized_modifications:
            for item in authorized_modifications:
                norm = item.strip().replace("\\", "/")
                while norm.startswith("./"):
                    norm = norm[2:]
                if norm and ".." not in norm.split("/"):
                    authorized.add(norm)

        baseline_keys = set(baseline)
        current_keys = set(current)
        added = sorted(current_keys - baseline_keys)
        deleted = sorted(baseline_keys - current_keys)
        modified: List[str] = []
        extended: List[str] = []
        fixture_modifications: List[str] = []
        weakening_notes: List[str] = []

        for k in sorted(baseline_keys & current_keys):
            if baseline[k] == current[k]:
                continue
            old, new = baseline_contents.get(k), current_contents.get(k)
            if isinstance(old, str) and self._normalize_text_and_hash(old.encode("utf-8"))[0] == current[k]:
                continue
            if k in authorized:
                if old is not None and new is not None:
                    _, added_lines = self._line_changes(old, new)
                    weak = self.weakening_lines(added_lines)
                    if k.endswith(".py"):
                        weak += [n for n in self.python_weakening(old, new, added_lines) if n not in weak]
                    if weak:
                        weakening_notes.append(f"{k}: added weakening lines {weak[:3]}")
                continue
            is_config = Path(k).name in self.KNOWN_CONFIG_NAMES and len(Path(k).parts) == 1
            if mode == "tdd" and not is_config and old is not None and new is not None:
                removed, added_lines = self._line_changes(old, new)
                weak = self.weakening_lines(added_lines)
                if not removed and k.endswith(".py"):
                    weak += [n for n in self.python_weakening(old, new, added_lines) if n not in weak]
                if not removed and not weak:
                    extended.append(k)
                    continue
                if not removed and weak:
                    weakening_notes.append(f"{k}: added weakening lines {weak[:3]}")
            modified.append(k)
            if any(k.endswith(ext) for ext in self.FIXTURE_EXTENSIONS) or "fixture" in k.lower():
                fixture_modifications.append(k)

        violations: List[str] = []
        if modified:
            label = "in TDD mode " if mode == "tdd" else ""
            violations.append(f"Existing tests/configs modified {label}without authorization: {modified}")
        if deleted:
            unaccounted_deleted: List[str] = []
            matched_added: Set[str] = set()
            for del_k in deleted:
                old_text = baseline_contents.get(del_k)
                renamed_ok = False
                if del_k.endswith(".py") and old_text is not None:
                    try:
                        old_tree = ast.parse(old_text)
                        before_facts = _PythonTestFacts(old_tree)
                    except (SyntaxError, ValueError, RecursionError):
                        old_tree = None
                        before_facts = None
                    if old_tree is not None and before_facts is not None and before_facts.test_names:
                        old_body = "\n".join(self._body_lines_after_module_docstring(old_tree, old_text))
                        for add_k in added:
                            if add_k in matched_added or not add_k.endswith(".py"):
                                continue
                            if del_k not in authorized and add_k not in authorized:
                                continue
                            new_text = current_contents.get(add_k)
                            if new_text is None:
                                continue
                            try:
                                new_tree = ast.parse(new_text)
                                after_facts = _PythonTestFacts(new_tree)
                            except (SyntaxError, ValueError, RecursionError):
                                continue
                            if not (before_facts.defined <= after_facts.defined and before_facts.test_names <= after_facts.test_names):
                                continue
                            new_body = "\n".join(self._body_lines_after_module_docstring(new_tree, new_text))
                            removed_body_lines, _ = self._line_changes(old_body, new_body)
                            if removed_body_lines:
                                continue
                            _, added_lines = self._line_changes(old_text, new_text)
                            weak = self.weakening_lines(added_lines)
                            weak += [n for n in self.python_weakening(old_text, new_text, added_lines) if n not in weak]
                            if weak:
                                weakening_notes.append(f"{add_k} (renamed from {del_k}): added weakening lines {weak[:3]}")
                            matched_added.add(add_k)
                            renamed_ok = True
                            break
                if not renamed_ok:
                    is_del_config = Path(del_k).name in self.KNOWN_CONFIG_NAMES and len(Path(del_k).parts) == 1
                    is_del_fixture = any(del_k.endswith(ext) for ext in self.FIXTURE_EXTENSIONS) or "fixture" in del_k.lower()
                    if not is_del_config and not is_del_fixture:
                        for add_k in added:
                            if add_k in matched_added:
                                continue
                            if del_k not in authorized and add_k not in authorized:
                                continue
                            is_add_config = Path(add_k).name in self.KNOWN_CONFIG_NAMES and len(Path(add_k).parts) == 1
                            if is_add_config:
                                continue
                            if current.get(add_k) == baseline.get(del_k):
                                matched_added.add(add_k)
                                renamed_ok = True
                                break
                if not renamed_ok:
                    unaccounted_deleted.append(del_k)
            if unaccounted_deleted:
                violations.append(f"Test/config files deleted: {unaccounted_deleted}")
        if weakening_notes:
            violations.append(f"Test weakening markers added: {weakening_notes}")
        if fixture_modifications:
            violations.append(f"Critical test data/fixture altered (Goodhart Invariant): {fixture_modifications}")

        return TestBoundaryReport(
            timestamp=timestamp,
            workspace_dir=str(self.workspace_dir),
            mode=mode,
            total_files=len(current),
            is_intact=not violations,
            modified=modified,
            added=added,
            deleted=deleted,
            violations=violations,
            fixture_modifications=fixture_modifications,
            extended=extended,
            baseline_source=source,
        )

    # ------------------------------------------------------------------
    # Reproducibility
    # ------------------------------------------------------------------
    @staticmethod
    def windows_command(command: Union[str, List[str]]) -> Union[str, List[str]]:
        """Rewrites POSIX-style 'python3 ...' commands for Windows (python3 is not on PATH there)."""
        if isinstance(command, str):
            exec_cmd = command
            if exec_cmd.startswith("python3 "):
                exec_cmd = f'"{sys.executable}" ' + exec_cmd[8:]
            if " -c '" in exec_cmd and exec_cmd.endswith("'"):
                exec_cmd = exec_cmd.replace(" -c '", ' -c "')[:-1] + '"'
            return exec_cmd
        if command and command[0] == "python3":
            return [sys.executable] + list(command[1:])
        return command

    def run_reproducible(
        self,
        command: Union[str, List[str]],
        passes: int = 2,
        cwd: Optional[Path] = None,
    ) -> Tuple[bool, str, List[int]]:
        """
        Executes a test command `passes` consecutive times in the same working directory
        and environment (not an isolated sandbox) and requires every run to exit 0.
        """
        if not isinstance(passes, int) or passes < 1:
            raise ValueError("passes must be a positive integer (use >= 2 to claim reproducibility).")
        work_dir = cwd or self.workspace_dir
        exit_codes: List[int] = []

        exec_cmd = self.windows_command(command) if os.name == "nt" else command
        self.last_commands.append(exec_cmd if isinstance(exec_cmd, str) else subprocess.list2cmdline(exec_cmd))

        for run_idx in range(1, passes + 1):
            try:
                proc = subprocess.run(
                    exec_cmd,
                    shell=isinstance(exec_cmd, str),
                    cwd=work_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=300,
                )
                exit_codes.append(proc.returncode)
                if proc.returncode != 0:
                    err_snippet = (proc.stderr or proc.stdout)[-500:].strip()
                    return False, f"Run {run_idx}/{passes} failed with exit code {proc.returncode}: {err_snippet}", exit_codes
            except subprocess.TimeoutExpired:
                exit_codes.append(-1)
                return False, f"Run {run_idx}/{passes} timed out after 300s.", exit_codes
            except OSError as e:
                exit_codes.append(-1)
                return False, f"Run {run_idx}/{passes} encountered execution error: {e}", exit_codes

        return True, f"Deterministic pass confirmed across {passes} consecutive runs.", exit_codes
