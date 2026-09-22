#!/usr/bin/env python3
"""
scripts/verify_invariants.py — Machine-Enforced Constitutional & Verification Guard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)

Deterministically verifies codebase modifications against fundamental invariants:
1. Goodhart's Invariant: Prohibits test weakening, skipped tests, commented-out assertions.
2. Anti-Sycophancy & Epistemic Objectivity: Flags sycophantic instructions.
3. Antislop & Hygiene Guard: Flags fake marketing placeholders and unverified metrics.
4. Supply-Chain & Security Invariant: Blocks unvetted dynamic script executions (curl | bash).

Usage:
  python3 scripts/verify_invariants.py [--diff | --all | --path <dir>] [--base-ref REF]
                                       [--test-boundary [--mode bugfix|tdd]]

Exit codes: 0 pass, 1 violations, 2 the check itself could not run (never reported as PASS).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

# Patterns strictly forbidden in test files or code diffs
TEST_WEAKENING_DIFF_PATTERNS = [
    (r"^\+[^+].*\b(it\.skip|test\.skip|describe\.skip)\b", "Skipped test block added (Goodhart Invariant violation)"),
    (r"^\+\s*(@pytest\.mark\.skip|pytestmark\s*=.*pytest\.mark\.skip)", "Pytest skip marker added without user transition approval"),
    (r"^\+[^+].*//\s*(expect|assert|self\.assert).*", "Commented-out test assertion detected"),
    (r"^\+[^+].*#\s*(assert|self\.assert|expect\().*", "Commented-out test assertion detected"),
    (r"^\+[^+].*\b(skip|ignore)\b.*\btests?\b", "Directive suggesting skipping or ignoring tests"),
]
PROSE_DIFF_PATTERN_DESC = "Directive suggesting skipping or ignoring tests"

# Patterns forbidden across all committed documentation and rules
CONSTITUTIONAL_SLOP_PATTERNS = [
    (r"(?i)\b10,?000\+\s+happy\s+users\b", "Unverified marketing metric placeholder (Antislop rule 1)"),
    (r"(?i)\balways\s+agree\s+with\s+the\s+user\b", "Sycophantic rule forcing automatic agreement (Rule 7 violation)"),
    (r"(?i)\bnever\s+(disagree|refuse|contradict)\b", "Prohibition on technical disagreement (Rule 7 violation)"),
    (r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+(-\S+\s+)*)?(ba|z|da|k)?sh\b", "Unvetted remote script piped into a shell (Rule 12 supply-chain violation)"),
    (r"\b(ba|z)?sh\s+<\(\s*(curl|wget)\b", "Unvetted remote script executed via process substitution (Rule 12)"),
    (r"\b(source|\.)\s+<\(\s*(curl|wget)\b", "Unvetted remote script sourced into the shell (Rule 12)"),
]

TEST_FILE_PATTERNS = [
    re.compile(r"(^|/)(tests?|__tests__|specs?)/"),
    re.compile(r"(^|/)test_[^/]*\.py$"),
    re.compile(r"_test\.(py|go)$"),
    re.compile(r"(^|/)conftest\.py$"),
    re.compile(r"\.(test|spec)\.[cm]?[jt]sx?$"),
    re.compile(r"_spec\.rb$"),
]


# Self-tests of the graders themselves (this scanner, the Porter sanitizer, the self-audit). Their string
# literals are adversarial samples, so the prose/sample patterns are not applied to them; the skip-marker
# and commented-out-assertion checks still are. Keep this list explicit and short: CI runs the base
# branch's copy of this file, so widening it is visible in review.
GRADER_SELF_TESTS = frozenset({
    "tests/test_porter.py",
    "tests/test_tooling.py",
})


def is_grader_self_test(rel_path: str) -> bool:
    return rel_path.replace("\\", "/") in GRADER_SELF_TESTS


class CheckUnavailable(RuntimeError):
    """Raised when a check cannot run; reported as an error, never as a pass."""


def is_test_path(rel_path: str) -> bool:
    rel = rel_path.replace("\\", "/")
    return any(p.search(rel) for p in TEST_FILE_PATTERNS)


def check_diff(base_ref: str = "") -> List[Tuple[str, str, str]]:
    """Checks the git diff (against base_ref, or HEAD~1, or the working tree) for invariant violations."""
    violations = []
    candidates = [["git", "diff", f"{base_ref}...HEAD", "--unified=0"]] if base_ref else []
    candidates += [["git", "diff", "HEAD~1", "--unified=0"], ["git", "diff", "--unified=0"]]
    diff_output = None
    errors = []
    for cmd in candidates:
        try:
            diff_output = subprocess.check_output(cmd, stderr=subprocess.PIPE, text=True)
            break
        except (OSError, subprocess.CalledProcessError) as e:
            errors.append(f"{' '.join(cmd)}: {getattr(e, 'stderr', '') or e}")
    if diff_output is None:
        raise CheckUnavailable("could not compute a git diff: " + " | ".join(errors))

    current_file = ""
    for line in diff_output.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue

        self_test = is_grader_self_test(current_file)
        # 1. Test weakening check on test files
        if is_test_path(current_file):
            for pattern, desc in TEST_WEAKENING_DIFF_PATTERNS:
                if self_test and desc == PROSE_DIFF_PATTERN_DESC:
                    continue
                if re.search(pattern, line):
                    violations.append((current_file, line, desc))

        # 2. General slop and security check
        for pattern, desc in ([] if self_test else CONSTITUTIONAL_SLOP_PATTERNS):
            if line.startswith("+") and not line.startswith("+++"):
                if re.search(pattern, line):
                    violations.append((current_file, line, desc))

    return violations


def scan_directory(base_path: Path) -> List[Tuple[str, str, str]]:
    """Scans all files in directory against static invariants."""
    violations = []
    ignore_dirs = {".git", "__pycache__", "node_modules", ".harness", "export", "dist", "build"}

    for root, dirs, files in os.walk(base_path):
        dirs[:] = sorted(d for d in dirs if d not in ignore_dirs)
        for f in sorted(files):
            file_path = Path(root) / f
            # Skip binary, documentation examples, and self
            if file_path.suffix in (".pyc", ".png", ".jpg", ".zip", ".tar", ".gz"):
                continue
            if file_path.name in ("verify_invariants.py", "sanitizer.py", "README.md", "MISTAKES.md"):
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            rel_path = file_path.relative_to(base_path).as_posix()
            is_test_file = is_test_path(rel_path)
            slop_patterns = [] if is_grader_self_test(rel_path) else CONSTITUTIONAL_SLOP_PATTERNS

            is_markdown = file_path.suffix.lower() in (".md", ".mdc")
            in_fence = False
            for line_idx, line in enumerate(content.splitlines(), start=1):
                if line.strip().startswith("```"):
                    in_fence = not in_fence
                # General constitutional slop. In Markdown prose, supply-chain commands are
                # usually quoted as prohibitions, so only fenced (executable) examples count.
                for pattern, desc in slop_patterns:
                    if is_markdown and not in_fence and "Rule 12" in desc:
                        continue
                    if re.search(pattern, line):
                        violations.append((f"{rel_path}:{line_idx}", line.strip(), desc))

                # Test file invariant checks
                if is_test_file:
                    for pattern, desc in [
                        (r"\b(it\.skip|test\.skip|describe\.skip)\b", "Skipped test block (Goodhart Invariant violation)"),
                        (r"^\s*(@pytest\.mark\.skip|pytestmark\s*=.*pytest\.mark\.skip)", "Pytest skip marker without transition approval"),
                        (r"//\s*(expect|assert|self\.assert).*", "Commented-out test assertion"),
                        (r"#\s*(assert|self\.assert|expect\().*", "Commented-out test assertion"),
                    ]:
                        if re.search(pattern, line):
                            violations.append((f"{rel_path}:{line_idx}", line.strip(), desc))

    return violations


def main() -> int:
    # Windows consoles default to cp1252: never let a status glyph crash the grader.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(
        prog="verify_invariants",
        description="Deterministic Verification Guard for Constitutional Invariants"
    )
    parser.add_argument("--diff", action="store_true", help="Inspect git diff")
    parser.add_argument("--all", action="store_true", help="Inspect entire repository tree")
    parser.add_argument("--test-boundary", action="store_true", help="Explicitly verify test & config trust boundary")
    parser.add_argument("--mode", choices=["bugfix", "tdd"], default="bugfix", help="Test boundary mode (bugfix/tdd)")
    parser.add_argument("--path", type=str, default=".", help="Base path to inspect")
    parser.add_argument("--base-ref", default="", help="Git ref for the diff and the test boundary (e.g. origin/main)")
    args = parser.parse_args()

    base_path = Path(args.path).resolve()
    print("=" * 64)
    print("      Antigravity Harness — Invariant Verification Guard        ")
    print("=" * 64)

    violations = []
    try:
        if args.all:
            print(f"[MODE] Full Repository Scan: {base_path}")
            violations = scan_directory(base_path)
        else:
            print("[MODE] Git Diff Invariant Check")
            violations = check_diff(args.base_ref)
    except CheckUnavailable as e:
        print(f"\n[ERROR] Invariant check could not run: {e}")
        return 2

    if args.test_boundary or args.base_ref:
        if str(base_path) not in sys.path:
            sys.path.insert(0, str(base_path))
        try:
            from guard.test_boundary import TestBoundaryGuard

            tb_guard = TestBoundaryGuard(workspace_dir=base_path)
            tb_report = tb_guard.verify(mode=args.mode, base_ref=args.base_ref or None)
        except Exception as e:
            print(f"\n[ERROR] Test boundary check could not run: {e}")
            return 2
        print(f"[TEST-BOUNDARY] {tb_report.summary()} (baseline: {tb_report.baseline_source or 'n/a'})")
        if tb_report.violations and tb_report.violations[0].startswith("BASELINE"):
            print(f"\n[ERROR] {tb_report.violations[0]}")
            return 2
        for v in tb_report.violations:
            violations.append(("test-boundary", tb_report.summary(), v))

    if not violations:
        print("\n✅ [PASS] All deterministic invariants satisfied.")
        print("   - Zero test weakening / skip mutations detected.")
        print("   - Zero conversational sycophancy or supply-chain violations.")
        print("=" * 64)
        return 0

    print(f"\n🚨 [FAIL] Detected {len(violations)} invariant violation(s):\n")
    for loc, line, desc in violations:
        print(f"  ❌ Location: {loc}")
        print(f"     Violation: {desc}")
        print(f"     Offending: {line[:90]}")
        print("-" * 64)

    print("\n[BLOCKED] Resolution required prior to delivery or merge.")
    print("=" * 64)
    return 1


if __name__ == "__main__":
    sys.exit(main())
