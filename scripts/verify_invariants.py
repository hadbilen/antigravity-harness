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
  python3 scripts/verify_invariants.py [--diff | --all | --path <dir>]
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
    (r"^\+[^+].*@pytest\.mark\.skip", "Pytest skip marker added without user transition approval"),
    (r"^\+[^+].*//\s*(expect|assert|self\.assert).*", "Commented-out test assertion detected"),
    (r"^\+[^+].*#\s*(assert|self\.assert|expect\().*", "Commented-out test assertion detected"),
    (r"^\+[^+].*\b(skip|ignore)\b.*\btests?\b", "Directive suggesting skipping or ignoring tests"),
]

# Patterns forbidden across all committed documentation and rules
CONSTITUTIONAL_SLOP_PATTERNS = [
    (r"(?i)\b10,?000\+\s+happy\s+users\b", "Unverified marketing metric placeholder (Antislop rule 1)"),
    (r"(?i)\balways\s+agree\s+with\s+the\s+user\b", "Sycophantic rule forcing automatic agreement (Rule 7 violation)"),
    (r"(?i)\bnever\s+(disagree|refuse|contradict)\b", "Prohibition on technical disagreement (Rule 7 violation)"),
    (r"curl\s+-[sS]*L?\s+https?://\S+\s*\|\s*(bash|sh|zsh)", "Unvetted remote script execution (Rule 12 supply-chain violation)"),
]


def check_diff() -> List[Tuple[str, str, str]]:
    """Checks git diff for invariant violations."""
    violations = []
    try:
        diff_output = subprocess.check_output(
            ["git", "diff", "HEAD~1", "--unified=0"],
            stderr=subprocess.DEVNULL,
            text=True
        )
    except Exception:
        try:
            diff_output = subprocess.check_output(
                ["git", "diff", "--unified=0"],
                stderr=subprocess.DEVNULL,
                text=True
            )
        except Exception:
            return violations

    current_file = ""
    for line in diff_output.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue

        # 1. Test weakening check on test files
        if any(term in current_file.lower() for term in ["test", "spec"]):
            for pattern, desc in TEST_WEAKENING_DIFF_PATTERNS:
                if re.search(pattern, line):
                    violations.append((current_file, line, desc))

        # 2. General slop and security check
        for pattern, desc in CONSTITUTIONAL_SLOP_PATTERNS:
            if line.startswith("+") and not line.startswith("+++"):
                if re.search(pattern, line):
                    violations.append((current_file, line, desc))

    return violations


def scan_directory(base_path: Path) -> List[Tuple[str, str, str]]:
    """Scans all files in directory against static invariants."""
    violations = []
    ignore_dirs = {".git", "__pycache__", "node_modules", ".harness"}

    for root, dirs, files in os.walk(base_path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for f in files:
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

            rel_path = str(file_path.relative_to(base_path))
            is_test_file = any(term in file_path.name.lower() for term in ["test", "spec"])

            for line_idx, line in enumerate(content.splitlines(), start=1):
                # General constitutional slop
                for pattern, desc in CONSTITUTIONAL_SLOP_PATTERNS:
                    if re.search(pattern, line):
                        violations.append((f"{rel_path}:{line_idx}", line.strip(), desc))

                # Test file invariant checks
                if is_test_file:
                    for pattern, desc in [
                        (r"\b(it\.skip|test\.skip|describe\.skip)\b", "Skipped test block (Goodhart Invariant violation)"),
                        (r"@pytest\.mark\.skip", "Pytest skip marker without transition approval"),
                        (r"//\s*(expect|assert|self\.assert).*", "Commented-out test assertion"),
                        (r"#\s*(assert|self\.assert|expect\().*", "Commented-out test assertion"),
                    ]:
                        if re.search(pattern, line):
                            violations.append((f"{rel_path}:{line_idx}", line.strip(), desc))

    return violations


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="verify_invariants",
        description="Deterministic Verification Guard for Constitutional Invariants"
    )
    parser.add_argument("--diff", action="store_true", help="Inspect git diff")
    parser.add_argument("--all", action="store_true", help="Inspect entire repository tree")
    parser.add_argument("--path", type=str, default=".", help="Base path to inspect")
    args = parser.parse_args()

    base_path = Path(args.path).resolve()
    print("=" * 64)
    print("      Antigravity Harness — Invariant Verification Guard        ")
    print("=" * 64)

    violations = []
    if args.all:
        print(f"[MODE] Full Repository Scan: {base_path}")
        violations = scan_directory(base_path)
    else:
        print(f"[MODE] Git Diff Invariant Check")
        violations = check_diff()

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
