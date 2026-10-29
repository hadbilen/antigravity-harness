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
                                       [--test-boundary [--mode bugfix|tdd]] [--authorize PATH]

Exit codes: 0 pass, 1 violations, 2 the check itself could not run (never reported as PASS).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

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

_RAW_TEST_LINE_PATTERNS = [
    (r"\b(it\.skip|test\.skip|describe\.skip)\b", "Skipped test block (Goodhart Invariant violation)"),
    (r"^\s*(@pytest\.mark\.skip|pytestmark\s*=.*pytest\.mark\.skip)", "Pytest skip marker without transition approval"),
    (r"//\s*(expect|assert|self\.assert).*", "Commented-out test assertion"),
    (r"#\s*(assert|self\.assert|expect\().*", "Commented-out test assertion"),
]

_COMPILED_DIFF_PATTERNS = [(re.compile(p), desc) for p, desc in TEST_WEAKENING_DIFF_PATTERNS]
_COMPILED_SLOP_PATTERNS = [(re.compile(p), desc, "Rule 12" in desc) for p, desc in CONSTITUTIONAL_SLOP_PATTERNS]
_COMPILED_TEST_LINE_PATTERNS = [(re.compile(p), desc) for p, desc in _RAW_TEST_LINE_PATTERNS]
_PROHIBITION_PROSE_RE = re.compile(r"(?i)\b(never|forbidden|prohibited|do\s+not)\b")
_ANY_SLOP_RE = re.compile(
    "|".join(
        f"(?i:{p[4:]})" if p.startswith("(?i)") else f"(?:{p})"
        for p, _ in CONSTITUTIONAL_SLOP_PATTERNS
    ),
    re.MULTILINE,
)
_ANY_TEST_LINE_RE = re.compile(
    "|".join(f"(?:{p})" for p, _ in _RAW_TEST_LINE_PATTERNS),
    re.MULTILINE,
)

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


_RAW_C9_SNIFF_RE = re.compile(
    r"(?:"
    r"PYTEST_CURRENT_TEST|"
    r"UNITTEST_RUNNING|"
    r"sys\.modules(?:\.get\s*\(|\s*\[)\s*['\"](?:unittest|pytest)['\"]|"
    r"['\"](?:unittest|pytest)['\"]\s+in\s+sys\.modules|"
    r"NODE_ENV\s*===\s*['\"]test['\"]|"
    r"NODE_ENV\s*==\s*['\"]test['\"]|"
    r"process\.env\.JEST_WORKER_ID|"
    r"process\.env\.VITEST"
    r")"
)
_C9_CODE_SUFFIXES = (".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs")
_MD_FENCE_MARKER_RE = re.compile(r"^\s*(`{3,}|~{3,})")
_GIT_SUBPROCESS_TIMEOUT = 15
_MAX_UNTRACKED_SCAN_BYTES = 1024 * 1024
_BINARY_SKIP_SUFFIXES = (
    ".pyc",
    ".pyo",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".mp4",
    ".webm",
    ".wav",
    ".flac",
    ".mp3",
    ".ogg",
    ".opus",
    ".zip",
    ".tar",
    ".gz",
    ".xz",
    ".zst",
    ".bz2",
    ".pdf",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".so",
    ".dylib",
    ".dll",
    ".exe",
    ".wasm",
)


def _advance_md_fence(
    line_body: str, fence: Optional[Tuple[str, int]]
) -> Tuple[Optional[Tuple[str, int]], bool]:
    """Updates CommonMark fenced code block state (` ``` ` or `~~~`) and returns `(new_fence, is_fence_delimiter)`."""
    m = _MD_FENCE_MARKER_RE.match(line_body)
    if not m:
        return fence, False
    marker = m.group(1)
    if fence is None:
        return (marker[0], len(marker)), True
    if fence[0] == marker[0] and len(marker) >= fence[1]:
        return None, True
    return fence, False


def is_test_path(rel_path: str) -> bool:
    rel = rel_path.replace("\\", "/")
    return any(p.search(rel) for p in TEST_FILE_PATTERNS)


def check_diff(base_ref: str = "", base_path: Optional[Path] = None) -> List[Tuple[str, str, str]]:
    """Checks the git diff (against base_ref, or HEAD, or HEAD~1, plus untracked files) for invariant violations."""
    violations: List[Tuple[str, str, str]] = []
    repo_dir = Path(base_path).resolve() if base_path is not None else REPO_ROOT
    cwd = str(repo_dir)
    diff_output: Optional[str] = None
    errors: List[str] = []

    if base_ref:
        candidates = [
            ["git", "-c", "core.quotePath=false", "diff", base_ref, "--unified=0"],
            ["git", "-c", "core.quotePath=false", "diff", f"{base_ref}...HEAD", "--unified=0"],
        ]
        for cmd in candidates:
            try:
                diff_output = subprocess.check_output(
                    cmd, stderr=subprocess.PIPE, text=True, cwd=cwd, timeout=_GIT_SUBPROCESS_TIMEOUT
                )
                break
            except (OSError, subprocess.SubprocessError) as e:
                errors.append(f"{' '.join(cmd)}: {getattr(e, 'stderr', '') or e}")
    else:
        try:
            head_diff = subprocess.check_output(
                ["git", "-c", "core.quotePath=false", "diff", "HEAD", "--unified=0"],
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                timeout=_GIT_SUBPROCESS_TIMEOUT,
            )
            if head_diff.strip():
                diff_output = head_diff
            else:
                try:
                    diff_output = subprocess.check_output(
                        ["git", "-c", "core.quotePath=false", "diff", "HEAD~1", "--unified=0"],
                        stderr=subprocess.PIPE,
                        text=True,
                        cwd=cwd,
                        timeout=_GIT_SUBPROCESS_TIMEOUT,
                    )
                except (OSError, subprocess.SubprocessError):
                    diff_output = head_diff
        except (OSError, subprocess.SubprocessError) as e:
            errors.append(f"git diff HEAD --unified=0: {getattr(e, 'stderr', '') or e}")
            try:
                staged = subprocess.check_output(
                    ["git", "-c", "core.quotePath=false", "diff", "--cached", "--unified=0"],
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=cwd,
                    timeout=_GIT_SUBPROCESS_TIMEOUT,
                )
                unstaged = subprocess.check_output(
                    ["git", "-c", "core.quotePath=false", "diff", "--unified=0"],
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=cwd,
                    timeout=_GIT_SUBPROCESS_TIMEOUT,
                )
                diff_output = f"{staged}\n{unstaged}"
            except (OSError, subprocess.SubprocessError) as e2:
                errors.append(f"git diff --cached/--unified=0: {getattr(e2, 'stderr', '') or e2}")

    if diff_output is None:
        raise CheckUnavailable("could not compute a git diff: " + " | ".join(errors))

    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    try:
        from guard.agy_hooks import _NEW_FILE_CAPABILITY_SKIP_RE, _unquote_git_diff_path, inspect_git_diff
    except ImportError as imp_err:
        raise CheckUnavailable(f"required diff scanner guard.agy_hooks could not be imported: {imp_err}") from imp_err

    # Synthesize added-line hunks for untracked files so brand-new files are never skipped
    untracked_chunks: List[str] = []
    unreadable_untracked: List[str] = []
    try:
        untracked = subprocess.run(
            ["git", "-c", "core.quotePath=false", "ls-files", "--others", "--exclude-standard", "-z"],
            capture_output=True,
            cwd=cwd,
            timeout=_GIT_SUBPROCESS_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as ls_err:
        raise CheckUnavailable(f"could not enumerate untracked files via git ls-files: {ls_err}") from ls_err

    if untracked.returncode != 0:
        err_msg = (untracked.stderr or b"").decode("utf-8", errors="replace").strip()
        raise CheckUnavailable(f"git ls-files --others failed (rc={untracked.returncode}): {err_msg}")

    if untracked.stdout:
        for raw_rel in untracked.stdout.split(b"\0"):
            if not raw_rel:
                continue
            rel = raw_rel.decode("utf-8", errors="replace").replace("\\", "/")
            fpath = repo_dir / rel
            if fpath.is_symlink():
                continue
            if fpath.suffix.lower() in _BINARY_SKIP_SUFFIXES:
                continue
            try:
                st = fpath.stat()
            except FileNotFoundError:
                continue
            except OSError as stat_err:
                unreadable_untracked.append(f"{rel}: {stat_err}")
                continue
            if not fpath.is_file():
                continue
            if st.st_size > _MAX_UNTRACKED_SCAN_BYTES:
                unreadable_untracked.append(
                    f"{rel}: untracked file size ({st.st_size} bytes) exceeds 1 MiB invariant scan cap"
                )
                continue
            try:
                raw_bytes = fpath.read_bytes()
            except OSError as read_err:
                unreadable_untracked.append(f"{rel}: {read_err}")
                continue
            try:
                text = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                continue
            line_list = text.splitlines()
            added_lines = "\n".join(f"+{ln}" for ln in line_list)
            untracked_chunks.append(
                f"--- /dev/null\n+++ b/{rel}\n@@ -0,0 +1,{max(1, len(line_list))} @@\n{added_lines}\n"
            )

    if untracked_chunks:
        diff_output = diff_output + "\n" + "\n".join(untracked_chunks)

    current_file = ""
    pending_old = ""
    file_is_new: set[str] = set()
    file_is_partial: set[str] = set()
    md_fence: Optional[Tuple[str, int]] = None
    for line in diff_output.splitlines():
        if line.startswith("diff --git "):
            current_file = ""
            pending_old = ""
            md_fence = None
            continue
        if line.startswith("--- "):
            raw_old = line[3:].strip()
            pending_old = "__DEV_NULL__" if (raw_old == "/dev/null" or raw_old.startswith("/dev/null\t")) else raw_old
            continue
        if line.startswith("+++ "):
            unq = _unquote_git_diff_path(line, prefix="b/")
            current_file = unq if unq else (line[6:] if line.startswith("+++ b/") else "")
            if current_file and pending_old == "__DEV_NULL__":
                file_is_new.add(current_file)
            pending_old = ""
            md_fence = None
            continue
        if not current_file:
            continue
        if line.startswith("@@ "):
            if re.match(r"^@@\s+-0,0\s+\+", line):
                if current_file not in file_is_partial:
                    file_is_new.add(current_file)
            else:
                file_is_partial.add(current_file)
                file_is_new.discard(current_file)
            continue
        if line.startswith("-") and not line.startswith("--- "):
            file_is_partial.add(current_file)
            file_is_new.discard(current_file)
            continue

        self_test = is_grader_self_test(current_file)
        is_new_file = current_file in file_is_new and current_file not in file_is_partial
        # 1. Test weakening check on test files
        if is_test_path(current_file):
            added_body_t = line[1:] if line.startswith("+") and not line.startswith("+++") else ""
            if not (is_new_file and added_body_t and _NEW_FILE_CAPABILITY_SKIP_RE.search(added_body_t)):
                for pat, desc in _COMPILED_DIFF_PATTERNS:
                    if self_test and desc == PROSE_DIFF_PATTERN_DESC:
                        continue
                    if pat.search(line):
                        violations.append((current_file, line, desc))

        # 2. General slop and security check (align with scan_directory exclusions)
        if current_file.startswith(".harness/") or Path(current_file).name in (
            "verify_invariants.py", "sanitizer.py", "README.md", "MISTAKES.md"
        ):
            continue
        is_markdown = current_file.lower().endswith((".md", ".mdc"))
        if not self_test and line.startswith("+") and not line.startswith("+++"):
            added_body = line[1:]
            if is_markdown:
                md_fence, is_delim = _advance_md_fence(added_body, md_fence)
                if is_delim:
                    continue
            in_fence = md_fence is not None
            for pat, desc, is_r12 in _COMPILED_SLOP_PATTERNS:
                if is_markdown and not in_fence and is_r12 and (
                    "`" in added_body or _PROHIBITION_PROSE_RE.search(added_body)
                ):
                    continue
                if pat.search(line):
                    violations.append((current_file, line, desc))

    seen_findings = set()
    for finding in inspect_git_diff(diff_output, workspace=repo_dir):
        m_path = re.search(r"in `([^`]+)`", finding)
        f_rel = m_path.group(1) if m_path else "<diff>"
        if not is_grader_self_test(f_rel) and finding not in seen_findings:
            seen_findings.add(finding)
            violations.append((f_rel, finding[:80], finding))

    if unreadable_untracked:
        raise CheckUnavailable("cannot inspect in-scope untracked file(s): " + "; ".join(unreadable_untracked))

    return violations


def scan_directory(base_path: Path) -> List[Tuple[str, str, str]]:
    """Scans all files in directory against static invariants."""
    if not base_path.exists():
        raise CheckUnavailable(f"path does not exist: {base_path}")
    violations = []
    ignore_dirs = {".git", "__pycache__", "node_modules", ".harness", "export", "dist", "build", ".claude"}
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    try:
        from guard.agy_hooks import _SCANNER_EXEMPT_SUFFIXES, validate_structured_content
    except ImportError as imp_err:
        raise CheckUnavailable(f"required scanner guard.agy_hooks could not be imported: {imp_err}") from imp_err
    validate_fn = validate_structured_content

    def _on_walk_error(err: OSError) -> None:
        raise CheckUnavailable(f"cannot traverse directory {err.filename or base_path}: {err}") from err

    for root, dirs, files in os.walk(base_path, onerror=_on_walk_error):
        dirs[:] = sorted(d for d in dirs if d not in ignore_dirs)
        for f in sorted(files):
            file_path = Path(root) / f
            if file_path.is_symlink() and not file_path.exists():
                continue
            # Skip binary, documentation examples, and self
            if file_path.suffix.lower() in _BINARY_SKIP_SUFFIXES:
                continue
            if file_path.name in ("verify_invariants.py", "sanitizer.py", "README.md", "MISTAKES.md"):
                continue

            try:
                raw_bytes = file_path.read_bytes()
            except OSError as e:
                raise CheckUnavailable(f"cannot read in-scope file {file_path}: {e}") from e
            content = raw_bytes.decode("utf-8", errors="ignore")

            rel_path = file_path.relative_to(base_path).as_posix()
            is_test_file = is_test_path(rel_path)
            self_test = is_grader_self_test(rel_path)
            slop_patterns = () if self_test else _COMPILED_SLOP_PATTERNS

            if validate_fn is not None and file_path.suffix.lower() in (".json", ".toml", ".svg"):
                for issue in validate_fn(rel_path, content):
                    violations.append((rel_path, file_path.name, issue))

            is_c9_candidate = (
                not is_test_file
                and not self_test
                and file_path.suffix.lower() in _C9_CODE_SUFFIXES
                and not any(rel_path.endswith(sfx) for sfx in _SCANNER_EXEMPT_SUFFIXES)
            )
            check_slop = bool(slop_patterns and _ANY_SLOP_RE.search(content))
            check_test = bool(is_test_file and _ANY_TEST_LINE_RE.search(content))
            check_c9 = bool(is_c9_candidate and _RAW_C9_SNIFF_RE.search(content))
            if not check_slop and not check_test and not check_c9:
                continue

            is_markdown = file_path.suffix.lower() in (".md", ".mdc")
            md_fence: Optional[Tuple[str, int]] = None
            for line_idx, line in enumerate(content.splitlines(), start=1):
                if is_markdown:
                    md_fence, is_delim = _advance_md_fence(line, md_fence)
                    if is_delim:
                        continue
                in_fence = md_fence is not None
                # General constitutional slop. In Markdown prose, quoted/prohibition supply-chain
                # references are skipped, whereas executable fenced blocks are always checked.
                if check_slop:
                    for pat, desc, is_r12 in slop_patterns:
                        if is_markdown and not in_fence and is_r12 and (
                            "`" in line or _PROHIBITION_PROSE_RE.search(line)
                        ):
                            continue
                        if pat.search(line):
                            violations.append((f"{rel_path}:{line_idx}", line.strip(), desc))

                # Production C9 test-runner sniffing check
                if check_c9 and not line.lstrip().startswith(("#", "//")) and _RAW_C9_SNIFF_RE.search(line):
                    violations.append(
                        (
                            f"{rel_path}:{line_idx}",
                            line.strip(),
                            "Test-runner detection in production file (Rule 9 C9 violation)",
                        )
                    )

                # Test file invariant checks
                if check_test:
                    for pat, desc in _COMPILED_TEST_LINE_PATTERNS:
                        if pat.search(line):
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
    parser.add_argument("--path", "--root", dest="path", type=str, default=".", help="Base path to inspect")
    parser.add_argument("--base-ref", default="", help="Git ref for the diff and the test boundary (e.g. origin/main)")
    parser.add_argument("--authorize", action="append", default=[], help="Relative test path authorized for contract modification (repeatable)")
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
            violations = check_diff(args.base_ref, base_path=base_path)
    except CheckUnavailable as e:
        print(f"\n[ERROR] Invariant check could not run: {e}")
        return 2

    if args.test_boundary or args.base_ref:
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
        try:
            from guard.test_boundary import TestBoundaryGuard

            tb_guard = TestBoundaryGuard(workspace_dir=base_path)
            tb_report = tb_guard.verify(
                mode=args.mode,
                base_ref=args.base_ref or None,
                authorized_modifications=set(args.authorize or []),
            )
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
