"""
guard/test_boundary.py — Test & Configuration Trust Boundary and Reproducibility Gate
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Semantics (aligned with GEMINI.md Rule 9):
- New test files are always permitted (regression tests are encouraged).
- 'bugfix' mode: existing test and runner-config files must stay byte-identical.
- 'tdd' mode: existing test files may be EXTENDED (pure line additions) as long as the
  added lines contain no skip/xfail/disable markers; any removed or changed line blocks.
- Runner configuration and fixtures may never change without explicit authorization.
The baseline lives in the per-user state directory or is computed from a git ref.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union

from guard.paths import atomic_write_json, path_key, state_dir

TEXT_SNAPSHOT_LIMIT = 256 * 1024

WEAKENING_LINE_PATTERNS = [
    re.compile(r"@pytest\.mark\.(skip|skipif|xfail)\b"),
    re.compile(r"\b(unittest\.)?skip(If|Unless)?\s*\("),
    re.compile(r"\b(it|test|describe)\.(skip|todo)\s*\("),
    re.compile(r"\bx(it|describe|test)\s*\("),
    re.compile(r"\bt\.Skip(Now|f)?\s*\("),
    re.compile(r"@(Disabled|Ignore)\b"),
    re.compile(r"^\s*(#|//)\s*(assert|expect|self\.assert)"),
]


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
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def _discover(self) -> Tuple[Dict[str, str], Dict[str, str]]:
        hashes: Dict[str, str] = {}
        contents: Dict[str, str] = {}
        for root, dirs, files in os.walk(self.workspace_dir):
            dirs[:] = sorted(d for d in dirs if d not in self.EXCLUDED_PATTERNS and not d.startswith("."))
            for f in sorted(files):
                path = Path(root) / f
                rel = path.relative_to(self.workspace_dir).as_posix()
                if not self._tracked(rel) or not path.is_file():
                    continue
                data = path.read_bytes()
                hashes[rel] = self._hash_bytes(data)
                text = self._as_text(data)
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
            capture_output=True, text=True, check=True,
        )
        hashes: Dict[str, str] = {}
        contents: Dict[str, str] = {}
        for rel in listing.stdout.splitlines():
            if not self._tracked(rel):
                continue
            blob = subprocess.run(
                ["git", "-C", str(self.workspace_dir), "show", f"{ref}:{rel}"],
                capture_output=True, check=True,
            ).stdout
            hashes[rel] = self._hash_bytes(blob)
            text = self._as_text(blob)
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
        return data.get("files", {}) if data is not None else None

    def _load_payload(self, target_path: Optional[Path] = None) -> Optional[Dict]:
        dest = self._snapshot_source(target_path)
        if not dest.exists():
            return None
        try:
            return json.loads(dest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------
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
        authorized = authorized_modifications or set()

        if base_ref:
            try:
                baseline, baseline_contents = self.baseline_from_git_ref(base_ref)
                source = f"git:{base_ref}"
            except (subprocess.CalledProcessError, OSError) as e:
                return TestBoundaryReport(
                    timestamp=timestamp, workspace_dir=str(self.workspace_dir), mode=mode,
                    total_files=len(current), is_intact=False,
                    violations=[f"BASELINE UNAVAILABLE: could not read git ref '{base_ref}' ({e})."],
                )
        else:
            payload = self._load_payload(snapshot_path)
            if payload is None:
                return TestBoundaryReport(
                    timestamp=timestamp, workspace_dir=str(self.workspace_dir), mode=mode,
                    total_files=len(current), is_intact=False,
                    violations=["BASELINE MISSING: No test boundary snapshot found. Run snapshot first."],
                )
            baseline = payload.get("files", {})
            baseline_contents = payload.get("contents", {})
            source = str(self._snapshot_source(snapshot_path))

        baseline_keys = set(baseline)
        current_keys = set(current)
        added = sorted(current_keys - baseline_keys)
        deleted = sorted(baseline_keys - current_keys)
        modified: List[str] = []
        extended: List[str] = []
        fixture_modifications: List[str] = []
        weakening_notes: List[str] = []

        for k in sorted(baseline_keys & current_keys):
            if baseline[k] == current[k] or k in authorized:
                continue
            is_config = Path(k).name in self.KNOWN_CONFIG_NAMES and len(Path(k).parts) == 1
            old, new = baseline_contents.get(k), current_contents.get(k)
            if mode == "tdd" and not is_config and old is not None and new is not None:
                removed, added_lines = self._line_changes(old, new)
                weak = self.weakening_lines(added_lines)
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
        if weakening_notes:
            violations.append(f"Test weakening markers added: {weakening_notes}")
        if deleted:
            violations.append(f"Test/config files deleted: {deleted}")
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
