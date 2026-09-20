"""
guard/test_boundary.py — Deterministic Test & Configuration Trust Boundary Guard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Provides cryptographic (SHA-256) immutability boundaries for test suites and
runner configurations, preventing agents from mutating tests, relaxing thresholds,
altering fixtures, or tampering with runner configurations to fake passes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


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

    def to_dict(self) -> Dict:
        return asdict(self)

    def summary(self) -> str:
        if self.is_intact:
            return f"[OK] Test & Config Boundary Verified ({self.total_files} files intact in '{self.mode}' mode)."
        
        reasons = []
        if self.modified:
            reasons.append(f"{len(self.modified)} modified")
        if self.deleted:
            reasons.append(f"{len(self.deleted)} deleted")
        if self.added and self.mode == "bugfix":
            reasons.append(f"{len(self.added)} unexpected additions in bugfix mode")
        if self.fixture_modifications:
            reasons.append(f"{len(self.fixture_modifications)} fixtures/data altered")
        
        return f"[BLOCKED] Test Boundary Violated: {', '.join(reasons)}."


class TestBoundaryGuard:
    """
    Guards test suites and configuration files as an external trust boundary.
    Separates 'agent got exit code 0' from 'implementation satisfied the contract'.
    """
    __test__ = False

    KNOWN_CONFIG_NAMES: Set[str] = {
        "pytest.ini",
        "setup.cfg",
        "pyproject.toml",
        "tox.ini",
        ".flake8",
        "tsconfig.json",
        "package.json",
        "jest.config.js",
        "jest.config.ts",
        "jest.config.mjs",
        "jest.config.cjs",
        "jest.config.json",
        ".eslintrc",
        ".eslintrc.json",
        ".eslintrc.js",
        ".eslintrc.yaml",
        ".eslintrc.yml",
        "vitest.config.ts",
        "vitest.config.js",
        "Cargo.toml",
        "go.mod",
        "pom.xml",
        "build.gradle",
    }

    TEST_DIR_NAMES: Set[str] = {"tests", "test", "__tests__", "spec", "specs"}
    
    EXCLUDED_PATTERNS: Set[str] = {
        "__pycache__",
        ".git",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "node_modules",
        ".harness",
        ".guard_snapshots",
        ".DS_Store",
    }

    FIXTURE_EXTENSIONS: Set[str] = {".json", ".yaml", ".yml", ".csv", ".tsv", ".xml", ".txt", ".sql"}

    def __init__(
        self,
        workspace_dir: Optional[Path] = None,
        state_file: Optional[Path] = None,
    ):
        self.workspace_dir = Path(workspace_dir).resolve() if workspace_dir else Path.cwd().resolve()
        if state_file:
            self.state_file = Path(state_file).resolve()
        else:
            self.state_file = self.workspace_dir / ".harness" / "test_boundary.json"

    def _hash_file(self, path: Path) -> str:
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def discover_files(self) -> Dict[str, str]:
        """
        Discovers all test files, test fixtures, and root configuration files.
        Returns a mapping of relative path string -> SHA-256 hash.
        """
        tracked_files: Dict[str, str] = {}

        # 1. Discover runner configuration files in workspace root
        for config_name in self.KNOWN_CONFIG_NAMES:
            cfg_path = self.workspace_dir / config_name
            if cfg_path.is_file():
                tracked_files[config_name] = self._hash_file(cfg_path)

        # 2. Discover test directories and their contents (including fixtures)
        for root, dirs, files in os.walk(self.workspace_dir):
            # Prune ignored directories
            dirs[:] = [d for d in dirs if d not in self.EXCLUDED_PATTERNS and not d.startswith(".")]

            rel_root = Path(root).relative_to(self.workspace_dir)
            is_in_test_dir = any(part in self.TEST_DIR_NAMES for part in rel_root.parts)

            if not is_in_test_dir:
                continue

            for f in files:
                if f.startswith(".") or f.endswith(".pyc"):
                    continue
                file_path = Path(root) / f
                if file_path.is_file():
                    rel_path = str(file_path.relative_to(self.workspace_dir)).replace("\\", "/")
                    tracked_files[rel_path] = self._hash_file(file_path)

        return tracked_files

    def snapshot(self, target_path: Optional[Path] = None) -> Tuple[int, Path]:
        """
        Creates or updates cryptographic baseline snapshot of test/config tree.
        """
        dest = Path(target_path).resolve() if target_path else self.state_file
        dest.parent.mkdir(parents=True, exist_ok=True)

        files_map = self.discover_files()
        payload = {
            "version": "1.3.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "workspace": str(self.workspace_dir),
            "total_files": len(files_map),
            "files": files_map,
        }

        temp_dest = dest.with_suffix(".tmp")
        temp_dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temp_dest.replace(dest)

        return len(files_map), dest

    def load_snapshot(self, target_path: Optional[Path] = None) -> Optional[Dict[str, str]]:
        dest = Path(target_path).resolve() if target_path else self.state_file
        if not dest.exists():
            return None
        try:
            data = json.loads(dest.read_text(encoding="utf-8"))
            return data.get("files", {})
        except Exception:
            return None

    def verify(
        self,
        mode: str = "bugfix",
        snapshot_path: Optional[Path] = None,
        authorized_modifications: Optional[Set[str]] = None,
    ) -> TestBoundaryReport:
        """
        Verifies current test & config files against baseline snapshot.
        Modes:
          - 'bugfix': Zero changes allowed. Any modified, added, or deleted test/config is blocked.
          - 'tdd': New test files permitted. Modified existing files blocked unless authorized.
        """
        dest = Path(snapshot_path).resolve() if snapshot_path else self.state_file
        baseline = self.load_snapshot(dest)
        current = self.discover_files()
        authorized = authorized_modifications or set()

        timestamp = datetime.now(timezone.utc).isoformat()

        if baseline is None:
            return TestBoundaryReport(
                timestamp=timestamp,
                workspace_dir=str(self.workspace_dir),
                mode=mode,
                total_files=len(current),
                is_intact=False,
                violations=["BASELINE MISSING: No test boundary snapshot found. Run snapshot first."],
            )

        baseline_keys = set(baseline.keys())
        current_keys = set(current.keys())

        modified: List[str] = []
        fixture_modifications: List[str] = []
        added: List[str] = sorted(list(current_keys - baseline_keys))
        deleted: List[str] = sorted(list(baseline_keys - current_keys))
        violations: List[str] = []

        common_keys = baseline_keys & current_keys
        for k in sorted(list(common_keys)):
            if baseline[k] != current[k]:
                if k not in authorized:
                    modified.append(k)
                    if any(k.endswith(ext) for ext in self.FIXTURE_EXTENSIONS) or "fixture" in k.lower():
                        fixture_modifications.append(k)

        # Evaluate violations based on mode
        if mode == "bugfix":
            if modified:
                violations.append(f"Existing tests/configs modified without authorization: {modified}")
            if added:
                violations.append(f"New test/config files added in bugfix mode: {added}")
            if deleted:
                violations.append(f"Test/config files deleted: {deleted}")
        else:  # tdd / feature mode
            if modified:
                violations.append(f"Existing tests/configs modified in TDD mode without authorization: {modified}")
            if deleted:
                violations.append(f"Test/config files deleted: {deleted}")

        if fixture_modifications:
            violations.append(f"Critical test data/fixture altered (Goodhart Invariant): {fixture_modifications}")

        is_intact = len(violations) == 0

        return TestBoundaryReport(
            timestamp=timestamp,
            workspace_dir=str(self.workspace_dir),
            mode=mode,
            total_files=len(current),
            is_intact=is_intact,
            modified=modified,
            added=added,
            deleted=deleted,
            violations=violations,
            fixture_modifications=fixture_modifications,
        )

    def run_reproducible(
        self,
        command: str | List[str],
        passes: int = 2,
        cwd: Optional[Path] = None,
    ) -> Tuple[bool, str, List[int]]:
        """
        Executes a targeted test command across multiple isolated runs to ensure
        reproducibility and eliminate stochastic / flaky passes.
        """
        work_dir = cwd or self.workspace_dir
        exit_codes: List[int] = []

        exec_cmd = command
        if os.name == "nt":
            if isinstance(command, str):
                if command.startswith("python3 "):
                    exec_cmd = f'"{sys.executable}" ' + command[8:]
                if " -c '" in exec_cmd and exec_cmd.endswith("'"):
                    exec_cmd = exec_cmd.replace(" -c '", ' -c "')[:-1] + '"'
            elif isinstance(command, list):
                if command and command[0] == "python3":
                    exec_cmd = [sys.executable] + command[1:]

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
                    return (
                        False,
                        f"Run {run_idx}/{passes} failed with exit code {proc.returncode}: {err_snippet}",
                        exit_codes,
                    )
            except subprocess.TimeoutExpired:
                exit_codes.append(-1)
                return False, f"Run {run_idx}/{passes} timed out after 300s.", exit_codes
            except Exception as e:
                exit_codes.append(-1)
                return False, f"Run {run_idx}/{passes} encountered execution error: {e}", exit_codes

        return True, f"Deterministic pass confirmed across {passes} consecutive runs.", exit_codes
