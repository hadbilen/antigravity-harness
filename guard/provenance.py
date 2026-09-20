"""
guard/provenance.py — Execution Provenance & Audit Trail Manifest
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Records execution provenance across agent sessions: files touched, git commit baselines,
environment overrides, test boundary status, and deterministic reproducibility scores.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from guard.test_boundary import TestBoundaryGuard


@dataclass
class RunProvenanceManifest:
    version: str
    session_timestamp: str
    workspace_dir: str
    git_base_commit: str
    git_status_clean: bool
    files_modified: List[str] = field(default_factory=list)
    files_added: List[str] = field(default_factory=list)
    files_deleted: List[str] = field(default_factory=list)
    environment_overrides: Dict[str, str] = field(default_factory=dict)
    test_boundary_verified: bool = False
    test_boundary_mode: str = "bugfix"
    reproducibility_verified: bool = False
    reproducibility_runs: int = 0
    tools_executed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_markdown(self) -> str:
        status_symbol = "✅ VERIFIED" if (self.test_boundary_verified and self.reproducibility_verified) else "⚠️ CAUTION"
        lines = [
            f"### Execution Provenance Manifest ({status_symbol})",
            f"- **Timestamp**: `{self.session_timestamp}`",
            f"- **Base Commit**: `{self.git_base_commit[:8] if self.git_base_commit else 'N/A'}`",
            f"- **Test Boundary Status**: `{'IN TACT (' + self.test_boundary_mode + ')' if self.test_boundary_verified else 'VIOLATED / UNVERIFIED'}`",
            f"- **Reproducibility**: `{'CONFIRMED (' + str(self.reproducibility_runs) + 'x)' if self.reproducibility_verified else 'UNVERIFIED'}`",
            f"- **Files Modified ({len(self.files_modified)})**: {', '.join(f'`{f}`' for f in self.files_modified[:5]) or 'None'}",
        ]
        if len(self.files_modified) > 5:
            lines.append(f"  *(and {len(self.files_modified) - 5} more)*")
        if self.environment_overrides:
            lines.append(f"- **Environment Overrides**: `{list(self.environment_overrides.keys())}`")
        return "\n".join(lines)


class RunProvenanceTracker:
    """
    Constructs and verifies audit trail manifest for AI coding sessions.
    Guarantees proof of execution and verifies non-tampering before delivery.
    """

    SUSPICIOUS_ENV_PREFIXES = ("MOCK_", "SKIP_", "FORCE_", "NO_VERIFY", "BYPASS_", "FAKE_")

    def __init__(
        self,
        workspace_dir: Optional[Path] = None,
        output_file: Optional[Path] = None,
    ):
        self.workspace_dir = Path(workspace_dir).resolve() if workspace_dir else Path.cwd().resolve()
        if output_file:
            self.output_file = Path(output_file).resolve()
        else:
            self.output_file = self.workspace_dir / ".harness" / "provenance.json"

    def _get_git_commit(self) -> str:
        try:
            out = subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                cwd=self.workspace_dir,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            return out.strip()
        except Exception:
            return "UNKNOWN_COMMIT"

    def _get_git_diff_status(self) -> Tuple[bool, List[str], List[str], List[str]]:
        modified, added, deleted = [], [], []
        try:
            out = subprocess.check_output(
                ["git", "status", "--porcelain"],
                cwd=self.workspace_dir,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in out.splitlines():
                if not line.strip():
                    continue
                code = line[:2].strip()
                path = line[3:].strip()
                if "?" in code or "A" in code:
                    added.append(path)
                elif "D" in code:
                    deleted.append(path)
                else:
                    modified.append(path)
            is_clean = len(modified) == 0 and len(added) == 0 and len(deleted) == 0
            return is_clean, modified, added, deleted
        except Exception:
            return False, [], [], []

    def _detect_env_overrides(self) -> Dict[str, str]:
        detected = {}
        for k, v in os.environ.items():
            if any(k.upper().startswith(p) for p in self.SUSPICIOUS_ENV_PREFIXES):
                detected[k] = v
        return detected

    def generate_manifest(
        self,
        mode: str = "bugfix",
        test_command: Optional[str] = None,
        reproducibility_passes: int = 2,
    ) -> RunProvenanceManifest:
        """
        Generates full audit manifest, evaluating git status, environment overrides,
        test boundary integrity, and reproducibility.
        """
        base_commit = self._get_git_commit()
        is_clean, mod, add, dlt = self._get_git_diff_status()
        env_overrides = self._detect_env_overrides()

        # Check test boundary
        guard = TestBoundaryGuard(workspace_dir=self.workspace_dir)
        report = guard.verify(mode=mode)
        test_boundary_verified = report.is_intact

        # Check reproducibility if test command provided
        repro_verified = False
        repro_runs = 0
        if test_command:
            success, _, _ = guard.run_reproducible(test_command, passes=reproducibility_passes)
            repro_verified = success
            repro_runs = reproducibility_passes

        manifest = RunProvenanceManifest(
            version="1.3.0",
            session_timestamp=datetime.now(timezone.utc).isoformat(),
            workspace_dir=str(self.workspace_dir),
            git_base_commit=base_commit,
            git_status_clean=is_clean,
            files_modified=mod,
            files_added=add,
            files_deleted=dlt,
            environment_overrides=env_overrides,
            test_boundary_verified=test_boundary_verified,
            test_boundary_mode=mode,
            reproducibility_verified=repro_verified,
            reproducibility_runs=repro_runs,
        )

        # Persist manifest to disk
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file = self.output_file.with_suffix(".tmp")
        temp_file.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
        temp_file.replace(self.output_file)

        return manifest
