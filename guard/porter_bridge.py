"""
guard/porter_bridge.py — Bridge to Porter Suitability & Transpilation Engine
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Ingestion is bound to what the operator reviewed: the inspected content hash must match
the content that is written, destination symlinks are refused, and the governance scope
ends locked (secure default) with a refreshed integrity baseline.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Ensure repository root is in python path for porter imports
SCRIPT_DIR = Path(__file__).resolve().parent.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from guard.environment import EnvironmentLocker, EnvironmentRegistry
from guard.integrity import FileIntegrityMonitor
from guard.os_adapter import OSProtectionAdapter
from guard.paths import config_dir
from guard.snapshot import SnapshotEngine, _AdapterLocker
from porter import __version__ as PORTER_VERSION
from porter.analyzer import SuitabilityAnalyzer
from porter.sanitizer import ConstitutionalSanitizer


class PorterBridge:
    """
    Connects Antigravity Guard with the Porter transpiler and suitability gate.
    The target is unlocked ONLY during vetted promotion and re-locked afterwards.
    """

    def __init__(self, target_dir: Optional[Path] = None, os_adapter: Optional[OSProtectionAdapter] = None):
        self.target_dir = Path(target_dir).resolve() if target_dir is not None else config_dir()
        self.os_adapter = os_adapter or OSProtectionAdapter(self.target_dir)
        registry = EnvironmentRegistry(os_adapter=self.os_adapter) if os_adapter is None else None
        global_env = registry.get_environment("antigravity") if registry else None
        if global_env is not None and global_env.get_root() == self.target_dir:
            self.locker = EnvironmentLocker(registry, "antigravity")
            self.integrity_monitor = FileIntegrityMonitor.for_environment(global_env, os_adapter=self.os_adapter)
            self.snapshot_engine = SnapshotEngine.for_environment(global_env, registry)
        else:
            self.locker = _AdapterLocker(self.os_adapter, self.target_dir)
            self.integrity_monitor = FileIntegrityMonitor(self.target_dir, os_adapter=self.os_adapter)
            self.snapshot_engine = SnapshotEngine(self.target_dir, os_adapter=self.os_adapter, locker=self.locker)

    def inspect_content(self, raw_content: str, name: str = "incoming_rule") -> Dict[str, Any]:
        """Runs the 4-dimensional suitability analysis on raw rule content."""
        analyzer = SuitabilityAnalyzer()
        report = analyzer.analyze(raw_content, source_identifier=name)
        sanitized = ConstitutionalSanitizer.sanitize_for_import(raw_content)

        violations = [issue.message for issue in report.issues if issue.severity == "CRITICAL"]
        warnings = [issue.message for issue in report.issues if issue.severity == "WARNING"]
        recommendations = [issue.suggested_fix for issue in report.issues]

        return {
            "name": report.recommended_name or name,
            "category": report.detected_format,
            "alignment_score": report.constitutional_score,
            "adaptability_score": report.adaptability_score,
            "target_type": report.recommended_type,
            "violations": violations,
            "warnings": warnings,
            "recommendations": recommendations,
            "redundancies": report.redundancies,
            "original_content": raw_content,
            "content_sha256": hashlib.sha256(raw_content.encode("utf-8")).hexdigest(),
            "sanitized_content": sanitized,
            "is_admissible": report.is_safe_to_import,
        }

    def inspect_source(self, source_path_or_url: str) -> Dict[str, Any]:
        """Loads and inspects an external file path or URL with strict SSRF protection."""
        import urllib.parse
        from porter.net import safe_fetch_url

        raw_content = ""
        source_name = "external_rule"

        if source_path_or_url.startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse(source_path_or_url)
            raw_content = safe_fetch_url(source_path_or_url, user_agent=f"AntigravityGuard/{PORTER_VERSION}")
            source_name = Path(parsed.path).name or "remote_rule"
        else:
            p = Path(source_path_or_url).resolve()
            if not p.is_file():
                raise FileNotFoundError(f"Source file not found: {source_path_or_url}")
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                raw_content = f.read()
            source_name = p.stem

        return self.inspect_content(raw_content, name=source_name)

    def stage_and_ingest(
        self,
        source_path_or_url: str,
        target_name: Optional[str] = None,
        force: bool = False,
        expected_sha256: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Executes the Staging & Ingestion Gate:
        1. Re-inspects the source and checks it matches the reviewed content hash.
        2. Takes an automatic pre-ingestion snapshot.
        3. Unlocks the governance scope (only if it is locked).
        4. Writes the sanitized rule into skills/, agents/ or rules/ (never through a symlink).
        5. Refreshes the integrity baseline.
        6. Re-locks the governance scope (always — secure default).
        """
        inspection = self.inspect_source(source_path_or_url)
        if expected_sha256 and inspection["content_sha256"] != expected_sha256:
            return False, "Ingestion rejected: the source changed after it was reviewed. Inspect it again."
        if not inspection["is_admissible"] and not force:
            return (
                False,
                f"Ingestion rejected: Constitutional Score {inspection['alignment_score']}/100. "
                f"Violations: {'; '.join(inspection['violations'])}",
            )

        raw_name = target_name or inspection["name"]
        name = re.sub(r"[^a-zA-Z0-9_-]", "-", Path(raw_name).name).strip("-").lower() or "imported-rule"

        target_type = inspection["target_type"]
        sanitized = inspection["sanitized_content"]

        if target_type == "skill":
            dest_dir = self.target_dir / "skills" / name
            dest_file = dest_dir / "SKILL.md"
        elif target_type in ("subagent", "agent"):
            dest_dir = self.target_dir / "agents"
            dest_file = dest_dir / f"{name}.md"
        else:
            dest_dir = self.target_dir / "rules"
            dest_file = dest_dir / f"{name}.md"

        # Containment and symlink invariants (checked lexically AND after resolution)
        for candidate in (dest_dir, dest_file):
            if os.path.islink(candidate):
                return False, f"Refusing to write through symlink {candidate}."
            try:
                candidate.resolve().relative_to(self.target_dir)
            except ValueError:
                return False, f"Invalid destination path traversal detected for '{name}'."

        try:
            snap_id, _ = self.snapshot_engine.create_snapshot(label=f"pre_ingest_{name}", kind="pre_ingest")
        except Exception as e:
            return False, f"Ingestion aborted: pre-ingestion snapshot failed ({e})."

        if self.locker.is_locked():
            ok, msg = self.locker.unlock()
            if not ok:
                self.locker.lock()
                return False, f"Ingestion aborted: could not unlock the target ({msg})."

        success = False
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(dest_file), flags, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(sanitized)
                f.write("\n")
            file_count, _ = self.integrity_monitor.save_baseline()
            status_msg = f"Ingested '{name}' ({target_type}) -> {dest_file.name}. Baseline updated ({file_count} files). Snapshot: {snap_id}"
            success = True
        except Exception as e:
            ok, rb_msg = self.snapshot_engine.restore_snapshot(snap_id)
            status_msg = f"Ingestion error: {e}. " + (f"Rolled back to {snap_id}." if ok else f"Rollback failed: {rb_msg}")
        finally:
            relock_ok, relock_msg = self.locker.lock()
            if not relock_ok:
                if success:
                    status_msg = f"{status_msg} [WARNING: Re-lock failed: {relock_msg}]"
                    success = False
                else:
                    status_msg = f"{status_msg} [Re-lock also failed: {relock_msg}]"

        return success, status_msg
