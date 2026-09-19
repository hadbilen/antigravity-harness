"""
guard/porter_bridge.py — Bridge to Porter Suitability & Transpilation Engine
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Ensure repository root is in python path for porter imports
SCRIPT_DIR = Path(__file__).resolve().parent.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from guard.integrity import FileIntegrityMonitor
from guard.os_adapter import OSProtectionAdapter
from guard.snapshot import SnapshotEngine
from porter import __version__ as PORTER_VERSION
from porter.analyzer import SuitabilityAnalyzer
from porter.manifest import ManifestEngine
from porter.parsers.generic_parser import GenericParser
from porter.sanitizer import ConstitutionalSanitizer


class PorterBridge:
    """
    Connects Antigravity Guard with the Porter transpiler and suitability gate.
    Enforces the write protection invariant: Target is unlocked atomically ONLY during
    vetted promotion, and immediately re-locked with a re-computed integrity manifest.
    """

    def __init__(self, target_dir: Optional[Path] = None, os_adapter: Optional[OSProtectionAdapter] = None):
        if target_dir is None:
            config_env = os.environ.get("ANTIGRAVITY_CONFIG_DIR")
            self.target_dir = Path(config_env).resolve() if config_env else Path.home() / ".gemini" / "config"
        else:
            self.target_dir = Path(target_dir).resolve()

        self.os_adapter = os_adapter or OSProtectionAdapter(self.target_dir)
        self.integrity_monitor = FileIntegrityMonitor(self.target_dir)
        self.snapshot_engine = SnapshotEngine(self.target_dir, os_adapter=self.os_adapter)

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
            "sanitized_content": sanitized,
            "is_admissible": report.is_safe_to_import,
        }

    def inspect_source(self, source_path_or_url: str) -> Dict[str, Any]:
        """Loads and inspects an external file path or URL with strict SSRF protection."""
        from porter.parsers.generic_parser import GenericParser
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
    ) -> Tuple[bool, str]:
        """
        Executes the Atomic Staging & Ingestion Gate:
        1. Inspects content and validates admissibility.
        2. Takes automatic pre-ingestion snapshot.
        3. Temporarily unlocks protected target directory.
        4. Writes sanitized rule into skills/ or agents/.
        5. Updates SHA-256 integrity baseline.
        6. Re-locks protected target directory.
        """
        import re
        inspection = self.inspect_source(source_path_or_url)
        if not inspection["is_admissible"] and not force:
            return (
                False,
                f"Ingestion rejected: Constitutional Score {inspection['alignment_score']}/100. "
                f"Violations: {'; '.join(inspection['violations'])}",
            )

        raw_name = target_name or inspection["name"]
        clean_name = re.sub(r"[^a-zA-Z0-9_-]", "-", Path(raw_name).name).strip("-").lower()
        if not clean_name:
            clean_name = "imported-rule"
        name = clean_name

        target_type = inspection["target_type"]
        sanitized = inspection["sanitized_content"]

        # Step 2: Pre-ingestion snapshot
        snap_id, _ = self.snapshot_engine.create_snapshot(label=f"pre_ingest_{name}")

        # Determine target file location with path traversal containment
        if target_type == "skill":
            dest_dir = (self.target_dir / "skills" / name).resolve()
            dest_file = dest_dir / "SKILL.md"
        elif target_type in ("subagent", "agent"):
            dest_dir = (self.target_dir / "agents").resolve()
            dest_file = dest_dir / f"{name}.md"
        else:
            dest_dir = (self.target_dir / "rules").resolve()
            dest_file = dest_dir / f"{name}.md"

        # Traversal containment invariant
        try:
            dest_dir.relative_to(self.target_dir.resolve())
            dest_file.relative_to(self.target_dir.resolve())
        except ValueError:
            return False, f"Invalid destination path traversal detected for '{name}'."

        # Step 3: Atomic Unlock
        self.os_adapter.unlock()

        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            with open(dest_file, "w", encoding="utf-8") as f:
                f.write(sanitized)
                f.write("\n")

            # Step 5: Update integrity baseline
            file_count, _ = self.integrity_monitor.save_baseline()
            status_msg = f"Ingested '{name}' ({target_type}) -> {dest_file.name}. Baseline updated ({file_count} files). Snapshot: {snap_id}"
            success = True
        except Exception as e:
            # If failed, attempt rollback
            self.snapshot_engine.restore_snapshot(snap_id)
            status_msg = f"Ingestion error: {e}. Rolled back to {snap_id}."
            success = False
        finally:
            # Step 6: Atomic Re-lock
            relock_ok, relock_msg = self.os_adapter.lock()
            if not relock_ok:
                if success:
                    status_msg = f"{status_msg} [WARNING: Re-lock failed: {relock_msg}]"
                    success = False
                else:
                    status_msg = f"{status_msg} [Re-lock also failed: {relock_msg}]"

        return success, status_msg
