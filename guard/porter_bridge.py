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
from porter.archive import inspect_zip
from porter.frontmatter import FrontmatterError, dump_frontmatter, parse_frontmatter_block, split_frontmatter
from porter.sanitizer import ConstitutionalSanitizer


class PorterBridge:
    """
    Connects Antigravity Guard with the Porter transpiler and suitability gate.
    The target is unlocked ONLY during vetted promotion and re-locked afterwards.
    """

    def __init__(self, target_dir: Optional[Path] = None, os_adapter: Optional[OSProtectionAdapter] = None):
        self.target_dir = Path(target_dir).resolve() if target_dir is not None else config_dir()
        self.os_adapter = os_adapter or OSProtectionAdapter(self.target_dir)
        self.registry = EnvironmentRegistry(os_adapter=self.os_adapter)
        matched_env = self.registry.get_environment("antigravity")
        if matched_env is None or matched_env.get_root() != self.target_dir:
            matched_env = None
            list_fn = getattr(self.registry, "list_environments", None)
            if callable(list_fn):
                for env in list_fn():
                    if env.get_root() == self.target_dir:
                        matched_env = env
                        break
        if matched_env is not None:
            self.env_id: Optional[str] = matched_env.id
            self.locker = EnvironmentLocker(self.registry, matched_env.id)
            self.integrity_monitor = FileIntegrityMonitor.for_environment(matched_env, os_adapter=self.os_adapter)
            self.snapshot_engine = SnapshotEngine.for_environment(matched_env, self.registry)
        else:
            self.env_id = None
            self.locker = _AdapterLocker(self.os_adapter, self.target_dir)
            self.integrity_monitor = FileIntegrityMonitor(self.target_dir, os_adapter=self.os_adapter)
            self.snapshot_engine = SnapshotEngine(self.target_dir, os_adapter=self.os_adapter, locker=self.locker)

    def inspect_content(self, raw_content: str, name: str = "incoming_rule") -> Dict[str, Any]:
        """Runs the 4-dimensional suitability analysis on raw rule content."""
        analyzer = SuitabilityAnalyzer(harness_root=self.target_dir)
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
            "is_archive": False,
            "violations": violations,
            "warnings": warnings,
            "recommendations": recommendations,
            "redundancies": report.redundancies,
            "original_content": raw_content,
            "content_sha256": hashlib.sha256(raw_content.encode("utf-8")).hexdigest(),
            "sanitized_content": sanitized,
            "is_admissible": report.is_safe_to_import,
        }

    def _inspect_zip_archive(self, archive_path: Path) -> Dict[str, Any]:
        """Runs read-only ZIP inspection via porter.archive.inspect_zip."""
        report = inspect_zip(archive_path, harness_root=self.target_dir)
        md = report.to_markdown()
        violations = [
            f"[{h.kind}] {h.member + ': ' if h.member else ''}{h.message}"
            for h in report.hazards
        ]
        warnings = []
        recommendations = [
            "Archives are read-only evidence (GEMINI.md Rule 16); never unpack or stage blindly."
        ]
        scores = []
        for m in report.members:
            if m.constitutional_score is not None:
                scores.append(m.constitutional_score)
            for issue in m.issues:
                entry = f"{m.name}: {issue.message}"
                if issue.severity == "CRITICAL":
                    violations.append(entry)
                elif issue.severity == "WARNING":
                    warnings.append(entry)
                if issue.suggested_fix:
                    recommendations.append(f"{m.name}: {issue.suggested_fix}")
        alignment_score = 0 if report.hazards else (min(scores) if scores else 100)
        return {
            "name": archive_path.stem,
            "category": "ZIP Archive",
            "alignment_score": alignment_score,
            "adaptability_score": 100 if report.is_safe else 0,
            "target_type": "archive",
            "is_archive": True,
            "violations": violations,
            "warnings": warnings,
            "recommendations": recommendations,
            "redundancies": [],
            "original_content": md,
            "content_sha256": hashlib.sha256(md.encode("utf-8")).hexdigest(),
            "sanitized_content": md,
            "is_admissible": report.is_safe,
        }

    @staticmethod
    def _is_zip_source(source_path_or_url: str) -> bool:
        import urllib.parse

        if source_path_or_url.startswith(("http://", "https://")):
            return urllib.parse.urlparse(source_path_or_url).path.lower().endswith(".zip")
        return source_path_or_url.lower().endswith(".zip")

    def inspect_source(self, source_path_or_url: str) -> Dict[str, Any]:
        """Loads and inspects an external file path, local ZIP archive, or URL with strict SSRF protection."""
        import urllib.parse
        from porter.net import safe_fetch_url

        raw_content = ""
        source_name = "external_rule"
        is_zip = self._is_zip_source(source_path_or_url)

        if source_path_or_url.startswith(("http://", "https://")):
            if is_zip:
                raise ValueError(
                    "Remote ZIP archives are not fetched over HTTP(S). "
                    "Download the archive and inspect the local file."
                )
            parsed = urllib.parse.urlparse(source_path_or_url)
            raw_content = safe_fetch_url(source_path_or_url, user_agent=f"AntigravityGuard/{PORTER_VERSION}")
            source_name = Path(parsed.path).name or "remote_rule"
        else:
            p = Path(source_path_or_url).resolve()
            if not p.is_file():
                raise FileNotFoundError(f"Source file not found: {source_path_or_url}")
            if is_zip or p.suffix.lower() == ".zip":
                return self._inspect_zip_archive(p)
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
        2. Refuses ZIP archives (GEMINI.md Rule 16: archives are inspected, never extracted/installed).
        3. Synthesizes valid YAML frontmatter via dump_frontmatter when absent.
        4. Takes an automatic pre-ingestion snapshot.
        5. Unlocks the governance scope (only if it is locked).
        6. Writes the sanitized rule into skills/, agents/ or rules/ (never through a symlink).
        7. Refreshes the integrity baseline.
        8. Re-locks the governance scope (always — secure default).
        """
        if self._is_zip_source(source_path_or_url):
            return (
                False,
                "Ingestion rejected: ZIP archives are read-only evidence and are never extracted or installed (GEMINI.md Rule 16).",
            )
        inspection = self.inspect_source(source_path_or_url)
        if inspection.get("is_archive") or inspection.get("target_type") == "archive":
            return (
                False,
                "Ingestion rejected: ZIP archives are read-only evidence and are never extracted or installed (GEMINI.md Rule 16).",
            )
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

        try:
            fm, body = split_frontmatter(sanitized)
        except FrontmatterError:
            fm, body = None, sanitized
        parsed_meta: Dict[str, Any] = {}
        if isinstance(fm, str):
            try:
                parsed_meta = dict(parse_frontmatter_block(fm))
            except FrontmatterError:
                parsed_meta = {}
        elif isinstance(fm, dict):
            parsed_meta = dict(fm)
        raw_desc = parsed_meta.get("description")
        default_desc = f"{name} ({target_type}) ingested via Porter."
        clean_desc = raw_desc.strip() if isinstance(raw_desc, str) and raw_desc.strip() else default_desc
        if target_type in ("subagent", "agent"):
            meta: Dict[str, Any] = {
                "name": name,
                "description": clean_desc,
                "access": "read-only",
            }
        else:
            meta = {"name": name}
            for k, v in parsed_meta.items():
                if k not in ("name", "description", "access", "tools", "EnableWriteTools", "EnableSubagentTools"):
                    meta[k] = v
            meta["description"] = clean_desc
        header = dump_frontmatter(meta)
        sanitized = f"{header}\n{body.lstrip()}"

        if target_type == "skill":
            dest_dir = self.target_dir / "skills" / name
            dest_file = dest_dir / "SKILL.md"
        elif target_type in ("subagent", "agent"):
            dest_dir = self.target_dir / "agents"
            dest_file = dest_dir / f"{name}.md"
        else:
            dest_dir = self.target_dir / "rules"
            dest_file = dest_dir / f"{name}.md"

        # Containment and symlink invariants (checked lexically on every segment BEFORE resolution)
        segments = (
            (self.target_dir, dest_dir.parent, dest_dir, dest_file)
            if dest_dir.parent != self.target_dir
            else (self.target_dir, dest_dir, dest_file)
        )
        for candidate in segments:
            if os.path.islink(candidate):
                return False, f"Refusing to write through symlink {candidate}."
            try:
                candidate.resolve().relative_to(self.target_dir.resolve())
            except ValueError:
                return False, f"Invalid destination path traversal detected for '{name}'."

        pre_report = self.integrity_monitor.verify()
        if pre_report.baseline_status != "missing" and not pre_report.is_intact:
            return (
                False,
                f"Ingestion aborted: target has pre-existing integrity drift or unreviewed changes "
                f"({pre_report.summary()}). Verify or resolve existing drift before staging new rules.",
            )

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
