"""
guard/integrity.py — Cryptographic File Integrity Monitor (FIM)
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from guard.os_adapter import OSProtectionAdapter


@dataclass
class IntegrityReport:
    timestamp: str
    target_dir: str
    total_files: int
    is_intact: bool
    modified: List[str] = field(default_factory=list)
    added: List[str] = field(default_factory=list)
    deleted: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)

    def summary(self) -> str:
        if self.is_intact:
            return f"[OK] Integrity Verified: {self.total_files} files intact. Zero drift or tampering detected."
        parts = []
        if self.modified:
            parts.append(f"{len(self.modified)} modified")
        if self.added:
            parts.append(f"{len(self.added)} unauthorized added")
        if self.deleted:
            parts.append(f"{len(self.deleted)} deleted")
        return f"[WARN] INTEGRITY DRIFT DETECTED: {', '.join(parts)} across {self.total_files} tracked files."


class FileIntegrityMonitor:
    """
    Cryptographic SHA-256 File Integrity Monitor (FIM).
    Tracks all constitutional files, skills, subagents, and configurations to guarantee
    zero tampering by rogue processes or hallucinating agents.
    """

    EXCLUDED_PATTERNS = {
        "__pycache__",
        ".git",
        ".pytest_cache",
        "node_modules",
        "guard_integrity.json",
        ".guard_integrity.json",
        ".guard_snapshots",
        ".DS_Store",
    }

    def __init__(
        self,
        target_dir: Optional[Path] = None,
        state_file: Optional[Path] = None,
        os_adapter: Optional[OSProtectionAdapter] = None,
    ):
        if target_dir is None:
            config_env = os.environ.get("ANTIGRAVITY_CONFIG_DIR")
            self.target_dir = Path(config_env).resolve() if config_env else Path.home() / ".gemini" / "config"
        else:
            self.target_dir = Path(target_dir).resolve()

        if state_file is not None:
            self.state_file = Path(state_file).resolve()
        elif "ANTIGRAVITY_INTEGRITY_FILE" in os.environ:
            self.state_file = Path(os.environ["ANTIGRAVITY_INTEGRITY_FILE"]).resolve()
        else:
            isolated_candidate = Path.home() / ".gemini" / ".guard_integrity.json"
            if isolated_candidate.exists() and not (self.target_dir / ".guard_integrity.json").exists():
                self.state_file = isolated_candidate.resolve()
            else:
                self.state_file = self.target_dir / ".guard_integrity.json"

        self.os_adapter = os_adapter or OSProtectionAdapter(self.target_dir)

    @property
    def is_isolated(self) -> bool:
        """Returns True if the integrity baseline is isolated outside the target directory."""
        try:
            self.state_file.relative_to(self.target_dir)
            return False
        except ValueError:
            return True

    def _hash_file(self, path: Path) -> str:
        """Calculates SHA-256 checksum of a file."""
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""

    def scan_directory(self) -> Dict[str, str]:
        """Recursively scans target directory and returns relative_path -> sha256."""
        hashes: Dict[str, str] = {}
        if not self.target_dir.exists():
            return hashes

        for root, dirs, files in os.walk(self.target_dir):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in self.EXCLUDED_PATTERNS and not d.startswith(".backup_")]
            for f in files:
                if (
                    f in self.EXCLUDED_PATTERNS
                    or f == self.state_file.name
                    or f.startswith(".guard_")
                    or f.endswith(".tmp")
                    or f.endswith(".swp")
                ):
                    continue
                file_path = Path(root) / f
                # Skip broken symlinks or unreadable files
                if not file_path.is_file():
                    continue
                rel_path = file_path.relative_to(self.target_dir).as_posix()
                file_hash = self._hash_file(file_path)
                if file_hash:
                    hashes[rel_path] = file_hash

        return dict(sorted(hashes.items()))

    def save_baseline(self) -> Tuple[int, str]:
        """Saves current state as the trusted baseline manifest."""
        was_locked = self.os_adapter.is_locked()
        if was_locked:
            self.os_adapter.unlock()

        try:
            current_hashes = self.scan_directory()
            payload = {
                "version": "1.2.5",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "target_dir": str(self.target_dir),
                "file_count": len(current_hashes),
                "files": current_hashes,
            }
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
                f.write("\n")
        finally:
            if was_locked:
                self.os_adapter.lock()

        return len(current_hashes), self.state_file.as_posix()

    def verify(self) -> IntegrityReport:
        """Compares current file hashes against the baseline manifest."""
        current_hashes = self.scan_directory()
        now_str = datetime.now(timezone.utc).isoformat()

        if not self.state_file.exists():
            # If no baseline exists, establish current as baseline
            self.save_baseline()
            return IntegrityReport(
                timestamp=now_str,
                target_dir=str(self.target_dir),
                total_files=len(current_hashes),
                is_intact=True,
            )

        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                baseline_data = json.load(f)
            baseline_files: Dict[str, str] = baseline_data.get("files", {})
        except Exception:
            return IntegrityReport(
                timestamp=now_str,
                target_dir=str(self.target_dir),
                total_files=len(current_hashes),
                is_intact=False,
                modified=["[ERROR: Corrupted baseline state file]"],
            )

        current_keys: Set[str] = set(current_hashes.keys())
        baseline_keys: Set[str] = set(baseline_files.keys())

        added = sorted(list(current_keys - baseline_keys))
        deleted = sorted(list(baseline_keys - current_keys))
        modified = sorted(
            [k for k in (current_keys & baseline_keys) if current_hashes[k] != baseline_files[k]]
        )

        is_intact = not (added or deleted or modified)

        return IntegrityReport(
            timestamp=now_str,
            target_dir=str(self.target_dir),
            total_files=len(current_hashes),
            is_intact=is_intact,
            modified=modified,
            added=added,
            deleted=deleted,
        )
