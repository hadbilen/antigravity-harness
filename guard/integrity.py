"""
guard/integrity.py — SHA-256 File Integrity Monitor (FIM)
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

The baseline is a flat, unsigned `relative path -> SHA-256` map stored in the per-user
state directory (outside the protected tree). It detects drift; it is not a tamper-proof
record against a process running as the same OS user, which could rewrite both.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from guard.os_adapter import OSProtectionAdapter
from guard.paths import atomic_write_json, config_dir, is_within, path_key, state_dir


@dataclass
class IntegrityReport:
    timestamp: str
    target_dir: str
    total_files: int
    is_intact: bool
    modified: List[str] = field(default_factory=list)
    added: List[str] = field(default_factory=list)
    deleted: List[str] = field(default_factory=list)
    unreadable: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    baseline_status: str = "ok"  # "ok", "missing" or "corrupt"

    def to_dict(self) -> Dict:
        return asdict(self)

    def summary(self) -> str:
        if self.baseline_status == "missing":
            return (f"[WARN] BASELINE MISSING: no trusted baseline yet ({self.total_files} files in scope). "
                    f"Run 'agy-guard rebaseline' after reviewing them.")
        if self.baseline_status == "corrupt":
            return f"[WARN] BASELINE CORRUPT: the baseline file could not be read ({self.total_files} files in scope)."
        if self.is_intact:
            return f"[OK] Integrity Verified: {self.total_files} files intact. Zero drift detected."
        parts = []
        if self.modified:
            parts.append(f"{len(self.modified)} modified")
        if self.added:
            parts.append(f"{len(self.added)} unauthorized added")
        if self.deleted:
            parts.append(f"{len(self.deleted)} deleted")
        if self.unreadable:
            parts.append(f"{len(self.unreadable)} unreadable")
        return f"[WARN] INTEGRITY DRIFT DETECTED: {', '.join(parts)} across {self.total_files} tracked files."


class FileIntegrityMonitor:
    """
    SHA-256 File Integrity Monitor (FIM) for constitutional files, skills and subagents.
    Symlinks are recorded as links (so retargeting is detected); links that leave the
    target tree are followed once, with cycle protection, so their content is hashed too.
    """

    EXCLUDED_NAMES = {
        "__pycache__",
        ".git",
        ".pytest_cache",
        "node_modules",
        "guard_integrity.json",
        ".DS_Store",
    }
    EXCLUDED_PREFIXES = (".guard_", "backup_", ".backup_")
    EXCLUDED_SUFFIXES = (".tmp", ".swp")
    HISTORY_KEEP = 10

    def __init__(
        self,
        target_dir: Optional[Path] = None,
        state_file: Optional[Path] = None,
        os_adapter: Optional[OSProtectionAdapter] = None,
        target_paths: Optional[Sequence[Path]] = None,
        env_id: Optional[str] = None,
    ):
        self.target_dir = Path(target_dir).resolve() if target_dir is not None else config_dir()
        self.target_paths = [Path(os.path.abspath(p)) for p in target_paths] if target_paths is not None else None
        self.env_id = env_id
        self.legacy_state_file: Optional[Path] = None

        is_global_scope = env_id == "antigravity" or (env_id is None and self.target_dir == config_dir())
        if state_file is not None:
            self.state_file = Path(state_file).resolve()
        elif "ANTIGRAVITY_INTEGRITY_FILE" in os.environ and is_global_scope:
            self.state_file = Path(os.environ["ANTIGRAVITY_INTEGRITY_FILE"]).expanduser().resolve()
        else:
            key = env_id or path_key(self.target_dir, *sorted(str(p) for p in (self.target_paths or [])))
            self.state_file = state_dir() / "integrity" / f"{key}.json"
            legacy = self.target_dir / ".guard_integrity.json"
            if not self.state_file.exists() and legacy.is_file():
                self.legacy_state_file = legacy

        self.os_adapter = os_adapter or OSProtectionAdapter(self.target_dir)

    @classmethod
    def for_environment(cls, env, os_adapter: Optional[OSProtectionAdapter] = None) -> "FileIntegrityMonitor":
        """Monitor scoped to an environment's governance seams with a per-environment baseline."""
        return cls(
            target_dir=env.get_root(),
            target_paths=env.get_governance_paths(existing_only=False),
            env_id=env.id,
            os_adapter=os_adapter,
        )

    @property
    def is_isolated(self) -> bool:
        """True if the baseline is stored outside the monitored target directory."""
        return not is_within(self.state_file, self.target_dir)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    def _excluded(self, name: str) -> bool:
        return (
            name in self.EXCLUDED_NAMES
            or name.startswith(self.EXCLUDED_PREFIXES)
            or name.endswith(self.EXCLUDED_SUFFIXES)
        )

    def _key(self, path: Path) -> str:
        try:
            return Path(os.path.abspath(path)).relative_to(self.target_dir).as_posix()
        except ValueError:
            return Path(os.path.abspath(path)).as_posix()

    @staticmethod
    def _hash_file(path: Path) -> str:
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except OSError as e:
            return f"UNREADABLE:{type(e).__name__}"

    def _scan_entry(self, path: Path, hashes: Dict[str, str], visited: Set[str]) -> None:
        key = self._key(path)
        if os.path.islink(path):
            link = os.readlink(path)
            real = Path(os.path.realpath(path))
            if real.is_dir():
                hashes[key] = f"symlink:{link}"
                if not is_within(real, self.target_dir):
                    self._scan_dir(path, hashes, visited)
            elif real.is_file():
                hashes[key] = f"{self._hash_file(real)}|symlink:{link}"
            else:
                hashes[key] = f"symlink-dangling:{link}"
        elif path.is_file():
            hashes[key] = self._hash_file(path)
        elif path.is_dir():
            self._scan_dir(path, hashes, visited)

    def _scan_dir(self, directory: Path, hashes: Dict[str, str], visited: Set[str]) -> None:
        real = os.path.realpath(directory)
        if real in visited:
            return
        visited.add(real)
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError as e:
            hashes[self._key(directory)] = f"UNREADABLE:{type(e).__name__}"
            return
        state_path = os.path.abspath(self.state_file)
        for entry in entries:
            if self._excluded(entry.name) or os.path.abspath(entry.path) == state_path:
                continue
            self._scan_entry(Path(entry.path), hashes, visited)

    def scan_directory(self) -> Dict[str, str]:
        """Scans the target (or its governance scope) and returns relative_path -> sha256."""
        hashes: Dict[str, str] = {}
        if not self.target_dir.exists():
            return hashes
        visited: Set[str] = set()
        if self.target_paths is None:
            self._scan_dir(self.target_dir, hashes, visited)
        else:
            for p in self.target_paths:
                if os.path.lexists(p):
                    self._scan_entry(p, hashes, visited)
        return dict(sorted(hashes.items()))

    # ------------------------------------------------------------------
    # Baseline management
    # ------------------------------------------------------------------
    def _archive_previous_baseline(self) -> None:
        if not self.state_file.is_file():
            return
        history = state_dir() / "integrity" / "history"
        try:
            history.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            shutil.copy2(self.state_file, history / f"{self.state_file.stem}-{stamp}.json")
            archived = sorted(history.glob(f"{self.state_file.stem}-*.json"))
            for old in archived[: -self.HISTORY_KEEP]:
                old.unlink(missing_ok=True)
        except OSError:
            pass

    def save_baseline(self) -> Tuple[int, str]:
        """Saves the current state as the trusted baseline (previous baseline is archived)."""
        from guard import __version__

        current_hashes = self.scan_directory()
        payload = {
            "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target_dir": str(self.target_dir),
            "scope": [str(p) for p in self.target_paths] if self.target_paths is not None else [str(self.target_dir)],
            "file_count": len(current_hashes),
            "files": current_hashes,
        }
        self._archive_previous_baseline()

        parent = self.state_file.parent
        relock_parent = False
        if is_within(self.state_file, self.target_dir) and parent.exists() and not os.access(parent, os.W_OK):
            ok, msg = self.os_adapter.unlock(parent, recursive=False)
            if not ok:
                raise PermissionError(f"Cannot write baseline inside locked directory {parent}: {msg}")
            relock_parent = True
        try:
            atomic_write_json(self.state_file, payload, mode=0o600)
        finally:
            if relock_parent:
                self.os_adapter.lock(self.state_file)
                self.os_adapter.lock(parent, recursive=False)

        return len(current_hashes), self.state_file.as_posix()

    def load_baseline(self) -> Optional[Dict[str, str]]:
        if not self.state_file.exists():
            return None
        with open(self.state_file, "r", encoding="utf-8") as f:
            return json.load(f).get("files", {})

    def verify(self) -> IntegrityReport:
        """Compares current file hashes against the baseline manifest."""
        current_hashes = self.scan_directory()
        now_str = datetime.now(timezone.utc).isoformat()

        if not self.state_file.exists():
            notes = []
            if self.legacy_state_file:
                notes.append(
                    f"A legacy baseline exists at {self.legacy_state_file} (different scope and location). "
                    f"Run 'agy-guard rebaseline' to adopt the per-user baseline."
                )
            return IntegrityReport(
                timestamp=now_str,
                target_dir=str(self.target_dir),
                total_files=len(current_hashes),
                is_intact=False,
                deleted=["[BASELINE MISSING: No baseline found. Run 'agy-guard rebaseline' to establish the initial trusted state]"],
                notes=notes,
                baseline_status="missing",
            )

        try:
            baseline_files = self.load_baseline() or {}
        except (OSError, ValueError, AttributeError):
            return IntegrityReport(
                timestamp=now_str,
                target_dir=str(self.target_dir),
                total_files=len(current_hashes),
                is_intact=False,
                modified=["[ERROR: Corrupted baseline state file]"],
                baseline_status="corrupt",
            )

        current_keys: Set[str] = set(current_hashes.keys())
        baseline_keys: Set[str] = set(baseline_files.keys())

        added = sorted(current_keys - baseline_keys)
        deleted = sorted(baseline_keys - current_keys)
        modified = sorted(k for k in (current_keys & baseline_keys) if current_hashes[k] != baseline_files[k])
        unreadable = sorted(k for k, v in current_hashes.items() if v.startswith("UNREADABLE:"))

        return IntegrityReport(
            timestamp=now_str,
            target_dir=str(self.target_dir),
            total_files=len(current_hashes),
            is_intact=not (added or deleted or modified or unreadable),
            modified=modified,
            added=added,
            deleted=deleted,
            unreadable=unreadable,
        )
