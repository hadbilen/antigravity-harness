"""
guard/snapshot.py — Lightweight Snapshot and Atomic Rollback Engine
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from guard.os_adapter import OSProtectionAdapter


class SnapshotEngine:
    """
    Manages lightweight local snapshots of the harness configuration and skills,
    enabling 1-click rollback before any external rule ingestion or experimental edits.
    """

    def __init__(
        self,
        target_dir: Optional[Path] = None,
        os_adapter: Optional[OSProtectionAdapter] = None,
    ):
        if target_dir is None:
            config_env = os.environ.get("ANTIGRAVITY_CONFIG_DIR")
            self.target_dir = Path(config_env).resolve() if config_env else Path.home() / ".gemini" / "config"
        else:
            self.target_dir = Path(target_dir).resolve()

        self.snapshots_dir = self.target_dir / ".guard_snapshots"
        self.os_adapter = os_adapter or OSProtectionAdapter(self.target_dir)

    def create_snapshot(self, label: Optional[str] = None) -> Tuple[str, Path]:
        """Creates a timestamped snapshot of all configuration, skills, and agents."""
        was_locked = self.os_adapter.is_locked()
        if was_locked:
            self.os_adapter.unlock()

        try:
            self.snapshots_dir.mkdir(parents=True, exist_ok=True)
            now = datetime.now(timezone.utc)
            timestamp = now.strftime("%Y%m%d_%H%M%S")
            safe_label = ("_" + "".join(c for c in label if c.isalnum() or c in "-_")) if label else ""
            snap_id = f"snap_{timestamp}{safe_label}"
            dest_dir = self.snapshots_dir / snap_id

            # Copy files excluding snapshot folder itself and temp files
            ignored_names = {".guard_snapshots", ".guard_integrity.json", "__pycache__", ".git"}

            def ignore_filter(src, names):
                return [n for n in names if n in ignored_names or n.startswith(".backup_")]

            shutil.copytree(self.target_dir, dest_dir, ignore=ignore_filter, dirs_exist_ok=True)

            meta = {
                "id": snap_id,
                "label": label or "Manual Snapshot",
                "created_at": now.isoformat(),
                "target_dir": str(self.target_dir),
            }
            with open(dest_dir / ".snap_meta.json", "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)

            return snap_id, dest_dir
        finally:
            if was_locked:
                self.os_adapter.lock()

    def list_snapshots(self) -> List[Dict]:
        """Returns a list of all available snapshots sorted newest first."""
        if not self.snapshots_dir.exists():
            return []

        results = []
        for d in sorted(self.snapshots_dir.iterdir(), reverse=True):
            if d.is_dir():
                meta_file = d / ".snap_meta.json"
                if meta_file.is_file():
                    try:
                        with open(meta_file, "r", encoding="utf-8") as f:
                            meta = json.load(f)
                        meta["path"] = str(d)
                        results.append(meta)
                    except Exception:
                        pass
                else:
                    results.append({"id": d.name, "label": d.name, "created_at": "Unknown", "path": str(d)})
        return results

    def restore_snapshot(self, snap_id: str) -> Tuple[bool, str]:
        """Restores target directory to the specified snapshot state."""
        source_dir = self.snapshots_dir / snap_id
        if not source_dir.is_dir():
            return False, f"Snapshot '{snap_id}' does not exist."

        was_locked = self.os_adapter.is_locked()
        if was_locked:
            self.os_adapter.unlock()

        try:
            # Take an emergency backup of current state first
            now_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            pre_rollback = self.snapshots_dir / f"pre_rollback_{now_ts}"
            try:
                shutil.copytree(
                    self.target_dir,
                    pre_rollback,
                    ignore=lambda s, names: [n for n in names if n == ".guard_snapshots"],
                    dirs_exist_ok=True,
                )
            except Exception:
                pass

            # 1. Index all valid relative paths present in snapshot
            ignored_names = {".guard_snapshots", ".guard_integrity.json", "__pycache__", ".git"}
            snap_rel_paths: Set[Path] = set()
            for root, dirs, files in os.walk(source_dir):
                dirs[:] = [d for d in dirs if d not in ignored_names]
                rel_root = Path(root).relative_to(source_dir)
                for f in files:
                    if f != ".snap_meta.json" and f not in ignored_names:
                        rel_path = f if str(rel_root) == "." else str(rel_root / f)
                        snap_rel_paths.add(Path(rel_path))
                for d in dirs:
                    rel_path = d if str(rel_root) == "." else str(rel_root / d)
                    snap_rel_paths.add(Path(rel_path))

            # 2. Prune extraneous files and directories created after snapshot
            for root, dirs, files in os.walk(self.target_dir, topdown=False):
                rel_root = Path(root).relative_to(self.target_dir)
                if str(rel_root) != ".":
                    top_ancestor = rel_root.parts[0]
                    if top_ancestor in ignored_names or top_ancestor.startswith(".backup_"):
                        continue

                for f in files:
                    if f in ignored_names or f.startswith(".backup_"):
                        continue
                    rel_file = Path(f) if str(rel_root) == "." else Path(rel_root / f)
                    if rel_file not in snap_rel_paths:
                        try:
                            (self.target_dir / rel_file).unlink(missing_ok=True)
                        except Exception:
                            pass

                for d in dirs:
                    if d in ignored_names or d.startswith(".backup_"):
                        continue
                    rel_dir = Path(d) if str(rel_root) == "." else Path(rel_root / d)
                    if rel_dir not in snap_rel_paths:
                        try:
                            shutil.rmtree(self.target_dir / rel_dir, ignore_errors=True)
                        except Exception:
                            pass

            # 3. Copy files back from snapshot
            for item in source_dir.iterdir():
                if item.name in ignored_names or item.name == ".snap_meta.json":
                    continue
                dest_item = self.target_dir / item.name
                if item.is_dir():
                    shutil.copytree(item, dest_item, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, dest_item)

            return True, f"Successfully restored snapshot '{snap_id}'."
        finally:
            if was_locked:
                self.os_adapter.lock()

    def prune_snapshots(self, keep: int = 5) -> int:
        """Prunes older snapshots, keeping only the most recent `keep` entries."""
        snaps = self.list_snapshots()
        if len(snaps) <= keep:
            return 0

        was_locked = self.os_adapter.is_locked()
        if was_locked:
            self.os_adapter.unlock()

        try:
            pruned = 0
            for snap in snaps[keep:]:
                path = Path(snap["path"])
                if path.exists():
                    shutil.rmtree(path, ignore_errors=True)
                    pruned += 1
            return pruned
        finally:
            if was_locked:
                self.os_adapter.lock()

    def get_snapshot_files(self, snap_id: str) -> List[str]:
        """Returns sorted relative paths of all files in the specified snapshot."""
        snap_path = self.snapshots_dir / snap_id
        if not snap_path.is_dir():
            return []
        files = []
        for p in snap_path.rglob("*"):
            if p.is_file() and p.name != ".snap_meta.json":
                files.append(str(p.relative_to(snap_path)))
        return sorted(files)

    def read_snapshot_file(self, snap_id: str, rel_path: str) -> Optional[str]:
        """Reads content of a specific file in a snapshot with path traversal guard."""
        snap_path = (self.snapshots_dir / snap_id).resolve()
        target_file = (snap_path / rel_path).resolve()
        # Security invariant: prevent path traversal outside snapshot directory
        if not str(target_file).startswith(str(snap_path)):
            return None
        if target_file.is_file():
            try:
                return target_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                return None
        return None

