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
from typing import Dict, List, Optional, Tuple

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

            # Copy files back from snapshot
            ignored_names = {".snap_meta.json"}
            for item in source_dir.iterdir():
                if item.name in ignored_names:
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
