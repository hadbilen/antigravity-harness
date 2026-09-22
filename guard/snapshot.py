"""
guard/snapshot.py — Snapshot and Verified Rollback Engine
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Snapshots are stored OUTSIDE the protected tree (per-user data directory), carry a
content manifest, preserve symlinks as symlinks, and are verified before restore.
Restore never writes through a destination symlink, takes a mandatory pre-restore
backup, and swaps entries with a journal so a failure rolls back to the prior state.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from guard.os_adapter import OSProtectionAdapter
from guard.paths import atomic_write_json, config_dir, data_dir, is_within, path_key

SNAP_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


class _AdapterLocker:
    """Default lock controller: the whole target directory via the OS adapter."""

    def __init__(self, adapter: OSProtectionAdapter, target: Path):
        self.adapter = adapter
        self.target = target

    def is_locked(self) -> bool:
        return self.adapter.is_locked(self.target)

    def unlock(self) -> Tuple[bool, str]:
        return self.adapter.unlock(self.target)

    def lock(self) -> Tuple[bool, str]:
        return self.adapter.lock(self.target)


class SnapshotEngine:
    """
    Manages local snapshots of the governance tree, enabling rollback before any
    external rule ingestion or experimental edits.
    """

    META_FILE = ".snap_meta.json"
    IGNORED_NAMES = {".guard_snapshots", ".guard_integrity.json", "__pycache__", ".git", ".DS_Store"}
    IGNORED_PREFIXES = (".backup_", "backup_", ".agy-restore-", ".agy-old-")

    def __init__(
        self,
        target_dir: Optional[Path] = None,
        os_adapter: Optional[OSProtectionAdapter] = None,
        scope_paths: Optional[Sequence[str]] = None,
        snapshots_dir: Optional[Path] = None,
        exclude_names: Optional[Iterable[str]] = None,
        locker=None,
        integrity_monitor=None,
    ):
        self.target_dir = Path(target_dir).resolve() if target_dir is not None else config_dir()
        self.os_adapter = os_adapter or OSProtectionAdapter(self.target_dir)
        self.scope_paths = list(scope_paths) if scope_paths is not None else None
        self.exclude_names: Set[str] = set(exclude_names or ())
        self.snapshots_dir = Path(snapshots_dir) if snapshots_dir else data_dir() / "snapshots" / path_key(self.target_dir)
        self.legacy_snapshots_dir = self.target_dir / ".guard_snapshots"
        self.locker = locker or _AdapterLocker(self.os_adapter, self.target_dir)
        self.integrity_monitor = integrity_monitor

    @classmethod
    def for_environment(cls, env, registry, integrity_monitor=None) -> "SnapshotEngine":
        from guard.environment import ANTIGRAVITY_RUNTIME_ENTRIES, EnvironmentLocker

        scope = [os.path.relpath(p, env.get_root()) for p in env.get_governance_paths(existing_only=False)]
        return cls(
            target_dir=env.get_root(),
            os_adapter=registry.os_adapter,
            scope_paths=scope,
            snapshots_dir=data_dir() / "snapshots" / env.id,
            exclude_names=ANTIGRAVITY_RUNTIME_ENTRIES,
            locker=EnvironmentLocker(registry, env.id),
            integrity_monitor=integrity_monitor,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _ignored(self, name: str) -> bool:
        return name in self.IGNORED_NAMES or name.startswith(self.IGNORED_PREFIXES)

    def _copytree_ignore(self, src: str, names: List[str]) -> List[str]:
        return [n for n in names if self._ignored(n)]

    def _scope_entries(self) -> List[str]:
        if self.scope_paths is not None:
            return [n for n in self.scope_paths if not self._ignored(Path(n).name)]
        if not self.target_dir.is_dir():
            return []
        return sorted(
            n for n in os.listdir(self.target_dir)
            if not self._ignored(n) and n not in self.exclude_names
        )

    @staticmethod
    def _copy_entry(src: Path, dst: Path, ignore: Callable) -> None:
        dst.parent.mkdir(parents=True, exist_ok=True)
        if os.path.islink(src):
            os.symlink(os.readlink(src), dst)
        elif src.is_dir():
            shutil.copytree(src, dst, symlinks=True, ignore=ignore)
        else:
            shutil.copy2(src, dst, follow_symlinks=False)

    @staticmethod
    def _remove_entry(path: Path) -> None:
        if os.path.islink(path) or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path)

    def _hash_tree(self, root: Path) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            for name in list(dirnames):
                p = Path(dirpath) / name
                if os.path.islink(p):
                    result[p.relative_to(root).as_posix()] = f"symlink:{os.readlink(p)}"
            for name in sorted(filenames):
                p = Path(dirpath) / name
                rel = p.relative_to(root).as_posix()
                if rel == self.META_FILE:
                    continue
                if os.path.islink(p):
                    result[rel] = f"symlink:{os.readlink(p)}"
                    continue
                hasher = hashlib.sha256()
                with open(p, "rb") as fh:
                    while chunk := fh.read(65536):
                        hasher.update(chunk)
                result[rel] = hasher.hexdigest()
        return result

    def _snapshot_path(self, snap_id: str) -> Optional[Path]:
        if not snap_id or not SNAP_ID_RE.match(snap_id):
            return None
        snap_root = self.snapshots_dir.resolve()
        snap_path = (self.snapshots_dir / snap_id).resolve()
        try:
            snap_path.relative_to(snap_root)
        except ValueError:
            return None
        return snap_path

    def _read_meta(self, snap_path: Path) -> Optional[Dict]:
        meta_file = snap_path / self.META_FILE
        if not meta_file.is_file():
            return None
        try:
            return json.loads(meta_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def create_snapshot(self, label: Optional[str] = None, kind: str = "manual") -> Tuple[str, Path]:
        """Creates a timestamped snapshot of the governance scope with a content manifest."""
        now = datetime.now(timezone.utc)
        timestamp = now.strftime("%Y%m%d_%H%M%S_%f")
        safe_label = ("_" + "".join(c for c in label if c.isalnum() or c in "-_")) if label else ""
        prefix = "pre_rollback" if kind == "pre_rollback" else "snap"
        snap_id = f"{prefix}_{timestamp}{safe_label if kind != 'pre_rollback' else ''}"
        dest_dir = self.snapshots_dir / snap_id
        dest_dir.mkdir(parents=True, exist_ok=False)
        try:
            entries = []
            for name in self._scope_entries():
                src = self.target_dir / name
                if not os.path.lexists(src):
                    continue
                self._copy_entry(src, dest_dir / name, self._copytree_ignore)
                entries.append(name)
            meta = {
                "id": snap_id,
                "label": label or ("Pre-restore backup" if kind == "pre_rollback" else "Manual Snapshot"),
                "kind": kind,
                "created_at": now.isoformat(),
                "target_dir": str(self.target_dir),
                "scope": entries,
                "files": self._hash_tree(dest_dir),
            }
            atomic_write_json(dest_dir / self.META_FILE, meta, mode=0o600)
        except Exception:
            shutil.rmtree(dest_dir, ignore_errors=True)
            raise
        return snap_id, dest_dir

    def list_snapshots(self) -> List[Dict]:
        """Returns all snapshots, newest first. Entries without metadata are marked 'unknown'."""
        if not self.snapshots_dir.exists():
            return []
        results = []
        for d in self.snapshots_dir.iterdir():
            if not d.is_dir():
                continue
            meta = self._read_meta(d)
            if meta is None:
                meta = {"id": d.name, "label": "Unknown (no metadata)", "created_at": "Unknown", "kind": "unknown"}
            meta = dict(meta)
            meta.pop("files", None)
            meta["path"] = str(d)
            meta.setdefault("kind", "manual")
            results.append(meta)
        results.sort(key=lambda m: (m.get("created_at") != "Unknown", m.get("created_at", "")), reverse=True)
        return results

    def restore_snapshot(self, snap_id: str) -> Tuple[bool, str]:
        """Restores the governance scope to the specified snapshot state (verified, journaled)."""
        source_dir = self._snapshot_path(snap_id)
        if source_dir is None:
            return False, f"Invalid snapshot identifier '{snap_id}' (path traversal or malformed id)."
        if not source_dir.is_dir():
            return False, f"Snapshot '{snap_id}' does not exist."

        meta = self._read_meta(source_dir)
        if meta and "files" in meta:
            actual = self._hash_tree(source_dir)
            if actual != meta["files"]:
                return False, f"Snapshot '{snap_id}' failed verification: its content no longer matches its manifest."

        restore_names = sorted(n for n in os.listdir(source_dir) if n != self.META_FILE)
        current_names = [n for n in self._scope_entries() if os.path.lexists(self.target_dir / n)]
        remove_names = sorted(set(current_names) - set(restore_names))

        for name in restore_names + remove_names:
            dst = self.target_dir / name
            src = source_dir / name
            if os.path.islink(dst) and not os.path.islink(src):
                return False, (
                    f"Refusing to restore: {dst} is a symlink and restore never writes through symlinks. "
                    f"Reinstall in copy mode first."
                )

        try:
            pre_id, _ = self.create_snapshot(label=f"before restore of {snap_id}", kind="pre_rollback")
        except Exception as e:
            return False, f"Emergency pre-restore backup failed ({e}); restore aborted without changes."

        was_locked = self.locker.is_locked()
        if was_locked:
            ok, msg = self.locker.unlock()
            if not ok:
                return False, f"Could not unlock target for restore: {msg}"

        token = uuid.uuid4().hex[:8]
        journal: List[Tuple[str, Optional[Path], bool]] = []  # (name, old_copy, new_placed)
        try:
            for name in restore_names:
                dst = self.target_dir / name
                staged = self.target_dir / f".agy-restore-{token}-{name}"
                self._copy_entry(source_dir / name, staged, self._copytree_ignore)
                old: Optional[Path] = None
                if os.path.lexists(dst):
                    old = self.target_dir / f".agy-old-{token}-{name}"
                    os.replace(dst, old)
                os.replace(staged, dst)
                journal.append((name, old, True))
            for name in remove_names:
                dst = self.target_dir / name
                old = self.target_dir / f".agy-old-{token}-{name}"
                os.replace(dst, old)
                journal.append((name, old, False))
        except Exception as e:
            rollback_errors = []
            for name, old, placed in reversed(journal):
                dst = self.target_dir / name
                try:
                    if placed and os.path.lexists(dst):
                        self._remove_entry(dst)
                    if old is not None and os.path.lexists(old):
                        os.replace(old, dst)
                except OSError as rb:
                    rollback_errors.append(f"{name}: {rb}")
            for leftover in self.target_dir.glob(f".agy-restore-{token}-*"):
                try:
                    self._remove_entry(leftover)
                except OSError:
                    pass
            if was_locked:
                self.locker.lock()
            extra = f" Rollback problems: {rollback_errors}. Pre-restore backup: {pre_id}." if rollback_errors else ""
            return False, f"Restore of '{snap_id}' failed and was rolled back: {e}.{extra}"

        cleanup_errors = []
        for _, old, _ in journal:
            if old is not None and os.path.lexists(old):
                try:
                    self._remove_entry(old)
                except OSError as ce:
                    cleanup_errors.append(str(ce))

        relock_msg = ""
        if was_locked:
            ok, lock_msg = self.locker.lock()
            if not ok:
                relock_msg = f" WARNING: re-lock failed: {lock_msg}"

        baseline_msg = ""
        if self.integrity_monitor is not None:
            try:
                count, _ = self.integrity_monitor.save_baseline()
                baseline_msg = f" Integrity baseline re-established ({count} files)."
            except Exception as be:
                baseline_msg = f" WARNING: baseline refresh failed: {be}."

        cleanup_msg = f" Cleanup warnings: {cleanup_errors}." if cleanup_errors else ""
        success = not relock_msg
        return success, (
            f"Successfully restored snapshot '{snap_id}' (pre-restore backup: {pre_id}).{baseline_msg}{relock_msg}{cleanup_msg}"
        )

    def prune_snapshots(self, keep: int = 5) -> int:
        """Keeps the newest `keep` snapshots of EACH kind (manual, pre_rollback, ...)."""
        by_kind: Dict[str, List[Dict]] = {}
        for snap in self.list_snapshots():
            by_kind.setdefault(snap.get("kind", "manual"), []).append(snap)
        pruned = 0
        for snaps in by_kind.values():
            for snap in snaps[keep:]:
                path = Path(snap["path"])
                if path.exists() and is_within(path, self.snapshots_dir):
                    shutil.rmtree(path, ignore_errors=True)
                    pruned += 1
        return pruned

    def get_snapshot_files(self, snap_id: str) -> List[str]:
        """Returns sorted relative paths of all files in the specified snapshot."""
        snap_path = self._snapshot_path(snap_id)
        if snap_path is None or not snap_path.is_dir():
            return []
        files = []
        for p in snap_path.rglob("*"):
            if p.is_file() and p.name != self.META_FILE:
                files.append(p.relative_to(snap_path).as_posix())
        return sorted(files)

    def resolve_snapshot_file(self, snap_id: str, rel_path: str) -> Optional[Path]:
        """Resolves a file inside a snapshot, rejecting any path that escapes the snapshot."""
        snap_path = self._snapshot_path(snap_id)
        if snap_path is None:
            return None
        target_file = (snap_path / rel_path).resolve()
        try:
            target_file.relative_to(snap_path)
        except ValueError:
            return None
        return target_file if target_file.is_file() else None

    def read_snapshot_file(self, snap_id: str, rel_path: str) -> Optional[str]:
        """Reads content of a specific file in a snapshot with path traversal guard."""
        target_file = self.resolve_snapshot_file(snap_id, rel_path)
        if target_file is None:
            return None
        try:
            return target_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
