#!/usr/bin/env python3
"""
install.py — Antigravity Harness Cross-Platform Installer
Zero-dependency: uses strictly the Python standard library.

Default (copy mode): governance files (constitution, design contract, agents, skills,
templates, manifest, hooks) are COPIED into ~/.gemini/config as real files so Antigravity
Guard can actually write-protect them. Guard's runtime code is copied into the per-user data
directory and small launchers are placed in ~/.local/bin (or %LOCALAPPDATA% on Windows).

--link (developer mode): governance entries are symlinked to this checkout instead. Guard
cannot lock symlinked entries; `agy-guard status` reports them as unprotected.

The installer is Guard-aware: if the governance scope is locked it asks a human to confirm,
unlocks, installs, re-establishes the integrity baseline and locks again. Existing files are
moved to a timestamped backup OUTSIDE the configuration tree; nothing is deleted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from guard import __version__  # noqa: E402
from guard.agy_hooks import PRE_TOOL_USE_MATCHER  # noqa: E402
from guard.approval import refusal_message, request_approval  # noqa: E402
from guard.doctor import recover_or_load_registry  # noqa: E402
from guard.environment import (  # noqa: E402
    ANTIGRAVITY_RUNTIME_ENTRIES,
    CONSOLIDATED_SKILL_SLUGS,
    CONSTITUTION_RULE_FRONTMATTER,
    CONSTITUTION_RULE_REL,
    AgentEnvironment,
    EnvironmentRegistry,
    RegistryError,
    StateFileSnapshot,
    is_harness_constitution_file,
    is_harness_plugin_dir,
    migrate_harness_mcp_config,
    read_install_receipt,
    render_constitution_rule,
    restore_state_files,
    snapshot_state_files,
    stage_hybrid_skill_tree,
    sync_antigravity_plugin_seams,
)
from guard.integrity import FileIntegrityMonitor  # noqa: E402
from guard.lease import LeaseManager  # noqa: E402
from guard.paths import atomic_write_json, atomic_write_text, copy_entry, data_dir, state_dir  # noqa: E402
from guard.plugins import (  # noqa: E402
    HARNESS_PLUGIN_NAMES,
    PLUGIN_ASSET_FILENAMES,
    PLUGIN_CATALOG,
    PLUGIN_OWNED_SKILL_SLUGS,
    _plugin_assets_dir,
    build_plugin_pack,
    rewrite_core_for_hybrid,
)
from guard.startup import StartupManager  # noqa: E402

IS_WINDOWS = platform.system().lower() == "windows"
SYSTEM = platform.system()
GOVERNANCE_FILES = ["DESIGN.md"]
RUNTIME_ENTRIES = ["guard", "porter", "scripts", "guard.py", "porter.py"]
RUNTIME_PORTABLE_SKILL_SCRIPTS = (
    "skills/antislop/scripts/check_ui_slop.py",
    "skills/antislop/scripts/check_synthetic_markers.py",
)
LAUNCHER_MARKER = "antigravity-harness launcher"
RELEASE_BASE = "https://github.com/hadbilen/antigravity-harness/releases/download"
BACKUP_RETENTION_KEEP = 10
_HEX_SHA256_CHARS = frozenset("0123456789abcdef")


def _is_valid_sha256(value: str) -> bool:
    s = (value or "").strip().lower()
    return len(s) == 64 and all(c in _HEX_SHA256_CHARS for c in s)


def _trees_identical(src: Path, dest: Path) -> bool:
    """Returns True when real directory `dest` has identical relative entries and contents to `src`."""
    if not src.is_dir() or not dest.is_dir() or os.path.islink(dest):
        return False

    def _collect(root_dir: Path, apply_ignore: bool) -> Optional[Dict[str, tuple]]:
        entries: Dict[str, tuple] = {}
        try:
            for cur_root, dirs, files in os.walk(root_dir, followlinks=False):
                if apply_ignore:
                    ignored_dirs = set(_ignore(cur_root, dirs))
                    dirs[:] = [d for d in dirs if d not in ignored_dirs]
                    ignored_files = set(_ignore(cur_root, files))
                    files = [f for f in files if f not in ignored_files]
                dirs.sort()
                files.sort()
                cur_path = Path(cur_root)
                rel_dir = cur_path.relative_to(root_dir).as_posix()
                if rel_dir != ".":
                    entries[rel_dir] = ("dir",)
                for d in list(dirs):
                    dp = cur_path / d
                    if os.path.islink(dp):
                        rel = dp.relative_to(root_dir).as_posix()
                        entries[rel] = ("symlink", os.readlink(dp))
                        dirs.remove(d)
                for f in files:
                    fp = cur_path / f
                    rel = fp.relative_to(root_dir).as_posix()
                    if os.path.islink(fp):
                        entries[rel] = ("symlink", os.readlink(fp))
                    elif fp.is_file():
                        st = fp.stat()
                        entries[rel] = ("file", st.st_size, hashlib.sha256(fp.read_bytes()).hexdigest())
                    else:
                        return None
        except OSError:
            return None
        return entries

    src_map = _collect(src, apply_ignore=True)
    if src_map is None:
        return False
    dest_map = _collect(dest, apply_ignore=False)
    if dest_map is None:
        return False
    return src_map == dest_map


def ensure_skill_script_permissions(skills_root: Path) -> None:
    """Ensures 0o755 executable permissions on .py, .sh, and .mjs skill scripts."""
    if not skills_root.is_dir() or os.path.islink(skills_root):
        return
    candidates: List[Path] = []
    for scripts_dir in skills_root.rglob("scripts"):
        if scripts_dir.is_dir() and not os.path.islink(scripts_dir):
            for entry in scripts_dir.rglob("*"):
                if entry.suffix in (".py", ".sh", ".mjs"):
                    candidates.append(entry)
    for script in candidates:
        if not os.path.islink(script) and script.is_file():
            try:
                script.chmod(script.stat().st_mode | 0o755)
            except OSError as exc:
                sys.stderr.write(f"[WARN] Could not set executable permission on {script}: {exc}\n")


def prune_install_backups(keep: int = BACKUP_RETENTION_KEEP, dry_run: bool = False) -> int:
    """Retains at most the newest `keep` `backups/install_*` directories."""
    if isinstance(keep, bool) or not isinstance(keep, int) or keep < 1:
        raise ValueError("keep must be an integer >= 1")
    backups_root = state_dir() / "backups"
    if not backups_root.is_dir() or os.path.islink(backups_root):
        return 0
    try:
        install_dirs = [
            p for p in backups_root.iterdir()
            if p.name.startswith("install_") and p.is_dir() and not os.path.islink(p)
        ]
    except OSError:
        return 0
    install_dirs.sort(key=lambda p: p.name)
    if len(install_dirs) <= keep:
        return 0
    removed = 0
    for old_dir in install_dirs[:-keep]:
        if dry_run:
            removed += 1
            continue
        try:
            Installer._release_legacy_tree(old_dir)
            shutil.rmtree(old_dir)
            removed += 1
        except OSError:
            pass
    return removed


def _write_protected(adapter, path: Path) -> bool:
    """os.access() ignores NTFS deny ACEs on directories, so directories are also asked via the adapter."""
    if not os.access(path, os.W_OK):
        return True
    return IS_WINDOWS and path.is_dir() and adapter.is_locked(path, recursive=False)


def _is_harness_constitution_file(path: Path) -> bool:
    """True when `path` appears to be an earlier Antigravity Harness GEMINI.md installation."""
    return is_harness_constitution_file(path, source_root=SCRIPT_DIR)


def _ignore(src: str, names: List[str]) -> List[str]:
    return [n for n in names if n in ("__pycache__", ".pytest_cache", ".DS_Store") or n.endswith((".pyc", ".pyo"))]


class Installer:
    def __init__(
        self,
        target_dir: Path,
        mode: str,
        dry_run: bool = False,
        expected_sha256: str = "",
        layout: str = "flat",
        explicit_flat: bool = False,
    ):
        if layout not in ("flat", "hybrid"):
            raise ValueError(f"Unsupported install layout: {layout!r}")
        self.target_dir = target_dir
        self.mode = mode  # "copy" | "link"
        self.layout = layout  # "flat" | "hybrid"
        self.explicit_flat = explicit_flat
        self.dry_run = dry_run
        self.expected_sha256 = (expected_sha256 or "").strip()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        self.backup_dir = state_dir() / "backups" / f"install_{stamp}"
        self.installed: List[str] = []
        self.installed_plugins: List[str] = []
        self.retired_mcp_servers: List[str] = []
        self._prior_installed_plugins: List[str] = []
        self._prior_retired_mcp_servers: List[str] = []
        self._backed_up: List[tuple[Path, Path]] = []
        self._placed_new: List[Path] = []
        self._created_dirs_for_cleanup: List[Path] = []
        self._state_snapshots: List[StateFileSnapshot] = []
        self._rollback_registry: Optional[EnvironmentRegistry] = None
        self._runtime_rotation: Optional[tuple[Path, Path]] = None
        self._binary_dest: Optional[Path] = None
        self._hybrid_link_notice_emitted = False

    # ------------------------------------------------------------------
    def log(self, msg: str) -> None:
        print(msg)

    def capture_rollback_state(
        self,
        registry: Optional[EnvironmentRegistry],
        env: Optional[AgentEnvironment],
    ) -> None:
        """Snapshots state files (registry, receipt, FIM baseline/pending) for transactional rollback."""
        if self.dry_run:
            return
        paths: List[Path] = [state_dir() / "install_receipt.json"]
        if registry is not None:
            paths.append(registry.config_path)
            if env is not None:
                monitor = FileIntegrityMonitor.for_environment(env, os_adapter=registry.os_adapter)
                paths.extend([monitor.state_file, monitor.pending_file])
        self._state_snapshots = snapshot_state_files(paths)
        self._rollback_registry = registry

    def _ensure_private_backup_dir(self, parent: Path) -> None:
        parent.mkdir(parents=True, exist_ok=True)
        if not IS_WINDOWS:
            for d in (self.backup_dir.parent, self.backup_dir):
                if d.exists() and not os.path.islink(d):
                    try:
                        os.chmod(d, 0o700)
                    except OSError:
                        pass

    def backup(self, dest: Path) -> bool:
        """Moves an existing entry (file, dir or symlink) into the external backup directory."""
        if not os.path.lexists(dest):
            return False
        rel = dest.relative_to(self.target_dir) if dest.is_relative_to(self.target_dir) else Path(dest.name)
        target = self.backup_dir / rel
        self.log(f"{'[DRY-RUN] backup' if self.dry_run else '[BACKUP]'} {rel} -> {target}")
        if self.dry_run:
            return True
        self._ensure_private_backup_dir(target.parent)
        if not os.path.islink(dest):
            if self._rollback_registry is not None:
                try:
                    self._rollback_registry.os_adapter.unlock(dest, recursive=dest.is_dir())
                except OSError:
                    pass
            if dest.is_dir():
                self._release_legacy_tree(dest)
            elif dest.is_file():
                try:
                    os.chmod(dest, (os.lstat(dest).st_mode & 0o7777) | 0o200)
                except OSError:
                    pass
        shutil.move(str(dest), str(target))
        if not IS_WINDOWS and target.is_file() and not os.path.islink(target) and dest.name in ("mcp_config.json", "config.json"):
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
        self._backed_up.append((dest, target))
        return True

    def rollback(self) -> None:
        """Restores backed-up entries, newly created entries, runtime, and state snapshots on a failed install."""
        if self.dry_run:
            return
        adapter = self._rollback_registry.os_adapter if self._rollback_registry is not None else None
        for created in reversed(self._placed_new):
            try:
                if adapter is not None and os.path.lexists(created) and not os.path.islink(created):
                    adapter.unlock(created, recursive=created.is_dir())
                if os.path.islink(created) or created.is_file():
                    created.unlink(missing_ok=True)
                elif created.is_dir():
                    self._release_legacy_tree(created)
                    shutil.rmtree(created)
            except OSError as exc:
                print(f"[WARN] Rollback failed removing created entry {created}: {exc}", file=sys.stderr)
        for orig_dest, backup_src in reversed(self._backed_up):
            try:
                if os.path.lexists(orig_dest):
                    if adapter is not None and not os.path.islink(orig_dest):
                        adapter.unlock(orig_dest, recursive=orig_dest.is_dir())
                    if os.path.islink(orig_dest) or orig_dest.is_file():
                        orig_dest.unlink(missing_ok=True)
                    elif orig_dest.is_dir():
                        self._release_legacy_tree(orig_dest)
                        shutil.rmtree(orig_dest)
                if os.path.lexists(backup_src):
                    orig_dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(backup_src), str(orig_dest))
            except OSError as exc:
                print(f"[WARN] Rollback failed restoring {orig_dest} from {backup_src}: {exc}", file=sys.stderr)
        for created_dir in reversed(self._created_dirs_for_cleanup):
            try:
                if created_dir.is_dir() and not os.path.islink(created_dir) and not any(created_dir.iterdir()):
                    created_dir.rmdir()
            except OSError as exc:
                print(f"[WARN] Rollback failed removing directory {created_dir}: {exc}", file=sys.stderr)
        if self._runtime_rotation is not None:
            runtime_path, prev_path = self._runtime_rotation
            try:
                if os.path.lexists(prev_path):
                    if runtime_path.exists():
                        if adapter is not None and not os.path.islink(runtime_path):
                            adapter.unlock(runtime_path, recursive=True)
                        self._release_legacy_tree(runtime_path)
                        shutil.rmtree(runtime_path)
                    os.replace(prev_path, runtime_path)
            except OSError as exc:
                print(f"[WARN] Rollback failed restoring runtime {runtime_path}: {exc}", file=sys.stderr)
        if self._state_snapshots:
            restore_state_files(self._state_snapshots, os_adapter=adapter)
        if self._rollback_registry is not None:
            try:
                self._rollback_registry.load()
            except Exception as exc:
                print(f"[WARN] Rollback failed reloading registry: {exc}", file=sys.stderr)

    def place(self, src: Path, dest: Path) -> None:
        """Copies (or links) src to dest after backing up whatever was there."""
        if self.dry_run:
            self.log(f"[DRY-RUN] {'link' if self.mode == 'link' else 'copy'} {src} -> {dest}")
            return
        if self.mode == "copy" and os.path.lexists(dest) and not os.path.islink(dest):
            if dest.is_file() and src.is_file() and dest.read_bytes() == src.read_bytes():
                self.installed.append(str(dest))
                return
            if dest.is_dir() and src.is_dir() and _trees_identical(src, dest):
                self.installed.append(str(dest))
                return
        had_existing = self.backup(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if self.mode == "link":
            try:
                dest.symlink_to(src.resolve(), target_is_directory=src.is_dir())
                self.log(f"[LINKED] {dest.name} -> {src}")
                self.installed.append(str(dest))
                if not had_existing:
                    self._placed_new.append(dest)
                return
            except (OSError, NotImplementedError):
                if IS_WINDOWS and src.is_dir():
                    try:
                        import _winapi

                        _winapi.CreateJunction(str(src.resolve()), str(dest))
                        self.log(f"[JUNCTION] {dest.name} -> {src}")
                        self.installed.append(str(dest))
                        if not had_existing:
                            self._placed_new.append(dest)
                        return
                    except Exception:
                        pass
                self.log(f"[NOTICE] Symlink not permitted for {dest.name}; copying instead.")
        copy_entry(src, dest, _ignore)
        self.log(f"[COPIED] {dest.relative_to(self.target_dir) if dest.is_relative_to(self.target_dir) else dest}")
        self.installed.append(str(dest))
        if not had_existing:
            self._placed_new.append(dest)

    def place_text(self, content: str, dest: Path, label: str = "") -> None:
        """Writes UTF-8 LF text content to dest after backing up any differing entry."""
        data = content.replace("\r\n", "\n").encode("utf-8")
        display = label or (
            str(dest.relative_to(self.target_dir)) if dest.is_relative_to(self.target_dir) else str(dest)
        )
        if self.dry_run:
            self.log(f"[DRY-RUN] write {display} -> {dest}")
            return
        if os.path.lexists(dest) and not os.path.islink(dest) and dest.is_file():
            try:
                if dest.read_bytes() == data:
                    self.installed.append(str(dest))
                    return
            except OSError:
                pass
        had_existing = self.backup(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(dest, content.replace("\r\n", "\n"), mode=0o644)
        self.log(f"[WRITTEN] {display}")
        self.installed.append(str(dest))
        if not had_existing:
            self._placed_new.append(dest)

    # ------------------------------------------------------------------
    def _place_core_file(self, src: Path, dest: Path, rel_path: str) -> None:
        """Places a core file, applying `rewrite_core_for_hybrid()` when installing in hybrid layout."""
        if self.layout == "hybrid" and src.suffix.lower() == ".md":
            raw_text = src.read_text(encoding="utf-8")
            rewritten = rewrite_core_for_hybrid(raw_text, rel_path)
            if rewritten != raw_text:
                if self.mode == "link" and not self._hybrid_link_notice_emitted:
                    self.log("[NOTICE] Hybrid-rewritten core files and plugin packs are installed as real copies even in --link mode.")
                    self._hybrid_link_notice_emitted = True
                self.place_text(rewritten, dest, rel_path)
                return
        self.place(src, dest)

    def _place_core_skill(self, src: Path, dest: Path, skill_name: str) -> None:
        """Places a core skill directory, rewriting plugin-skill paths atomically in hybrid layout."""
        if self.layout != "hybrid":
            self.place(src, dest)
            return
        with tempfile.TemporaryDirectory(prefix=f"agy-core-{skill_name}-") as tmp_stage:
            staged_dir = Path(tmp_stage) / skill_name
            changed_by_rewrite = stage_hybrid_skill_tree(src, skill_name, staged_dir, _ignore)
            if self.dry_run:
                if changed_by_rewrite:
                    self.log(f"[DRY-RUN] copy (hybrid-rewritten) {src} -> {dest}")
                else:
                    self.place(src, dest)
                return
            if self.mode == "link" and not changed_by_rewrite:
                self.place(src, dest)
                return
            if self.mode == "link" and changed_by_rewrite and not self._hybrid_link_notice_emitted:
                self.log("[NOTICE] Hybrid-rewritten core files and plugin packs are installed as real copies even in --link mode.")
                self._hybrid_link_notice_emitted = True
            if os.path.lexists(dest) and not os.path.islink(dest) and dest.is_dir() and _trees_identical(staged_dir, dest):
                self.installed.append(str(dest))
                return
            had_existing = self.backup(dest)
            dest.parent.mkdir(parents=True, exist_ok=True)
            copy_entry(staged_dir, dest, _ignore)
            self.log(f"[COPIED] {dest.relative_to(self.target_dir) if dest.is_relative_to(self.target_dir) else dest}")
            self.installed.append(str(dest))
            if not had_existing:
                self._placed_new.append(dest)

    def install_plugins(self) -> None:
        """Atomically builds and copies the 4 canonical Plugin Packs into `plugins/<pack>/` (copy-only)."""
        target_plugins = self.target_dir / "plugins"
        if os.path.islink(target_plugins) or (os.path.lexists(target_plugins) and not target_plugins.is_dir()):
            raise ValueError(
                f"Refusing to install plugin packs: {target_plugins} is a symbolic link or not a directory."
            )
        if self.mode == "link" and not self._hybrid_link_notice_emitted:
            self.log("[NOTICE] Plugin packs under plugins/ are installed as real copies (not symlinks) even in --link mode.")
            self._hybrid_link_notice_emitted = True
        if self.dry_run:
            assets_dir = _plugin_assets_dir(SCRIPT_DIR)
            for asset_name in PLUGIN_ASSET_FILENAMES:
                asset_path = assets_dir / asset_name
                if os.path.islink(asset_path) or not asset_path.is_file():
                    raise ValueError(f"Plugin SVG logo asset missing or symlink: {asset_path}")
            for pack_name in sorted(PLUGIN_CATALOG):
                dest = target_plugins / pack_name
                if os.path.lexists(dest) and (os.path.islink(dest) or not dest.is_dir()):
                    self.backup(dest)
                self.log(f"[DRY-RUN] install plugin pack {pack_name} -> {dest}")
            return

        plugins_existed = target_plugins.exists()
        target_plugins.mkdir(parents=True, exist_ok=True)
        if not plugins_existed:
            self._created_dirs_for_cleanup.append(target_plugins)

        for pack_name in sorted(PLUGIN_CATALOG):
            dest = target_plugins / pack_name
            stage_parent = Path(tempfile.mkdtemp(prefix=f".{pack_name}-inst-", dir=str(target_plugins)))
            try:
                staged = build_plugin_pack(
                    pack_name,
                    SCRIPT_DIR,
                    stage_parent / pack_name,
                    portable_mcp=False,
                )
                if (
                    os.path.lexists(dest)
                    and not os.path.islink(dest)
                    and dest.is_dir()
                    and _trees_identical(staged, dest)
                ):
                    if not IS_WINDOWS:
                        ensure_skill_script_permissions(dest / "skills")
                    self.installed.append(str(dest))
                    self.installed_plugins.append(pack_name)
                    continue
                had_existing = self.backup(dest)
                os.replace(staged, dest)
                if not IS_WINDOWS:
                    ensure_skill_script_permissions(dest / "skills")
                self.log(f"[PLUGIN] {pack_name} -> {dest.relative_to(self.target_dir)}")
                self.installed.append(str(dest))
                self.installed_plugins.append(pack_name)
                if not had_existing:
                    self._placed_new.append(dest)
            finally:
                shutil.rmtree(stage_parent, ignore_errors=True)

    def install_governance(self) -> None:
        prior_installed: set[str] = set()
        self._prior_installed_plugins = []
        self._prior_retired_mcp_servers = []
        receipt_path = state_dir() / "install_receipt.json"
        rec = read_install_receipt(receipt_path=receipt_path, target_dir=self.target_dir)
        if rec is not None:
            if isinstance(rec.get("installed"), list):
                prior_installed = {str(p).replace("\\", "/") for p in rec["installed"]}
                if isinstance(rec.get("installed_plugins"), list):
                    self._prior_installed_plugins = [
                        str(p) for p in rec["installed_plugins"] if isinstance(p, str) and p in HARNESS_PLUGIN_NAMES
                    ]
                if isinstance(rec.get("retired_mcp_servers"), list):
                    self._prior_retired_mcp_servers = [
                        str(k) for k in rec["retired_mcp_servers"] if isinstance(k, str) and k.strip()
                    ]
            else:
                self.log(f"[WARN] {receipt_path} has no valid 'installed' list; preserving unrecorded custom entries.")

        for name in GOVERNANCE_FILES:
            src = SCRIPT_DIR / name
            if src.is_file():
                self._place_core_file(src, self.target_dir / name, name)

        # Install the global constitution under rules/ (loaded once across Antigravity App, CLI, and IDE/Extensions).
        gemini_src = SCRIPT_DIR / "GEMINI.md"
        if gemini_src.is_file():
            target_rules = self.target_dir / "rules"
            if os.path.lexists(target_rules) and (os.path.islink(target_rules) or not target_rules.is_dir()):
                self.backup(target_rules)
            rule_dest = self.target_dir / CONSTITUTION_RULE_REL
            rule_text = render_constitution_rule(gemini_src, mode=self.mode)
            if self.layout == "hybrid" and self.mode != "link":
                rule_text = rewrite_core_for_hybrid(rule_text, "GEMINI.md")
            self.place_text(
                rule_text,
                rule_dest,
                CONSTITUTION_RULE_REL,
            )
            legacy_gemini = self.target_dir / "GEMINI.md"
            if os.path.lexists(legacy_gemini) and (
                "GEMINI.md" in prior_installed or _is_harness_constitution_file(legacy_gemini)
            ):
                self.backup(legacy_gemini)

        # Retire any previously installed harness-internal MISTAKES.md without touching unrecorded user files.
        legacy_mistakes = self.target_dir / "MISTAKES.md"
        if os.path.lexists(legacy_mistakes):
            is_repo_link = False
            if os.path.islink(legacy_mistakes):
                try:
                    is_repo_link = Path(os.path.realpath(legacy_mistakes)) == (SCRIPT_DIR / "MISTAKES.md").resolve()
                except OSError:
                    is_repo_link = False
            if "MISTAKES.md" in prior_installed or is_repo_link:
                self.backup(legacy_mistakes)
        manifest = SCRIPT_DIR / ".harness" / "manifest.json"
        if manifest.is_file():
            target_harness = self.target_dir / ".harness"
            if os.path.lexists(target_harness) and (os.path.islink(target_harness) or not target_harness.is_dir()):
                self.backup(target_harness)
            manifest_dest = target_harness / "manifest.json"
            if self.layout == "hybrid" and self.mode == "link":
                self.place_text(manifest.read_text(encoding="utf-8"), manifest_dest, ".harness/manifest.json")
            else:
                self.place(manifest, manifest_dest)
        for sub in ("agents",):
            target_sub = self.target_dir / sub
            if os.path.lexists(target_sub) and (os.path.islink(target_sub) or not target_sub.is_dir()):
                self.backup(target_sub)
            src_agents = {p.name: p for p in sorted((SCRIPT_DIR / sub).glob("*.md"))}
            if target_sub.is_dir() and not os.path.islink(target_sub):
                for existing in sorted(target_sub.glob("*.md")):
                    if existing.name not in src_agents and f"{sub}/{existing.name}" in prior_installed:
                        self.backup(existing)
            for name, agent in src_agents.items():
                self._place_core_file(agent, target_sub / name, f"{sub}/{name}")
        skills_src = SCRIPT_DIR / "skills"
        target_skills = self.target_dir / "skills"
        if os.path.lexists(target_skills) and (os.path.islink(target_skills) or not target_skills.is_dir()):
            self.backup(target_skills)
        src_skills = {
            p.name: p
            for p in sorted(p for p in skills_src.iterdir() if p.is_dir())
            if self.layout != "hybrid" or p.name not in PLUGIN_OWNED_SKILL_SLUGS
        }
        retired_skill_slugs = set(CONSOLIDATED_SKILL_SLUGS)
        if self.layout == "hybrid":
            retired_skill_slugs.update(PLUGIN_OWNED_SKILL_SLUGS)
        if target_skills.is_dir() and not os.path.islink(target_skills):
            for existing in sorted(target_skills.iterdir()):
                if (
                    (existing.is_dir() or os.path.islink(existing) or existing.name in PLUGIN_OWNED_SKILL_SLUGS)
                    and existing.name not in src_skills
                    and (f"skills/{existing.name}" in prior_installed or existing.name in retired_skill_slugs)
                ):
                    self.backup(existing)
        for name, skill in src_skills.items():
            self._place_core_skill(skill, target_skills / name, name)
        templates = SCRIPT_DIR / "templates"
        if templates.is_dir():
            target_templates = self.target_dir / "templates"
            if os.path.lexists(target_templates) and (
                os.path.islink(target_templates) or not target_templates.is_dir()
            ):
                self.backup(target_templates)
            src_templates = {
                p.name: p
                for p in sorted(templates.iterdir())
                if p.is_file() and p.name != "config.example.json"
            }
            if target_templates.is_dir() and not os.path.islink(target_templates):
                for existing in sorted(target_templates.iterdir()):
                    if (
                        (existing.is_file() or os.path.islink(existing))
                        and existing.name not in src_templates
                        and existing.name != "config.example.json"
                        and f"templates/{existing.name}" in prior_installed
                    ):
                        self.backup(existing)
            for name, tmpl in src_templates.items():
                self._place_core_file(tmpl, target_templates / name, f"templates/{name}")

        if self.layout == "hybrid":
            self.install_plugins()
        elif self.explicit_flat or self._prior_installed_plugins:
            target_plugins = self.target_dir / "plugins"
            if target_plugins.is_dir() and not os.path.islink(target_plugins):
                for pack_name in sorted(HARNESS_PLUGIN_NAMES):
                    pdir = target_plugins / pack_name
                    if os.path.lexists(pdir) and (
                        pack_name in self._prior_installed_plugins
                        or is_harness_plugin_dir(pdir, expected_pack=pack_name)
                    ):
                        self.backup(pdir)
                if not self.dry_run:
                    try:
                        if not any(target_plugins.iterdir()):
                            target_plugins.rmdir()
                    except OSError:
                        pass

    def install_hooks(self) -> bool:
        """Merges the upstream-watchdog and harness-gate hooks into hooks.json (other hooks are preserved)."""
        hooks_path = self.target_dir / "hooks.json"
        watcher = self.target_dir / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
        existing: Dict = {}
        if hooks_path.is_file():  # reading through a legacy symlink is fine; writing never is
            try:
                existing = json.loads(hooks_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                existing = None
                reason = str(e)
            if not isinstance(existing, dict):
                # Rewriting an unreadable hooks.json would silently drop every other hook in it.
                self.log(f"[WARN] {hooks_path} is not a valid JSON object"
                         + (f" ({reason})" if existing is None else "")
                         + "; it was left untouched and the upstream-watchdog / harness-gate hooks were NOT registered. "
                         "Fix the file and re-run the installer.")
                return False
        python_bin = sys.executable or ("python" if IS_WINDOWS else "python3")
        runtime_root = SCRIPT_DIR if self.mode == "link" else (data_dir() / "runtime")
        hooks_script = runtime_root / "guard" / "agy_hooks.py"

        def _cmd(*parts: str) -> str:
            # POSIX: single-quoted words, so `$()`/backticks in a path are never expanded by the hook shell.
            return subprocess.list2cmdline([python_bin, *parts]) if IS_WINDOWS else shlex.join([python_bin, *parts])

        command = _cmd(str(watcher))
        merged = dict(existing)
        merged["upstream-watchdog"] = {"SessionStart": [{"type": "command", "command": command, "timeout": 15}]}
        merged["harness-gate"] = {
            "PreInvocation": [
                {"type": "command", "command": _cmd(str(hooks_script), "pre-invocation"), "timeout": 5}
            ],
            "PreToolUse": [
                {
                    "matcher": PRE_TOOL_USE_MATCHER,
                    "hooks": [
                        {"type": "command", "command": _cmd(str(hooks_script), "pre-tool-use"), "timeout": 5}
                    ],
                }
            ],
            "Stop": [
                {"type": "command", "command": _cmd(str(hooks_script), "stop"), "timeout": 15}
            ],
        }
        if self.dry_run:
            self.log(f"[DRY-RUN] hooks.json -> {command}")
            return True
        if merged == existing and not os.path.islink(hooks_path):
            self.installed.append(str(hooks_path))
            return True
        had_existing = self.backup(hooks_path)
        atomic_write_json(hooks_path, merged, mode=0o644)
        self.installed.append(str(hooks_path))
        if not had_existing:
            self._placed_new.append(hooks_path)
        self.log(f"[CONFIGURED] hooks.json (upstream-watchdog -> {watcher}, harness-gate -> {hooks_script})")
        return True

    @staticmethod
    def _harness_skill_names() -> set[str]:
        skills_dir = SCRIPT_DIR / "skills"
        try:
            if not skills_dir.is_dir():
                return set()
            return {p.name for p in skills_dir.iterdir() if p.is_dir()}
        except OSError:
            return set()

    @staticmethod
    def _is_within_lexically(path: Path, root: Path) -> bool:
        try:
            Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
            return True
        except ValueError:
            return False

    def migrate_mcp_config(self) -> None:
        """Repoints, retires (hybrid), or restores (flat) harness-owned skill MCP servers."""
        if self.layout == "hybrid":
            newly_retired: List[str] = []
            migrate_harness_mcp_config(
                self.target_dir,
                SCRIPT_DIR,
                dry_run=self.dry_run,
                python_executable=sys.executable,
                backup_fn=self.backup,
                log_fn=self.log,
                retire_plugin_mcp=HARNESS_PLUGIN_NAMES,
                retired_out=newly_retired,
            )
            merged: List[str] = []
            for key in [*self._prior_retired_mcp_servers, *newly_retired]:
                if key not in merged:
                    merged.append(key)
            self.retired_mcp_servers = merged
            return

        mcp_path = self.target_dir / "mcp_config.json"
        mcp_existed_before = os.path.lexists(mcp_path)
        restore_keys = self._prior_retired_mcp_servers if (self.explicit_flat or self._prior_retired_mcp_servers) else None
        restored_keys: List[str] = []
        migrate_harness_mcp_config(
            self.target_dir,
            SCRIPT_DIR,
            dry_run=self.dry_run,
            python_executable=sys.executable,
            backup_fn=self.backup,
            log_fn=self.log,
            restore_flat_keys=restore_keys,
            restored_out=restored_keys,
        )
        if not self.dry_run and not mcp_existed_before and os.path.lexists(mcp_path):
            self._placed_new.append(mcp_path)
        self.retired_mcp_servers = [k for k in self._prior_retired_mcp_servers if k not in restored_keys]

    @staticmethod
    def _release_legacy_tree(path: Path) -> None:
        """Pre-1.3.1 Guard and locked runtime trees may have read-only directories/files; restore owner write before moving/deleting."""
        if os.path.islink(path) or not path.is_dir():
            return
        for root, dirs, files in os.walk(path):
            for d in [root] + [os.path.join(root, n) for n in dirs]:
                if not os.path.islink(d):
                    try:
                        mode = os.lstat(d).st_mode
                        if not mode & 0o200:
                            os.chmod(d, (mode & 0o7777) | 0o200)
                    except OSError:
                        pass
            for f in files:
                fp = os.path.join(root, f)
                if not os.path.islink(fp):
                    try:
                        mode = os.lstat(fp).st_mode
                        if not mode & 0o200:
                            os.chmod(fp, (mode & 0o7777) | 0o200)
                    except OSError:
                        pass

    def _move_out(self, src: Path, dest: Path, label: str, note: str = "") -> None:
        """Moves a legacy entry out of the configuration tree; failures are reported, never fatal."""
        if self.dry_run:
            self.log(f"[DRY-RUN] move {label} {src.name} -> {dest}")
            return
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not IS_WINDOWS:
                os.chmod(dest.parent, 0o700)
            self._release_legacy_tree(src)
            shutil.move(str(src), str(dest))
            self.log(f"[MOVED] {label} {src.name} -> {dest}{note}")
        except OSError as e:
            self.log(f"[WARN] Could not move {label} {src}: {e}. Move it out of the config tree manually.")

    def move_legacy_backups(self) -> None:
        for legacy in sorted(self.target_dir.glob("backup_*")):
            if legacy.is_dir() and not legacy.is_symlink():
                self._move_out(legacy, state_dir() / "backups" / legacy.name, "legacy installer backup")

    def move_legacy_guard_state(self) -> None:
        """Pre-1.3.1 baselines and snapshots lived inside the protected tree (snapshots copied config.json)."""
        stamp = self.backup_dir.name.replace("install_", "config_")
        for name in (".guard_snapshots", ".guard_integrity.json"):
            src = self.target_dir / name
            if os.path.lexists(src):
                self._move_out(src, state_dir() / "legacy" / stamp / name, "legacy Guard data",
                               " (may contain copies of config.json with tokens; delete it once reviewed)")

    def move_legacy_runtime_links(self) -> None:
        """Earlier link-mode installs placed runtime symlinks (guard, porter, ...) into the config root."""
        for name in RUNTIME_ENTRIES:
            link = self.target_dir / name
            if not os.path.islink(link):
                continue
            checkout = Path(os.path.realpath(link)).parent
            if (checkout / "guard" / "__init__.py").is_file() and (checkout / "porter.py").is_file():
                if self.dry_run:
                    self.log(f"[DRY-RUN] backup legacy runtime link {name}")
                    continue
                self.backup(link)

    # ------------------------------------------------------------------
    def install_runtime(self) -> Path:
        """Copies Guard/Porter code to the data directory (copy mode) or uses this checkout (link mode)."""
        if self.mode == "link":
            return SCRIPT_DIR
        runtime = data_dir() / "runtime"
        if self.dry_run:
            self.log(f"[DRY-RUN] runtime -> {runtime}")
            return runtime
        staging = runtime.with_name("runtime.new")
        if staging.exists():
            self._release_legacy_tree(staging)
            shutil.rmtree(staging)
        staging.mkdir(parents=True)
        for name in RUNTIME_ENTRIES:
            src = SCRIPT_DIR / name
            if src.is_dir():
                shutil.copytree(src, staging / name, ignore=_ignore)
            elif src.is_file():
                shutil.copy2(src, staging / name)
        for rel_script in RUNTIME_PORTABLE_SKILL_SCRIPTS:
            src_script = SCRIPT_DIR / rel_script
            if src_script.is_file():
                dst_script = staging / rel_script
                dst_script.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_script, dst_script)
            else:
                print(f"[WARN] Missing declared portable skill script during runtime install: {src_script}", file=sys.stderr)
        if not IS_WINDOWS:
            for sc in (
                list((staging / "scripts").glob("*.py"))
                + [staging / rel for rel in RUNTIME_PORTABLE_SKILL_SCRIPTS]
            ):
                if sc.is_file() and not os.path.islink(sc):
                    try:
                        sc.chmod(sc.stat().st_mode | 0o755)
                    except OSError as exc:
                        print(f"[WARN] Could not set executable permissions on {sc}: {exc}", file=sys.stderr)
        previous = runtime.with_name("runtime.prev")
        if previous.exists():
            self._release_legacy_tree(previous)
            shutil.rmtree(previous)
        if runtime.exists():
            self._release_legacy_tree(runtime)
            os.replace(runtime, previous)
            self._runtime_rotation = (runtime, previous)
        os.replace(staging, runtime)
        self.log(f"[RUNTIME] Guard {__version__} runtime installed -> {runtime}")
        return runtime

    def _write_launcher(self, path: Path, content: str, executable: bool = True) -> None:
        had_existing = os.path.lexists(path)
        content_bytes = content.encode("utf-8")
        if had_existing and not os.path.islink(path) and path.is_file():
            try:
                if path.read_bytes() == content_bytes:
                    if executable and not IS_WINDOWS and not (os.lstat(path).st_mode & 0o111):
                        os.chmod(path, 0o755)
                    return
            except OSError:
                pass
        if had_existing:
            if not os.path.islink(path):
                try:
                    mode = os.lstat(path).st_mode
                    os.chmod(path, (mode & 0o7777) | 0o200)
                except OSError:
                    pass
            self._backup_external(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content_bytes)
        if executable and not IS_WINDOWS:
            path.chmod(0o755)
        if not had_existing:
            self._placed_new.append(path)
        self.log(f"[LAUNCHER] {path}")

    def _backup_external(self, path: Path) -> None:
        target = self.backup_dir / "launchers" / path.name
        self._ensure_private_backup_dir(target.parent)
        if os.path.lexists(target):
            if os.path.islink(target) or target.is_file():
                target.unlink(missing_ok=True)
            elif target.is_dir():
                self._release_legacy_tree(target)
                shutil.rmtree(target, ignore_errors=True)
        shutil.move(str(path), str(target))
        self._backed_up.append((path, target))
        self.log(f"[BACKUP] {path} -> {target}")

    def install_launchers(self, runtime: Path) -> None:
        python_bin = sys.executable or ("python" if IS_WINDOWS else "python3")
        if self.dry_run:
            self.log("[DRY-RUN] launchers agy-guard / agy-porter")
            return
        if IS_WINDOWS:
            bin_dir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Programs" / "antigravity-guard"
            for name, script in (("agy-guard", "guard.py"), ("agy-porter", "porter.py")):
                body = f'@echo off\r\nrem {LAUNCHER_MARKER}\r\n"{python_bin}" "{runtime / script}" %*\r\n'
                self._write_launcher(bin_dir / f"{name}.cmd", body, executable=False)
            self.log(f"[PATH] Add {bin_dir} to your PATH to use agy-guard / agy-porter.")
            return
        bin_dir = Path.home() / ".local" / "bin"
        for name, script in (("agy-guard", "guard.py"), ("agy-porter", "porter.py")):
            body = f'#!/bin/sh\n# {LAUNCHER_MARKER}\nexec {shlex.quote(python_bin)} {shlex.quote(str(runtime / script))} "$@"\n'
            self._write_launcher(bin_dir / name, body)
        porter_alias = bin_dir / "porter"
        if not os.path.lexists(porter_alias) or LAUNCHER_MARKER in (porter_alias.read_text(errors="ignore") if porter_alias.is_file() else "") or os.path.islink(porter_alias):
            body = f'#!/bin/sh\n# {LAUNCHER_MARKER}\nexec {shlex.quote(python_bin)} {shlex.quote(str(runtime / "porter.py"))} "$@"\n'
            self._write_launcher(porter_alias, body)
        else:
            self.log(f"[NOTICE] {porter_alias} belongs to another tool; use 'agy-porter'.")
        if str(bin_dir) not in os.environ.get("PATH", "").split(os.pathsep):
            self.log(f"[PATH] {bin_dir} is not on PATH; add it to use agy-guard.")

    @staticmethod
    def _lookup_pinned_binary_sha256(binary_name: str) -> str:
        """Looks up a repository-pinned SHA-256 digest for `binary_name` if shipped in checkout."""
        for rel in (Path("installers") / "release_checksums.json", Path(".harness") / "manifest.json"):
            cand = SCRIPT_DIR / rel
            if not cand.is_file():
                continue
            try:
                payload = json.loads(cand.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(payload, dict):
                continue
            for mapping in (
                payload.get("release_binaries"),
                payload.get("binary_checksums"),
                payload.get("binaries"),
                payload if rel.name == "release_checksums.json" else None,
            ):
                if isinstance(mapping, dict):
                    val = mapping.get(binary_name)
                    if isinstance(val, str) and _is_valid_sha256(val):
                        return val.strip().lower()
        return ""

    def install_binary(self, expected_sha256: str = "") -> bool:
        """Installs a standalone binary ONLY after verifying it against a pinned or local .sha256 digest."""
        machine = platform.machine().lower()
        machine = "x86_64" if machine in ("amd64", "x86_64") else ("arm64" if machine in ("arm64", "aarch64") else machine)
        names = {"Linux": f"agy-guard-linux-{machine}", "Darwin": f"agy-guard-macos-{machine}", "Windows": f"agy-guard-windows-{machine}.exe"}
        binary_name = names.get(SYSTEM)
        if not binary_name:
            self.log(f"[NOTICE] No standalone binary is published for {SYSTEM}; using the Python runtime.")
            return False
        pinned = (expected_sha256 or self.expected_sha256 or "").strip().lower()
        if pinned and not _is_valid_sha256(pinned):
            self.log(f"[SECURITY] Invalid --sha256 digest format for {binary_name}; expected 64 hex characters.")
            return False
        dest = (Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Programs" / "antigravity-guard" / "agy-guard.exe") if IS_WINDOWS \
            else Path.home() / ".local" / "bin" / "agy-guard"
        local = SCRIPT_DIR / "dist" / binary_name
        sums = ""
        try:
            if local.is_file():
                data = local.read_bytes()
                sums_file = SCRIPT_DIR / "dist" / f"{binary_name}.sha256"
                sums = sums_file.read_text(encoding="utf-8") if sums_file.is_file() else ""
            else:
                pinned = pinned or self._lookup_pinned_binary_sha256(binary_name)
                if not pinned:
                    self.log(
                        f"[SECURITY] Remote binary download for {binary_name} requires --sha256 <64-hex> "
                        "or a repository-pinned checksum manifest entry; refusing unpinned remote .sha256 verification."
                    )
                    return False
                max_sums = 65536
                max_bin = 128 * 1024 * 1024
                base = f"{RELEASE_BASE}/v{__version__}"
                parsed_base = urllib.parse.urlparse(base)
                if parsed_base.scheme != "https" or (parsed_base.hostname or "").lower() != "github.com":
                    raise ValueError(f"Disallowed binary release host: {base}")
                from porter.net import DEADLINE_FACTOR, build_safe_opener, safe_fetch_url, validate_safe_url

                user_agent = f"AntigravityHarness-Installer/{__version__}"
                sums = safe_fetch_url(
                    f"{base}/{binary_name}.sha256",
                    user_agent=user_agent,
                    timeout=15.0,
                    max_bytes=max_sums,
                )
                bin_url = f"{base}/{binary_name}"
                validate_safe_url(bin_url)
                opener = build_safe_opener(deadline=time.monotonic() + (60.0 * DEADLINE_FACTOR))
                req = urllib.request.Request(bin_url, headers={"User-Agent": user_agent})
                with opener.open(req, timeout=60.0) as r:
                    data = r.read(max_bin + 1)
                    if len(data) > max_bin:
                        raise ValueError("Binary download exceeded 128 MiB safety limit")
        except Exception as e:
            self.log(f"[NOTICE] Standalone binary unavailable ({e}); using the Python runtime.")
            return False
        published = next((l.split()[0] for l in sums.splitlines() if l.strip().endswith(binary_name)), None)
        if pinned and published and published.lower() != pinned:
            self.log(f"[SECURITY] Published .sha256 does not match pinned digest for {binary_name}; binary NOT installed.")
            return False
        expected = pinned or published
        actual = hashlib.sha256(data).hexdigest()
        if not expected or expected.lower() != actual:
            self.log(f"[SECURITY] Checksum verification failed for {binary_name}; binary NOT installed.")
            return False
        if self.dry_run:
            self.log(f"[DRY-RUN] verified binary {binary_name} -> {dest}")
            return True
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".tmp")
        if os.path.islink(tmp) or os.path.islink(dest):
            self.log(f"[SECURITY] Refusing symlink target during binary installation: {dest}")
            return False
        if tmp.is_file():
            tmp.unlink(missing_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(str(tmp), flags, 0o755)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
            if not IS_WINDOWS:
                os.chmod(str(tmp), 0o755)
            os.replace(tmp, dest)
        except OSError as e:
            try:
                if not os.path.islink(tmp):
                    tmp.unlink(missing_ok=True)
            except OSError:
                pass
            self.log(f"[SECURITY] Failed atomic binary placement for {dest}: {e}")
            return False
        self._binary_dest = dest
        self.log(f"[STANDALONE] Verified (sha256 {actual[:12]}…) binary installed -> {dest}")
        return True

    def write_receipt(self) -> None:
        commit, dirty = "", False
        try:
            commit = subprocess.check_output(["git", "-C", str(SCRIPT_DIR), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
            dirty = bool(subprocess.check_output(["git", "-C", str(SCRIPT_DIR), "status", "--porcelain"], text=True, stderr=subprocess.DEVNULL).strip())
        except (OSError, subprocess.CalledProcessError):
            pass
        if not self.dry_run:
            installed_rel = [
                Path(p).relative_to(self.target_dir).as_posix()
                if Path(p).is_relative_to(self.target_dir)
                else str(p)
                for p in self.installed
            ]
            payload = {
                "version": __version__,
                "installed_at": datetime.now(timezone.utc).isoformat(),
                "source": str(SCRIPT_DIR),
                "source_commit": commit,
                "source_dirty": dirty,
                "mode": self.mode,
                "layout": self.layout,
                "target": str(self.target_dir),
                "backup_dir": str(self.backup_dir) if self.backup_dir.exists() else None,
                "installed": installed_rel,
                "installed_plugins": list(self.installed_plugins),
                "retired_mcp_servers": list(self.retired_mcp_servers),
            }
            if self._binary_dest is not None:
                payload["binary_path"] = str(self._binary_dest)
            atomic_write_json(state_dir() / "install_receipt.json", payload)


def _is_harness_launcher(path: Path, runtime_root: Path, recorded_binary_path: str = "") -> bool:
    """Returns True only when `path` was created by Antigravity Harness."""
    if not os.path.lexists(path):
        return False
    if os.path.islink(path):
        try:
            resolved = Path(os.path.realpath(path))
            return resolved.is_relative_to(runtime_root) or resolved.is_relative_to(SCRIPT_DIR)
        except (OSError, ValueError):
            return False
    if not path.is_file():
        return False
    if recorded_binary_path:
        try:
            if path.resolve() == Path(recorded_binary_path).resolve():
                return True
        except OSError:
            pass
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
    except OSError:
        return False
    return LAUNCHER_MARKER.encode("utf-8") in head


def uninstall_harness(target_dir: Path, dry_run: bool = False) -> int:
    """Safely uninstalls Antigravity Harness governance, hooks, launchers, and Guard runtime."""
    print("=" * 60)
    print(f"      Antigravity Harness {__version__} Uninstaller")
    print("=" * 60)
    print(f"Target   : {target_dir}")
    print("-" * 60)

    if not dry_run:
        if not request_approval(
            "uninstall",
            "Uninstall Antigravity Harness governance files, hooks, launchers, and Guard runtime?",
            [
                str(target_dir),
                "Custom user files, sidecars, and non-harness hooks in hooks.json are preserved.",
            ],
        ):
            print(f"[APPROVAL REQUIRED] {refusal_message('uninstall')}", file=sys.stderr)
            return 3

    cleanup_failed = False
    if dry_run:
        try:
            registry = EnvironmentRegistry()
        except RegistryError as exc:
            print(f"[DRY-RUN] corrupt environment registry ({exc}) would be quarantined")
            registry = EnvironmentRegistry(config_path=target_dir / ".dry_run_nonexistent_environments.json")
    else:
        registry, quarantined = recover_or_load_registry(recover=True)
        if quarantined is not None:
            print(f"[RECOVERED] Quarantined corrupt environment registry -> {quarantined}")

    env = registry.get_environment("antigravity")
    lease_mgr = LeaseManager(registry=registry)

    try:
        startup_mgr = StartupManager(target_dir=target_dir, registry=registry)
        st_status = startup_mgr.status()
        if st_status.get("installed") or st_status.get("active"):
            if dry_run:
                print(f"[DRY-RUN] disable boot sentinel ({st_status.get('target_path')})")
            else:
                ok_dis, msg_dis = startup_mgr.disable()
                if ok_dis:
                    print(f"[DISABLED] Boot sentinel: {msg_dis}")
                else:
                    print(f"[ERROR] Could not disable boot sentinel: {msg_dis}", file=sys.stderr)
                    cleanup_failed = True
    except Exception as exc:
        print(f"[WARN] Boot sentinel check failed: {exc}", file=sys.stderr)

    if not dry_run:
        try:
            if lease_mgr.get_active_lease("antigravity") is not None:
                lease_mgr.complete_lease(env_id="antigravity", interactive=False)
        except Exception:
            pass
        if env is not None:
            ok_unlock, msg_unlock = registry.unlock("antigravity")
            if not ok_unlock:
                print(f"[ERROR] Could not unlock antigravity environment: {msg_unlock}", file=sys.stderr)
                cleanup_failed = True
        if os.path.lexists(target_dir) and not os.path.islink(target_dir):
            ok_dir, msg_dir = registry.os_adapter.unlock(target_dir, recursive=True)
            if not ok_dir:
                print(f"[WARN] Could not unlock {target_dir}: {msg_dir}", file=sys.stderr)
            Installer._release_legacy_tree(target_dir)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    uninstall_backup = state_dir() / "backups" / f"uninstall_{stamp}"

    def _stash(entry: Path, rel_name: Path) -> None:
        dest = uninstall_backup / rel_name
        if dry_run:
            print(f"[DRY-RUN] remove {entry} -> {dest}")
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not IS_WINDOWS:
            for d in (uninstall_backup.parent, uninstall_backup):
                if d.exists() and not os.path.islink(d):
                    try:
                        os.chmod(d, 0o700)
                    except OSError:
                        pass
        if not os.path.islink(entry) and entry.is_dir():
            Installer._release_legacy_tree(entry)
        elif not os.path.islink(entry) and entry.is_file():
            try:
                os.chmod(entry, (os.lstat(entry).st_mode & 0o7777) | 0o200)
            except OSError:
                pass
        shutil.move(str(entry), str(dest))
        print(f"[REMOVED] {entry} (backed up -> {dest})")

    receipt_path = state_dir() / "install_receipt.json"
    tracked_rel: List[str] = []
    recorded_binary_path = ""
    receipt_matches_target = False
    if receipt_path.is_file():
        try:
            rec = json.loads(receipt_path.read_text(encoding="utf-8"))
            if isinstance(rec, dict):
                rec_target = rec.get("target")
                if not rec_target or Path(str(rec_target)).expanduser().resolve() == target_dir.resolve():
                    receipt_matches_target = True
                    if isinstance(rec.get("installed"), list):
                        for raw_item in rec["installed"]:
                            if not isinstance(raw_item, str):
                                continue
                            norm_i = raw_item.replace("\\", "/").strip("/")
                            if norm_i == "plugins" or norm_i.startswith("plugins/"):
                                sub_parts = norm_i.split("/")
                                if len(sub_parts) == 2 and sub_parts[1] in HARNESS_PLUGIN_NAMES:
                                    tracked_rel.append(norm_i)
                            else:
                                tracked_rel.append(raw_item)
                    if isinstance(rec.get("installed_plugins"), list):
                        for p in rec["installed_plugins"]:
                            if isinstance(p, str) and p in HARNESS_PLUGIN_NAMES:
                                rel_p = f"plugins/{p}"
                                if rel_p not in tracked_rel:
                                    tracked_rel.append(rel_p)
                    if isinstance(rec.get("binary_path"), str):
                        recorded_binary_path = rec["binary_path"]
        except (OSError, ValueError) as exc:
            print(f"[WARN] Could not parse {receipt_path} ({exc}); falling back to canonical harness manifest.", file=sys.stderr)

    if not receipt_matches_target and os.path.lexists(target_dir / "plugins"):
        print(
            f"[WARN] Install receipt missing or unmatched for {target_dir}; preserving {target_dir / 'plugins'} "
            "untouched so third-party and unmanaged plugins are never deleted.",
            file=sys.stderr,
        )

    if not tracked_rel:
        tracked_rel = list(GOVERNANCE_FILES) + [CONSTITUTION_RULE_REL, "GEMINI.md", "MISTAKES.md", ".harness/manifest.json"]
        if (SCRIPT_DIR / "agents").is_dir():
            tracked_rel.extend(f"agents/{p.name}" for p in sorted((SCRIPT_DIR / "agents").glob("*.md")))
        if (SCRIPT_DIR / "skills").is_dir():
            tracked_rel.extend(f"skills/{p.name}" for p in sorted((SCRIPT_DIR / "skills").iterdir()) if p.is_dir())
        for slug in CONSOLIDATED_SKILL_SLUGS:
            rel_slug = f"skills/{slug}"
            if rel_slug not in tracked_rel:
                tracked_rel.append(rel_slug)
        if (SCRIPT_DIR / "templates").is_dir():
            tracked_rel.extend(
                f"templates/{p.name}"
                for p in sorted((SCRIPT_DIR / "templates").iterdir())
                if p.is_file() and p.name != "config.example.json"
            )

    # 1. Clean harness entries out of hooks.json without breaking other user hooks.
    hooks_path = target_dir / "hooks.json"
    if os.path.lexists(hooks_path):
        if os.path.islink(hooks_path):
            _stash(hooks_path, Path("hooks.json"))
        elif hooks_path.is_file():
            try:
                hooks_data = json.loads(hooks_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                print(f"[WARN] {hooks_path} is not valid JSON ({exc}); leaving hooks.json untouched.", file=sys.stderr)
                hooks_data = None
            if isinstance(hooks_data, dict):
                removed_keys = [k for k in ("harness-gate", "upstream-watchdog") if k in hooks_data]
                if removed_keys:
                    remaining = {k: v for k, v in hooks_data.items() if k not in ("harness-gate", "upstream-watchdog")}
                    if remaining:
                        if dry_run:
                            print(f"[DRY-RUN] prune {', '.join(removed_keys)} from {hooks_path} (preserving {len(remaining)} user hook group(s))")
                        else:
                            backup_hooks = uninstall_backup / "hooks.json"
                            backup_hooks.parent.mkdir(parents=True, exist_ok=True)
                            if not IS_WINDOWS:
                                for d in (uninstall_backup.parent, uninstall_backup):
                                    if d.exists() and not os.path.islink(d):
                                        try:
                                            os.chmod(d, 0o700)
                                        except OSError:
                                            pass
                            shutil.copy2(hooks_path, backup_hooks)
                            atomic_write_json(hooks_path, remaining, mode=0o644)
                            print(f"[CLEANED] Removed {', '.join(removed_keys)} from {hooks_path} ({len(remaining)} other hook group(s) preserved)")
                    else:
                        _stash(hooks_path, Path("hooks.json"))

    # 2. Remove receipt-tracked governance files/directories (preserving untracked user files).
    target_resolved = target_dir.resolve()
    for rel_item in tracked_rel:
        norm_rel = rel_item.replace("\\", "/").strip("/")
        if not norm_rel or norm_rel == "hooks.json":
            continue
        cand_path = Path(rel_item)
        entry = cand_path if cand_path.is_absolute() else (target_dir / norm_rel)
        try:
            parent_resolved = entry.parent.resolve()
            if entry != target_dir and not (parent_resolved == target_resolved or parent_resolved.is_relative_to(target_resolved)):
                continue
        except OSError:
            continue
        if os.path.lexists(entry):
            rel_dest = entry.relative_to(target_dir) if entry.is_relative_to(target_dir) else Path(entry.name)
            _stash(entry, rel_dest)

    if not dry_run and target_dir.is_dir() and not os.path.islink(target_dir):
        cleanup_subdirs = (".harness", "agents", "rules", "skills", "templates", "plugins") if receipt_matches_target else (".harness", "agents", "rules", "skills", "templates")
        for sub_name in cleanup_subdirs:
            sub_dir = target_dir / sub_name
            if sub_dir.is_dir() and not os.path.islink(sub_dir):
                try:
                    if not any(sub_dir.iterdir()):
                        sub_dir.rmdir()
                except OSError:
                    pass

    # 3. Remove launchers ONLY if created by Antigravity Harness.
    runtime_root = data_dir() / "runtime"
    if IS_WINDOWS:
        bin_dir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Programs" / "antigravity-guard"
        launcher_candidates = [bin_dir / "agy-guard.cmd", bin_dir / "agy-porter.cmd", bin_dir / "agy-guard.exe"]
    else:
        bin_dir = Path.home() / ".local" / "bin"
        launcher_candidates = [bin_dir / "agy-guard", bin_dir / "agy-porter", bin_dir / "porter"]
    for lpath in launcher_candidates:
        if _is_harness_launcher(lpath, runtime_root, recorded_binary_path=recorded_binary_path):
            if dry_run:
                print(f"[DRY-RUN] remove launcher {lpath}")
            else:
                try:
                    if not os.path.islink(lpath):
                        os.chmod(lpath, 0o600)
                except OSError:
                    pass
                lpath.unlink(missing_ok=True)
                print(f"[REMOVED] Launcher {lpath}")

    # 4. Remove runtime directory, FIM baseline, and install receipt.
    for rt_cand in (runtime_root, runtime_root.with_name("runtime.prev"), runtime_root.with_name("runtime.new")):
        if os.path.lexists(rt_cand):
            if dry_run:
                print(f"[DRY-RUN] remove runtime {rt_cand}")
            else:
                Installer._release_legacy_tree(rt_cand)
                if os.path.islink(rt_cand) or rt_cand.is_file():
                    try:
                        rt_cand.unlink(missing_ok=True)
                    except OSError as exc:
                        print(f"[ERROR] Failed to remove runtime file {rt_cand}: {exc}", file=sys.stderr)
                        cleanup_failed = True
                else:
                    shutil.rmtree(rt_cand, ignore_errors=True)
                if os.path.lexists(rt_cand):
                    print(f"[ERROR] Runtime directory could not be completely removed: {rt_cand}", file=sys.stderr)
                    cleanup_failed = True
                else:
                    print(f"[REMOVED] Runtime {rt_cand}")

    if env is not None:
        env_matches_target = False
        try:
            env_matches_target = Path(env.get_root()).resolve() == target_resolved
        except OSError:
            env_matches_target = False
        state_files_to_remove: List[Path] = []
        if env_matches_target:
            monitor = FileIntegrityMonitor.for_environment(env, os_adapter=registry.os_adapter)
            state_files_to_remove.extend([monitor.state_file, monitor.pending_file])
        if receipt_matches_target or env_matches_target:
            state_files_to_remove.append(receipt_path)
        for st_file in state_files_to_remove:
            if os.path.lexists(st_file):
                if dry_run:
                    print(f"[DRY-RUN] remove state file {st_file}")
                else:
                    registry.os_adapter.unlock(st_file, recursive=False)
                    try:
                        if not os.path.islink(st_file):
                            os.chmod(st_file, 0o600)
                        st_file.unlink(missing_ok=True)
                    except OSError as exc:
                        print(f"[ERROR] Could not remove state file {st_file}: {exc}", file=sys.stderr)
                        cleanup_failed = True
        if env_matches_target and not dry_run:
            sync_antigravity_plugin_seams(env)
            if registry.config_path.exists():
                try:
                    registry.save()
                except RegistryError as exc:
                    print(f"[ERROR] Could not update environment registry after uninstall: {exc}", file=sys.stderr)
                    cleanup_failed = True

    print("=" * 60)
    if cleanup_failed:
        print("[ERROR] Antigravity Harness uninstall completed with cleanup errors.", file=sys.stderr)
        print("=" * 60)
        return 1
    print("[SUCCESS] Antigravity Harness uninstalled." + (" (dry run: nothing was modified)" if dry_run else ""))
    if not dry_run and uninstall_backup.exists():
        print(f"Removed governance files were archived to: {uninstall_backup}")
    print("=" * 60)
    return 0


def release_runtime_state(adapter, target_dir: Path, dry_run: bool = False) -> List[str]:
    """
    Guard 1.3.0 and earlier locked the whole configuration tree, which also froze Antigravity's
    own state (config.json, projects/, ...). Restores owner write access on the root directory
    entry and on those runtime entries only; governance seams (including OS-locked harness
    plugin packs under `plugins/<pack>`) are handled by the registry.
    """
    released: List[str] = []
    candidates: List[tuple[Path, bool]] = [(target_dir, False)]
    for name in ANTIGRAVITY_RUNTIME_ENTRIES:
        entry = target_dir / name
        if name == "plugins":
            candidates.append((entry, False))
            if entry.is_dir() and not os.path.islink(entry):
                try:
                    for child in sorted(entry.iterdir()):
                        if child.name not in HARNESS_PLUGIN_NAMES:
                            candidates.append((child, True))
                except OSError:
                    pass
        else:
            candidates.append((entry, True))
    for entry, recursive in candidates:
        if not os.path.lexists(entry) or os.path.islink(entry):
            continue
        frozen = _write_protected(adapter, entry) or (IS_WINDOWS and recursive and entry.is_dir())
        if not frozen and recursive and entry.is_dir():
            frozen = any(not os.access(os.path.join(root, n), os.W_OK)
                         for root, dirs, files in os.walk(entry) for n in dirs + files
                         if not os.path.islink(os.path.join(root, n)))
        if not frozen:
            continue
        if dry_run:
            released.append(f"[DRY-RUN] restore write access: {entry}")
            continue
        ok, msg = adapter.unlock(entry, recursive=recursive)
        released.append(f"[{'RELEASED' if ok else 'WARN'}] runtime state {entry.name or entry}: {msg}")
    return released


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Antigravity Harness installer")
    parser.add_argument("--link", "--dev", action="store_true", dest="link",
                        help="Developer mode: symlink governance files to this checkout (cannot be locked)")
    layout_group = parser.add_mutually_exclusive_group()
    layout_group.add_argument(
        "--plugins",
        action="store_true",
        help="Install Hybrid Layout: 14 core skills + 4 OS-locked Antigravity Plugin Packs under plugins/",
    )
    layout_group.add_argument(
        "--flat-skills",
        action="store_true",
        help="Install or revert to Flat Layout: all 20 canonical skills under skills/ and restore retired MCP entries",
    )
    parser.add_argument("--from-source", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--binary", action="store_true", help="Also install the checksum-verified standalone agy-guard binary")
    parser.add_argument("--sha256", default="", help="Expected 64-hex SHA-256 digest when downloading --binary from GitHub Releases")
    parser.add_argument("--uninstall", action="store_true", help="Cleanly remove harness governance, hooks, launchers, and runtime")
    parser.add_argument("--no-lock", action="store_true", help="Do not lock the governance scope after installing")
    parser.add_argument("--enable-startup", action="store_true", help="Register the boot sentinel")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    args = parser.parse_args(argv)

    raw_target = Path(os.environ.get("ANTIGRAVITY_CONFIG_DIR", Path.home() / ".gemini" / "config")).expanduser()
    if os.path.islink(raw_target):
        print(
            f"[ERROR] Refusing to install into symlinked configuration directory: {raw_target}",
            file=sys.stderr,
        )
        return 1
    target_dir = raw_target.resolve()
    if not args.uninstall and target_dir == SCRIPT_DIR.resolve():
        print(
            f"[ERROR] Refusing to install into the Antigravity Harness source checkout itself: {target_dir}",
            file=sys.stderr,
        )
        return 1
    if args.uninstall:
        return uninstall_harness(target_dir, dry_run=args.dry_run)
    mode = "link" if args.link else "copy"
    prior_receipt = read_install_receipt(target_dir=target_dir)
    has_existing_hybrid_packs = (
        not os.path.islink(target_dir / "plugins")
        and (target_dir / "plugins").is_dir()
        and any(is_harness_plugin_dir(target_dir / "plugins" / p, expected_pack=p) for p in HARNESS_PLUGIN_NAMES)
    )
    if args.plugins:
        layout = "hybrid"
        explicit_flat = False
    elif args.flat_skills:
        layout = "flat"
        explicit_flat = True
    elif (prior_receipt is not None and prior_receipt.get("layout") == "hybrid") or (
        prior_receipt is None and has_existing_hybrid_packs
    ):
        layout = "hybrid"
        explicit_flat = False
        print("[NOTICE] Preserving existing hybrid plugin layout (pass --flat-skills to revert to flat skills).")
    else:
        layout = "flat"
        explicit_flat = False

    installer = Installer(
        target_dir,
        mode,
        dry_run=args.dry_run,
        expected_sha256=args.sha256,
        layout=layout,
        explicit_flat=explicit_flat,
    )

    print("=" * 60)
    print(f"      Antigravity Harness {__version__} Installer ({mode} mode, {layout} layout)")
    print("=" * 60)
    print(f"Platform : {SYSTEM} ({platform.release()})")
    print(f"Source   : {SCRIPT_DIR}")
    print(f"Target   : {target_dir}")
    print("-" * 60)

    if not args.dry_run:
        target_dir.mkdir(parents=True, exist_ok=True)
    install_approved = False
    try:
        registry = EnvironmentRegistry()
    except RegistryError as exc:
        if args.dry_run:
            print(f"[DRY-RUN] corrupt environment registry ({exc}) would be quarantined")
            registry = EnvironmentRegistry(config_path=target_dir / ".dry_run_nonexistent_environments.json")
        else:
            if not request_approval(
                "install",
                "The environment registry is corrupt. Quarantine it and proceed with installation?",
                [str(state_dir() / "environments.json"), str(exc)],
            ):
                print(f"[APPROVAL REQUIRED] {refusal_message('install')}", file=sys.stderr)
                return 3
            install_approved = True
            registry, quarantined = recover_or_load_registry(recover=True)
            if quarantined is not None:
                print(f"[RECOVERED] Quarantined corrupt environment registry -> {quarantined}")
    env = registry.get_environment("antigravity")
    was_locked = registry.is_locked("antigravity").get("antigravity", False)
    # Anything already write-protected (fully or partially, including legacy retired GEMINI.md / MISTAKES.md) must be released first.
    legacy_release_paths = [
        target_dir / name
        for name in ("GEMINI.md", "MISTAKES.md")
        if os.path.lexists(target_dir / name) and not os.path.islink(target_dir / name)
    ]
    has_locked_parts = any(
        _write_protected(registry.os_adapter, Path(p))
        for p in ([target_dir] if target_dir.exists() else [])
        + env.get_governance_paths(existing_only=True)
        + legacy_release_paths
        if not os.path.islink(p)
    )
    if (was_locked or has_locked_parts) and not args.dry_run:
        if not install_approved and not request_approval(
            "install",
            "The governance scope is write-protected. Unlock it to install?",
            [str(target_dir), "It is re-locked and re-baselined after installation."],
        ):
            print(f"[APPROVAL REQUIRED] {refusal_message('install')}", file=sys.stderr)
            return 3
        ok, msg = registry.unlock("antigravity")
        if not ok:
            print(f"[ERROR] Could not unlock the governance scope: {msg}", file=sys.stderr)
            return 1
        for lp in legacy_release_paths:
            registry.os_adapter.unlock(lp, recursive=False)

    for line in release_runtime_state(registry.os_adapter, target_dir, dry_run=args.dry_run):
        print(line)

    installer.capture_rollback_state(registry, env)
    install_failed = False
    lock_failed = False
    try:
        installer.install_governance()
        runtime = installer.install_runtime()
        if not installer.install_hooks():
            install_failed = True
            installer.rollback()
            print("[ERROR] Installation aborted and rolled back because hooks.json could not be updated.", file=sys.stderr)
            return 1
        installer.migrate_mcp_config()
        installer.move_legacy_backups()
        installer.move_legacy_guard_state()
        installer.move_legacy_runtime_links()
        config_file = target_dir / "config.json"
        template_config = SCRIPT_DIR / "templates" / "config.example.json"
        if not os.path.lexists(config_file) and template_config.is_file() and not args.dry_run:
            shutil.copy2(template_config, config_file)
            if not IS_WINDOWS:
                os.chmod(config_file, 0o600)
            installer._placed_new.append(config_file)
            print(f"[CREATED] Initialized {config_file.name} from template.")
        if not IS_WINDOWS and not args.dry_run:
            ensure_skill_script_permissions(target_dir / "skills")
        installer.install_launchers(runtime)
        if args.binary:
            if not installer.install_binary(expected_sha256=args.sha256):
                install_failed = True
                installer.rollback()
                print("[ERROR] Standalone binary installation failed verification; rolled back.", file=sys.stderr)
                return 1
        installer.write_receipt()
        if not args.dry_run:
            sync_antigravity_plugin_seams(env)
            registry.save()
            prune_install_backups(keep=BACKUP_RETENTION_KEEP, dry_run=False)
            monitor = FileIntegrityMonitor.for_environment(env, os_adapter=registry.os_adapter)
            count, path = monitor.save_baseline()
            print(f"[BASELINE] Integrity baseline established for {count} governance entries -> {path}")
    except ValueError as exc:
        install_failed = True
        installer.rollback()
        print(f"[ERROR] Installation aborted and rolled back: {exc}", file=sys.stderr)
        return 1
    except Exception:
        install_failed = True
        installer.rollback()
        raise
    finally:
        should_lock = was_locked if install_failed else ((not args.no_lock) and (mode != "link" or was_locked))
        if not args.dry_run and should_lock:
            ok, msg = registry.lock("antigravity")
            print(f"[{'LOCKED' if ok else 'LOCK WARNING'}] {msg.splitlines()[0] if msg else ''}")
            if not ok and mode != "link":
                lock_failed = True

    if lock_failed and not install_failed:
        print("[ERROR] Failed to engage OS write protection on the governance scope.", file=sys.stderr)
        return 1

    if args.enable_startup and not args.dry_run:
        from guard.startup import StartupManager

        ok, msg = StartupManager(target_dir=target_dir).enable()
        if not ok:
            print(f"[FAILED] {msg}", file=sys.stderr)
            return 1
        print(f"[SUCCESS] {msg}")

    print("=" * 60)
    print("[SUCCESS] Antigravity Harness installed." + (" (dry run: nothing was written)" if args.dry_run else ""))
    if installer.backup_dir.exists():
        print(f"Replaced files were backed up to: {installer.backup_dir}")
    if mode == "link":
        print("[NOTICE] Developer link mode: symlinked entries cannot be write-protected by Guard.")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
