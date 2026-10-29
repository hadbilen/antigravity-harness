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
from guard.environment import ANTIGRAVITY_RUNTIME_ENTRIES, EnvironmentRegistry, RegistryError  # noqa: E402
from guard.integrity import FileIntegrityMonitor  # noqa: E402
from guard.lease import LeaseManager  # noqa: E402
from guard.paths import atomic_write_json, copy_entry, data_dir, state_dir  # noqa: E402
from guard.startup import StartupManager  # noqa: E402

IS_WINDOWS = platform.system().lower() == "windows"
SYSTEM = platform.system()
GOVERNANCE_FILES = ["GEMINI.md", "DESIGN.md", "MISTAKES.md"]
RUNTIME_ENTRIES = ["guard", "porter", "scripts", "guard.py", "porter.py"]
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
    """Ensures 0o755 executable permissions on .py, .sh, .mjs skill scripts and contrast-*.py."""
    if IS_WINDOWS or not skills_root.is_dir() or os.path.islink(skills_root):
        return
    candidates: List[Path] = []
    for scripts_dir in skills_root.rglob("scripts"):
        if scripts_dir.is_dir() and not os.path.islink(scripts_dir):
            for entry in scripts_dir.rglob("*"):
                if entry.suffix in (".py", ".sh", ".mjs"):
                    candidates.append(entry)
    antislop_human = skills_root / "antislop-human"
    if antislop_human.is_dir() and not os.path.islink(antislop_human):
        candidates.extend(antislop_human.glob("contrast-*.py"))
    for script in candidates:
        if not os.path.islink(script) and script.is_file():
            try:
                script.chmod(script.stat().st_mode | 0o755)
            except OSError:
                pass


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


def _ignore(src: str, names: List[str]) -> List[str]:
    return [n for n in names if n in ("__pycache__", ".pytest_cache", ".DS_Store") or n.endswith((".pyc", ".pyo"))]


class Installer:
    def __init__(self, target_dir: Path, mode: str, dry_run: bool = False, expected_sha256: str = ""):
        self.target_dir = target_dir
        self.mode = mode  # "copy" | "link"
        self.dry_run = dry_run
        self.expected_sha256 = (expected_sha256 or "").strip()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        self.backup_dir = state_dir() / "backups" / f"install_{stamp}"
        self.installed: List[str] = []
        self._backed_up: List[tuple[Path, Path]] = []
        self._placed_new: List[Path] = []
        self._runtime_rotation: Optional[tuple[Path, Path]] = None
        self._binary_dest: Optional[Path] = None

    # ------------------------------------------------------------------
    def log(self, msg: str) -> None:
        print(msg)

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
        shutil.move(str(dest), str(target))
        if not IS_WINDOWS and target.is_file() and not os.path.islink(target) and dest.name in ("mcp_config.json", "config.json"):
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
        self._backed_up.append((dest, target))
        return True

    def rollback(self) -> None:
        """Restores backed-up entries and removes newly created entries on a failed install."""
        if self.dry_run:
            return
        for created in reversed(self._placed_new):
            try:
                if os.path.islink(created) or created.is_file():
                    created.unlink(missing_ok=True)
                elif created.is_dir():
                    self._release_legacy_tree(created)
                    shutil.rmtree(created, ignore_errors=True)
            except OSError:
                pass
        for orig_dest, backup_src in reversed(self._backed_up):
            try:
                if os.path.lexists(orig_dest):
                    if os.path.islink(orig_dest) or orig_dest.is_file():
                        orig_dest.unlink(missing_ok=True)
                    elif orig_dest.is_dir():
                        self._release_legacy_tree(orig_dest)
                        shutil.rmtree(orig_dest, ignore_errors=True)
                if os.path.lexists(backup_src):
                    orig_dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(backup_src), str(orig_dest))
            except OSError:
                pass
        if self._runtime_rotation is not None:
            runtime_path, prev_path = self._runtime_rotation
            try:
                if os.path.lexists(prev_path):
                    if runtime_path.exists():
                        self._release_legacy_tree(runtime_path)
                        shutil.rmtree(runtime_path, ignore_errors=True)
                    os.replace(prev_path, runtime_path)
            except OSError:
                pass

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

    # ------------------------------------------------------------------
    def install_governance(self) -> None:
        prior_installed: set[str] = set()
        receipt_path = state_dir() / "install_receipt.json"
        if os.path.lexists(receipt_path):
            try:
                rec = json.loads(receipt_path.read_text(encoding="utf-8"))
                if isinstance(rec, dict) and isinstance(rec.get("installed"), list):
                    rec_target = rec.get("target")
                    if not rec_target or Path(str(rec_target)).resolve() == self.target_dir.resolve():
                        prior_installed = {str(p).replace("\\", "/") for p in rec["installed"]}
                else:
                    self.log(f"[WARN] {receipt_path} has no valid 'installed' list; preserving unrecorded custom entries.")
            except (OSError, ValueError) as e:
                self.log(f"[WARN] Could not parse {receipt_path} ({e}); preserving unrecorded custom entries.")

        for name in GOVERNANCE_FILES:
            src = SCRIPT_DIR / name
            if src.is_file():
                self.place(src, self.target_dir / name)
        manifest = SCRIPT_DIR / ".harness" / "manifest.json"
        if manifest.is_file():
            if os.path.islink(self.target_dir / ".harness"):
                self.backup(self.target_dir / ".harness")
            self.place(manifest, self.target_dir / ".harness" / "manifest.json")
        for sub in ("agents",):
            target_sub = self.target_dir / sub
            if os.path.islink(target_sub):
                self.backup(target_sub)
            src_agents = {p.name: p for p in sorted((SCRIPT_DIR / sub).glob("*.md"))}
            if target_sub.is_dir() and not os.path.islink(target_sub):
                for existing in sorted(target_sub.glob("*.md")):
                    if existing.name not in src_agents and f"{sub}/{existing.name}" in prior_installed:
                        self.backup(existing)
            for name, agent in src_agents.items():
                self.place(agent, target_sub / name)
        skills_src = SCRIPT_DIR / "skills"
        target_skills = self.target_dir / "skills"
        if os.path.islink(target_skills):
            self.backup(target_skills)
        src_skills = {p.name: p for p in sorted(p for p in skills_src.iterdir() if p.is_dir())}
        if target_skills.is_dir() and not os.path.islink(target_skills):
            for existing in sorted(target_skills.iterdir()):
                if (
                    (existing.is_dir() or os.path.islink(existing))
                    and existing.name not in src_skills
                    and f"skills/{existing.name}" in prior_installed
                ):
                    self.backup(existing)
        for name, skill in src_skills.items():
            self.place(skill, target_skills / name)
        templates = SCRIPT_DIR / "templates"
        if templates.is_dir():
            target_templates = self.target_dir / "templates"
            if os.path.islink(target_templates):
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
                self.place(tmpl, target_templates / name)

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
        merged["upstream-watchdog"] = {"PreInvocation": [{"type": "command", "command": command, "timeout": 15}]}
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

    def migrate_mcp_config(self) -> None:
        """Repoints MCP server scripts that live in a skill of this harness to the installed copy."""
        mcp = self.target_dir / "mcp_config.json"
        if not mcp.is_file():
            return
        try:
            data = json.loads(mcp.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            self.log(f"[WARN] Could not parse {mcp}: {exc}; skipping MCP path migration.")
            return
        if not isinstance(data, dict):
            self.log(f"[WARN] {mcp} root is not a JSON object; skipping MCP path migration.")
            return
        mcp_servers = data.get("mcpServers")
        if mcp_servers is not None and not isinstance(mcp_servers, dict):
            self.log(f"[WARN] {mcp} 'mcpServers' is not a JSON object; skipping MCP path migration.")
            return
        changed = False
        for server in (mcp_servers or {}).values():
            if not isinstance(server, dict):
                continue
            args = server.get("args") or []
            if not isinstance(args, list):
                continue
            for i, arg in enumerate(args):
                parts = Path(str(arg)).parts
                if "skills" in parts and parts.index("skills") > 0 and parts[parts.index("skills") - 1] == "antigravity-harness":
                    rel = Path(*parts[parts.index("skills"):])
                    candidate = self.target_dir / rel
                    if candidate.exists() and str(candidate) != arg:
                        args[i] = str(candidate)
                        changed = True
        if changed and not self.dry_run:
            self.backup(mcp)
            atomic_write_json(mcp, data, mode=0o600)
            self.log("[CONFIGURED] mcp_config.json now points to the protected skill copies")

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
        if had_existing:
            if not os.path.islink(path):
                try:
                    mode = os.lstat(path).st_mode
                    os.chmod(path, (mode & 0o7777) | 0o200)
                except OSError:
                    pass
            self._backup_external(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
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
                str(Path(p).relative_to(self.target_dir))
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
                "target": str(self.target_dir),
                "backup_dir": str(self.backup_dir) if self.backup_dir.exists() else None,
                "installed": installed_rel,
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
    if receipt_path.is_file():
        try:
            rec = json.loads(receipt_path.read_text(encoding="utf-8"))
            if isinstance(rec, dict):
                if isinstance(rec.get("installed"), list):
                    tracked_rel = [str(x) for x in rec["installed"] if isinstance(x, str)]
                if isinstance(rec.get("binary_path"), str):
                    recorded_binary_path = rec["binary_path"]
        except (OSError, ValueError) as exc:
            print(f"[WARN] Could not parse {receipt_path} ({exc}); falling back to canonical harness manifest.", file=sys.stderr)

    if not tracked_rel:
        tracked_rel = list(GOVERNANCE_FILES) + [".harness/manifest.json"]
        if (SCRIPT_DIR / "agents").is_dir():
            tracked_rel.extend(f"agents/{p.name}" for p in sorted((SCRIPT_DIR / "agents").glob("*.md")))
        if (SCRIPT_DIR / "skills").is_dir():
            tracked_rel.extend(f"skills/{p.name}" for p in sorted((SCRIPT_DIR / "skills").iterdir()) if p.is_dir())
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
        for sub_name in (".harness", "agents", "skills", "templates"):
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
        monitor = FileIntegrityMonitor.for_environment(env, os_adapter=registry.os_adapter)
        for st_file in (monitor.state_file, monitor.pending_file, receipt_path):
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
    entry and on those runtime entries only; governance seams are handled by the registry.
    """
    released: List[str] = []
    candidates = [(target_dir, False)] + [(target_dir / n, True) for n in ANTIGRAVITY_RUNTIME_ENTRIES]
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
    parser.add_argument("--from-source", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--binary", action="store_true", help="Also install the checksum-verified standalone agy-guard binary")
    parser.add_argument("--sha256", default="", help="Expected 64-hex SHA-256 digest when downloading --binary from GitHub Releases")
    parser.add_argument("--uninstall", action="store_true", help="Cleanly remove harness governance, hooks, launchers, and runtime")
    parser.add_argument("--no-lock", action="store_true", help="Do not lock the governance scope after installing")
    parser.add_argument("--enable-startup", action="store_true", help="Register the boot sentinel")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    args = parser.parse_args(argv)

    target_dir = Path(os.environ.get("ANTIGRAVITY_CONFIG_DIR", Path.home() / ".gemini" / "config")).expanduser().resolve()
    if args.uninstall:
        return uninstall_harness(target_dir, dry_run=args.dry_run)
    mode = "link" if args.link else "copy"
    installer = Installer(target_dir, mode, dry_run=args.dry_run, expected_sha256=args.sha256)

    print("=" * 60)
    print(f"      Antigravity Harness {__version__} Installer ({mode} mode)")
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
    # Anything already write-protected (fully or partially) must be released first.
    has_locked_parts = any(_write_protected(registry.os_adapter, Path(p))
                           for p in ([target_dir] if target_dir.exists() else []) + env.get_governance_paths(existing_only=True)
                           if not os.path.islink(p))
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

    for line in release_runtime_state(registry.os_adapter, target_dir, dry_run=args.dry_run):
        print(line)

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
        if not config_file.exists() and template_config.is_file() and not args.dry_run:
            shutil.copy2(template_config, config_file)
            if not IS_WINDOWS:
                os.chmod(config_file, 0o600)
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
            prune_install_backups(keep=BACKUP_RETENTION_KEEP, dry_run=False)
            monitor = FileIntegrityMonitor.for_environment(env, os_adapter=registry.os_adapter)
            count, path = monitor.save_baseline()
            print(f"[BASELINE] Integrity baseline established for {count} governance entries -> {path}")
    except Exception:
        install_failed = True
        installer.rollback()
        raise
    finally:
        if not args.dry_run and not args.no_lock and (mode != "link" or was_locked):
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
