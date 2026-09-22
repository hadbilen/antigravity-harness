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
import shutil
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from guard import __version__  # noqa: E402
from guard.approval import refusal_message, request_approval  # noqa: E402
from guard.environment import ANTIGRAVITY_RUNTIME_ENTRIES, EnvironmentRegistry  # noqa: E402
from guard.integrity import FileIntegrityMonitor  # noqa: E402
from guard.paths import atomic_write_json, copy_entry, data_dir, state_dir  # noqa: E402

IS_WINDOWS = platform.system().lower() == "windows"
SYSTEM = platform.system()
GOVERNANCE_FILES = ["GEMINI.md", "DESIGN.md", "MISTAKES.md"]
RUNTIME_ENTRIES = ["guard", "porter", "scripts", "guard.py", "porter.py"]
LAUNCHER_MARKER = "antigravity-harness launcher"
RELEASE_BASE = "https://github.com/hadbilen/antigravity-harness/releases/download"


def _write_protected(adapter, path: Path) -> bool:
    """os.access() ignores NTFS deny ACEs on directories, so directories are also asked via the adapter."""
    if not os.access(path, os.W_OK):
        return True
    return IS_WINDOWS and path.is_dir() and adapter.is_locked(path, recursive=False)


def _ignore(src: str, names: List[str]) -> List[str]:
    return [n for n in names if n in ("__pycache__", ".pytest_cache", ".DS_Store") or n.endswith((".pyc", ".pyo"))]


class Installer:
    def __init__(self, target_dir: Path, mode: str, dry_run: bool = False):
        self.target_dir = target_dir
        self.mode = mode  # "copy" | "link"
        self.dry_run = dry_run
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.backup_dir = state_dir() / "backups" / f"install_{stamp}"
        self.installed: List[str] = []

    # ------------------------------------------------------------------
    def log(self, msg: str) -> None:
        print(msg)

    def backup(self, dest: Path) -> None:
        """Moves an existing entry (file, dir or symlink) into the external backup directory."""
        if not os.path.lexists(dest):
            return
        rel = dest.relative_to(self.target_dir) if dest.is_relative_to(self.target_dir) else Path(dest.name)
        target = self.backup_dir / rel
        self.log(f"{'[DRY-RUN] backup' if self.dry_run else '[BACKUP]'} {rel} -> {target}")
        if self.dry_run:
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(dest), str(target))

    def place(self, src: Path, dest: Path) -> None:
        """Copies (or links) src to dest after backing up whatever was there."""
        if self.dry_run:
            self.log(f"[DRY-RUN] {'link' if self.mode == 'link' else 'copy'} {src} -> {dest}")
            return
        if self.mode == "copy" and os.path.lexists(dest) and not os.path.islink(dest) and dest.is_file() and src.is_file():
            if dest.read_bytes() == src.read_bytes():
                self.installed.append(str(dest))
                return
        self.backup(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if self.mode == "link":
            try:
                dest.symlink_to(src.resolve(), target_is_directory=src.is_dir())
                self.log(f"[LINKED] {dest.name} -> {src}")
                self.installed.append(str(dest))
                return
            except (OSError, NotImplementedError):
                if IS_WINDOWS and src.is_dir():
                    try:
                        import _winapi

                        _winapi.CreateJunction(str(src.resolve()), str(dest))
                        self.log(f"[JUNCTION] {dest.name} -> {src}")
                        self.installed.append(str(dest))
                        return
                    except Exception:
                        pass
                self.log(f"[NOTICE] Symlink not permitted for {dest.name}; copying instead.")
        copy_entry(src, dest, _ignore)
        self.log(f"[COPIED] {dest.relative_to(self.target_dir) if dest.is_relative_to(self.target_dir) else dest}")
        self.installed.append(str(dest))

    # ------------------------------------------------------------------
    def install_governance(self) -> None:
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
            for agent in sorted((SCRIPT_DIR / sub).glob("*.md")):
                self.place(agent, self.target_dir / sub / agent.name)
        skills_src = SCRIPT_DIR / "skills"
        if os.path.islink(self.target_dir / "skills"):
            self.backup(self.target_dir / "skills")
        for skill in sorted(p for p in skills_src.iterdir() if p.is_dir()):
            self.place(skill, self.target_dir / "skills" / skill.name)
        templates = SCRIPT_DIR / "templates"
        if templates.is_dir():
            for tmpl in sorted(templates.iterdir()):
                if tmpl.is_file() and tmpl.name != "config.example.json":
                    self.place(tmpl, self.target_dir / "templates" / tmpl.name)

    def install_hooks(self) -> None:
        """Merges the upstream watchdog hook into hooks.json (other hooks are preserved)."""
        hooks_path = self.target_dir / "hooks.json"
        watcher = self.target_dir / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
        existing: Dict = {}
        if hooks_path.is_file():  # reading through a legacy symlink is fine; writing never is
            try:
                existing = json.loads(hooks_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                existing = {}
        python_bin = sys.executable or ("python" if IS_WINDOWS else "python3")
        command = subprocess.list2cmdline([python_bin, str(watcher)]) if IS_WINDOWS else f'"{python_bin}" "{watcher}"'
        merged = dict(existing)
        merged["upstream-watchdog"] = {"PreInvocation": [{"type": "command", "command": command, "timeout": 15}]}
        if self.dry_run:
            self.log(f"[DRY-RUN] hooks.json -> {command}")
            return
        if merged == existing:
            return
        self.backup(hooks_path)
        hooks_path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
        self.installed.append(str(hooks_path))
        self.log(f"[CONFIGURED] hooks.json (upstream-watchdog -> {watcher})")

    def migrate_mcp_config(self) -> None:
        """Repoints MCP server scripts that live in a skill of this harness to the installed copy."""
        mcp = self.target_dir / "mcp_config.json"
        if not mcp.is_file():
            return
        try:
            data = json.loads(mcp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        changed = False
        for server in (data.get("mcpServers") or {}).values():
            args = server.get("args") or []
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
            mcp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            self.log("[CONFIGURED] mcp_config.json now points to the protected skill copies")

    @staticmethod
    def _release_legacy_tree(path: Path) -> None:
        """Pre-1.3.1 Guard locked whole trees read-only; moving a directory needs write access to it."""
        if os.path.islink(path) or not path.is_dir():
            return
        for root, dirs, _files in os.walk(path):
            for d in [root] + [os.path.join(root, n) for n in dirs]:
                if not os.path.islink(d):
                    mode = os.lstat(d).st_mode
                    if not mode & 0o200:
                        os.chmod(d, (mode & 0o7777) | 0o200)

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
            shutil.rmtree(previous)
        if runtime.exists():
            os.replace(runtime, previous)
        os.replace(staging, runtime)
        self.log(f"[RUNTIME] Guard {__version__} runtime installed -> {runtime}")
        return runtime

    def _write_launcher(self, path: Path, content: str, executable: bool = True) -> None:
        if os.path.lexists(path):
            try:
                existing = path.read_text(encoding="utf-8", errors="ignore") if path.is_file() else ""
            except OSError:
                existing = ""
            if LAUNCHER_MARKER not in existing and not os.path.islink(path):
                self._backup_external(path)
            else:
                path.unlink()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        if executable and not IS_WINDOWS:
            path.chmod(0o755)
        self.log(f"[LAUNCHER] {path}")

    def _backup_external(self, path: Path) -> None:
        target = self.backup_dir / "launchers" / path.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(target))
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
            body = f'#!/bin/sh\n# {LAUNCHER_MARKER}\nexec "{python_bin}" "{runtime / script}" "$@"\n'
            self._write_launcher(bin_dir / name, body)
        porter_alias = bin_dir / "porter"
        if not os.path.lexists(porter_alias) or LAUNCHER_MARKER in (porter_alias.read_text(errors="ignore") if porter_alias.is_file() else "") or os.path.islink(porter_alias):
            body = f'#!/bin/sh\n# {LAUNCHER_MARKER}\nexec "{python_bin}" "{runtime / "porter.py"}" "$@"\n'
            self._write_launcher(porter_alias, body)
        else:
            self.log(f"[NOTICE] {porter_alias} belongs to another tool; use 'agy-porter'.")
        if str(bin_dir) not in os.environ.get("PATH", "").split(os.pathsep):
            self.log(f"[PATH] {bin_dir} is not on PATH; add it to use agy-guard.")

    def install_binary(self) -> bool:
        """Installs a standalone binary ONLY after verifying it against its published .sha256 file."""
        machine = platform.machine().lower()
        machine = "x86_64" if machine in ("amd64", "x86_64") else ("arm64" if machine in ("arm64", "aarch64") else machine)
        names = {"Linux": f"agy-guard-linux-{machine}", "Darwin": f"agy-guard-macos-{machine}", "Windows": f"agy-guard-windows-{machine}.exe"}
        binary_name = names.get(SYSTEM)
        if not binary_name:
            self.log(f"[NOTICE] No standalone binary is published for {SYSTEM}; using the Python runtime.")
            return False
        dest = (Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Programs" / "antigravity-guard" / "agy-guard.exe") if IS_WINDOWS \
            else Path.home() / ".local" / "bin" / "agy-guard"
        local = SCRIPT_DIR / "dist" / binary_name
        try:
            if local.is_file():
                data = local.read_bytes()
                sums_file = SCRIPT_DIR / "dist" / f"{binary_name}.sha256"
                sums = sums_file.read_text(encoding="utf-8") if sums_file.is_file() else ""
            else:
                base = f"{RELEASE_BASE}/v{__version__}"
                headers = {"User-Agent": f"AntigravityHarness-Installer/{__version__}"}
                with urllib.request.urlopen(urllib.request.Request(f"{base}/{binary_name}.sha256", headers=headers), timeout=15) as r:
                    sums = r.read().decode("utf-8")
                with urllib.request.urlopen(urllib.request.Request(f"{base}/{binary_name}", headers=headers), timeout=60) as r:
                    data = r.read()
        except Exception as e:
            self.log(f"[NOTICE] Standalone binary unavailable ({e}); using the Python runtime.")
            return False
        expected = next((l.split()[0] for l in sums.splitlines() if l.strip().endswith(binary_name)), None)
        actual = hashlib.sha256(data).hexdigest()
        if not expected or expected.lower() != actual:
            self.log(f"[SECURITY] Checksum verification failed for {binary_name}; binary NOT installed.")
            return False
        if self.dry_run:
            self.log(f"[DRY-RUN] verified binary {binary_name} -> {dest}")
            return True
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".tmp")
        tmp.write_bytes(data)
        if not IS_WINDOWS:
            tmp.chmod(0o755)
        os.replace(tmp, dest)
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
            atomic_write_json(state_dir() / "install_receipt.json", {
                "version": __version__,
                "installed_at": datetime.now(timezone.utc).isoformat(),
                "source": str(SCRIPT_DIR),
                "source_commit": commit,
                "source_dirty": dirty,
                "mode": self.mode,
                "target": str(self.target_dir),
                "backup_dir": str(self.backup_dir) if self.backup_dir.exists() else None,
            })


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
    parser.add_argument("--no-lock", action="store_true", help="Do not lock the governance scope after installing")
    parser.add_argument("--enable-startup", action="store_true", help="Register the boot sentinel")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    args = parser.parse_args(argv)

    target_dir = Path(os.environ.get("ANTIGRAVITY_CONFIG_DIR", Path.home() / ".gemini" / "config")).expanduser().resolve()
    mode = "link" if args.link else "copy"
    installer = Installer(target_dir, mode, dry_run=args.dry_run)

    print("=" * 60)
    print(f"      Antigravity Harness {__version__} Installer ({mode} mode)")
    print("=" * 60)
    print(f"Platform : {SYSTEM} ({platform.release()})")
    print(f"Source   : {SCRIPT_DIR}")
    print(f"Target   : {target_dir}")
    print("-" * 60)

    target_dir.mkdir(parents=True, exist_ok=True)
    registry = EnvironmentRegistry()
    env = registry.get_environment("antigravity")
    was_locked = registry.is_locked("antigravity").get("antigravity", False)
    # Anything already write-protected (fully or partially) must be released first.
    has_locked_parts = any(_write_protected(registry.os_adapter, Path(p))
                           for p in [target_dir] + env.get_governance_paths(existing_only=True) if not os.path.islink(p))
    if (was_locked or has_locked_parts) and not args.dry_run:
        if not request_approval("install", "The governance scope is write-protected. Unlock it to install?",
                                [str(target_dir), "It is re-locked and re-baselined after installation."]):
            print(f"[APPROVAL REQUIRED] {refusal_message('install')}", file=sys.stderr)
            return 3
        ok, msg = registry.unlock("antigravity")
        if not ok:
            print(f"[ERROR] Could not unlock the governance scope: {msg}", file=sys.stderr)
            return 1

    for line in release_runtime_state(registry.os_adapter, target_dir, dry_run=args.dry_run):
        print(line)

    try:
        installer.install_governance()
        installer.install_hooks()
        installer.migrate_mcp_config()
        installer.move_legacy_backups()
        installer.move_legacy_guard_state()
        installer.move_legacy_runtime_links()
        config_file = target_dir / "config.json"
        template_config = SCRIPT_DIR / "templates" / "config.example.json"
        if not config_file.exists() and template_config.is_file() and not args.dry_run:
            shutil.copy2(template_config, config_file)
            print(f"[CREATED] Initialized {config_file.name} from template.")
        if not IS_WINDOWS and not args.dry_run:
            for script in (target_dir / "skills" / "upstream-auditor" / "scripts").glob("*"):
                if script.suffix in (".py", ".sh") and script.is_file() and not script.is_symlink():
                    script.chmod(script.stat().st_mode | 0o755)
        runtime = installer.install_runtime()
        installer.install_launchers(runtime)
        if args.binary:
            installer.install_binary()
        installer.write_receipt()
    finally:
        if not args.dry_run:
            monitor = FileIntegrityMonitor.for_environment(env, os_adapter=registry.os_adapter)
            count, path = monitor.save_baseline()
            print(f"[BASELINE] Integrity baseline established for {count} governance entries -> {path}")
            if not args.no_lock:
                ok, msg = registry.lock("antigravity")
                print(f"[{'LOCKED' if ok else 'LOCK WARNING'}] {msg.splitlines()[0] if msg else ''}")

    if args.enable_startup and not args.dry_run:
        from guard.startup import StartupManager

        ok, msg = StartupManager(target_dir=target_dir).enable()
        print(f"[{'SUCCESS' if ok else 'FAILED'}] {msg}")

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
