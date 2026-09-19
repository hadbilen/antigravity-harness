#!/usr/bin/env python3
"""
install.py — Antigravity Harness Cross-Platform Installer
Compatible with Windows, Linux, macOS, and FreeBSD.
Zero-dependency: uses strictly the Python standard library.

Installs the clean AI workspace configuration (constitution, design contracts,
autonomous subagents, modular skills) into ~/.gemini/config/
Installs the standalone Antigravity Guard (agy-guard) binary into ~/.local/bin/
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import sys
from datetime import datetime
from pathlib import Path

IS_WINDOWS = platform.system().lower() == "windows"


def make_symlink_or_copy(src: Path, dest: Path, backup_dir: Path) -> str:
    """Creates a symlink with automatic Windows junction/copy fallback."""
    # Backup non-symlink existing file/directory
    if dest.exists() and not dest.is_symlink():
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_target = backup_dir / dest.name
        print(f"[BACKUP] Existing {dest.name} -> {backup_dir.name}/")
        if dest.is_dir():
            shutil.move(str(dest), str(backup_target))
        else:
            shutil.move(str(dest), str(backup_target))

    # Remove existing link or broken symlink
    if dest.is_symlink() or dest.exists():
        if dest.is_dir() and not dest.is_symlink():
            shutil.rmtree(dest)
        else:
            dest.unlink(missing_ok=True)

    # Attempt symlink creation
    try:
        dest.symlink_to(src.resolve(), target_is_directory=src.is_dir())
        return f"[LINKED] {dest.name} -> {src}"
    except (OSError, NotImplementedError):
        # Windows without Developer Mode or SeCreateSymbolicLinkPrivilege
        if IS_WINDOWS and src.is_dir():
            try:
                import _winapi

                _winapi.CreateJunction(str(src.resolve()), str(dest))
                return f"[JUNCTION] {dest.name} -> {src}"
            except Exception:
                pass

        # Fallback to copy mode
        if src.is_dir():
            shutil.copytree(src, dest, dirs_exist_ok=True)
            return f"[COPIED (Fallback)] {dest.name} (directory copy)"
        else:
            shutil.copy2(src, dest)
            return f"[COPIED (Fallback)] {dest.name} (file copy)"


def install_guard_binary(script_dir: Path, from_source: bool = False) -> str:
    """
    Installs the agy-guard standalone binary into ~/.local/bin/ (POSIX) or local app data (Windows).
    Falls back gracefully to the Python launcher if offline or in developer mode.
    """
    system = platform.system()
    raw_machine = platform.machine().lower()
    machine = "x86_64" if raw_machine in ("amd64", "x86_64") else ("arm64" if raw_machine in ("arm64", "aarch64") else raw_machine)

    if IS_WINDOWS:
        local_bin = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Programs" / "antigravity-guard"
        dest_bin = local_bin / "agy-guard.exe"
        binary_name = f"agy-guard-windows-{machine}.exe"
    else:
        local_bin = Path.home() / ".local" / "bin"
        dest_bin = local_bin / "agy-guard"
        if system == "Darwin":
            binary_name = f"agy-guard-macos-{machine}"
        else:
            binary_name = f"agy-guard-linux-{machine}"

    local_bin.mkdir(parents=True, exist_ok=True)

    # Developer / source mode: Link the script directly
    if from_source:
        guard_bin = script_dir / "bin" / ("agy-guard.bat" if IS_WINDOWS else "agy-guard")
        if guard_bin.is_file():
            if not IS_WINDOWS:
                guard_bin.chmod(guard_bin.stat().st_mode | 0o755)
            if dest_bin.is_symlink() or dest_bin.exists():
                dest_bin.unlink(missing_ok=True)
            try:
                dest_bin.symlink_to(guard_bin.resolve())
                return f"[LAUNCHER (Source Mode)] Linked agy-guard -> {dest_bin}"
            except Exception:
                shutil.copy2(guard_bin, dest_bin)
                return f"[LAUNCHER (Source Mode)] Copied agy-guard -> {dest_bin}"

    # Production mode: Try local dist/ binary first
    local_dist_binary = script_dir / "dist" / binary_name
    if local_dist_binary.is_file():
        if dest_bin.is_symlink() or dest_bin.exists():
            dest_bin.unlink(missing_ok=True)
        shutil.copy2(local_dist_binary, dest_bin)
        if not IS_WINDOWS:
            dest_bin.chmod(dest_bin.stat().st_mode | 0o755)
        return f"[STANDALONE] Installed agy-guard from local build -> {dest_bin}"

    # Try downloading the compiled binary from GitHub Releases
    release_url = f"https://github.com/hadbilen/antigravity-harness/releases/download/v1.2.8/{binary_name}"
    print(f"[FETCH] Downloading standalone binary from GitHub Releases ({binary_name})...")
    try:
        import urllib.request
        req = urllib.request.Request(release_url, headers={"User-Agent": "AntigravityHarness-Installer/1.2.8"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status == 200:
                if dest_bin.is_symlink() or dest_bin.exists():
                    dest_bin.unlink(missing_ok=True)
                with open(dest_bin, "wb") as f:
                    shutil.copyfileobj(resp, f)
                if not IS_WINDOWS:
                    dest_bin.chmod(dest_bin.stat().st_mode | 0o755)
                return f"[STANDALONE] Downloaded & installed standalone binary -> {dest_bin}"
    except Exception as e:
        print(f"[NOTICE] Could not download standalone binary ({e}). Falling back to Python launcher.")

    # Graceful fallback to Python launcher
    guard_bin = script_dir / "bin" / ("agy-guard.bat" if IS_WINDOWS else "agy-guard")
    if guard_bin.is_file():
        if not IS_WINDOWS:
            guard_bin.chmod(guard_bin.stat().st_mode | 0o755)
        if dest_bin.is_symlink() or dest_bin.exists():
            dest_bin.unlink(missing_ok=True)
        try:
            dest_bin.symlink_to(guard_bin.resolve())
            return f"[LAUNCHER (Fallback)] Linked Python launcher -> {dest_bin}"
        except Exception:
            shutil.copy2(guard_bin, dest_bin)
            return f"[LAUNCHER (Fallback)] Copied Python launcher -> {dest_bin}"

    return "[WARN] Could not install agy-guard executable."


def main() -> int:
    parser = argparse.ArgumentParser(description="Antigravity Harness Setup & Installer")
    parser.add_argument("--from-source", "--dev", action="store_true", dest="from_source", help="Use Python source code launcher instead of standalone binary")
    parser.add_argument("--enable-startup", action="store_true", help="Automatically register Pre-Session Boot Sentinel service")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    target_dir = Path(os.environ.get("ANTIGRAVITY_CONFIG_DIR", Path.home() / ".gemini" / "config"))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = target_dir / f"backup_{timestamp}"

    print("=" * 56)
    print("      Antigravity Harness Setup & Installer (Python)    ")
    print("=" * 56)
    print(f"Platform : {platform.system()} ({platform.release()})")
    print(f"Source   : {script_dir}")
    print(f"Target   : {target_dir}")
    print("-" * 56)

    target_dir.mkdir(parents=True, exist_ok=True)

    # 1. Clean Policy Plane: Core constitution, design contracts, mistakes
    core_files = ["GEMINI.md", "DESIGN.md", "MISTAKES.md"]
    for file_name in core_files:
        src = script_dir / file_name
        if src.is_file():
            status = make_symlink_or_copy(src, target_dir / file_name, backup_dir)
            print(status)

    # 1.1 Canonical manifest
    harness_manifest = script_dir / ".harness"
    if harness_manifest.is_dir():
        status = make_symlink_or_copy(harness_manifest, target_dir / ".harness", backup_dir)
        print(status)

    # 1.2 Control Plane: Standalone binary or launcher installation
    guard_status = install_guard_binary(script_dir, from_source=args.from_source)
    print(guard_status)

    # 1.3 Porter CLI launcher in ~/.local/bin
    if not IS_WINDOWS:
        dest_porter = Path.home() / ".local" / "bin" / "porter"
        porter_src = script_dir / "porter.py"
        if porter_src.is_file():
            try:
                if dest_porter.is_symlink() or dest_porter.exists():
                    dest_porter.unlink(missing_ok=True)
                dest_porter.symlink_to(porter_src.resolve())
                print(f"[LAUNCHER] Linked porter -> {dest_porter}")
            except Exception:
                pass

    # 1.4 Cross-platform hook configuration with absolute path and platform Python binary
    import json
    watcher_target = (target_dir / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py").resolve()
    python_bin = "python" if IS_WINDOWS else "python3"
    hooks_payload = {
        "upstream-watchdog": {
            "PreInvocation": [
                {
                    "type": "command",
                    "command": f"{python_bin} \"{watcher_target}\"",
                    "timeout": 15
                }
            ]
        }
    }
    target_hooks = target_dir / "hooks.json"
    with open(target_hooks, "w", encoding="utf-8") as f:
        json.dump(hooks_payload, f, indent=2)
        f.write("\n")
    print(f"[CONFIGURED] hooks.json -> {python_bin} \"{watcher_target}\"")

    # 2. Autonomous subagents
    agents_src_dir = script_dir / "agents"
    agents_target_dir = target_dir / "agents"
    agents_target_dir.mkdir(parents=True, exist_ok=True)

    if agents_src_dir.is_dir():
        for agent_path in sorted(agents_src_dir.glob("*.md")):
            status = make_symlink_or_copy(agent_path, agents_target_dir / agent_path.name, backup_dir)
            print(status)

    # 3. Modular skills
    skills_src_dir = script_dir / "skills"
    skills_target_dir = target_dir / "skills"
    skills_target_dir.mkdir(parents=True, exist_ok=True)

    if skills_src_dir.is_dir():
        for skill_path in sorted(skills_src_dir.iterdir()):
            if skill_path.is_dir():
                status = make_symlink_or_copy(skill_path, skills_target_dir / skill_path.name, backup_dir)
                print(status)

    # 4. Initialize config.json from template if absent
    config_file = target_dir / "config.json"
    template_config = script_dir / "templates" / "config.example.json"
    if not config_file.exists() and template_config.is_file():
        shutil.copy2(template_config, config_file)
        print(f"[CREATED] Initialized {config_file.name} from template.")

    # 5. Make watcher scripts executable on POSIX platforms
    if not IS_WINDOWS:
        watcher_py = target_dir / "skills" / "upstream-auditor" / "scripts" / "upstream_watcher.py"
        watcher_sh = target_dir / "skills" / "upstream-auditor" / "scripts" / "check_skills.sh"
        for script in [watcher_py, watcher_sh]:
            if script.exists():
                try:
                    script.chmod(script.stat().st_mode | 0o755)
                except OSError:
                    pass

    # 6. Optional Pre-Session Boot Sentinel registration
    if args.enable_startup:
        print("\n[STARTUP] Enabling Pre-Session Boot Sentinel...")
        try:
            from guard.startup import StartupManager
            mgr = StartupManager(target_dir=target_dir)
            ok, msg = mgr.enable()
            print(f"[{'SUCCESS' if ok else 'FAILED'}] {msg}")
        except Exception as e:
            print(f"[WARN] Could not configure startup sentinel: {e}")

    print("=" * 56)
    print("[SUCCESS] Antigravity Harness successfully installed!")
    print(f"Target directory: {target_dir}")
    if backup_dir.exists():
        print(f"Previous files backed up at: {backup_dir}")
    print("=" * 56)
    return 0


if __name__ == "__main__":
    sys.exit(main())
