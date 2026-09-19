#!/usr/bin/env python3
"""
install.py — Antigravity Harness Cross-Platform Installer
Compatible with Windows, Linux, macOS, and FreeBSD.
Zero-dependency: uses strictly the Python standard library.

Symlinks or installs the harness constitution, design contracts,
autonomous subagents, modular skills, and templates into ~/.gemini/config/
"""

from __future__ import annotations

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


def main() -> int:
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

    # 1. Core constitution, design contracts, mistakes, hooks, and porter CLI
    core_files = ["GEMINI.md", "DESIGN.md", "MISTAKES.md", "hooks.json", "porter.py"]
    for file_name in core_files:
        src = script_dir / file_name
        if src.is_file():
            status = make_symlink_or_copy(src, target_dir / file_name, backup_dir)
            print(status)

    # 1.1 Porter engine package & canonical manifest
    porter_src_dir = script_dir / "porter"
    if porter_src_dir.is_dir():
        status = make_symlink_or_copy(porter_src_dir, target_dir / "porter", backup_dir)
        print(status)

    harness_src_dir = script_dir / ".harness"
    if harness_src_dir.is_dir():
        status = make_symlink_or_copy(harness_src_dir, target_dir / ".harness", backup_dir)
        print(status)

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

    print("=" * 56)
    print("[SUCCESS] Antigravity Harness successfully installed!")
    print(f"Target directory: {target_dir}")
    if backup_dir.exists():
        print(f"Previous files backed up at: {backup_dir}")
    print("=" * 56)
    return 0


if __name__ == "__main__":
    sys.exit(main())
