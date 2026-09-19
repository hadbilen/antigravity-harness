#!/usr/bin/env python3
"""
installers/build_binaries.py — Standalone Binary Builder for Antigravity Guard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)

Packages `agy-guard` CLI and GUI into a single standalone executable using PyInstaller.
Bundles `pystray` and `Pillow` for native system tray integration on Linux, macOS, and Windows.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    dist_dir = repo_root / "dist"
    build_dir = repo_root / "build"

    system = platform.system()
    machine = platform.machine().lower()

    if system == "Linux":
        binary_name = f"agy-guard-linux-{machine}"
    elif system == "Darwin":
        binary_name = f"agy-guard-macos-{machine}"
    elif system == "Windows":
        binary_name = f"agy-guard-windows-{machine}.exe"
    else:
        binary_name = f"agy-guard-{system.lower()}-{machine}"

    print(f"Building standalone binary for {system} ({machine}) -> {binary_name}...")

    # Check for pyinstaller
    pyinstaller = shutil.which("pyinstaller")
    if not pyinstaller:
        print("[ERROR] PyInstaller is not installed or not in PATH.", file=sys.stderr)
        print("Please install PyInstaller: pip install pyinstaller pystray pillow", file=sys.stderr)
        return 1

    entry_point = repo_root / "guard" / "cli.py"

    cmd = [
        pyinstaller,
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name", binary_name,
        "--hidden-import", "guard",
        "--hidden-import", "guard.gui",
        "--hidden-import", "guard.tray",
        "--hidden-import", "guard.integrity",
        "--hidden-import", "guard.os_adapter",
        "--hidden-import", "guard.snapshot",
        "--hidden-import", "guard.upstream",
        "--hidden-import", "guard.porter_bridge",
        "--hidden-import", "pystray",
        "--hidden-import", "PIL",
        "--hidden-import", "PIL.Image",
        "--hidden-import", "PIL.ImageDraw",
        str(entry_point),
    ]

    print("Running command:", " ".join(cmd))
    res = subprocess.run(cmd, cwd=repo_root)
    if res.returncode != 0:
        print("[ERROR] PyInstaller build failed.", file=sys.stderr)
        return res.returncode

    out_file = dist_dir / binary_name
    print(f"[SUCCESS] Binary built successfully: {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
