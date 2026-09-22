#!/usr/bin/env python3
"""
installers/build_binaries.py — Standalone Binary Builder for Antigravity Guard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)

Packages `agy-guard` CLI and GUI into a single standalone executable using PyInstaller.
Bundles `pystray` and `Pillow` for native system tray integration on Linux, macOS, and Windows.
"""

from __future__ import annotations

import hashlib
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    dist_dir = repo_root / "dist"

    system = platform.system()
    raw_machine = platform.machine().lower()
    if raw_machine in ("amd64", "x86_64"):
        machine = "x86_64"
    elif raw_machine in ("arm64", "aarch64"):
        machine = "arm64"
    else:
        machine = raw_machine

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

    entry_point = repo_root / "guard.py"
    exe_name = binary_name[:-4] if binary_name.endswith(".exe") else binary_name

    cmd = [
        pyinstaller,
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name", exe_name,
        "--paths", str(repo_root),
        "--collect-submodules", "guard",
        "--collect-submodules", "porter",
        "--hidden-import", "scripts.meta_audit",
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
    if not out_file.is_file():
        print(f"[ERROR] Expected build output {out_file} is missing.", file=sys.stderr)
        return 1
    digest = hashlib.sha256(out_file.read_bytes()).hexdigest()
    (dist_dir / f"{binary_name}.sha256").write_text(f"{digest}  {binary_name}\n", encoding="utf-8")
    print(f"[SUCCESS] Binary built successfully: {out_file} (sha256 {digest})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
