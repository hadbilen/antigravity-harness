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
from typing import List, Tuple

PORTABLE_SKILL_SCRIPTS = (
    "skills/ui-refinery/scripts/check_ui_slop.py",
    "skills/ui-refinery/scripts/check_synthetic_markers.py",
)

PORTABLE_PLUGIN_ASSETS = (
    "guard/plugin_assets/ui-refinery.svg",
    "guard/plugin_assets/rust-suite.svg",
    "guard/plugin_assets/media-studio.svg",
    "guard/plugin_assets/game-engineering.svg",
)


def build_pyinstaller_command(
    repo_root: Path,
    system: str,
    machine: str,
    pyinstaller: str,
) -> Tuple[str, List[str]]:
    """Constructs the PyInstaller build command with portable script assets and Linux GTK+Tk isolation."""
    if system == "Linux":
        binary_name = f"agy-guard-linux-{machine}"
    elif system == "Darwin":
        binary_name = f"agy-guard-macos-{machine}"
    elif system == "Windows":
        binary_name = f"agy-guard-windows-{machine}.exe"
    else:
        binary_name = f"agy-guard-{system.lower()}-{machine}"

    entry_point = repo_root / "guard.py"
    exe_name = binary_name[:-4] if binary_name.endswith(".exe") else binary_name
    data_sep = ";" if system == "Windows" else ":"

    cmd: List[str] = [
        pyinstaller,
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name", exe_name,
        "--paths", str(repo_root),
        "--collect-submodules", "guard",
        "--collect-submodules", "porter",
        "--collect-submodules", "scripts",
        "--collect-submodules", "pystray",
        "--hidden-import", "scripts.meta_audit",
        "--hidden-import", "scripts.verify_invariants",
        "--hidden-import", "scripts.code_map",
        "--hidden-import", "pystray",
        "--hidden-import", "PIL",
        "--hidden-import", "PIL.Image",
        "--hidden-import", "PIL.ImageDraw",
    ]

    for rel_script in PORTABLE_SKILL_SCRIPTS:
        src_script = repo_root / rel_script
        if not src_script.is_file():
            raise FileNotFoundError(f"Declared portable skill script missing for binary build: {src_script}")
        dest_dir = str(Path(rel_script).parent.as_posix())
        cmd.extend(["--add-data", f"{src_script}{data_sep}{dest_dir}"])

    for rel_asset in PORTABLE_PLUGIN_ASSETS:
        src_asset = repo_root / rel_asset
        if not src_asset.is_file():
            raise FileNotFoundError(f"Declared plugin SVG asset missing for binary build: {src_asset}")
        dest_dir = str(Path(rel_asset).parent.as_posix())
        cmd.extend(["--add-data", f"{src_asset}{data_sep}{dest_dir}"])

    if system == "Linux":
        # Prevent PyInstaller from bundling colliding system GTK3/PyGObject libraries alongside Tcl/Tk.
        cmd.extend(["--exclude-module", "gi"])

    cmd.append(str(entry_point))
    return binary_name, cmd


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

    # Check for pyinstaller
    pyinstaller = shutil.which("pyinstaller")
    if not pyinstaller:
        print("[ERROR] PyInstaller is not installed or not in PATH.", file=sys.stderr)
        print("Please install PyInstaller: pip install pyinstaller pystray pillow", file=sys.stderr)
        return 1

    binary_name, cmd = build_pyinstaller_command(repo_root, system, machine, pyinstaller)
    print(f"Building standalone binary for {system} ({machine}) -> {binary_name}...")
    if system == "Linux":
        print(
            "[INFO] Linux GTK+Tk/Wayland tray isolation: excluding `gi` from onefile bundle "
            "(runtime falls back cleanly to standard taskbar mode when Wayland lacks an isolated tray)."
        )

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
