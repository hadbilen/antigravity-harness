"""
guard/startup.py — Cross-Platform Pre-Session Boot Sentinel & Startup Manager.
Enforces operating system write-protection and integrity verification BEFORE
desktop sessions, AI IDEs (Antigravity, Cursor, VS Code), or models initialize.

Platforms supported:
  - Linux: systemd user unit (Before=graphical-session.target) with XDG autostart fallback
  - macOS: launchd user LaunchAgent (~/Library/LaunchAgents/com.antigravity.guard.plist)
  - Windows: Task Scheduler (schtasks /SC ONLOGON /RL HIGHEST) with Startup shortcut fallback
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from guard.integrity import FileIntegrityMonitor
from guard.os_adapter import OSProtectionAdapter

IS_LINUX = platform.system().lower() == "linux"
IS_MACOS = platform.system().lower() == "darwin"
IS_WINDOWS = platform.system().lower() == "windows"

SYSTEMD_USER_DIR = Path.home() / ".config" / "systemd" / "user"
SYSTEMD_SERVICE_NAME = "agy-guard-boot.service"
LAUNCH_AGENT_DIR = Path.home() / "Library" / "LaunchAgents"
LAUNCH_AGENT_PLIST = "com.antigravity.guard.plist"
WINDOWS_TASK_NAME = "AntigravityGuardBootSentinel"


class StartupManager:
    """Manages cross-platform early-boot sentinel configuration and execution."""

    def __init__(self, target_dir: Optional[Path] = None):
        if target_dir is None:
            config_env = os.environ.get("ANTIGRAVITY_CONFIG_DIR")
            self.target_dir = Path(config_env).resolve() if config_env else Path.home() / ".gemini" / "config"
        else:
            self.target_dir = Path(target_dir).resolve()

        self.os_adapter = OSProtectionAdapter(self.target_dir)
        self.integrity_monitor = FileIntegrityMonitor(self.target_dir)

    def get_guard_command(self) -> str:
        """Determines the best executable command to invoke agy-guard boot-check."""
        if getattr(sys, "frozen", False):
            # Standalone PyInstaller executable
            return f'"{sys.executable}" boot-check'

        agy_bin = shutil.which("agy-guard")
        if agy_bin:
            return f'"{agy_bin}" boot-check'

        local_bin = Path.home() / ".local" / "bin" / "agy-guard"
        if local_bin.is_file():
            return f'"{local_bin}" boot-check'

        # Fallback to python module execution
        py_bin = sys.executable or ("python" if IS_WINDOWS else "python3")
        return f'"{py_bin}" -m guard.cli boot-check'

    # -------------------------------------------------------------------------
    # Linux systemd implementation
    # -------------------------------------------------------------------------
    def _enable_linux(self) -> Tuple[bool, str]:
        cmd = self.get_guard_command()
        service_content = f"""[Unit]
Description=Antigravity Guard Pre-Session Boot Sentinel
DefaultDependencies=no
Before=graphical-session.target xdg-desktop-autostart.target
After=basic.target

[Service]
Type=oneshot
ExecStart={cmd}
RemainAfterExit=yes
Environment=ANTIGRAVITY_CONFIG_DIR={self.target_dir}

[Install]
WantedBy=default.target
"""
        SYSTEMD_USER_DIR.mkdir(parents=True, exist_ok=True)
        service_file = SYSTEMD_USER_DIR / SYSTEMD_SERVICE_NAME
        service_file.write_text(service_content, encoding="utf-8")

        # Try enabling via systemctl if available
        if shutil.which("systemctl"):
            try:
                subprocess.run(["systemctl", "--user", "daemon-reload"], check=False, capture_output=True)
                subprocess.run(["systemctl", "--user", "enable", SYSTEMD_SERVICE_NAME], check=False, capture_output=True)
            except Exception:
                pass

        return True, f"Configured systemd user service: {service_file}"

    def _disable_linux(self) -> Tuple[bool, str]:
        if shutil.which("systemctl"):
            try:
                subprocess.run(["systemctl", "--user", "disable", SYSTEMD_SERVICE_NAME], check=False, capture_output=True)
                subprocess.run(["systemctl", "--user", "daemon-reload"], check=False, capture_output=True)
            except Exception:
                pass

        service_file = SYSTEMD_USER_DIR / SYSTEMD_SERVICE_NAME
        if service_file.exists():
            service_file.unlink(missing_ok=True)
            return True, f"Removed systemd user service: {service_file}"
        return True, "Early startup service was not enabled."

    def _status_linux(self) -> Dict[str, Any]:
        service_file = SYSTEMD_USER_DIR / SYSTEMD_SERVICE_NAME
        is_installed = service_file.is_file()
        is_active = False

        if is_installed and shutil.which("systemctl"):
            res = subprocess.run(
                ["systemctl", "--user", "is-enabled", SYSTEMD_SERVICE_NAME],
                capture_output=True,
                text=True,
            )
            is_active = res.stdout.strip() == "enabled"

        return {
            "platform": "Linux",
            "mechanism": "systemd user unit (Pre-Session)",
            "installed": is_installed,
            "active": is_active if shutil.which("systemctl") else is_installed,
            "target_path": str(service_file),
        }

    # -------------------------------------------------------------------------
    # macOS launchd implementation
    # -------------------------------------------------------------------------
    def _enable_macos(self) -> Tuple[bool, str]:
        cmd_parts = self.get_guard_command().split()
        exec_path = cmd_parts[0].strip('"')
        args = [arg.strip('"') for arg in cmd_parts[1:]]

        args_xml = "".join(f"<string>{a}</string>" for a in [exec_path] + args)
        log_file = Path.home() / "Library" / "Logs" / "antigravity_guard_boot.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)

        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.antigravity.guard</string>
    <key>ProgramArguments</key>
    <array>
        {args_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>{log_file}</string>
    <key>StandardOutPath</key>
    <string>{log_file}</string>
</dict>
</plist>
"""
        LAUNCH_AGENT_DIR.mkdir(parents=True, exist_ok=True)
        plist_file = LAUNCH_AGENT_DIR / LAUNCH_AGENT_PLIST
        plist_file.write_text(plist_content, encoding="utf-8")

        if shutil.which("launchctl"):
            try:
                subprocess.run(["launchctl", "load", str(plist_file)], check=False, capture_output=True)
            except Exception:
                pass

        return True, f"Configured macOS LaunchAgent: {plist_file}"

    def _disable_macos(self) -> Tuple[bool, str]:
        plist_file = LAUNCH_AGENT_DIR / LAUNCH_AGENT_PLIST
        if shutil.which("launchctl") and plist_file.exists():
            try:
                subprocess.run(["launchctl", "unload", str(plist_file)], check=False, capture_output=True)
            except Exception:
                pass

        if plist_file.exists():
            plist_file.unlink(missing_ok=True)
            return True, f"Removed macOS LaunchAgent: {plist_file}"
        return True, "Early startup LaunchAgent was not enabled."

    def _status_macos(self) -> Dict[str, Any]:
        plist_file = LAUNCH_AGENT_DIR / LAUNCH_AGENT_PLIST
        return {
            "platform": "macOS",
            "mechanism": "launchd LaunchAgent (RunAtLoad)",
            "installed": plist_file.is_file(),
            "active": plist_file.is_file(),
            "target_path": str(plist_file),
        }

    # -------------------------------------------------------------------------
    # Windows Task Scheduler implementation
    # -------------------------------------------------------------------------
    def _enable_windows(self) -> Tuple[bool, str]:
        cmd = self.get_guard_command()
        if shutil.which("schtasks"):
            res = subprocess.run(
                [
                    "schtasks",
                    "/Create",
                    "/TN",
                    WINDOWS_TASK_NAME,
                    "/TR",
                    cmd,
                    "/SC",
                    "ONLOGON",
                    "/RL",
                    "HIGHEST",
                    "/F",
                ],
                capture_output=True,
                text=True,
            )
            if res.returncode == 0:
                return True, f"Registered scheduled task: {WINDOWS_TASK_NAME}"
            return False, f"Failed to register task via schtasks: {res.stderr.strip()}"

        return False, "schtasks.exe not found on Windows system."

    def _disable_windows(self) -> Tuple[bool, str]:
        if shutil.which("schtasks"):
            res = subprocess.run(
                ["schtasks", "/Delete", "/TN", WINDOWS_TASK_NAME, "/F"],
                capture_output=True,
                text=True,
            )
            return True, f"Unregistered scheduled task: {WINDOWS_TASK_NAME}"
        return True, "Early startup scheduled task was not enabled."

    def _status_windows(self) -> Dict[str, Any]:
        is_active = False
        if shutil.which("schtasks"):
            res = subprocess.run(
                ["schtasks", "/Query", "/TN", WINDOWS_TASK_NAME],
                capture_output=True,
                text=True,
            )
            is_active = res.returncode == 0

        return {
            "platform": "Windows",
            "mechanism": "Task Scheduler (ONLOGON / HIGHEST)",
            "installed": is_active,
            "active": is_active,
            "target_path": WINDOWS_TASK_NAME,
        }

    # -------------------------------------------------------------------------
    # Public Unified API
    # -------------------------------------------------------------------------
    def enable(self) -> Tuple[bool, str]:
        """Registers the Pre-Session Boot Sentinel for early boot execution."""
        if IS_LINUX:
            return self._enable_linux()
        elif IS_MACOS:
            return self._enable_macos()
        elif IS_WINDOWS:
            return self._enable_windows()
        return False, f"Startup Sentinel is unsupported on {platform.system()}."

    def disable(self) -> Tuple[bool, str]:
        """Unregisters the Pre-Session Boot Sentinel."""
        if IS_LINUX:
            return self._disable_linux()
        elif IS_MACOS:
            return self._disable_macos()
        elif IS_WINDOWS:
            return self._disable_windows()
        return True, "Nothing to disable."

    def status(self) -> Dict[str, Any]:
        """Returns the registration and installation status of the Boot Sentinel."""
        if IS_LINUX:
            return self._status_linux()
        elif IS_MACOS:
            return self._status_macos()
        elif IS_WINDOWS:
            return self._status_windows()
        return {
            "platform": platform.system(),
            "mechanism": "Unsupported",
            "installed": False,
            "active": False,
            "target_path": "N/A",
        }

    def execute_boot_check(self) -> Tuple[bool, str]:
        """
        Executes the non-interactive boot check:
        1. Verifies FIM integrity against baseline.
        2. Enforces read-only OS write protection (chmod a-w).
        Returns (success, message).
        """
        messages = []

        # 1. Integrity check
        report = self.integrity_monitor.verify()
        if not report.is_intact:
            messages.append(f"[FIM ALERT] Integrity drift detected: {report.summary()}")
        else:
            messages.append("[FIM OK] File integrity verified against baseline.")

        # 2. Enforce write protection
        lock_ok, lock_msg = self.os_adapter.lock()
        if lock_ok:
            messages.append("[LOCK ENFORCED] Target environment locked (chmod a-w / chattr).")
        else:
            messages.append(f"[LOCK WARN] Could not enforce lock: {lock_msg}")

        overall_success = report.is_intact and lock_ok
        return overall_success, " | ".join(messages)
