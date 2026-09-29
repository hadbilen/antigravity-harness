"""
guard/startup.py — Cross-Platform Pre-Session Boot Sentinel & Startup Manager.
Enforces operating system write-protection and integrity verification BEFORE
desktop sessions, AI IDEs (Antigravity, Cursor, VS Code), or models initialize.

Platforms supported:
  - Linux: systemd user unit started by the user manager (ordering before the graphical
    session is best-effort, not guaranteed)
  - macOS: launchd user LaunchAgent (~/Library/LaunchAgents/com.antigravity.guard.plist)
  - Windows: Task Scheduler (schtasks /SC ONLOGON)

On drift the sentinel quarantines instead of trusting: it takes a forensic snapshot,
keeps the governance scope locked, sends a CRITICAL notification and exits non-zero.
It never rebaselines on its own.
"""

from __future__ import annotations

import os
import platform
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape as xml_escape

from guard.environment import AgentEnvironment, EnvironmentRegistry, default_antigravity_environment
from guard.integrity import FileIntegrityMonitor
from guard.notifier import GuardNotifier, NotificationSeverity
from guard.os_adapter import OSProtectionAdapter
from guard.paths import path_key

IS_LINUX = platform.system().lower() == "linux"
IS_MACOS = platform.system().lower() == "darwin"
IS_WINDOWS = platform.system().lower() == "windows"

SYSTEMD_USER_DIR = Path.home() / ".config" / "systemd" / "user"
SYSTEMD_SERVICE_NAME = "agy-guard-boot.service"
LAUNCH_AGENT_DIR = Path.home() / "Library" / "LaunchAgents"
LAUNCH_AGENT_PLIST = "com.antigravity.guard.plist"
WINDOWS_TASK_NAME = "AntigravityGuardBootSentinel"
BOOT_DRIFT_KEEP = 3


class StartupManager:
    """Manages cross-platform early-boot sentinel configuration and execution."""

    def __init__(self, target_dir: Optional[Path] = None, registry: Optional[EnvironmentRegistry] = None):
        if target_dir is None:
            config_env = os.environ.get("ANTIGRAVITY_CONFIG_DIR")
            self.target_dir = Path(os.path.abspath(config_env)) if config_env else Path.home() / ".gemini" / "config"
        else:
            self.target_dir = Path(os.path.abspath(target_dir))

        self.os_adapter = OSProtectionAdapter(self.target_dir)
        self.registry = registry or EnvironmentRegistry(os_adapter=self.os_adapter)
        global_env = self.registry.get_environment("antigravity")
        if global_env is not None and global_env.get_root() == self.target_dir:
            self.environment: AgentEnvironment = global_env
        else:
            self.environment = default_antigravity_environment(self.target_dir)
            self.environment.id = f"boot-target-{path_key(self.target_dir)}"
        self.integrity_monitor = FileIntegrityMonitor.for_environment(self.environment, os_adapter=self.os_adapter)

    def get_guard_argv(self) -> List[str]:
        """Determines the argv that invokes `agy-guard boot-check` for this installation."""
        if getattr(sys, "frozen", False):
            return [sys.executable, "boot-check"]
        agy_bin = shutil.which("agy-guard")
        if agy_bin:
            return [agy_bin, "boot-check"]
        local_bin = Path.home() / ".local" / "bin" / "agy-guard"
        if local_bin.is_file():
            return [str(local_bin), "boot-check"]
        py_bin = sys.executable or ("python" if IS_WINDOWS else "python3")
        return [py_bin, "-m", "guard.cli", "boot-check"]

    def get_guard_command(self) -> str:
        """Shell-safe rendering of get_guard_argv() for the current platform."""
        argv = self.get_guard_argv()
        return subprocess.list2cmdline(argv) if IS_WINDOWS else shlex.join(argv)

    @staticmethod
    def _systemd_quote(value: str, exec_word: bool = False) -> str:
        """
        Quotes one systemd unit-file word. Control characters (newlines in particular) are
        rejected outright: a newline inside a value would start a new directive, e.g. an
        injected ExecStartPre= line taken from a crafted ANTIGRAVITY_CONFIG_DIR.
        """
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
            raise ValueError(f"Refusing to write a systemd unit value containing control characters: {value!r}")
        escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
        if exec_word:  # ExecStart= expands $VAR; Environment= values do not
            escaped = escaped.replace("$", "$$")
        return f'"{escaped}"'

    def render_systemd_unit(self) -> str:
        exec_start = " ".join(self._systemd_quote(a, exec_word=True) for a in self.get_guard_argv())
        env_line = self._systemd_quote(f"ANTIGRAVITY_CONFIG_DIR={self.target_dir}")
        return f"""[Unit]
Description=Antigravity Guard Boot Sentinel (integrity check + governance lock)
# Ordering before the graphical session is best-effort for user units.
Before=graphical-session.target xdg-desktop-autostart.target

[Service]
Type=oneshot
ExecStart={exec_start}
RemainAfterExit=yes
Environment={env_line}

[Install]
WantedBy=default.target
"""

    def render_launchd_plist(self) -> str:
        args_xml = "".join(f"<string>{xml_escape(a)}</string>" for a in self.get_guard_argv())
        log_file = Path.home() / "Library" / "Logs" / "antigravity_guard_boot.log"
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.antigravity.guard</string>
    <key>ProgramArguments</key>
    <array>
        {args_xml}
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>ANTIGRAVITY_CONFIG_DIR</key>
        <string>{xml_escape(str(self.target_dir))}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>{xml_escape(str(log_file))}</string>
    <key>StandardOutPath</key>
    <string>{xml_escape(str(log_file))}</string>
</dict>
</plist>
"""

    # -------------------------------------------------------------------------
    # Linux systemd implementation
    # -------------------------------------------------------------------------
    def _enable_linux(self) -> Tuple[bool, str]:
        service_content = self.render_systemd_unit()
        SYSTEMD_USER_DIR.mkdir(parents=True, exist_ok=True)
        service_file = SYSTEMD_USER_DIR / SYSTEMD_SERVICE_NAME
        service_file.write_text(service_content, encoding="utf-8")

        if not shutil.which("systemctl"):
            return False, (f"Wrote {service_file}, but systemctl is not available, so the sentinel is NOT "
                           f"enabled. Enable it with your init system manually.")
        problems = []
        for cmd in (["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", SYSTEMD_SERVICE_NAME]):
            try:
                res = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError) as e:
                problems.append(f"{' '.join(cmd)}: {e}")
                continue
            if res.returncode != 0:
                problems.append(f"{' '.join(cmd)}: {(res.stderr or res.stdout).strip() or f'exit {res.returncode}'}")
        if problems:
            return False, f"Wrote {service_file}, but enabling it failed: " + "; ".join(problems)
        return True, f"Configured and enabled systemd user service: {service_file}"

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
            "mechanism": "systemd user unit (started by the user manager)",
            "installed": is_installed,
            "active": is_active if shutil.which("systemctl") else is_installed,
            "target_path": str(service_file),
        }

    # -------------------------------------------------------------------------
    # macOS launchd implementation
    # -------------------------------------------------------------------------
    def _enable_macos(self) -> Tuple[bool, str]:
        (Path.home() / "Library" / "Logs").mkdir(parents=True, exist_ok=True)
        plist_content = self.render_launchd_plist()
        LAUNCH_AGENT_DIR.mkdir(parents=True, exist_ok=True)
        plist_file = LAUNCH_AGENT_DIR / LAUNCH_AGENT_PLIST
        plist_file.write_text(plist_content, encoding="utf-8")

        if not shutil.which("launchctl"):
            return False, f"Wrote {plist_file}, but launchctl is not available, so the sentinel is NOT loaded."
        try:
            res = subprocess.run(["launchctl", "load", str(plist_file)], check=False, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as e:
            return False, f"Wrote {plist_file}, but launchctl load failed: {e}"
        if res.returncode != 0:
            return False, f"Wrote {plist_file}, but launchctl load failed: {(res.stderr or res.stdout).strip()}"
        return True, f"Configured and loaded macOS LaunchAgent: {plist_file}"

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
                    # Least privilege: the task runs a per-user, user-writable launcher, so it must
                    # never run elevated (a replaced binary would otherwise gain admin rights).
                    "/RL",
                    "LIMITED",
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
            if res.returncode == 0:
                return True, f"Unregistered scheduled task: {WINDOWS_TASK_NAME}"
            if not self._status_windows().get("installed"):
                return True, "Early startup scheduled task was not enabled."
            return False, f"Failed to delete scheduled task via schtasks: {(res.stderr or res.stdout).strip()}"
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
            "mechanism": "Task Scheduler (ONLOGON / LIMITED)",
            "installed": is_active,
            "active": is_active,
            "target_path": WINDOWS_TASK_NAME,
        }

    # -------------------------------------------------------------------------
    # Public Unified API
    # -------------------------------------------------------------------------
    def enable(self) -> Tuple[bool, str]:
        """Registers the Pre-Session Boot Sentinel for early boot execution."""
        from guard.audit_log import audit

        try:
            if IS_LINUX:
                ok, msg = self._enable_linux()
            elif IS_MACOS:
                ok, msg = self._enable_macos()
            elif IS_WINDOWS:
                ok, msg = self._enable_windows()
            else:
                ok, msg = False, f"Startup Sentinel is unsupported on {platform.system()}."
        except (ValueError, OSError) as e:
            ok, msg = False, f"Could not register the boot sentinel: {e}"
        audit("startup.enable", ok=ok, detail=msg)
        return ok, msg

    def disable(self) -> Tuple[bool, str]:
        """Unregisters the Pre-Session Boot Sentinel."""
        from guard.audit_log import audit

        if IS_LINUX:
            ok, msg = self._disable_linux()
        elif IS_MACOS:
            ok, msg = self._disable_macos()
        elif IS_WINDOWS:
            ok, msg = self._disable_windows()
        else:
            ok, msg = True, "Nothing to disable."
        audit("startup.disable", ok=ok, detail=msg)
        return ok, msg

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

    def _forensic_snapshot(self, report) -> str:
        """Captures a boot-drift snapshot unless an identical drift state was already captured."""
        import hashlib
        import json

        from guard.snapshot import SnapshotEngine

        engine = SnapshotEngine.for_environment(self.environment, self.registry) if not self.environment.id.startswith("boot-target") \
            else SnapshotEngine(self.target_dir, os_adapter=self.os_adapter)
        signature = hashlib.sha256(json.dumps(
            {"modified": report.modified, "added": report.added, "deleted": report.deleted,
             "files": self.integrity_monitor.scan_directory()}, sort_keys=True).encode("utf-8")).hexdigest()
        latest = engine.latest_snapshot(kind="boot-drift")
        if latest is not None and latest.get("drift_signature") == signature:
            return f"[QUARANTINE] Drift unchanged since forensic snapshot {latest.get('id')}; no new copy taken."
        snap_id, _ = engine.create_snapshot(label="boot-drift-forensics", kind="boot-drift",
                                            extra_meta={"drift_signature": signature})
        pruned = engine.prune_kind("boot-drift", keep=BOOT_DRIFT_KEEP)
        note = f" ({pruned} older boot-drift snapshot(s) pruned)" if pruned else ""
        return f"[QUARANTINE] Forensic snapshot {snap_id} captured; baseline left untouched{note}."

    def execute_boot_check(self) -> Tuple[bool, str]:
        """
        Executes the non-interactive boot check:
        1. Enforces the governance write lock FIRST (a failing check must never leave it open).
        2. Verifies governance integrity against the per-environment baseline.
        3. On drift: forensic snapshot (deduplicated) + CRITICAL notification (no rebaseline).
           Changes recorded when a maintenance window closed are reported as pending review.
        Returns (success, message).
        """
        from guard.audit_log import audit

        messages: List[str] = []
        notifier = GuardNotifier()

        if self.environment.id.startswith("boot-target"):
            paths = self.environment.get_governance_paths(existing_only=True)
            lock_ok, lock_msg = self.os_adapter.lock(paths) if paths else (True, "")
            root_ok, root_msg = self.os_adapter.lock(self.target_dir, recursive=False)
            lock_ok, lock_msg = lock_ok and root_ok, f"{lock_msg} {root_msg}".strip()
        else:
            lock_ok, lock_msg = self.registry.lock(self.environment.id)
        if lock_ok:
            messages.append("[LOCK ENFORCED] Governance scope write-protected.")
        else:
            messages.append(f"[LOCK WARN] Could not enforce lock: {lock_msg}")
            notifier.notify(
                title="Antigravity Guard — Boot Lock Failed",
                message=lock_msg[:300],
                severity=NotificationSeverity.CRITICAL,
                force=True,
            )

        intact = False
        try:
            report = self.integrity_monitor.verify()
        except Exception as e:  # noqa: BLE001 - a broken check must be reported, not crash the sentinel
            report = None
            messages.append(f"[FIM ERROR] Integrity check failed: {type(e).__name__}: {e}")
            notifier.notify(title="Antigravity Guard — Boot Integrity Check Failed", message=str(e)[:300],
                            severity=NotificationSeverity.CRITICAL, force=True)
        if report is not None:
            if report.baseline_status == "missing":
                messages.append("[FIM WARN] No integrity baseline yet; run 'agy-guard rebaseline' from a terminal.")
            elif report.baseline_status == "pending_review":
                messages.append(f"[FIM REVIEW] {report.summary()}")
                notifier.notify(
                    title="Antigravity Guard — Changes Await Review",
                    message=report.summary(),
                    severity=NotificationSeverity.WARNING,
                    key="boot-pending-review",
                )
            elif not report.is_intact:
                messages.append(f"[FIM ALERT] Integrity drift detected: {report.summary()}")
                try:
                    messages.append(self._forensic_snapshot(report))
                except Exception as e:  # noqa: BLE001 - evidence capture is best effort, reported below
                    messages.append(f"[QUARANTINE] Forensic snapshot failed: {e}")
                notifier.notify(
                    title="Antigravity Guard — Boot Integrity Drift",
                    message=f"{report.summary()} Review with 'agy-guard verify' before trusting the environment.",
                    severity=NotificationSeverity.CRITICAL,
                    force=True,
                )
            else:
                intact = True
                messages.append("[FIM OK] File integrity verified against baseline.")

        overall_success = intact and lock_ok
        audit("boot_check", ok=overall_success, lock_ok=lock_ok,
              integrity=(report.baseline_status if report is not None else "error"), detail=" | ".join(messages)[:2000])
        return overall_success, " | ".join(messages)
