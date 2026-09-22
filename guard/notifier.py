"""
guard/notifier.py — Low-Frequency Ergonomic Notification Engine for Antigravity Guard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Rules:
- `enabled=False` is absolute: nothing is emitted, not even with force=True.
- quiet mode passes CRITICAL only.
- force=True bypasses the cooldown window only.
- Message text is passed to native notifiers as DATA (argv / environment), never as code.
"""

from __future__ import annotations

import enum
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from guard.paths import atomic_write_json, read_json, state_dir


class NotificationSeverity(str, enum.Enum):
    CRITICAL = "critical"  # Relock failures, active integrity tampering
    WARNING = "warning"    # Pending unlock requests, stale unlocked states
    INFO = "info"          # Lease lifecycle, upstream updates, status digests


def settings_file() -> Path:
    return state_dir() / "notifier.json"


def load_settings() -> Dict[str, bool]:
    data = read_json(settings_file(), default={}) or {}
    settings = {"enabled": bool(data.get("enabled", True)), "quiet": bool(data.get("quiet", False))}
    env = os.environ.get("AGY_GUARD_NOTIFY", "").strip().lower()
    if env in ("0", "off", "false", "disabled"):
        settings["enabled"] = False
    return settings


def save_settings(enabled: bool, quiet: bool) -> Path:
    return atomic_write_json(settings_file(), {"enabled": bool(enabled), "quiet": bool(quiet)})


class GuardNotifier:
    """
    Cross-platform desktop & terminal notification dispatcher.
    Enforces anti-fatigue debouncing, severity tiers, and quiet modes.
    """

    DEFAULT_COOLDOWNS = {
        NotificationSeverity.CRITICAL: 0,        # Immediate, never suppressed
        NotificationSeverity.WARNING: 1800,      # 30 minutes minimum between identical warnings
        NotificationSeverity.INFO: 86400,        # 24 hours minimum between identical info digests
    }
    CACHE_MAX_ENTRIES = 500

    def __init__(
        self,
        cache_file: Optional[Path] = None,
        enabled: Optional[bool] = None,
        quiet_mode: Optional[bool] = None,
    ):
        self.system = platform.system().lower()
        settings = load_settings() if enabled is None or quiet_mode is None else {}
        self.enabled = settings.get("enabled", True) if enabled is None else bool(enabled)
        self.quiet_mode = settings.get("quiet", False) if quiet_mode is None else bool(quiet_mode)
        self.terminal_only = os.environ.get("AGY_GUARD_NOTIFY", "").strip().lower() == "terminal"

        self.cache_file = Path(cache_file).resolve() if cache_file is not None else state_dir() / "notify_cache.json"
        self._cache: Dict[str, float] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        data = read_json(self.cache_file, default={}) or {}
        last_sent = data.get("last_sent", {}) if isinstance(data, dict) else {}
        self._cache = {str(k): float(v) for k, v in last_sent.items() if isinstance(v, (int, float))}

    def _save_cache(self) -> None:
        horizon = time.time() - max(self.DEFAULT_COOLDOWNS.values())
        pruned = {k: v for k, v in self._cache.items() if v >= horizon}
        if len(pruned) > self.CACHE_MAX_ENTRIES:
            newest = sorted(pruned.items(), key=lambda kv: kv[1], reverse=True)[: self.CACHE_MAX_ENTRIES]
            pruned = dict(newest)
        self._cache = pruned
        try:
            atomic_write_json(self.cache_file, {"last_sent": self._cache})
        except OSError:
            pass

    def _get_cache_key(self, title: str, message: str, key: Optional[str] = None) -> str:
        if key:
            return key
        raw = f"{title}:{message}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _allowed(self, severity: NotificationSeverity) -> bool:
        if not self.enabled:
            return False
        if self.quiet_mode and severity != NotificationSeverity.CRITICAL:
            return False
        return True

    def can_send(
        self,
        severity: NotificationSeverity,
        title: str,
        message: str,
        key: Optional[str] = None,
        cooldown_seconds: Optional[int] = None,
    ) -> bool:
        if not self._allowed(severity):
            return False
        cooldown = cooldown_seconds if cooldown_seconds is not None else self.DEFAULT_COOLDOWNS.get(severity, 3600)
        if cooldown <= 0:
            return True
        last_sent = self._cache.get(self._get_cache_key(title, message, key), 0.0)
        return (time.time() - last_sent) >= cooldown

    # ------------------------------------------------------------------
    # Native dispatchers (message text is data, never program source)
    # ------------------------------------------------------------------
    def _dispatch_linux(self, title: str, message: str, severity: NotificationSeverity) -> bool:
        notify_send = shutil.which("notify-send")
        if not (notify_send and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))):
            return False
        urgency = "critical" if severity == NotificationSeverity.CRITICAL else "normal"
        res = subprocess.run(
            [notify_send, "-u", urgency, "-a", "Antigravity Guard", "--", title, message],
            check=False, capture_output=True, timeout=5,
        )
        return res.returncode == 0

    def _dispatch_macos(self, title: str, message: str) -> bool:
        osa = shutil.which("osascript")
        if not osa:
            return False
        script = [
            "-e", "on run argv",
            "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
            "-e", "end run",
        ]
        res = subprocess.run([osa, *script, title, message], check=False, capture_output=True, timeout=5)
        return res.returncode == 0

    def _dispatch_windows(self, title: str, message: str) -> bool:
        powershell = shutil.which("powershell.exe") or shutil.which("powershell")
        if not powershell:
            return False
        ps_script = (
            '[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null; '
            '[reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null; '
            "$notify = New-Object System.Windows.Forms.NotifyIcon; "
            "$notify.Icon = [System.Drawing.SystemIcons]::Information; "
            "$notify.Visible = $true; "
            "$notify.ShowBalloonTip(10000, $env:AGY_NOTIFY_TITLE, $env:AGY_NOTIFY_MESSAGE, [System.Windows.Forms.ToolTipIcon]::Info)"
        )
        env = dict(os.environ)
        env["AGY_NOTIFY_TITLE"] = title
        env["AGY_NOTIFY_MESSAGE"] = message
        res = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", ps_script],
            check=False, capture_output=True, timeout=10, env=env,
        )
        return res.returncode == 0

    def _dispatch_native(self, title: str, message: str, severity: NotificationSeverity) -> Tuple[bool, str]:
        if self.terminal_only:
            return False, "terminal-only mode"
        try:
            if self.system == "linux":
                return self._dispatch_linux(title, message, severity), "notify-send"
            if self.system == "darwin":
                return self._dispatch_macos(title, message), "osascript"
            if self.system == "windows":
                return self._dispatch_windows(title, message), "powershell"
        except (OSError, subprocess.SubprocessError) as e:
            return False, str(e)
        return False, "unsupported platform"

    def notify(
        self,
        title: str,
        message: str,
        severity: NotificationSeverity = NotificationSeverity.INFO,
        key: Optional[str] = None,
        cooldown_seconds: Optional[int] = None,
        force: bool = False,
    ) -> bool:
        """
        Dispatches a notification if the severity rules and cooldown allow it.
        Returns True if the notification was delivered to a native notifier or the terminal.
        """
        if not self._allowed(severity):
            return False
        if not force and not self.can_send(severity, title, message, key, cooldown_seconds):
            return False

        dispatched, _ = self._dispatch_native(title, message, severity)
        if not dispatched:
            bell = "\a" if severity == NotificationSeverity.CRITICAL else ""
            sys.stderr.write(f"{bell}\n[ANTIGRAVITY GUARD - {severity.value.upper()}] {title}\n  {message}\n")
            sys.stderr.flush()
            dispatched = True

        self._cache[self._get_cache_key(title, message, key)] = time.time()
        self._save_cache()
        return dispatched
