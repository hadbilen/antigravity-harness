"""
guard/notifier.py — Low-Frequency Ergonomic Notification Engine for Antigravity Guard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import enum
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional


class NotificationSeverity(str, enum.Enum):
    CRITICAL = "critical"  # Interactive unlock requests, active FIM tampering
    WARNING = "warning"    # Stale unlocked states, recovering locks
    INFO = "info"          # Upstream updates, status digests


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

    def __init__(
        self,
        cache_file: Optional[Path] = None,
        enabled: bool = True,
        quiet_mode: bool = False,
    ):
        self.system = platform.system().lower()
        self.enabled = enabled
        self.quiet_mode = quiet_mode

        if cache_file is not None:
            self.cache_file = Path(cache_file).resolve()
        else:
            self.cache_file = Path.home() / ".gemini" / ".notify_cache.json"

        self._cache: Dict[str, float] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        if self.cache_file.exists():
            try:
                data = json.loads(self.cache_file.read_text(encoding="utf-8"))
                self._cache = data.get("last_sent", {})
            except Exception:
                self._cache = {}

    def _save_cache(self) -> None:
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {"last_sent": self._cache}
            self.cache_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _get_cache_key(self, title: str, message: str, key: Optional[str] = None) -> str:
        if key:
            return key
        raw = f"{title}:{message}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def can_send(
        self,
        severity: NotificationSeverity,
        title: str,
        message: str,
        key: Optional[str] = None,
        cooldown_seconds: Optional[int] = None,
    ) -> bool:
        if not self.enabled:
            return False

        # In quiet mode, only CRITICAL notifications pass through
        if self.quiet_mode and severity != NotificationSeverity.CRITICAL:
            return False

        cooldown = (
            cooldown_seconds
            if cooldown_seconds is not None
            else self.DEFAULT_COOLDOWNS.get(severity, 3600)
        )

        if cooldown <= 0:
            return True

        cache_key = self._get_cache_key(title, message, key)
        last_sent = self._cache.get(cache_key, 0.0)
        now = time.time()
        return (now - last_sent) >= cooldown

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
        Dispatches a notification if debouncing and severity rules allow it.
        Returns True if the notification was dispatched, False otherwise.
        """
        if not force and not self.can_send(severity, title, message, key, cooldown_seconds):
            return False

        dispatched = False

        # 1. Linux notify-send
        if self.system == "linux":
            notify_send = shutil.which("notify-send")
            if notify_send and os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
                urgency = "critical" if severity == NotificationSeverity.CRITICAL else "normal"
                try:
                    subprocess.run(
                        [notify_send, "-u", urgency, "-a", "Antigravity Guard", title, message],
                        check=False,
                        capture_output=True,
                        timeout=5,
                    )
                    dispatched = True
                except Exception:
                    dispatched = False

        # 2. macOS osascript
        elif self.system == "darwin":
            osa = shutil.which("osascript")
            if osa:
                clean_title = title.replace('"', '\\"')
                clean_msg = message.replace('"', '\\"')
                script = f'display notification "{clean_msg}" with title "{clean_title}"'
                try:
                    subprocess.run([osa, "-e", script], check=False, capture_output=True, timeout=5)
                    dispatched = True
                except Exception:
                    dispatched = False

        # 3. Windows PowerShell Toast
        elif self.system == "windows":
            powershell = shutil.which("powershell.exe") or shutil.which("powershell")
            if powershell:
                ps_script = (
                    f'[reflection.assembly]::loadwithpartialname("System.Windows.Forms"); '
                    f'[reflection.assembly]::loadwithpartialname("System.Drawing"); '
                    f'$notify = new-object system.windows.forms.notifyicon; '
                    f'$notify.icon = [system.drawing.systemicons]::information; '
                    f'$notify.visible = $true; '
                    f'$notify.showballoontip(10000, "{title}", "{message}", [system.windows.forms.tooltipicon]::Info)'
                )
                try:
                    subprocess.run([powershell, "-NoProfile", "-Command", ps_script], check=False, capture_output=True, timeout=5)
                    dispatched = True
                except Exception:
                    dispatched = False

        # 4. Fallback: Terminal alert
        if not dispatched:
            bell = "\a" if severity == NotificationSeverity.CRITICAL else ""
            sys.stderr.write(f"{bell}\n[ANTIGRAVITY GUARD - {severity.value.upper()}] {title}\n  {message}\n")
            sys.stderr.flush()
            dispatched = True

        # Update cooldown timestamp
        cache_key = self._get_cache_key(title, message, key)
        self._cache[cache_key] = time.time()
        self._save_cache()

        return dispatched
