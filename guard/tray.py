"""
guard/tray.py — Cross-Platform System Tray Adapter for Plumb Guard
Part of Plumbwork (https://github.com/tozhax/plumbwork)

Supports:
1. AyatanaAppIndicator3 / AppIndicator3 via PyGObject (native on Kubuntu/KDE Plasma, GNOME, XFCE).
2. pystray (cross-platform, bundled in standalone PyInstaller builds for Linux, Windows, macOS).
3. Graceful fallback to standard window lifecycle when no tray service is available.
"""

from __future__ import annotations

import os
import platform
import sys
import threading
from typing import Any, Callable, Dict, List, Mapping, Optional

# Attempt to load PIL for generating high-contrast status icons
try:
    from PIL import Image, ImageDraw
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False


def generate_shield_icon(is_locked: bool, size: int = 64):
    """Generates an anti-aliased, high-contrast shield icon in memory."""
    if not PIL_AVAILABLE:
        return None

    try:
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        accent = "#22C55E" if is_locked else "#F59E0B"
        bg_surface = "#18181B"

        scale = size / 64.0
        pts = [
            (32 * scale, 4 * scale),
            (56 * scale, 14 * scale),
            (56 * scale, 36 * scale),
            (32 * scale, 60 * scale),
            (8 * scale, 36 * scale),
            (8 * scale, 14 * scale),
        ]
        draw.polygon(pts, fill=bg_surface, outline=accent, width=max(2, int(3 * scale)))

        if is_locked:
            check_pts = [(22 * scale, 32 * scale), (29 * scale, 40 * scale), (43 * scale, 24 * scale)]
            draw.line(check_pts, fill=accent, width=max(2, int(4 * scale)), joint="curve")
        else:
            draw.line([(32 * scale, 20 * scale), (32 * scale, 36 * scale)], fill=accent, width=max(2, int(4 * scale)))
            draw.ellipse([(29 * scale, 42 * scale), (35 * scale, 48 * scale)], fill=accent)

        return img
    except Exception:
        return None


def detect_linux_display_session(env: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """Classifies the active Linux display session for GTK+Tk isolation and Wayland diagnostics."""
    source = os.environ if env is None else env
    session_type = (source.get("XDG_SESSION_TYPE") or "").strip().lower()
    wayland_display = (source.get("WAYLAND_DISPLAY") or "").strip()
    x11_display = (source.get("DISPLAY") or "").strip()
    no_tray_raw = (source.get("PLUMB_GUARD_NO_TRAY") or "").strip().lower()
    is_wayland = session_type == "wayland" or bool(wayland_display)
    has_x11 = bool(x11_display)
    return {
        "session_type": session_type or ("wayland" if wayland_display else ("x11" if x11_display else "headless")),
        "is_wayland": is_wayland,
        "has_x11": has_x11,
        "is_headless": not has_x11 and not wayland_display,
        "is_frozen": bool(getattr(sys, "frozen", False)),
        "disabled_by_env": no_tray_raw in ("1", "true", "yes", "on"),
        "pystray_backend": (source.get("PYSTRAY_BACKEND") or "").strip().lower(),
    }


class BaseTrayAdapter:
    failed = False  # set when the tray backend crashed after start()
    fallback_reason: str = ""

    def __init__(self) -> None:
        self.failed = False
        self.fallback_reason = ""
        self.diagnostics: List[str] = []

    def start(self):
        pass

    @property
    def is_running(self) -> bool:
        """True only while a tray icon is actually shown (the window may then hide to the tray)."""
        thread = getattr(self, "_gtk_thread", None) or getattr(self, "_thread", None)
        return self.is_available and not self.failed and thread is not None and thread.is_alive()

    def _safe_invoke(self, label: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - tray callbacks must never crash the backend thread
            self._record_failure(RuntimeError(f"tray callback '{label}' failed: {exc}"))

    def _record_failure(self, exc: BaseException) -> None:
        was_failed = bool(getattr(self, "failed", False))
        self.failed = True
        detail = f"{type(self).__name__} failed ({type(exc).__name__}: {exc})"
        if platform.system() == "Linux":
            session = detect_linux_display_session()
            if session["is_wayland"]:
                detail += " [Wayland session: falling back to standard taskbar/window lifecycle]"
        self.fallback_reason = detail
        if hasattr(self, "diagnostics"):
            self.diagnostics.append(detail)
        try:
            from guard.audit_log import warn
            warn("tray.failed", backend=type(self).__name__, error=f"{type(exc).__name__}: {exc}", detail=detail)
        except Exception as log_exc:  # noqa: BLE001 - diagnostics must never crash the GUI
            sys.stderr.write(f"[WARN] {detail} (audit_log failed: {log_exc})\n")
        if not was_failed:
            try:
                self.stop()
            except Exception:  # noqa: BLE001
                pass

    def stop(self):
        pass

    def update_status(self, is_locked: bool):
        pass

    @property
    def is_available(self) -> bool:
        return False


class AyatanaAdapter(BaseTrayAdapter):
    """Native Linux implementation for KDE Plasma (Kubuntu), GNOME, and XFCE."""

    def __init__(
        self,
        on_open: Callable[[], None],
        on_toggle_lock: Callable[[], None],
        on_exit: Callable[[], None],
    ):
        super().__init__()
        self.on_open = on_open
        self.on_toggle_lock = on_toggle_lock
        self.on_exit = on_exit
        self.indicator = None
        self.is_locked = True
        self._gtk_thread = None
        self._icon_file = self._private_icon_path()
        self._appindicator = None
        self._gtk = None
        self._glib = None
        self._init_backend()

    def _init_backend(self):
        session = detect_linux_display_session()
        if session["is_frozen"]:
            self.fallback_reason = (
                "Frozen Linux binary isolates Tk from system GTK3/PyGObject."
            )
            self.diagnostics.append(self.fallback_reason)
            return
        try:
            import gi
            gi.require_version("Gtk", "3.0")
            from gi.repository import Gtk, GLib
            if hasattr(Gtk, "init_check"):
                init_res = Gtk.init_check()
                init_ok = init_res[0] if isinstance(init_res, tuple) else bool(init_res)
                if not init_ok:
                    wayland_note = " on Wayland" if session["is_wayland"] else ""
                    self.fallback_reason = (
                        f"GTK3 init_check failed{wayland_note}; isolating Tk GUI from GTK tray failure."
                    )
                    self.diagnostics.append(self.fallback_reason)
                    return
            self._gtk = Gtk
            self._glib = GLib
            try:
                gi.require_version("AyatanaAppIndicator3", "0.1")
                from gi.repository import AyatanaAppIndicator3
                self._appindicator = AyatanaAppIndicator3
            except Exception:
                gi.require_version("AppIndicator3", "0.1")
                from gi.repository import AppIndicator3
                self._appindicator = AppIndicator3
        except Exception as exc:
            self._gtk = None
            self._glib = None
            self._appindicator = None
            self.fallback_reason = f"AyatanaAppIndicator3/GTK3 unavailable ({type(exc).__name__}: {exc})"
            self.diagnostics.append(self.fallback_reason)

    @property
    def is_available(self) -> bool:
        return self._appindicator is not None and self._gtk is not None and not self.failed

    @staticmethod
    def _private_icon_path() -> str:
        """Icon lives in a private 0700 per-user runtime directory (never a shared /tmp path)."""
        try:
            from guard.paths import runtime_dir
            return str(runtime_dir() / "tray_icon.png")
        except Exception:
            return ""

    def _save_icon(self):
        if not self._icon_file:
            return
        img = generate_shield_icon(self.is_locked, size=32)
        if img:
            tmp = f"{self._icon_file}.{os.getpid()}.tmp"
            try:
                img.save(tmp, format="PNG")
                os.replace(tmp, self._icon_file)
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def start(self):
        if not self.is_available:
            return
        self._save_icon()
        icon_name = self._icon_file if self._icon_file and os.path.isfile(self._icon_file) else "security-high"

        def _run_gtk():
            try:
                self.indicator = self._appindicator.Indicator.new(
                    "plumb_guard",
                    icon_name,
                    self._appindicator.IndicatorCategory.APPLICATION_STATUS,
                )
                self.indicator.set_status(self._appindicator.IndicatorStatus.ACTIVE)
                self._update_gtk_menu()
                self._gtk.main()
            except Exception as e:  # noqa: BLE001 - reported via is_running / audit log
                self._record_failure(e)
                try:
                    if self._gtk and hasattr(self._gtk, "main_quit"):
                        self._gtk.main_quit()
                except Exception:
                    pass

        try:
            self._gtk_thread = threading.Thread(target=_run_gtk, daemon=True)
            self._gtk_thread.start()
        except Exception as e:  # noqa: BLE001
            self._record_failure(e)

    def _update_gtk_menu(self):
        if not self.indicator or not self._gtk:
            return
        try:
            menu = self._gtk.Menu()

            item_open = self._gtk.MenuItem(label="Open Plumb Guard")
            item_open.connect("activate", lambda w: self._safe_invoke("open", self.on_open))
            menu.append(item_open)

            menu.append(self._gtk.SeparatorMenuItem())

            status_text = "🔒 Status: Protected" if self.is_locked else "🔓 Status: Unlocked"
            item_status = self._gtk.MenuItem(label=status_text)
            item_status.set_sensitive(False)
            menu.append(item_status)

            toggle_text = "Unlock Shield (Maintenance)" if self.is_locked else "Lock Shield Now"
            item_toggle = self._gtk.MenuItem(label=toggle_text)
            item_toggle.connect("activate", lambda w: self._safe_invoke("toggle_lock", self.on_toggle_lock))
            menu.append(item_toggle)

            menu.append(self._gtk.SeparatorMenuItem())

            item_exit = self._gtk.MenuItem(label="Exit Guard")
            item_exit.connect("activate", lambda w: self._safe_invoke("exit", self.on_exit))
            menu.append(item_exit)

            menu.show_all()
            self.indicator.set_menu(menu)
        except Exception as exc:  # noqa: BLE001 - isolate GTK menu errors from Tk UI
            self._record_failure(exc)

    def stop(self):
        if self._glib and self._gtk:
            try:
                self._glib.idle_add(self._gtk.main_quit)
            except Exception:
                pass

    def update_status(self, is_locked: bool):
        self.is_locked = is_locked
        self._save_icon()
        if self._glib and not self.failed:
            try:
                self._glib.idle_add(self._update_gtk_status)
            except Exception as exc:
                self._record_failure(exc)

    def _update_gtk_status(self):
        try:
            if self.indicator:
                if self._icon_file and os.path.isfile(self._icon_file):
                    self.indicator.set_icon_full(self._icon_file, "Plumb Guard")
                self._update_gtk_menu()
        except Exception as exc:  # noqa: BLE001
            self._record_failure(exc)
        return False


class PystrayAdapter(BaseTrayAdapter):
    """Cross-platform pystray implementation (Windows, macOS, Linux X11)."""

    def __init__(
        self,
        on_open: Callable[[], None],
        on_toggle_lock: Callable[[], None],
        on_exit: Callable[[], None],
    ):
        super().__init__()
        self.on_open = on_open
        self.on_toggle_lock = on_toggle_lock
        self.on_exit = on_exit
        self.icon = None
        self.is_locked = True
        self._thread = None
        self._pystray = None
        self._init_backend()

    def _init_backend(self):
        is_linux = platform.system() == "Linux"
        session = detect_linux_display_session() if is_linux else None
        if session is not None:
            if session["is_wayland"] and not session["has_x11"] and session["pystray_backend"] in ("", "xorg"):
                self.fallback_reason = (
                    "Pure Wayland session without X11/XWayland DISPLAY; skipping pystray Xorg backend "
                    "and falling back to standard taskbar lifecycle."
                )
                self.diagnostics.append(self.fallback_reason)
                self._pystray = None
                return
        try:
            import pystray
            if session is not None:
                backend_mod = getattr(getattr(pystray, "Icon", None), "__module__", "")
                if session["is_wayland"] and "xorg" in backend_mod and session["pystray_backend"] != "xorg":
                    self.fallback_reason = (
                        f"Wayland session detected; rejecting XEmbed pystray backend '{backend_mod}' "
                        "to prevent invisible tray icon withdrawal."
                    )
                    self.diagnostics.append(self.fallback_reason)
                    self._pystray = None
                    return
                if session["is_frozen"] and any(tok in backend_mod for tok in ("gtk", "appindicator")):
                    self.fallback_reason = (
                        f"Frozen Linux binary isolates Tk from pystray GTK backend '{backend_mod}'."
                    )
                    self.diagnostics.append(self.fallback_reason)
                    self._pystray = None
                    return
            self._pystray = pystray
        except Exception as exc:
            self._pystray = None
            self.fallback_reason = f"pystray unavailable ({type(exc).__name__}: {exc})"
            self.diagnostics.append(self.fallback_reason)

    @property
    def is_available(self) -> bool:
        return self._pystray is not None and PIL_AVAILABLE and not self.failed

    def _build_menu(self):
        if not self._pystray:
            return None
        status_text = "🔒 Status: Protected" if self.is_locked else "🔓 Status: Unlocked"
        toggle_text = "Unlock Shield (Maintenance)" if self.is_locked else "Lock Shield Now"

        return self._pystray.Menu(
            self._pystray.MenuItem("Open Plumb Guard", lambda icon, item: self._safe_invoke("open", self.on_open), default=True),
            self._pystray.Menu.SEPARATOR,
            self._pystray.MenuItem(status_text, lambda icon, item: None, enabled=False),
            self._pystray.MenuItem(toggle_text, lambda icon, item: self._safe_invoke("toggle_lock", self.on_toggle_lock)),
            self._pystray.Menu.SEPARATOR,
            self._pystray.MenuItem("Exit Guard", lambda icon, item: self._safe_invoke("exit", self.on_exit)),
        )

    def start(self):
        if not self.is_available or not self._pystray:
            return
        icon_img = generate_shield_icon(self.is_locked)
        if not icon_img:
            return

        try:
            self.icon = self._pystray.Icon(
                "plumb_guard",
                icon_img,
                "Plumb Guard",
                self._build_menu(),
            )

            def _run():
                try:
                    self.icon.run()
                except Exception as e:  # noqa: BLE001 - reported via is_running / audit log
                    self._record_failure(e)

            self._thread = threading.Thread(target=_run, daemon=True)
            self._thread.start()
        except Exception as e:  # noqa: BLE001 - reported via is_running / audit log
            self._record_failure(e)
            self.icon = None

    def stop(self):
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass
            self.icon = None

    def update_status(self, is_locked: bool):
        self.is_locked = is_locked
        if self.icon and not self.failed:
            try:
                img = generate_shield_icon(is_locked)
                if img:
                    self.icon.icon = img
                self.icon.menu = self._build_menu()
            except Exception as exc:
                self._record_failure(exc)


class DummyAdapter(BaseTrayAdapter):
    def __init__(self, fallback_reason: str = "", diagnostics: Optional[List[str]] = None):
        super().__init__()
        self.fallback_reason = fallback_reason
        self.diagnostics = list(diagnostics or [])

    @property
    def is_available(self) -> bool:
        return False


def _log_tray_fallback(reason: str, session_type: str = "") -> None:
    try:
        from guard.audit_log import warn
        warn("tray.fallback", session=session_type or platform.system(), reason=reason)
    except Exception as log_exc:  # noqa: BLE001 - diagnostics must never crash GUI startup
        sys.stderr.write(f"[WARN] Tray fallback ({session_type or platform.system()}): {reason} (audit_log failed: {log_exc})\n")


def create_tray_adapter(
    on_open: Callable[[], None],
    on_toggle_lock: Callable[[], None],
    on_exit: Callable[[], None],
) -> BaseTrayAdapter:
    """Factory creating the optimal tray backend for the current OS and environment."""
    diagnostics: List[str] = []
    if os.environ.get("PLUMB_GUARD_NO_TRAY", "").strip().lower() in ("1", "true", "yes", "on"):
        reason = "System tray disabled via PLUMB_GUARD_NO_TRAY=1; using standard window lifecycle."
        return DummyAdapter(fallback_reason=reason, diagnostics=[reason])
    if platform.system() == "Linux":
        session = detect_linux_display_session()
        if session["is_headless"]:
            reason = "No Linux graphical display (DISPLAY/WAYLAND_DISPLAY unset); skipping tray backends."
            return DummyAdapter(fallback_reason=reason, diagnostics=[reason])

        # On Linux, try AyatanaAppIndicator3 first (native for KDE Plasma SNI & GNOME without Xlib errors)
        try:
            adapter = AyatanaAdapter(on_open, on_toggle_lock, on_exit)
            if adapter.is_available:
                return adapter
            if adapter.fallback_reason:
                diagnostics.append(adapter.fallback_reason)
        except Exception as exc:
            diagnostics.append(f"AyatanaAdapter init failed ({type(exc).__name__}: {exc})")

        # Fallback to pystray if Ayatana is unavailable
        try:
            adapter = PystrayAdapter(on_open, on_toggle_lock, on_exit)
            if adapter.is_available:
                return adapter
            if adapter.fallback_reason:
                diagnostics.append(adapter.fallback_reason)
        except Exception as exc:
            diagnostics.append(f"PystrayAdapter init failed ({type(exc).__name__}: {exc})")

        if session["is_wayland"]:
            prefix = (
                "Wayland session detected without an active StatusNotifier/AppIndicator tray backend; "
                "falling back to standard taskbar lifecycle"
            )
        else:
            prefix = "Linux system tray unavailable; falling back to standard taskbar lifecycle"
        reason = f"{prefix} ({'; '.join(diagnostics)})" if diagnostics else f"{prefix}."
        _log_tray_fallback(reason, session_type=session["session_type"])
        return DummyAdapter(fallback_reason=reason, diagnostics=diagnostics)

    # On Windows and macOS, use pystray
    try:
        adapter = PystrayAdapter(on_open, on_toggle_lock, on_exit)
        if adapter.is_available:
            return adapter
        if adapter.fallback_reason:
            diagnostics.append(adapter.fallback_reason)
    except Exception as exc:
        diagnostics.append(f"PystrayAdapter init failed ({type(exc).__name__}: {exc})")

    reason = (
        f"System tray unavailable ({'; '.join(diagnostics)}); using standard window lifecycle."
        if diagnostics
        else "System tray unavailable; using standard window lifecycle."
    )
    _log_tray_fallback(reason, session_type=platform.system())
    return DummyAdapter(fallback_reason=reason, diagnostics=diagnostics)
