"""
guard/tray.py — Cross-Platform System Tray Adapter for Antigravity Guard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)

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
from typing import Callable, Optional

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
        from PIL import Image, ImageDraw

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


class BaseTrayAdapter:
    def start(self):
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
        self.on_open = on_open
        self.on_toggle_lock = on_toggle_lock
        self.on_exit = on_exit
        self.indicator = None
        self.is_locked = True
        self._gtk_thread = None
        self._icon_file = "/tmp/antigravity_guard_tray.png"
        self._appindicator = None
        self._gtk = None
        self._glib = None
        self._init_backend()

    def _init_backend(self):
        try:
            import gi
            gi.require_version("Gtk", "3.0")
            from gi.repository import Gtk, GLib
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
        except Exception:
            self._appindicator = None

    @property
    def is_available(self) -> bool:
        return self._appindicator is not None and self._gtk is not None

    def _save_icon(self):
        img = generate_shield_icon(self.is_locked, size=32)
        if img:
            try:
                img.save(self._icon_file)
            except Exception:
                pass

    def start(self):
        if not self.is_available:
            return
        self._save_icon()
        icon_name = self._icon_file if os.path.isfile(self._icon_file) else "security-high"

        def _run_gtk():
            try:
                self.indicator = self._appindicator.Indicator.new(
                    "antigravity_guard",
                    icon_name,
                    self._appindicator.IndicatorCategory.APPLICATION_STATUS,
                )
                self.indicator.set_status(self._appindicator.IndicatorStatus.ACTIVE)
                self._update_gtk_menu()
                self._gtk.main()
            except Exception:
                pass

        self._gtk_thread = threading.Thread(target=_run_gtk, daemon=True)
        self._gtk_thread.start()

    def _update_gtk_menu(self):
        if not self.indicator or not self._gtk:
            return

        menu = self._gtk.Menu()

        item_open = self._gtk.MenuItem(label="Open Antigravity Guard")
        item_open.connect("activate", lambda w: self.on_open())
        menu.append(item_open)

        menu.append(self._gtk.SeparatorMenuItem())

        status_text = "🔒 Status: Protected" if self.is_locked else "🔓 Status: Unlocked"
        item_status = self._gtk.MenuItem(label=status_text)
        item_status.set_sensitive(False)
        menu.append(item_status)

        toggle_text = "Unlock Shield (Maintenance)" if self.is_locked else "Lock Shield Now"
        item_toggle = self._gtk.MenuItem(label=toggle_text)
        item_toggle.connect("activate", lambda w: self.on_toggle_lock())
        menu.append(item_toggle)

        menu.append(self._gtk.SeparatorMenuItem())

        item_exit = self._gtk.MenuItem(label="Exit Guard")
        item_exit.connect("activate", lambda w: self.on_exit())
        menu.append(item_exit)

        menu.show_all()
        self.indicator.set_menu(menu)

    def stop(self):
        if self._glib and self._gtk:
            try:
                self._glib.idle_add(self._gtk.main_quit)
            except Exception:
                pass

    def update_status(self, is_locked: bool):
        self.is_locked = is_locked
        self._save_icon()
        if self._glib:
            try:
                self._glib.idle_add(self._update_gtk_status)
            except Exception:
                pass

    def _update_gtk_status(self):
        if self.indicator:
            if os.path.isfile(self._icon_file):
                self.indicator.set_icon_full(self._icon_file, "Antigravity Guard")
            self._update_gtk_menu()
        return False


class PystrayAdapter(BaseTrayAdapter):
    """Cross-platform pystray implementation (Windows, macOS, Linux X11)."""

    def __init__(
        self,
        on_open: Callable[[], None],
        on_toggle_lock: Callable[[], None],
        on_exit: Callable[[], None],
    ):
        self.on_open = on_open
        self.on_toggle_lock = on_toggle_lock
        self.on_exit = on_exit
        self.icon = None
        self.is_locked = True
        self._thread = None
        self._pystray = None
        self._init_backend()

    def _init_backend(self):
        try:
            import pystray
            self._pystray = pystray
        except Exception:
            self._pystray = None

    @property
    def is_available(self) -> bool:
        return self._pystray is not None and PIL_AVAILABLE

    def _build_menu(self):
        if not self._pystray:
            return None
        status_text = "🔒 Status: Protected" if self.is_locked else "🔓 Status: Unlocked"
        toggle_text = "Unlock Shield (Maintenance)" if self.is_locked else "Lock Shield Now"

        return self._pystray.Menu(
            self._pystray.MenuItem("Open Antigravity Guard", lambda icon, item: self.on_open(), default=True),
            self._pystray.Menu.SEPARATOR,
            self._pystray.MenuItem(status_text, lambda icon, item: None, enabled=False),
            self._pystray.MenuItem(toggle_text, lambda icon, item: self.on_toggle_lock()),
            self._pystray.Menu.SEPARATOR,
            self._pystray.MenuItem("Exit Guard", lambda icon, item: self.on_exit()),
        )

    def start(self):
        if not self.is_available or not self._pystray:
            return
        icon_img = generate_shield_icon(self.is_locked)
        if not icon_img:
            return

        try:
            self.icon = self._pystray.Icon(
                "antigravity_guard",
                icon_img,
                "Antigravity Guard",
                self._build_menu(),
            )

            def _run():
                try:
                    self.icon.run()
                except Exception:
                    pass

            self._thread = threading.Thread(target=_run, daemon=True)
            self._thread.start()
        except Exception:
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
        if self.icon:
            try:
                img = generate_shield_icon(is_locked)
                if img:
                    self.icon.icon = img
                self.icon.menu = self._build_menu()
            except Exception:
                pass


class DummyAdapter(BaseTrayAdapter):
    @property
    def is_available(self) -> bool:
        return False


def create_tray_adapter(
    on_open: Callable[[], None],
    on_toggle_lock: Callable[[], None],
    on_exit: Callable[[], None],
) -> BaseTrayAdapter:
    """Factory creating the optimal tray backend for the current OS and environment."""
    if platform.system() == "Linux":
        # On Linux, try AyatanaAppIndicator3 first (native for KDE Plasma SNI & GNOME without Xlib errors)
        try:
            adapter = AyatanaAdapter(on_open, on_toggle_lock, on_exit)
            if adapter.is_available:
                return adapter
        except Exception:
            pass

        # Fallback to pystray if Ayatana is unavailable
        try:
            adapter = PystrayAdapter(on_open, on_toggle_lock, on_exit)
            if adapter.is_available:
                return adapter
        except Exception:
            pass
    else:
        # On Windows and macOS, use pystray
        try:
            adapter = PystrayAdapter(on_open, on_toggle_lock, on_exit)
            if adapter.is_available:
                return adapter
        except Exception:
            pass

    return DummyAdapter()
