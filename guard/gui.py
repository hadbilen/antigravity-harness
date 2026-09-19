"""
guard/gui.py — High-Contrast Desktop Interface for Antigravity Guard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Strictly adheres to DESIGN.md (ENERGY 2 / RHYTHM 2 / Dark Zinc Palette).
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

# Safe tkinter imports
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from guard import __version__
from guard.integrity import FileIntegrityMonitor
from guard.os_adapter import OSProtectionAdapter
from guard.porter_bridge import PorterBridge
from guard.snapshot import SnapshotEngine
from guard.startup import StartupManager
from guard.tray import create_tray_adapter
from guard.upstream import UpstreamAuditorBridge

# Design Tokens from DESIGN.md (Dark Theme)
BG_CANVAS = "#09090B"
BG_SURFACE = "#18181B"
BG_SURFACE_ALT = "#27272A"
BORDER_COLOR = "#3F3F46"
TEXT_PRIMARY = "#F4F4F5"
TEXT_MUTED = "#A1A1AA"
TEXT_DISABLED = "#71717A"
BG_DISABLED = "#27272A"
ACCENT_BLUE = "#2563EB"
ACCENT_GREEN = "#22C55E"
ACCENT_AMBER = "#F59E0B"
ACCENT_RED = "#EF4444"


class AntigravityGuardApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"Antigravity Guard v{__version__}")
        self.root.geometry("1040x720")
        self.root.minsize(920, 620)
        self.root.configure(bg=BG_CANVAS)

        self.adapter = OSProtectionAdapter()
        self.monitor = FileIntegrityMonitor()
        self.snapshot_engine = SnapshotEngine()
        self.porter_bridge = PorterBridge()
        self.upstream_bridge = UpstreamAuditorBridge()
        self.startup_mgr = StartupManager(self.adapter.target_dir)

        self.var_minimize_to_tray = tk.BooleanVar(value=True)
        st_info = self.startup_mgr.status()
        self.var_early_startup = tk.BooleanVar(value=st_info.get("installed", False))

        # Cross-Platform System Tray Integration
        self.tray_adapter = create_tray_adapter(
            self.show_window,
            self.toggle_lock,
            self.quit_app,
        )
        if self.tray_adapter.is_available:
            self.tray_adapter.start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close_window)

        self._configure_styles()
        self._build_header()
        self._build_tabs()

        # Initial background state load
        self.refresh_status()

    def _configure_styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(".", background=BG_CANVAS, foreground=TEXT_PRIMARY, font=("Sans-serif", 10))
        style.configure("TNotebook", background=BG_CANVAS, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_SURFACE, foreground=TEXT_MUTED, padding=[16, 8], font=("Sans-serif", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", BG_SURFACE_ALT)], foreground=[("selected", TEXT_PRIMARY)])

        style.configure("TFrame", background=BG_CANVAS)
        style.configure("Card.TFrame", background=BG_SURFACE, relief="flat")
        style.configure("TLabel", background=BG_CANVAS, foreground=TEXT_PRIMARY)
        style.configure("Card.TLabel", background=BG_SURFACE, foreground=TEXT_PRIMARY)
        style.configure("Muted.TLabel", background=BG_SURFACE, foreground=TEXT_MUTED, font=("Sans-serif", 9))
        style.configure("Header.TLabel", background=BG_SURFACE, foreground=TEXT_PRIMARY, font=("Sans-serif", 13, "bold"))

        # Primary Button (WCAG AA compliant enabled: 5.17:1, disabled: 5.81:1)
        style.configure("Primary.TButton", background=ACCENT_BLUE, foreground="#FFFFFF", font=("Sans-serif", 10, "bold"), borderwidth=0, padding=6)
        style.map(
            "Primary.TButton",
            background=[("disabled", BG_DISABLED), ("active", "#1D4ED8")],
            foreground=[("disabled", TEXT_MUTED), ("active", "#FFFFFF")],
        )

        # Action Button
        style.configure("Action.TButton", background=BG_SURFACE_ALT, foreground=TEXT_PRIMARY, font=("Sans-serif", 9), borderwidth=1, padding=5)
        style.map(
            "Action.TButton",
            background=[("disabled", BG_SURFACE), ("active", "#3F3F46")],
            foreground=[("disabled", TEXT_DISABLED), ("active", TEXT_PRIMARY)],
        )

        # Danger Button
        style.configure("Danger.TButton", background=ACCENT_RED, foreground="#FFFFFF", font=("Sans-serif", 9, "bold"), borderwidth=0, padding=5)
        style.map(
            "Danger.TButton",
            background=[("disabled", BG_DISABLED), ("active", "#DC2626")],
            foreground=[("disabled", TEXT_DISABLED), ("active", "#FFFFFF")],
        )

        # Checkbutton
        style.configure("TCheckbutton", background=BG_SURFACE, foreground=TEXT_PRIMARY, font=("Sans-serif", 9))
        style.map(
            "TCheckbutton",
            background=[("active", BG_SURFACE)],
            foreground=[("disabled", TEXT_DISABLED), ("active", TEXT_PRIMARY)],
        )

        style.configure("Treeview", background=BG_SURFACE, foreground=TEXT_PRIMARY, fieldbackground=BG_SURFACE, borderwidth=0, font=("Sans-serif", 9))
        style.configure("Treeview.Heading", background=BG_SURFACE_ALT, foreground=TEXT_PRIMARY, font=("Sans-serif", 9, "bold"))
        style.map("Treeview", background=[("selected", ACCENT_BLUE)], foreground=[("selected", "#FFFFFF")])

    def _build_header(self):
        header = ttk.Frame(self.root, style="Card.TFrame", padding=16)
        header.pack(fill="x", padx=16, pady=(16, 8))

        left_box = ttk.Frame(header, style="Card.TFrame")
        left_box.pack(side="left", fill="y")

        title = ttk.Label(left_box, text=f"ANTIGRAVITY GUARD v{__version__}", style="Header.TLabel")
        title.pack(anchor="w")

        self.lbl_subtitle = ttk.Label(left_box, text="OS-Level Governance & Write Protection Suite", style="Muted.TLabel")
        self.lbl_subtitle.pack(anchor="w", pady=(2, 0))

        right_box = ttk.Frame(header, style="Card.TFrame")
        right_box.pack(side="right", fill="y")

        self.badge_status = tk.Label(
            right_box,
            text="CHECKING...",
            bg=BG_SURFACE_ALT,
            fg=TEXT_PRIMARY,
            font=("Sans-serif", 11, "bold"),
            padx=12,
            pady=4,
            relief="flat",
        )
        self.badge_status.pack(side="left", padx=(0, 12))

        self.btn_toggle_lock = ttk.Button(right_box, text="Unlock Maintenance", style="Action.TButton", command=self.toggle_lock)
        self.btn_toggle_lock.pack(side="left")

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=8)

        self.tab_shield = ttk.Frame(self.notebook, padding=12)
        self.tab_porter = ttk.Frame(self.notebook, padding=12)
        self.tab_upstream = ttk.Frame(self.notebook, padding=12)
        self.tab_settings = ttk.Frame(self.notebook, padding=12)

        self.notebook.add(self.tab_shield, text="Shield & Integrity")
        self.notebook.add(self.tab_porter, text="Porter Staging Gate")
        self.notebook.add(self.tab_upstream, text="Upstream Auditor")
        self.notebook.add(self.tab_settings, text="Snapshots & Settings")

        self._build_tab_shield()
        self._build_tab_porter()
        self._build_tab_upstream()
        self._build_tab_settings()

    # --- TAB 1: Shield & Integrity ---
    def _build_tab_shield(self):
        card_stat = ttk.Frame(self.tab_shield, style="Card.TFrame", padding=16)
        card_stat.pack(fill="x", pady=(0, 12))

        ttk.Label(card_stat, text="File Integrity Monitor (FIM)", style="Header.TLabel").pack(anchor="w")
        self.lbl_fim_summary = ttk.Label(card_stat, text="Scanning configuration baseline...", style="Card.TLabel")
        self.lbl_fim_summary.pack(anchor="w", pady=(4, 8))

        btn_bar = ttk.Frame(card_stat, style="Card.TFrame")
        btn_bar.pack(fill="x")
        ttk.Button(btn_bar, text="Verify Integrity Now", style="Action.TButton", command=self.verify_integrity).pack(side="left", padx=(0, 8))
        ttk.Button(btn_bar, text="Establish Baseline (Re-baseline)", style="Primary.TButton", command=self.rebaseline).pack(side="left", padx=(0, 8))
        ttk.Button(btn_bar, text="Create Snapshot Point", style="Action.TButton", command=self.create_snapshot).pack(side="left")

        card_list = ttk.Frame(self.tab_shield, style="Card.TFrame", padding=16)
        card_list.pack(fill="both", expand=True)

        ttk.Label(card_list, text="Monitored Target Files", style="Header.TLabel").pack(anchor="w", pady=(0, 8))

        cols = ("status", "path")
        self.tree_fim = ttk.Treeview(card_list, columns=cols, show="headings", height=12)
        self.tree_fim.heading("status", text="Integrity State")
        self.tree_fim.heading("path", text="Protected Path")
        self.tree_fim.column("status", width=140)
        self.tree_fim.column("path", width=680)
        self.tree_fim.pack(fill="both", expand=True)

    # --- TAB 2: Porter Staging Gate ---
    def _build_tab_porter(self):
        input_frame = ttk.Frame(self.tab_porter, style="Card.TFrame", padding=12)
        input_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(input_frame, text="Source Path or URL:", style="Card.TLabel").pack(side="left", padx=(0, 8))
        self.ent_porter_source = tk.Entry(input_frame, bg=BG_SURFACE_ALT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief="flat", font=("Sans-serif", 10))
        self.ent_porter_source.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ttk.Button(input_frame, text="Browse...", style="Action.TButton", command=self._browse_porter_file).pack(side="left", padx=(0, 8))
        ttk.Button(input_frame, text="Inspect & Sanitize", style="Primary.TButton", command=self.inspect_porter).pack(side="left")

        # Score Card
        self.card_score = ttk.Frame(self.tab_porter, style="Card.TFrame", padding=12)
        self.card_score.pack(fill="x", pady=(0, 10))

        self.lbl_porter_score = ttk.Label(self.card_score, text="Score: Enter source to analyze pre-flight suitability", style="Card.TLabel", font=("Sans-serif", 11, "bold"))
        self.lbl_porter_score.pack(anchor="w")

        self.lbl_porter_details = ttk.Label(self.card_score, text="", style="Muted.TLabel")
        self.lbl_porter_details.pack(anchor="w", pady=(2, 6))

        self.btn_ingest = ttk.Button(self.card_score, text="Approve & Ingest (Atomic Unlock -> Write -> Re-lock)", style="Primary.TButton", command=self.ingest_porter)
        self.btn_ingest.pack(anchor="w")
        self.btn_ingest.state(["disabled"])

        # Split Diff Area
        diff_frame = ttk.Frame(self.tab_porter, style="Card.TFrame", padding=8)
        diff_frame.pack(fill="both", expand=True)

        p_left = ttk.Frame(diff_frame, style="Card.TFrame")
        p_left.pack(side="left", fill="both", expand=True, padx=(0, 4))
        ttk.Label(p_left, text="Raw Incoming Rule", style="Muted.TLabel").pack(anchor="w")
        self.txt_raw = tk.Text(p_left, bg=BG_SURFACE_ALT, fg=TEXT_PRIMARY, relief="flat", font=("Monospace", 9))
        self.txt_raw.pack(fill="both", expand=True)

        p_right = ttk.Frame(diff_frame, style="Card.TFrame")
        p_right.pack(side="right", fill="both", expand=True, padx=(4, 0))
        ttk.Label(p_right, text="Sanitized Antigravity Contract", style="Muted.TLabel").pack(anchor="w")
        self.txt_sanitized = tk.Text(p_right, bg=BG_SURFACE_ALT, fg=TEXT_PRIMARY, relief="flat", font=("Monospace", 9))
        self.txt_sanitized.pack(fill="both", expand=True)

    # --- TAB 3: Upstream Auditor ---
    def _build_tab_upstream(self):
        header_card = ttk.Frame(self.tab_upstream, style="Card.TFrame", padding=12)
        header_card.pack(fill="x", pady=(0, 10))

        ttk.Label(header_card, text="Tracked Ecosystem & Model Drift", style="Header.TLabel").pack(anchor="w")
        model_info = self.upstream_bridge.get_model_drift_status()
        ttk.Label(header_card, text=f"Active Antigravity Model: {model_info['active_model']} | Monitored: {model_info['tracked_ecosystems']} ecosystems", style="Muted.TLabel").pack(anchor="w", pady=(2, 8))

        ttk.Button(header_card, text="Check Repositories Now", style="Primary.TButton", command=self.check_upstream_async).pack(anchor="w")

        table_frame = ttk.Frame(self.tab_upstream, style="Card.TFrame", padding=12)
        table_frame.pack(fill="both", expand=True)

        cols = ("repo", "local", "remote", "status", "commit")
        self.tree_upstream = ttk.Treeview(table_frame, columns=cols, show="headings", height=10)
        self.tree_upstream.heading("repo", text="Tracked Ecosystem")
        self.tree_upstream.heading("local", text="Local SHA")
        self.tree_upstream.heading("remote", text="Remote SHA")
        self.tree_upstream.heading("status", text="Sync State")
        self.tree_upstream.heading("commit", text="Latest Remote Commit")

        self.tree_upstream.column("repo", width=160)
        self.tree_upstream.column("local", width=90)
        self.tree_upstream.column("remote", width=90)
        self.tree_upstream.column("status", width=140)
        self.tree_upstream.column("commit", width=380)
        self.tree_upstream.pack(fill="both", expand=True)

    # --- TAB 4: Settings & Snapshots ---
    def _build_tab_settings(self):
        # 1. Desktop & System Tray Preferences Card
        pref_card = ttk.Frame(self.tab_settings, style="Card.TFrame", padding=12)
        pref_card.pack(fill="x", pady=(0, 10))

        ttk.Label(pref_card, text="Desktop & System Preferences", style="Header.TLabel").pack(anchor="w")

        if getattr(self, "tray_adapter", None) and getattr(self.tray_adapter, "is_available", False):
            backend_name = type(self.tray_adapter).__name__
            tray_info = f"Active ({backend_name})"
        else:
            tray_info = "Disabled (Standard Taskbar Mode)"

        chk_tray = ttk.Checkbutton(
            pref_card,
            text=f"Minimize to System Tray on close / minimize [System Tray: {tray_info}]",
            variable=self.var_minimize_to_tray,
            style="TCheckbutton",
        )
        chk_tray.pack(anchor="w", pady=(6, 2))
        ttk.Label(pref_card, text="When enabled, closing or minimizing the window keeps Antigravity Guard active in the system tray.", style="Muted.TLabel").pack(anchor="w")

        # Early Boot Sentinel
        st_info = self.startup_mgr.status()
        chk_startup = ttk.Checkbutton(
            pref_card,
            text=f"Run Pre-Session Boot Sentinel on Startup [Mechanism: {st_info.get('mechanism', 'OS Boot')}]",
            variable=self.var_early_startup,
            command=self.toggle_early_startup,
            style="TCheckbutton",
        )
        chk_startup.pack(anchor="w", pady=(8, 2))
        ttk.Label(
            pref_card,
            text="When enabled, verifies FIM baseline and enforces write-lock BEFORE desktop AI IDEs or models start.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(0, 4))

        # 2. Dual-Pane Snapshot Frame
        snap_frame = ttk.Frame(self.tab_settings, style="Card.TFrame", padding=12)
        snap_frame.pack(fill="both", expand=True)

        ttk.Label(snap_frame, text="Recorded Configuration Snapshots & Inspection", style="Header.TLabel").pack(anchor="w")
        ttk.Label(snap_frame, text="Point-in-time state records. Select a snapshot to inspect files in read-only mode or rollback.", style="Muted.TLabel").pack(anchor="w", pady=(2, 8))

        split_box = ttk.Frame(snap_frame, style="Card.TFrame")
        split_box.pack(fill="both", expand=True, pady=(0, 8))

        # Left Column: Snapshots Tree
        left_box = ttk.Frame(split_box, style="Card.TFrame")
        left_box.pack(side="left", fill="both", expand=True, padx=(0, 6))

        cols = ("id", "label", "date")
        self.tree_snaps = ttk.Treeview(left_box, columns=cols, show="headings", height=8)
        self.tree_snaps.heading("id", text="Snapshot ID")
        self.tree_snaps.heading("label", text="Description")
        self.tree_snaps.heading("date", text="Created At (UTC)")
        self.tree_snaps.column("id", width=160)
        self.tree_snaps.column("label", width=220)
        self.tree_snaps.column("date", width=180)
        self.tree_snaps.pack(fill="both", expand=True)
        self.tree_snaps.bind("<<TreeviewSelect>>", self.on_snapshot_selected)

        # Right Column: Files in Snapshot
        right_box = ttk.Frame(split_box, style="Card.TFrame")
        right_box.pack(side="right", fill="both", expand=True, padx=(6, 0))

        ttk.Label(right_box, text="Files in Selected Snapshot (Read-Only)", style="Muted.TLabel").pack(anchor="w", pady=(0, 4))
        self.tree_snap_files = ttk.Treeview(right_box, columns=("file",), show="headings", height=8)
        self.tree_snap_files.heading("file", text="Relative File Path")
        self.tree_snap_files.column("file", width=300)
        self.tree_snap_files.pack(fill="both", expand=True)
        self.tree_snap_files.bind("<Double-1>", lambda e: self.inspect_selected_snapshot_file())

        # Button Row
        btn_row = ttk.Frame(snap_frame, style="Card.TFrame")
        btn_row.pack(fill="x")

        ttk.Button(btn_row, text="Restore Selected Snapshot", style="Danger.TButton", command=self.restore_snapshot).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Inspect File (In-App)", style="Primary.TButton", command=self.inspect_selected_snapshot_file).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Open in External Editor", style="Action.TButton", command=self.open_external_snapshot_file).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Prune Older Snapshots", style="Action.TButton", command=self.prune_snapshots).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Refresh", style="Action.TButton", command=self.refresh_snapshots).pack(side="right")

    # --- Operational Actions ---
    def toggle_early_startup(self):
        if self.var_early_startup.get():
            ok, msg = self.startup_mgr.enable()
            if not ok:
                self.var_early_startup.set(False)
                messagebox.showerror("Startup Sentinel Error", msg)
            else:
                messagebox.showinfo("Startup Sentinel", msg)
        else:
            ok, msg = self.startup_mgr.disable()
            if not ok:
                self.var_early_startup.set(True)
                messagebox.showerror("Startup Sentinel Error", msg)
            else:
                messagebox.showinfo("Startup Sentinel", msg)

    def refresh_status(self):
        is_locked = self.adapter.is_locked()
        if is_locked:
            self.badge_status.config(text="🔒 PROTECTED", bg=ACCENT_GREEN, fg="#09090B")
            self.btn_toggle_lock.config(text="Unlock for Maintenance")
        else:
            self.badge_status.config(text="🔓 UNLOCKED", bg=ACCENT_AMBER, fg="#000000")
            self.btn_toggle_lock.config(text="Lock Shield Now")

        if hasattr(self, "tray_adapter") and self.tray_adapter.is_available:
            self.tray_adapter.update_status(is_locked)

        self.verify_integrity()
        self.refresh_snapshots()

    def toggle_lock(self):
        if self.adapter.is_locked():
            success, msg = self.adapter.unlock()
            if success:
                messagebox.showinfo("Maintenance Mode", "Environment unlocked for maintenance. Remember to re-lock when finished!")
        else:
            success, msg = self.adapter.lock()
            if success:
                messagebox.showinfo("Shield Engaged", "Environment write-protection active. Files are immutable/read-only.")
        self.refresh_status()

    def verify_integrity(self):
        report = self.monitor.verify()
        self.lbl_fim_summary.config(text=report.summary())

        for row in self.tree_fim.get_children():
            self.tree_fim.delete(row)

        if report.is_intact:
            self.tree_fim.insert("", "end", values=("✅ INTACT", f"All {report.total_files} tracked files verified via SHA-256 baseline."))
        else:
            for f in report.modified:
                self.tree_fim.insert("", "end", values=("⚠️ MODIFIED", f))
            for f in report.added:
                self.tree_fim.insert("", "end", values=("➕ UNAUTHORIZED", f))
            for f in report.deleted:
                self.tree_fim.insert("", "end", values=("❌ DELETED", f))

    def rebaseline(self):
        count, path = self.monitor.save_baseline()
        messagebox.showinfo("Baseline Saved", f"Established trusted SHA-256 baseline across {count} files.")
        self.verify_integrity()

    def create_snapshot(self):
        snap_id, _ = self.snapshot_engine.create_snapshot(label="User GUI Snapshot")
        messagebox.showinfo("Snapshot Created", f"Snapshot '{snap_id}' saved successfully.")
        self.refresh_snapshots()

    def refresh_snapshots(self):
        for row in self.tree_snaps.get_children():
            self.tree_snaps.delete(row)
        for s in self.snapshot_engine.list_snapshots():
            self.tree_snaps.insert("", "end", values=(s.get("id"), s.get("label"), s.get("created_at")))

    def on_snapshot_selected(self, event=None):
        selected = self.tree_snaps.selection()
        for row in self.tree_snap_files.get_children():
            self.tree_snap_files.delete(row)
        if not selected:
            return
        snap_id = self.tree_snaps.item(selected[0])["values"][0]
        files = self.snapshot_engine.get_snapshot_files(snap_id)
        for f in files:
            self.tree_snap_files.insert("", "end", values=(f,))

    def inspect_selected_snapshot_file(self):
        sel_snap = self.tree_snaps.selection()
        sel_file = self.tree_snap_files.selection()
        if not sel_snap or not sel_file:
            messagebox.showwarning("Selection Required", "Please select a snapshot and a file from the list to inspect.")
            return

        snap_id = self.tree_snaps.item(sel_snap[0])["values"][0]
        rel_path = self.tree_snap_files.item(sel_file[0])["values"][0]

        content = self.snapshot_engine.read_snapshot_file(snap_id, rel_path)
        if content is None:
            messagebox.showerror("Read Error", f"Unable to read file: {rel_path}")
            return

        # Modal Read-Only Viewer
        win = tk.Toplevel(self.root)
        win.title(f"Read-Only Viewer: {rel_path} ({snap_id})")
        win.geometry("820x580")
        win.configure(bg=BG_CANVAS)

        top_bar = ttk.Frame(win, style="Card.TFrame", padding=10)
        top_bar.pack(fill="x")
        ttk.Label(top_bar, text=f"Snapshot: {snap_id} | Path: {rel_path}", style="Card.TLabel", font=("Sans-serif", 10, "bold")).pack(side="left")
        ttk.Label(top_bar, text="[IMMUTABLE READ-ONLY]", style="Muted.TLabel").pack(side="right")

        text_area = tk.Text(win, bg=BG_SURFACE_ALT, fg=TEXT_PRIMARY, font=("Monospace", 10), relief="flat")
        text_area.pack(fill="both", expand=True, padx=10, pady=10)
        text_area.insert("1.0", content)
        text_area.configure(state="disabled")

        bottom_bar = ttk.Frame(win, style="Card.TFrame", padding=10)
        bottom_bar.pack(fill="x")
        ttk.Button(bottom_bar, text="Open in External Editor (Read-Only)", style="Action.TButton", command=lambda: self._open_external_file_by_path(snap_id, rel_path)).pack(side="left")
        ttk.Button(bottom_bar, text="Close", style="Action.TButton", command=win.destroy).pack(side="right")

    def _open_external_file_by_path(self, snap_id: str, rel_path: str):
        snap_path = (self.snapshot_engine.snapshots_dir / snap_id / rel_path).resolve()
        if not snap_path.is_file():
            messagebox.showerror("Error", "File does not exist.")
            return

        # Ensure snapshot file is read-only
        try:
            os.chmod(snap_path, 0o444)
        except Exception:
            pass

        try:
            if sys.platform == "win32":
                os.startfile(str(snap_path))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(snap_path)])
            else:
                editor = os.environ.get("EDITOR") or os.environ.get("VISUAL")
                if editor:
                    subprocess.Popen([editor, str(snap_path)])
                else:
                    subprocess.Popen(["xdg-open", str(snap_path)])
        except Exception as e:
            messagebox.showerror("Open Error", f"Failed to launch external editor: {e}")

    def open_external_snapshot_file(self):
        sel_snap = self.tree_snaps.selection()
        sel_file = self.tree_snap_files.selection()
        if not sel_snap or not sel_file:
            messagebox.showwarning("Selection Required", "Please select a snapshot and a file to open.")
            return
        snap_id = self.tree_snaps.item(sel_snap[0])["values"][0]
        rel_path = self.tree_snap_files.item(sel_file[0])["values"][0]
        self._open_external_file_by_path(snap_id, rel_path)

    def restore_snapshot(self):
        selected = self.tree_snaps.selection()
        if not selected:
            messagebox.showwarning("Select Snapshot", "Please select a snapshot to restore.")
            return
        item = self.tree_snaps.item(selected[0])
        snap_id = item["values"][0]
        if messagebox.askyesno("Confirm Rollback", f"Restore environment to snapshot '{snap_id}'? Current state will be backed up."):
            success, msg = self.snapshot_engine.restore_snapshot(snap_id)
            messagebox.showinfo("Rollback Result", msg)
            self.refresh_status()

    def prune_snapshots(self):
        count = self.snapshot_engine.prune_snapshots(keep=5)
        messagebox.showinfo("Prune Complete", f"Pruned {count} older snapshots.")
        self.refresh_snapshots()

    def _browse_porter_file(self):
        f = filedialog.askopenfilename(title="Select Rule File", filetypes=[("Markdown / Rule", "*.md *.mdc *.txt"), ("All Files", "*.*")])
        if f:
            self.ent_porter_source.delete(0, "end")
            self.ent_porter_source.insert(0, f)

    def inspect_porter(self):
        src = self.ent_porter_source.get().strip()
        if not src:
            messagebox.showwarning("Source Required", "Please enter a file path or URL.")
            return
        try:
            report = self.porter_bridge.inspect_source(src)
            self.current_porter_report = report

            score_txt = f"Constitutional Alignment: {report['alignment_score']}/100 | Adaptability: {report['adaptability_score']}/100 | Type: {report['target_type']}"
            self.lbl_porter_score.config(text=score_txt)

            details = []
            if report["violations"]:
                details.append(f"Violations: {'; '.join(report['violations'])}")
            if report["recommendations"]:
                details.append(f"Notes: {'; '.join(report['recommendations'])}")
            self.lbl_porter_details.config(text=" | ".join(details) or "All constitutional gates passed cleanly.")

            self.txt_raw.delete("1.0", "end")
            self.txt_raw.insert("1.0", report["original_content"])

            self.txt_sanitized.delete("1.0", "end")
            self.txt_sanitized.insert("1.0", report["sanitized_content"])

            if report["is_admissible"]:
                self.btn_ingest.state(["!disabled"])
            else:
                self.btn_ingest.state(["disabled"])
        except Exception as e:
            messagebox.showerror("Inspection Error", str(e))

    def ingest_porter(self):
        src = self.ent_porter_source.get().strip()
        if not src:
            return
        if messagebox.askyesno("Confirm Ingestion", "Ingest this rule into your environment? An atomic snapshot will be taken first."):
            success, msg = self.porter_bridge.stage_and_ingest(src)
            if success:
                messagebox.showinfo("Ingested Successfully", msg)
                self.refresh_status()
            else:
                messagebox.showerror("Ingestion Failed", msg)

    def check_upstream_async(self):
        q: queue.Queue = queue.Queue()

        def worker():
            try:
                results = self.upstream_bridge.check_repositories()
                q.put(results)
            except Exception as e:
                q.put(e)

        threading.Thread(target=worker, daemon=True).start()

        def poll():
            try:
                item = q.get_nowait()
                if isinstance(item, Exception):
                    messagebox.showerror("Upstream Check Error", str(item))
                else:
                    self._populate_upstream(item)
            except queue.Empty:
                self.root.after(100, poll)

        self.root.after(100, poll)

    def _populate_upstream(self, results):
        for row in self.tree_upstream.get_children():
            self.tree_upstream.delete(row)
        for r in results:
            self.tree_upstream.insert(
                "", "end",
                values=(r["name"], r["local_sha"] or "None", r["remote_sha"] or "None", r["status"], r["commit_message"]),
            )

    # --- Window & Tray Lifecycle ---
    def on_close_window(self):
        if self.var_minimize_to_tray.get() and hasattr(self, "tray_adapter") and self.tray_adapter.is_available:
            self.root.withdraw()
        else:
            self.quit_app()

    def show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def quit_app(self):
        if hasattr(self, "tray_adapter") and self.tray_adapter.is_available:
            self.tray_adapter.stop()
        self.root.destroy()


def launch_gui():
    root = tk.Tk()
    app = AntigravityGuardApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(launch_gui())
