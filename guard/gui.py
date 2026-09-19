"""
guard/gui.py — High-Contrast Desktop Interface for Antigravity Guard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly Python standard library tkinter/ttk.
Strictly adheres to DESIGN.md (ENERGY 2 / RHYTHM 2 / Dark Zinc Palette).
"""

from __future__ import annotations

import os
import queue
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
from guard.upstream import UpstreamAuditorBridge

# Design Tokens from DESIGN.md (Dark Theme)
BG_CANVAS = "#09090B"
BG_SURFACE = "#18181B"
BG_SURFACE_ALT = "#27272A"
BORDER_COLOR = "#3F3F46"
TEXT_PRIMARY = "#F4F4F5"
TEXT_MUTED = "#A1A1AA"
ACCENT_BLUE = "#3B82F6"
ACCENT_GREEN = "#22C55E"
ACCENT_AMBER = "#F59E0B"
ACCENT_RED = "#EF4444"


class AntigravityGuardApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"Antigravity Guard v{__version__}")
        self.root.geometry("980x680")
        self.root.minsize(860, 580)
        self.root.configure(bg=BG_CANVAS)

        self.adapter = OSProtectionAdapter()
        self.monitor = FileIntegrityMonitor()
        self.snapshot_engine = SnapshotEngine()
        self.porter_bridge = PorterBridge()
        self.upstream_bridge = UpstreamAuditorBridge()

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
        style.configure("Header.TLabel", background=BG_SURFACE, foreground=TEXT_PRIMARY, font=("Sans-serif", 14, "bold"))

        style.configure("Primary.TButton", background=ACCENT_BLUE, foreground="#FFFFFF", font=("Sans-serif", 10, "bold"), borderwidth=0, padding=6)
        style.map("Primary.TButton", background=[("active", "#2563EB")])

        style.configure("Action.TButton", background=BG_SURFACE_ALT, foreground=TEXT_PRIMARY, font=("Sans-serif", 9), borderwidth=1, padding=5)
        style.map("Action.TButton", background=[("active", "#3F3F46")])

        style.configure("Danger.TButton", background=ACCENT_RED, foreground="#FFFFFF", font=("Sans-serif", 9, "bold"), borderwidth=0, padding=5)
        style.map("Danger.TButton", background=[("active", "#DC2626")])

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

        self.tab_integrity = ttk.Frame(self.notebook, padding=12)
        self.tab_porter = ttk.Frame(self.notebook, padding=12)
        self.tab_upstream = ttk.Frame(self.notebook, padding=12)
        self.tab_settings = ttk.Frame(self.notebook, padding=12)

        self.notebook.add(self.tab_integrity, text="Shield & Integrity")
        self.notebook.add(self.tab_porter, text="Porter Staging Gate")
        self.notebook.add(self.tab_upstream, text="Upstream Auditor")
        self.notebook.add(self.tab_settings, text="Snapshots & Audit Log")

        self._build_tab_integrity()
        self._build_tab_porter()
        self._build_tab_upstream()
        self._build_tab_settings()

    # --- TAB 1: Integrity & Shield ---
    def _build_tab_integrity(self):
        card = ttk.Frame(self.tab_integrity, style="Card.TFrame", padding=16)
        card.pack(fill="x", pady=(0, 10))

        lbl_sec = ttk.Label(card, text="Cryptographic File Integrity Monitor (SHA-256)", style="Header.TLabel")
        lbl_sec.pack(anchor="w")

        self.lbl_fim_summary = ttk.Label(card, text="Scanning file tree...", style="Muted.TLabel")
        self.lbl_fim_summary.pack(anchor="w", pady=(4, 12))

        btn_row = ttk.Frame(card, style="Card.TFrame")
        btn_row.pack(fill="x")

        ttk.Button(btn_row, text="Verify Integrity", style="Primary.TButton", command=self.verify_integrity).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Update Baseline", style="Action.TButton", command=self.rebaseline).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Create Snapshot", style="Action.TButton", command=self.create_snapshot).pack(side="left")

        # Treeview for modified/drift files
        tree_frame = ttk.Frame(self.tab_integrity, style="Card.TFrame", padding=12)
        tree_frame.pack(fill="both", expand=True)

        ttk.Label(tree_frame, text="File System Status Matrix:", style="Header.TLabel").pack(anchor="w", pady=(0, 6))

        columns = ("status", "file")
        self.tree_fim = ttk.Treeview(tree_frame, columns=columns, show="headings", height=12)
        self.tree_fim.heading("status", text="Status")
        self.tree_fim.heading("file", text="Relative File Path")
        self.tree_fim.column("status", width=140, anchor="w")
        self.tree_fim.column("file", width=700, anchor="w")
        self.tree_fim.pack(fill="both", expand=True)

    # --- TAB 2: Porter Staging Gate ---
    def _build_tab_porter(self):
        top_bar = ttk.Frame(self.tab_porter, style="Card.TFrame", padding=12)
        top_bar.pack(fill="x", pady=(0, 10))

        ttk.Label(top_bar, text="Source Path or URL:", style="Card.TLabel").pack(side="left", padx=(0, 8))
        self.ent_porter_source = tk.Entry(top_bar, bg=BG_SURFACE_ALT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief="flat", font=("Sans-serif", 10))
        self.ent_porter_source.pack(side="left", fill="x", expand=True, padx=(0, 8), ipady=4)

        ttk.Button(top_bar, text="Browse...", style="Action.TButton", command=self._browse_porter_file).pack(side="left", padx=(0, 8))
        ttk.Button(top_bar, text="Inspect Gate", style="Primary.TButton", command=self.inspect_porter).pack(side="left")

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

        model_info = self.upstream_bridge.get_model_drift_status()
        ttk.Label(header_card, text=f"Active Model: {model_info['active_model']}", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header_card, text="Tracking 7 community repositories & Antigravity runtime (Zero LLM token cost)", style="Muted.TLabel").pack(anchor="w", pady=(2, 8))

        ttk.Button(header_card, text="Check Repositories Now", style="Primary.TButton", command=self.check_upstream_async).pack(anchor="w")

        # Repos Table
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
        snap_frame = ttk.Frame(self.tab_settings, style="Card.TFrame", padding=12)
        snap_frame.pack(fill="both", expand=True)

        ttk.Label(snap_frame, text="Recorded Configuration Snapshots", style="Header.TLabel").pack(anchor="w")
        ttk.Label(snap_frame, text="One-click atomic rollback points created before rule imports or edits.", style="Muted.TLabel").pack(anchor="w", pady=(2, 8))

        cols = ("id", "label", "date")
        self.tree_snaps = ttk.Treeview(snap_frame, columns=cols, show="headings", height=8)
        self.tree_snaps.heading("id", text="Snapshot ID")
        self.tree_snaps.heading("label", text="Description")
        self.tree_snaps.heading("date", text="Created At (UTC)")
        self.tree_snaps.column("id", width=220)
        self.tree_snaps.column("label", width=340)
        self.tree_snaps.column("date", width=240)
        self.tree_snaps.pack(fill="both", expand=True, pady=(0, 8))

        btn_row = ttk.Frame(snap_frame, style="Card.TFrame")
        btn_row.pack(fill="x")

        ttk.Button(btn_row, text="Restore Selected Snapshot", style="Danger.TButton", command=self.restore_snapshot).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Refresh List", style="Action.TButton", command=self.refresh_snapshots).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Prune Older Snapshots", style="Action.TButton", command=self.prune_snapshots).pack(side="left")

    # --- Operational Actions ---
    def refresh_status(self):
        is_locked = self.adapter.is_locked()
        if is_locked:
            self.badge_status.config(text="🔒 PROTECTED", bg=ACCENT_GREEN, fg="#09090B")
            self.btn_toggle_lock.config(text="Unlock for Maintenance")
        else:
            self.badge_status.config(text="🔓 UNLOCKED", bg=ACCENT_AMBER, fg="#000000")
            self.btn_toggle_lock.config(text="Lock Shield Now")

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

    def restore_snapshot(self):
        selected = self.tree_snaps.selection()
        if not selected:
            messagebox.showwarning("Select Snapshot", "Please select a snapshot to restore.")
            return
        item = self.tree_snaps.item(selected[0])
        snap_id = item["values"][0]
        if messagebox.askyesno("Confirm Rollback", f"Restore environment to snapshot '{snap_id}'? Current state will be backed up."):
            self.adapter.unlock()
            success, msg = self.snapshot_engine.restore_snapshot(snap_id)
            self.adapter.lock()
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


def launch_gui():
    root = tk.Tk()
    app = AntigravityGuardApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(launch_gui())
