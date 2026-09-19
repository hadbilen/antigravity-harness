"""
guard/cli.py — Ergonomic Command-Line Interface for Antigravity Guard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from guard import __version__
from guard.integrity import FileIntegrityMonitor
from guard.os_adapter import OSProtectionAdapter
from guard.porter_bridge import PorterBridge
from guard.snapshot import SnapshotEngine
from guard.upstream import UpstreamAuditorBridge


def cmd_status(args: argparse.Namespace) -> int:
    adapter = OSProtectionAdapter()
    monitor = FileIntegrityMonitor()
    upstream = UpstreamAuditorBridge()

    is_locked = adapter.is_locked()
    report = monitor.verify()
    model_info = upstream.get_model_drift_status()

    lock_symbol = "🔒 [LOCKED]" if is_locked else "🔓 [UNLOCKED / MAINTENANCE]"
    status_color = "PROTECTED" if is_locked and report.is_intact else "ACTION REQUIRED"

    print("=" * 64)
    print(f"       Antigravity Guard (agy-guard) v{__version__} — Status        ")
    print("=" * 64)
    print(f"Platform       : {adapter.get_platform_name()}")
    print(f"Target Directory: {adapter.target_dir}")
    print(f"Write Shield   : {lock_symbol}")
    print(f"Integrity (FIM): {report.summary()}")
    print(f"Active Model   : {model_info['active_model']}")
    print(f"Overall State  : {status_color}")
    print("=" * 64)
    return 0 if (is_locked and report.is_intact) else 1


def cmd_lock(args: argparse.Namespace) -> int:
    adapter = OSProtectionAdapter()
    success, msg = adapter.lock()
    print(f"[{'SUCCESS' if success else 'ERROR'}] {msg}")
    return 0 if success else 1


def cmd_unlock(args: argparse.Namespace) -> int:
    adapter = OSProtectionAdapter()
    success, msg = adapter.unlock()
    print(f"[{'SUCCESS' if success else 'ERROR'}] {msg}")
    return 0 if success else 1


def cmd_verify(args: argparse.Namespace) -> int:
    monitor = FileIntegrityMonitor()
    report = monitor.verify()
    print(report.summary())
    if report.modified:
        print("\nModified Files:")
        for f in report.modified:
            print(f"  ~ {f}")
    if report.added:
        print("\nUnauthorized Added Files:")
        for f in report.added:
            print(f"  + {f}")
    if report.deleted:
        print("\nDeleted Files:")
        for f in report.deleted:
            print(f"  - {f}")
    return 0 if report.is_intact else 1


def cmd_rebaseline(args: argparse.Namespace) -> int:
    monitor = FileIntegrityMonitor()
    count, path = monitor.save_baseline()
    print(f"[REBASELINED] Established baseline for {count} files -> {path}")
    return 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    engine = SnapshotEngine()
    if args.action == "create":
        snap_id, dest = engine.create_snapshot(label=args.label)
        print(f"[CREATED] Snapshot '{snap_id}' saved to {dest.name}")
        return 0
    elif args.action == "list":
        snaps = engine.list_snapshots()
        if not snaps:
            print("No snapshots recorded.")
            return 0
        print(f"Recorded Snapshots ({len(snaps)}):")
        for s in snaps:
            print(f"  - {s.get('id')}: {s.get('label')} ({s.get('created_at')})")
        return 0
    elif args.action == "restore":
        if not args.id:
            print("Error: Specify snapshot ID to restore.")
            return 1
        success, msg = engine.restore_snapshot(args.id)
        print(f"[{'SUCCESS' if success else 'ERROR'}] {msg}")
        return 0 if success else 1
    elif args.action == "prune":
        count = engine.prune_snapshots(keep=args.keep or 5)
        print(f"[PRUNED] Removed {count} older snapshots.")
        return 0
    return 0


def cmd_porter(args: argparse.Namespace) -> int:
    bridge = PorterBridge()
    if args.action == "inspect":
        report = bridge.inspect_source(args.source)
        print("=" * 64)
        print(f" Porter Pre-Flight Inspection: {report['name']} ({report['target_type']})")
        print("=" * 64)
        print(f"Constitutional Score : {report['alignment_score']}/100")
        print(f"Adaptability Score   : {report['adaptability_score']}/100")
        print(f"Admissible           : {'YES' if report['is_admissible'] else 'NO'}")
        if report["violations"]:
            print("\nViolations:")
            for v in report["violations"]:
                print(f"  [X] {v}")
        if report["recommendations"]:
            print("\nRecommendations:")
            for r in report["recommendations"]:
                print(f"  - {r}")
        print("=" * 64)
        return 0 if report["is_admissible"] else 1

    elif args.action == "stage":
        success, msg = bridge.stage_and_ingest(args.source, target_name=args.name, force=args.force)
        print(f"[{'SUCCESS' if success else 'REJECTED'}] {msg}")
        return 0 if success else 1
    return 0


def cmd_upstream(args: argparse.Namespace) -> int:
    bridge = UpstreamAuditorBridge()
    if args.action in ("check", "status"):
        print("Checking tracked repositories (zero LLM token cost)...")
        results = bridge.check_repositories()
        print(f"\nTracked Repositories Status ({len(results)}):")
        print(f"{'Repository':<24} {'Local':<10} {'Remote':<10} {'Status':<18}")
        print("-" * 64)
        for r in results:
            print(f"{r['name']:<24} {r['local_sha'] or 'None':<10} {r['remote_sha'] or 'None':<10} {r['status']:<18}")
        return 0
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    adapter = OSProtectionAdapter()
    monitor = FileIntegrityMonitor()
    engine = SnapshotEngine()
    upstream = UpstreamAuditorBridge()

    is_locked = adapter.is_locked()
    report = monitor.verify()
    model_info = upstream.get_model_drift_status()
    snapshots = engine.list_snapshots()
    is_isolated = monitor.is_isolated

    print("=" * 64)
    print(f"       Antigravity Guard (agy-guard) v{__version__} — Doctor & Health       ")
    print("=" * 64)
    print(f"Platform       : {adapter.get_platform_name()}")
    print(f"Target Directory: {adapter.target_dir}")
    print(f"Write Shield   : {'🔒 [LOCKED / PROTECTED]' if is_locked else '🔓 [UNLOCKED / STALE EXPOSURE]'}")
    anchor_str = f"🛡️  ISOLATED ({monitor.state_file})" if is_isolated else f"📁 LOCAL ({monitor.state_file})"
    print(f"Trust Anchor   : {anchor_str}")
    print(f"Integrity (FIM): {report.summary()}")
    print(f"Snapshots      : {len(snapshots)} snapshots recorded")
    print(f"Active Model   : {model_info['active_model']}")
    print("-" * 64)

    diagnostics = []
    if not is_locked:
        diagnostics.append("Environment is UNLOCKED (vulnerable to rogue process or agent modification).")
    if not report.is_intact:
        diagnostics.append(f"Integrity drift detected ({len(report.modified)} mod, {len(report.added)} add, {len(report.deleted)} del).")
    if not is_isolated:
        diagnostics.append("Trust anchor is stored inside target directory; consider setting ANTIGRAVITY_INTEGRITY_FILE.")

    if not diagnostics:
        print("✅ Environment is in optimal operational health. All invariants passing.")
        print("=" * 64)
        return 0

    print("Diagnostics:")
    for d in diagnostics:
        print(f"  ⚠️  {d}")

    if getattr(args, "fix", False) or getattr(args, "recover", False):
        print("\n[Auto-Healing]")
        if not is_locked:
            rec_ok, rec_msg = adapter.recover_stale_lock()
            print(f"  - OS Write Shield: {rec_msg}")
        if not monitor.state_file.exists():
            cnt, pth = monitor.save_baseline()
            print(f"  - Baseline established for {cnt} files -> {pth}")
        print("Doctor auto-healing routine completed.")

    print("=" * 64)
    return 0 if (adapter.is_locked() and monitor.verify().is_intact) else 1


def cmd_gui(args: argparse.Namespace) -> int:
    from guard.gui import launch_gui
    return launch_gui()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agy-guard",
        description=f"Antigravity Guard v{__version__} — OS-Level Governance, Write Protection, & Staging Suite",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # status
    p_status = subparsers.add_parser("status", help="Show environment write protection and integrity status")
    p_status.set_defaults(func=cmd_status)

    # lock
    p_lock = subparsers.add_parser("lock", help="Lock environment with OS write protection")
    p_lock.set_defaults(func=cmd_lock)

    # unlock
    p_unlock = subparsers.add_parser("unlock", help="Unlock environment for maintenance")
    p_unlock.set_defaults(func=cmd_unlock)

    # verify
    p_verify = subparsers.add_parser("verify", help="Run File Integrity Monitor (FIM) check")
    p_verify.set_defaults(func=cmd_verify)

    # rebaseline
    p_rebaseline = subparsers.add_parser("rebaseline", help="Update trusted SHA-256 integrity baseline")
    p_rebaseline.set_defaults(func=cmd_rebaseline)

    # snapshot
    p_snap = subparsers.add_parser("snapshot", help="Manage lightweight configuration snapshots")
    p_snap.add_argument("action", choices=["create", "list", "restore", "prune"], help="Snapshot action")
    p_snap.add_argument("--label", "-l", help="Label for snapshot create")
    p_snap.add_argument("--id", help="Snapshot ID for restore")
    p_snap.add_argument("--keep", type=int, default=5, help="Number of snapshots to retain during prune")
    p_snap.set_defaults(func=cmd_snapshot)

    # porter
    p_porter = subparsers.add_parser("porter", help="Run Porter inspection and safe staging gate")
    p_porter.add_argument("action", choices=["inspect", "stage"], help="Porter action")
    p_porter.add_argument("source", help="Path to rule file or HTTP(S) URL")
    p_porter.add_argument("--name", "-n", help="Override destination target name")
    p_porter.add_argument("--force", "-f", action="store_true", help="Force ingestion ignoring warnings")
    p_porter.set_defaults(func=cmd_porter)

    # upstream
    p_up = subparsers.add_parser("upstream", help="Check upstream repositories and active model")
    p_up.add_argument("action", choices=["check", "status"], default="check", nargs="?", help="Upstream action")
    p_up.set_defaults(func=cmd_upstream)

    # gui
    p_gui = subparsers.add_parser("gui", help="Launch Antigravity Guard desktop interface")
    p_gui.set_defaults(func=cmd_gui)

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Run comprehensive environment health check & auto-heal")
    p_doc.add_argument("--fix", "--recover", action="store_true", dest="fix", help="Automatically recover stale locks and missing baselines")
    p_doc.set_defaults(func=cmd_doctor)

    args = parser.parse_args(argv)
    if not args.command:
        # Default behavior: If terminal is interactive with DISPLAY, launch GUI, otherwise show status
        if sys.stdout.isatty() and len(sys.argv) == 1:
            try:
                import os
                if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
                    return cmd_gui(args)
            except Exception:
                pass
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
