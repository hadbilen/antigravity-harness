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
from guard.environment import AgentEnvironment, EnvironmentRegistry
from guard.integrity import FileIntegrityMonitor
from guard.lease import LeaseManager
from guard.notifier import GuardNotifier, NotificationSeverity
from guard.os_adapter import OSProtectionAdapter
from guard.porter_bridge import PorterBridge
from guard.provenance import RunProvenanceTracker
from guard.snapshot import SnapshotEngine
from guard.startup import StartupManager
from guard.test_boundary import TestBoundaryGuard
from guard.upstream import UpstreamAuditorBridge


def cmd_status(args: argparse.Namespace) -> int:
    adapter = OSProtectionAdapter()
    monitor = FileIntegrityMonitor()
    upstream = UpstreamAuditorBridge()
    registry = EnvironmentRegistry()

    is_locked = adapter.is_locked()
    report = monitor.verify()
    model_info = upstream.get_model_drift_status()
    matrix = registry.get_status_matrix()

    lock_symbol = "[LOCKED]" if is_locked else "[UNLOCKED / MAINTENANCE]"
    status_color = "PROTECTED" if is_locked and report.is_intact else "ACTION REQUIRED"

    print("=" * 64)
    print(f"       Antigravity Guard (agy-guard) v{__version__} - Status        ")
    print("=" * 64)
    print(f"Platform       : {adapter.get_platform_name()}")
    print(f"Target Directory: {adapter.target_dir}")
    print(f"Write Shield   : {lock_symbol}")
    print(f"Integrity (FIM): {report.summary()}")
    print(f"Active Model   : {model_info['active_model']}")
    print(f"Overall State  : {status_color}")
    print("-" * 64)
    print("Multi-Environment Governance Matrix:")
    for item in matrix:
        env_lock = "[LOCKED]" if item["is_locked"] else "[UNLOCKED]"
        print(f"  * {item['name']:<28} {env_lock:<10} ({item['policy']}, {item['file_count']} tracked)")
    print("=" * 64)
    return 0 if (is_locked and report.is_intact) else 1


def cmd_lock(args: argparse.Namespace) -> int:
    env_target = getattr(args, "env", None)
    all_target = getattr(args, "all", False)
    if env_target or all_target:
        registry = EnvironmentRegistry()
        success, msg = registry.lock(env_id=None if all_target else env_target)
        print(msg)
        return 0 if success else 1

    adapter = OSProtectionAdapter()
    success, msg = adapter.lock()
    print(f"[{'SUCCESS' if success else 'ERROR'}] {msg}")
    return 0 if success else 1


def cmd_unlock(args: argparse.Namespace) -> int:
    env_target = getattr(args, "env", None)
    all_target = getattr(args, "all", False)
    if env_target or all_target:
        registry = EnvironmentRegistry()
        success, msg = registry.unlock(env_id=None if all_target else env_target)
        print(msg)
        return 0 if success else 1

    adapter = OSProtectionAdapter()
    success, msg = adapter.unlock()
    print(f"[{'SUCCESS' if success else 'ERROR'}] {msg}")
    return 0 if success else 1


def cmd_verify(args: argparse.Namespace) -> int:
    env_target = getattr(args, "env", None)
    all_target = getattr(args, "all", False)
    if env_target or all_target:
        registry = EnvironmentRegistry()
        targets = registry.list_environments() if all_target else [registry.get_environment(env_target)]
        any_failed = False
        for env in targets:
            if not env:
                print(f"Error: Environment '{env_target}' not found.", file=sys.stderr)
                return 1
            paths = env.get_governance_paths(existing_only=True)
            mon = FileIntegrityMonitor(target_dir=env.get_root(), target_paths=paths)
            rep = mon.verify()
            print(f"[{env.name}] {rep.summary()}")
            if not rep.is_intact:
                any_failed = True
        return 1 if any_failed else 0

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
    print(f"       Antigravity Guard (agy-guard) v{__version__} - Doctor & Health       ")
    print("=" * 64)
    print(f"Platform       : {adapter.get_platform_name()}")
    print(f"Target Directory: {adapter.target_dir}")
    print(f"Write Shield   : {'[LOCKED / PROTECTED]' if is_locked else '[UNLOCKED / STALE EXPOSURE]'}")
    anchor_str = f"[ISOLATED] ({monitor.state_file})" if is_isolated else f"[LOCAL] ({monitor.state_file})"
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
        print("[OK] Environment is in optimal operational health. All invariants passing.")
        print("=" * 64)
        return 0

    print("Diagnostics:")
    for d in diagnostics:
        print(f"  [WARN] {d}")

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


def cmd_startup(args: argparse.Namespace) -> int:
    manager = StartupManager()
    action = getattr(args, "action", "status") or "status"

    if action == "enable":
        ok, msg = manager.enable()
        print(f"[{'SUCCESS' if ok else 'FAILED'}] {msg}")
        return 0 if ok else 1
    elif action == "disable":
        ok, msg = manager.disable()
        print(f"[{'SUCCESS' if ok else 'FAILED'}] {msg}")
        return 0 if ok else 1
    else:
        st = manager.status()
        print("=" * 64)
        print("   Antigravity Guard — Pre-Session Boot Sentinel Status   ")
        print("=" * 64)
        print(f"Platform       : {st['platform']}")
        print(f"Mechanism      : {st['mechanism']}")
        print(f"Service Path   : {st['target_path']}")
        print(f"Installed      : {'YES' if st['installed'] else 'NO'}")
        print(f"Active/Enabled : {'YES' if st['active'] else 'NO'}")
        print("=" * 64)
        return 0


def cmd_boot_check(args: argparse.Namespace) -> int:
    manager = StartupManager()
    ok, msg = manager.execute_boot_check()
    print(f"[BOOT-SENTINEL] {msg}")
    return 0 if ok else 1


def cmd_test_boundary(args: argparse.Namespace) -> int:
    guard = TestBoundaryGuard(workspace_dir=getattr(args, "dir", None))
    action = getattr(args, "action", "verify")

    if action == "snapshot":
        count, path = guard.snapshot(target_path=getattr(args, "output", None))
        print(f"[TEST-BOUNDARY] Baseline snapshot captured for {count} test & config files -> {path}")
        return 0

    elif action == "verify":
        mode = getattr(args, "mode", "bugfix") or "bugfix"
        report = guard.verify(mode=mode, snapshot_path=getattr(args, "snapshot", None))
        print("=" * 64)
        print("      Antigravity Guard — Test & Config Boundary Verification     ")
        print("=" * 64)
        print(f"Workspace      : {report.workspace_dir}")
        print(f"Mode           : {report.mode.upper()}")
        print(f"Tracked Files  : {report.total_files}")
        print(f"Status         : {report.summary()}")
        print("=" * 64)

        if report.violations:
            print("\n🚨 Violations Detected:")
            for v in report.violations:
                print(f"  ❌ {v}")
            if report.modified:
                print("\n  Modified Files:")
                for m in report.modified:
                    print(f"    ~ {m}")
            if report.fixture_modifications:
                print("\n  Altered Fixtures / Test Data:")
                for f in report.fixture_modifications:
                    print(f"    ! {f}")
            print("\n[BLOCKED] Delivery halted. Test or configuration mutation is prohibited.")
            print("=" * 64)
            return 1

        print("✅ [PASS] Test trust boundary is intact. No unauthorized test mutations.")
        print("=" * 64)
        return 0

    elif action == "run-reproducible":
        if not getattr(args, "cmd", None):
            print("Error: Specify test command using --cmd '<command>'")
            return 1
        passes = getattr(args, "passes", 2) or 2
        print(f"[REPRODUCIBILITY-GATE] Running command across {passes} isolated runs: {args.cmd}")
        success, msg, codes = guard.run_reproducible(command=args.cmd, passes=passes)
        print(f"[{'PASS' if success else 'FAIL'}] {msg} (Exit Codes: {codes})")
        return 0 if success else 1

    return 0


def cmd_provenance(args: argparse.Namespace) -> int:
    tracker = RunProvenanceTracker(workspace_dir=getattr(args, "dir", None))
    action = getattr(args, "action", "generate") or "generate"

    if action == "generate":
        mode = getattr(args, "mode", "bugfix") or "bugfix"
        test_cmd = getattr(args, "test_cmd", None)
        passes = getattr(args, "passes", 2) or 2
        manifest = tracker.generate_manifest(
            mode=mode,
            test_command=test_cmd,
            reproducibility_passes=passes,
        )
        print("=" * 64)
        print("        Antigravity Guard — Run Provenance Manifest Generated     ")
        print("=" * 64)
        print(manifest.to_markdown())
        print("=" * 64)
        print(f"Manifest written -> {tracker.output_file}")
        return 0

    elif action == "status":
        if not tracker.output_file.exists():
            print("No provenance manifest found. Run 'provenance generate' first.")
            return 1
        try:
            import json
            data = json.loads(tracker.output_file.read_text(encoding="utf-8"))
            print("=" * 64)
            print("         Antigravity Guard — Active Provenance Manifest          ")
            print("=" * 64)
            print(f"Timestamp       : {data.get('session_timestamp')}")
            print(f"Base Commit     : {data.get('git_base_commit')}")
            print(f"Boundary Status : {'IN TACT' if data.get('test_boundary_verified') else 'UNVERIFIED / VIOLATED'}")
            print(f"Reproducibility : {'VERIFIED' if data.get('reproducibility_verified') else 'UNVERIFIED'}")
            print(f"Modified Files  : {len(data.get('files_modified', []))}")
            print("=" * 64)
            return 0
        except Exception as e:
            print(f"Error reading provenance manifest: {e}")
            return 1

    return 0


def cmd_env(args: argparse.Namespace) -> int:
    registry = EnvironmentRegistry()
    action = getattr(args, "action", "list") or "list"

    if action == "list":
        matrix = registry.get_status_matrix()
        print("=" * 64)
        print("          Antigravity Guard — Registered Environments          ")
        print("=" * 64)
        for item in matrix:
            lock_str = "[LOCKED]" if item["is_locked"] else "[UNLOCKED]"
            print(f"ID       : {item['id']}")
            print(f"Name     : {item['name']}")
            print(f"Platform : {item['platform']}")
            print(f"Root     : {item['root']}")
            print(f"Policy   : {item['policy']}")
            print(f"Shield   : {lock_str}")
            print(f"Tracked  : {item['file_count']} files")
            print("-" * 64)
        return 0

    elif action == "detect":
        discovered = registry.discover_environments(register=not getattr(args, "dry_run", False))
        print(f"Discovered {len(discovered)} coding agent environment(s):")
        for env in discovered:
            paths = env.get_governance_paths(existing_only=True)
            print(f"  - {env.name} (id: {env.id}, platform: {env.platform_type}) -> {len(paths)} governance files")
        if not getattr(args, "dry_run", False):
            print(f"\n[SAVED] Environments registered to {registry.config_path}")
        return 0

    elif action == "add":
        name = getattr(args, "name", None)
        path = getattr(args, "path", None)
        if not name or not path:
            print("Error: Specify environment name and path to add.", file=sys.stderr)
            return 1
        env = AgentEnvironment(
            id=name.lower().replace(" ", "-"),
            name=name,
            platform_type=getattr(args, "type", "custom") or "custom",
            root_path=str(Path(path).resolve()),
            policy=getattr(args, "policy", "enforced") or "enforced",
        )
        registry.register_environment(env)
        print(f"[REGISTERED] Environment '{env.id}' added -> {env.root_path}")
        return 0

    elif action == "remove":
        name = getattr(args, "name", None)
        if not name:
            print("Error: Specify environment ID to remove.", file=sys.stderr)
            return 1
        if registry.unregister_environment(name):
            print(f"[REMOVED] Environment '{name}' removed from registry.")
            return 0
        print(f"Environment '{name}' not found.", file=sys.stderr)
        return 1

    elif action == "policy":
        name = getattr(args, "name", None)
        policy_val = getattr(args, "policy_val", None)
        if not name or not policy_val:
            print("Error: Specify environment ID and policy value (enforced/monitored/disabled).", file=sys.stderr)
            return 1
        try:
            if registry.set_policy(name, policy_val):
                print(f"[POLICY UPDATED] '{name}' policy set to '{policy_val}'")
                return 0
            print(f"Environment '{name}' not found.", file=sys.stderr)
            return 1
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    return 0


def cmd_request_unlock(args: argparse.Namespace) -> int:
    lease_manager = LeaseManager()
    success, msg, lease = lease_manager.request_unlock(
        env_id=getattr(args, "env", "antigravity") or "antigravity",
        reason=getattr(args, "reason", "Agent maintenance operation") or "Agent maintenance operation",
        duration_seconds=getattr(args, "duration", 60) or 60,
        interactive=not getattr(args, "non_interactive", False),
        auto_approve=getattr(args, "auto_approve", False),
    )
    print(f"[{'AUTHORIZED' if success else 'REJECTED'}] {msg}")
    return 0 if success else 1


def cmd_lock_complete(args: argparse.Namespace) -> int:
    lease_manager = LeaseManager()
    ok, msg = lease_manager.complete_lease(env_id=getattr(args, "env", None))
    print(f"[{'LOCKED' if ok else 'ERROR'}] {msg}")
    return 0 if ok else 1


def cmd_drift(args: argparse.Namespace) -> int:
    registry = EnvironmentRegistry()
    target_id = getattr(args, "env", None)
    targets = [registry.get_environment(target_id)] if target_id else registry.list_environments()
    any_drift = False

    print("=" * 64)
    print("        Antigravity Guard — Multi-Environment Drift Analysis     ")
    print("=" * 64)

    for env in targets:
        if not env:
            continue
        paths = env.get_governance_paths(existing_only=True)
        mon = FileIntegrityMonitor(target_dir=env.get_root(), target_paths=paths)
        report = mon.verify()

        if not report.is_intact:
            any_drift = True
            print(f"\n🚨 [DRIFT DETECTED] {env.name} ({env.id}):")
            if report.modified:
                print("   Modified governance files:")
                for f in report.modified:
                    print(f"     ~ {f}")
            if report.added:
                print("   Unauthorized added files:")
                for f in report.added:
                    print(f"     + {f}")
            if report.deleted:
                print("   Deleted governance files:")
                for f in report.deleted:
                    print(f"     - {f}")
        else:
            print(f"✅ [INTACT] {env.name} ({env.id}): {report.total_files} governance files verified.")

    print("=" * 64)
    return 1 if any_drift else 0


def cmd_self_audit(args: argparse.Namespace) -> int:
    from scripts.meta_audit import MetaAuditEngine
    engine = MetaAuditEngine()
    findings = engine.run_all_passes()
    criticals = [f for f in findings if f.severity == "CRITICAL"]

    if getattr(args, "json", False):
        import json
        print(json.dumps({
            "is_valid": len(criticals) == 0,
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }, indent=2))
        return 0 if len(criticals) == 0 else 1

    print("=" * 64)
    print("    Antigravity Guard — Autonomous Self-Audit & Meta-Check      ")
    print("=" * 64)
    for f in findings:
        prefix = "🚨 [CRITICAL]" if f.severity == "CRITICAL" else ("⚠️  [WARNING]" if f.severity == "WARNING" else "ℹ️  [INFO]")
        print(f"{prefix} {f.pass_name} -> {f.target}")
        print(f"   Message: {f.message}")
        print(f"   Fix    : {f.suggested_fix}\n")
    print("=" * 64)
    if criticals:
        print("❌ [FAIL] Critical self-audit violations detected.")
        return 1
    print("✅ [PASS] Harness self-consistency verified.")
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    from guard.gui import launch_gui
    return launch_gui()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agy-guard",
        description=f"Antigravity Guard v{__version__} - OS-Level Governance, Write Protection, & Staging Suite",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # status
    p_status = subparsers.add_parser("status", help="Show environment write protection and integrity status")
    p_status.set_defaults(func=cmd_status)

    # lock
    p_lock = subparsers.add_parser("lock", help="Lock environment with OS write protection")
    p_lock.add_argument("--env", "-e", help="Target environment ID (e.g. antigravity, claude, codex)")
    p_lock.add_argument("--all", "-a", action="store_true", help="Lock all registered environments")
    p_lock.set_defaults(func=cmd_lock)

    # unlock
    p_unlock = subparsers.add_parser("unlock", help="Unlock environment for maintenance")
    p_unlock.add_argument("--env", "-e", help="Target environment ID to unlock")
    p_unlock.add_argument("--all", "-a", action="store_true", help="Unlock all registered environments")
    p_unlock.set_defaults(func=cmd_unlock)

    # verify
    p_verify = subparsers.add_parser("verify", help="Run File Integrity Monitor (FIM) check")
    p_verify.add_argument("--env", "-e", help="Target environment ID to verify")
    p_verify.add_argument("--all", "-a", action="store_true", help="Verify all registered environments")
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

    # startup
    p_startup = subparsers.add_parser("startup", help="Manage Pre-Session Boot Sentinel startup registration")
    p_startup.add_argument("action", choices=["enable", "disable", "status"], default="status", nargs="?", help="Startup action")
    p_startup.set_defaults(func=cmd_startup)

    # boot-check (headless oneshot)
    p_boot = subparsers.add_parser("boot-check", help="Fast headless boot verification and lock enforcement")
    p_boot.set_defaults(func=cmd_boot_check)

    # gui
    p_gui = subparsers.add_parser("gui", help="Launch Antigravity Guard desktop interface")
    p_gui.set_defaults(func=cmd_gui)

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Run comprehensive environment health check & auto-heal")
    p_doc.add_argument("--fix", "--recover", action="store_true", dest="fix", help="Automatically recover stale locks and missing baselines")
    p_doc.set_defaults(func=cmd_doctor)

    # test-boundary
    p_tb = subparsers.add_parser("test-boundary", help="Guard test suites and configurations as an immutable trust boundary")
    p_tb.add_argument("action", choices=["snapshot", "verify", "run-reproducible"], help="Test boundary action")
    p_tb.add_argument("--mode", choices=["bugfix", "tdd"], default="bugfix", help="Verification mode (default: bugfix)")
    p_tb.add_argument("--dir", help="Target workspace root directory")
    p_tb.add_argument("--output", help="Snapshot output path")
    p_tb.add_argument("--snapshot", help="Custom snapshot path to verify against")
    p_tb.add_argument("--cmd", help="Target test command for run-reproducible")
    p_tb.add_argument("--passes", type=int, default=2, help="Number of reproducible passes required (default: 2)")
    p_tb.set_defaults(func=cmd_test_boundary)

    # provenance
    p_prov = subparsers.add_parser("provenance", help="Generate and inspect execution provenance and audit trail")
    p_prov.add_argument("action", choices=["generate", "status"], default="status", nargs="?", help="Provenance action")
    p_prov.add_argument("--mode", choices=["bugfix", "tdd"], default="bugfix", help="Operating mode for boundary check")
    p_prov.add_argument("--dir", help="Target workspace root directory")
    p_prov.add_argument("--test-cmd", help="Optional test command to check reproducibility")
    p_prov.add_argument("--passes", type=int, default=2, help="Reproducibility passes (default: 2)")
    p_prov.set_defaults(func=cmd_provenance)

    # env
    p_env = subparsers.add_parser("env", help="Manage multi-environment registration and policies")
    p_env.add_argument("action", choices=["list", "detect", "add", "remove", "policy"], default="list", nargs="?", help="Environment action")
    p_env.add_argument("--name", "-n", help="Environment ID or display name")
    p_env.add_argument("--path", "-p", help="Target root path for env add")
    p_env.add_argument("--type", "-t", choices=["antigravity", "claude", "codex", "cursor", "aider", "custom"], help="Platform type")
    p_env.add_argument("--policy", choices=["enforced", "monitored", "disabled"], help="Policy setting for env add")
    p_env.add_argument("--policy-val", choices=["enforced", "monitored", "disabled"], help="Policy setting for env policy")
    p_env.add_argument("--dry-run", action="store_true", help="Preview discovery without saving to registry")
    p_env.set_defaults(func=cmd_env)

    # request-unlock
    p_req = subparsers.add_parser("request-unlock", help="Request human-authorized temporary lease unlock for an agent")
    p_req.add_argument("--env", "-e", default="antigravity", help="Target environment ID to unlock")
    p_req.add_argument("--reason", "-r", default="Agent maintenance operation", help="Reason for requesting unlock")
    p_req.add_argument("--duration", "-d", type=int, default=60, help="Lease duration in seconds (default: 60)")
    p_req.add_argument("--non-interactive", action="store_true", help="Disallow interactive terminal prompt")
    p_req.add_argument("--auto-approve", action="store_true", help="Auto-approve lease request (testing/automated CI)")
    p_req.set_defaults(func=cmd_request_unlock)

    # lock-complete
    p_lc = subparsers.add_parser("lock-complete", help="Signal completion of maintenance lease and immediately re-lock")
    p_lc.add_argument("--env", "-e", help="Target environment ID (optional)")
    p_lc.set_defaults(func=cmd_lock_complete)

    # drift
    p_drift = subparsers.add_parser("drift", help="Analyze and display drift across multi-environment baselines")
    p_drift.add_argument("--env", "-e", help="Target environment ID to inspect (defaults to all)")
    p_drift.set_defaults(func=cmd_drift)

    # self-audit
    p_sa = subparsers.add_parser("self-audit", help="Run harness meta-consistency and schema self-audit")
    p_sa.add_argument("--json", action="store_true", help="Output findings as structured JSON")
    p_sa.set_defaults(func=cmd_self_audit)

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
