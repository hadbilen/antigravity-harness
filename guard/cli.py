"""
guard/cli.py — Command-Line Interface for Antigravity Guard
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Administration commands that weaken protection (unlock, rebaseline, snapshot restore,
startup disable, porter stage, test-boundary re-snapshot) require a human to confirm
in an interactive terminal. They exit with code 3 when that confirmation is missing.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

from guard import __version__
from guard.approval import refusal_message, request_approval
from guard.environment import (
    VALID_POLICIES,
    AgentEnvironment,
    EnvironmentRegistry,
    RegistryError,
)
from guard.integrity import FileIntegrityMonitor, IntegrityReport
from guard.lease import MAX_LEASE_SECONDS, MIN_LEASE_SECONDS, LeaseManager
from guard.notifier import load_settings, save_settings
from guard.paths import config_dir, state_dir
from guard.porter_bridge import PorterBridge
from guard.provenance import RunProvenanceTracker
from guard.snapshot import SnapshotEngine
from guard.startup import StartupManager
from guard.test_boundary import TestBoundaryGuard
from guard.upstream import UpstreamAuditorBridge

EXIT_APPROVAL_REQUIRED = 3


# ----------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------
def _registry(args: Optional[argparse.Namespace] = None) -> EnvironmentRegistry:
    path = getattr(args, "registry", None) if args is not None else None
    return EnvironmentRegistry(config_path=Path(path) if path else None)


def _resolve(registry: EnvironmentRegistry, env_id: Optional[str]) -> Tuple[Optional[AgentEnvironment], str]:
    return registry.resolve_environment(env_id or "antigravity")


def _monitor(env: AgentEnvironment, registry: EnvironmentRegistry) -> FileIntegrityMonitor:
    return FileIntegrityMonitor.for_environment(env, os_adapter=registry.os_adapter)


def _refuse(action: str) -> int:
    print(f"[APPROVAL REQUIRED] {refusal_message(action)}", file=sys.stderr)
    return EXIT_APPROVAL_REQUIRED


def _print_report_details(report: IntegrityReport, indent: str = "") -> None:
    if report.baseline_status != "ok":
        for note in report.notes:
            print(f"{indent}Note: {note}")
        return
    for title, items, mark in (
        ("Modified Files", report.modified, "~"),
        ("Unauthorized Added Files", report.added, "+"),
        ("Deleted Files", report.deleted, "-"),
        ("Unreadable Files", report.unreadable, "!"),
    ):
        if items:
            print(f"\n{indent}{title}:")
            for f in items:
                print(f"{indent}  {mark} {f}")
    for note in report.notes:
        print(f"{indent}Note: {note}")


def _print_issues(issues: List[str], limit: int = 6) -> None:
    for issue in issues[:limit]:
        print(f"    - {issue}")
    if len(issues) > limit:
        print(f"    ... and {len(issues) - limit} more")


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------
def cmd_status(args: argparse.Namespace) -> int:
    registry = _registry(args)
    env, err = _resolve(registry, getattr(args, "env", None))
    if not env:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    issues = registry.protection_issues(env) if env.policy == "enforced" else ["policy is not 'enforced'"]
    monitor = _monitor(env, registry)
    report = monitor.verify()
    model_info = UpstreamAuditorBridge().get_model_drift_status()
    leases = LeaseManager(registry=registry).list_leases()
    protected = not issues and report.is_intact

    print("=" * 64)
    print(f"       Antigravity Guard (agy-guard) v{__version__} - Status        ")
    print("=" * 64)
    print(f"Platform       : {registry.os_adapter.get_platform_name()}")
    print(f"Protection     : {registry.os_adapter.protection_kind()}")
    print(f"Environment    : {env.name} ({env.id}) -> {env.get_root()}")
    if issues:
        print(f"Write Shield   : [UNPROTECTED] {len(issues)} issue(s):")
        _print_issues(issues)
    else:
        print("Write Shield   : [LOCKED] all governance entries write-protected")
    print(f"Integrity (FIM): {report.summary()}")
    location = "[ISOLATED]" if monitor.is_isolated else "[IN TARGET]"
    if not monitor.state_file.exists():
        location = "[MISSING]"
    print(f"Baseline       : {location} {monitor.state_file}")
    if leases:
        for lease in leases:
            print(f"Active Lease   : {lease.env_id} ({lease.state}, {int(lease.remaining_seconds)}s left, id {lease.lease_id})")
    print(f"Active Model   : {model_info['active_model']}")
    print(f"Overall State  : {'PROTECTED' if protected else 'ACTION REQUIRED'}")
    print("-" * 64)
    print("Multi-Environment Governance Matrix:")
    for item in registry.get_status_matrix():
        env_lock = "[LOCKED]" if item["is_locked"] else "[UNLOCKED]"
        print(f"  * {item['name']:<30} {env_lock:<10} ({item['policy']}, {item['file_count']} seams)")
    print("=" * 64)
    return 0 if protected else 1


def cmd_lock(args: argparse.Namespace) -> int:
    registry = _registry(args)
    target = None if getattr(args, "all", False) else (getattr(args, "env", None) or "antigravity")
    success, msg = registry.lock(env_id=target)
    print(f"[{'LOCKED' if success else 'ERROR'}] {msg}")
    return 0 if success else 1


def cmd_unlock(args: argparse.Namespace) -> int:
    registry = _registry(args)
    target = None if getattr(args, "all", False) else (getattr(args, "env", None) or "antigravity")
    if target:
        env, err = registry.resolve_environment(target)
        if not env:
            print(f"Error: {err}", file=sys.stderr)
            return 1
        details = [f"{env.name}: {len(env.get_governance_paths(existing_only=True))} governance entries"]
    else:
        details = [e.name for e in registry.list_environments()]
    details.append("Prefer 'agy-guard request-unlock' for a time-bounded window with automatic relock.")
    if not request_approval("unlock", "Remove write protection WITHOUT an automatic relock?", details):
        return _refuse("unlock")
    success, msg = registry.unlock(env_id=target)
    print(f"[{'UNLOCKED' if success else 'ERROR'}] {msg}")
    if success:
        print("Remember to run 'agy-guard lock' when maintenance is finished.")
    return 0 if success else 1


def cmd_verify(args: argparse.Namespace) -> int:
    registry = _registry(args)
    if getattr(args, "all", False):
        targets = registry.list_environments()
    else:
        env, err = _resolve(registry, getattr(args, "env", None))
        if not env:
            print(f"Error: {err}", file=sys.stderr)
            return 1
        targets = [env]
    any_failed = False
    for env in targets:
        report = _monitor(env, registry).verify()
        print(f"[{env.name}] {report.summary()}")
        _print_report_details(report, indent="  ")
        any_failed = any_failed or not report.is_intact
    return 1 if any_failed else 0


def cmd_rebaseline(args: argparse.Namespace) -> int:
    registry = _registry(args)
    env, err = _resolve(registry, getattr(args, "env", None))
    if not env:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    monitor = _monitor(env, registry)
    report = monitor.verify()
    details = [report.summary()]
    details += [f"~ {f}" for f in report.modified[:10]] + [f"+ {f}" for f in report.added[:10]] + [f"- {f}" for f in report.deleted[:10]]
    if not request_approval("rebaseline", f"Accept the CURRENT state of {env.name} as trusted?", details):
        return _refuse("rebaseline")
    count, path = monitor.save_baseline()
    print(f"[REBASELINED] Established baseline for {count} entries -> {path} (previous baseline archived)")
    return 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    registry = _registry(args)
    env, err = _resolve(registry, getattr(args, "env", None))
    if not env:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    engine = SnapshotEngine.for_environment(env, registry, integrity_monitor=_monitor(env, registry))
    if args.action == "create":
        snap_id, dest = engine.create_snapshot(label=args.label)
        print(f"[CREATED] Snapshot '{snap_id}' saved to {dest}")
        return 0
    if args.action == "list":
        snaps = engine.list_snapshots()
        if not snaps:
            print("No snapshots recorded.")
            return 0
        print(f"Recorded Snapshots ({len(snaps)}):")
        for s in snaps:
            print(f"  - {s.get('id')}: {s.get('label')} [{s.get('kind')}] ({s.get('created_at')})")
        return 0
    if args.action == "restore":
        if not args.id:
            print("Error: Specify snapshot ID to restore (--id).")
            return 1
        if not request_approval("snapshot restore", f"Replace the governance scope of {env.name} with snapshot {args.id}?",
                                ["A pre-restore backup is taken first", "The integrity baseline is re-established afterwards"]):
            return _refuse("snapshot restore")
        success, msg = engine.restore_snapshot(args.id)
        print(f"[{'SUCCESS' if success else 'ERROR'}] {msg}")
        return 0 if success else 1
    if args.action == "prune":
        count = engine.prune_snapshots(keep=args.keep or 5)
        print(f"[PRUNED] Removed {count} older snapshots (kept {args.keep or 5} per kind).")
        return 0
    return 0


def cmd_porter(args: argparse.Namespace) -> int:
    bridge = PorterBridge()
    report = bridge.inspect_source(args.source)
    print("=" * 64)
    print(f" Porter Pre-Flight Inspection: {report['name']} ({report['target_type']})")
    print("=" * 64)
    print(f"Constitutional Score : {report['alignment_score']}/100")
    print(f"Adaptability Score   : {report['adaptability_score']}/100")
    print(f"Admissible           : {'YES' if report['is_admissible'] else 'NO'}")
    print(f"Content SHA-256      : {report['content_sha256']}")
    if report["violations"]:
        print("\nViolations:")
        for v in report["violations"]:
            print(f"  [X] {v}")
    if report["recommendations"]:
        print("\nRecommendations:")
        for r in report["recommendations"]:
            print(f"  - {r}")
    print("=" * 64)
    if args.action == "inspect":
        return 0 if report["is_admissible"] else 1

    expected = getattr(args, "expect_sha256", None) or report["content_sha256"]
    summary = f"Write '{report['name']}' ({report['target_type']}) into the protected governance tree?"
    details = [f"content sha256 {expected}"]
    if args.force and not report["is_admissible"]:
        details.append("FORCE: constitutional violations above will be ingested")
    if not request_approval("porter stage", summary, details):
        return _refuse("porter stage")
    success, msg = bridge.stage_and_ingest(args.source, target_name=args.name, force=args.force, expected_sha256=expected)
    print(f"[{'SUCCESS' if success else 'REJECTED'}] {msg}")
    return 0 if success else 1


def cmd_upstream(args: argparse.Namespace) -> int:
    bridge = UpstreamAuditorBridge()
    print("Checking tracked repositories (zero LLM token cost)...")
    results = bridge.check_repositories()
    print(f"\nTracked Repositories Status ({len(results)}):")
    print(f"{'Repository':<24} {'Local':<10} {'Remote':<10} {'Status':<18}")
    print("-" * 64)
    for r in results:
        print(f"{r['name']:<24} {r['local_sha'] or 'None':<10} {r['remote_sha'] or 'None':<10} {r['status']:<18}")
    return 0


def _world_writable_ancestors(path: Path, depth: int = 3) -> List[str]:
    found = []
    current = Path(os.path.realpath(path))
    for _ in range(depth + 1):
        try:
            mode = os.stat(current).st_mode
            # Sticky world-writable dirs (/tmp) do not let other users replace our entries.
            if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
                found.append(str(current))
        except OSError:
            break
        if current.parent == current:
            break
        current = current.parent
    return found


def _grant_statistics(config_json: Path) -> Optional[dict]:
    """Counts risky permission grants WITHOUT printing their contents."""
    try:
        data = json.loads(config_json.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    allow = (((data.get("userSettings") or {}).get("globalPermissionGrants") or {}).get("allow")) or []
    entries = [e if isinstance(e, str) else json.dumps(e) for e in allow]
    governance_markers = (".gemini/config", ".gemini/antigravity-harness")
    return {
        "total": len(entries),
        "governance_writes": sum(1 for e in entries if e.startswith("write_file") and any(m in e for m in governance_markers)),
        "secret_like": sum(1 for e in entries if re.search(r"(token|api[_-]?key|secret|password)=", e, re.I)),
        "unsandboxed": sum(1 for e in entries if e.startswith("unsandboxed")),
        "oversized": sum(1 for e in entries if len(e) > 500),
    }


def cmd_doctor(args: argparse.Namespace) -> int:
    registry = _registry(args)
    env, err = _resolve(registry, getattr(args, "env", None))
    if not env:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    root = env.get_root()
    monitor = _monitor(env, registry)
    issues = registry.protection_issues(env)
    report = monitor.verify()
    warnings: List[str] = []
    infos: List[str] = []

    if issues:
        warnings.append(f"Governance scope is not fully write-protected ({len(issues)} issue(s)); first: {issues[0]}")
    if not report.is_intact:
        warnings.append(f"Integrity: {report.summary()}")
    if not monitor.is_isolated:
        warnings.append(f"Baseline is stored inside the protected tree ({monitor.state_file}).")
    legacy_baseline = root / ".guard_integrity.json"
    if legacy_baseline.exists():
        warnings.append(f"Legacy baseline {legacy_baseline} is no longer used; remove it after 'agy-guard rebaseline'.")
    legacy_snaps = root / ".guard_snapshots"
    if legacy_snaps.exists():
        warnings.append(
            f"Legacy snapshots in {legacy_snaps} may contain copies of config.json (permission grants, tokens). "
            f"Review and delete them manually."
        )
    moved_legacy = state_dir() / "legacy"
    if moved_legacy.is_dir() and any(moved_legacy.iterdir()):
        warnings.append(
            f"Legacy Guard data moved out of the config tree by the installer is kept in {moved_legacy}; "
            f"it may contain copies of config.json (tokens). Delete it once reviewed."
        )
    backups = sorted(p.name for p in root.glob("backup_*"))
    if backups:
        warnings.append(f"Installer backups inside the config tree: {', '.join(backups)} (move them out).")
    for p in env.get_governance_paths(existing_only=True):
        if os.path.islink(p):
            warnings.append(f"{p.name} is a symlink (symlink installs cannot be locked); reinstall with 'python3 install.py'.")
            break
    writable_sources = set()
    for p in env.get_governance_paths(existing_only=True):
        writable_sources.update(_world_writable_ancestors(p))
    if writable_sources:
        warnings.append(f"World-writable locations hold governance content: {', '.join(sorted(writable_sources)[:5])}")
    if env.is_global:
        stats = _grant_statistics(root / "config.json")
        if stats and (stats["governance_writes"] or stats["secret_like"]):
            warnings.append(
                f"Antigravity permission grants: {stats['total']} total, {stats['governance_writes']} persistent write grant(s) "
                f"to governance paths, {stats['secret_like']} containing secret-like values, {stats['unsandboxed']} unsandboxed. "
                f"Review them in Antigravity settings and rotate any exposed tokens."
            )
    if not StartupManager(root).status().get("active"):
        infos.append("Boot sentinel is not enabled ('agy-guard startup enable').")
    if not load_settings().get("enabled", True):
        infos.append("Desktop notifications are disabled ('agy-guard notify enable').")

    print("=" * 64)
    print(f"       Antigravity Guard (agy-guard) v{__version__} - Doctor       ")
    print("=" * 64)
    print(f"Environment    : {env.name} -> {root}")
    print(f"Protection     : {registry.os_adapter.protection_kind()}")
    print(f"Write Shield   : {'[LOCKED]' if not issues else '[UNPROTECTED]'}")
    print(f"Trust Anchor   : {monitor.state_file}")
    print(f"Integrity (FIM): {report.summary()}")
    print("-" * 64)
    for w in warnings:
        print(f"  [WARN] {w}")
    for i in infos:
        print(f"  [INFO] {i}")
    if not warnings:
        print("[OK] No problems found.")

    if getattr(args, "fix", False):
        print("\n[Auto-Healing]")
        if issues:
            ok, msg = registry.lock(env.id)
            print(f"  - Write shield: {'re-engaged' if ok else 'FAILED'}: {msg}")
        if not monitor.state_file.exists():
            if request_approval("rebaseline", f"Establish the initial integrity baseline for {env.name}?", [report.summary()]):
                cnt, pth = monitor.save_baseline()
                print(f"  - Baseline established for {cnt} entries -> {pth}")
            else:
                print(f"  - Baseline NOT established: {refusal_message('rebaseline')}")
        print("Doctor auto-healing completed (nothing was deleted; manual items remain listed above).")
        issues = registry.protection_issues(env)
        report = monitor.verify()
        warnings = [w for w in warnings if not w.startswith(("Governance scope", "Integrity:"))]

    print("=" * 64)
    return 0 if (not issues and report.is_intact and not warnings) else 1


def cmd_startup(args: argparse.Namespace) -> int:
    manager = StartupManager()
    action = getattr(args, "action", "status") or "status"
    if action == "enable":
        ok, msg = manager.enable()
        print(f"[{'SUCCESS' if ok else 'FAILED'}] {msg}")
        return 0 if ok else 1
    if action == "disable":
        if not request_approval("startup disable", "Disable the boot sentinel?", []):
            return _refuse("startup disable")
        ok, msg = manager.disable()
        print(f"[{'SUCCESS' if ok else 'FAILED'}] {msg}")
        return 0 if ok else 1
    st = manager.status()
    print("=" * 64)
    print("   Antigravity Guard — Boot Sentinel Status   ")
    print("=" * 64)
    print(f"Platform       : {st['platform']}")
    print(f"Mechanism      : {st['mechanism']}")
    print(f"Service Path   : {st['target_path']}")
    print(f"Installed      : {'YES' if st['installed'] else 'NO'}")
    print(f"Active/Enabled : {'YES' if st['active'] else 'NO'}")
    print("=" * 64)
    return 0


def cmd_boot_check(args: argparse.Namespace) -> int:
    ok, msg = StartupManager().execute_boot_check()
    print(f"[BOOT-SENTINEL] {msg}")
    return 0 if ok else 1


def cmd_test_boundary(args: argparse.Namespace) -> int:
    guard = TestBoundaryGuard(workspace_dir=getattr(args, "dir", None))
    action = getattr(args, "action", "verify")

    if action == "snapshot":
        target = Path(args.output).resolve() if getattr(args, "output", None) else guard.state_file
        if target.exists() and not request_approval(
            "test-boundary snapshot", "Overwrite the existing test boundary baseline with the CURRENT tests?",
            [str(target), "Re-snapshotting after editing tests would legitimise those edits."],
        ):
            return _refuse("test-boundary snapshot")
        count, path = guard.snapshot(target_path=getattr(args, "output", None))
        print(f"[TEST-BOUNDARY] Baseline snapshot captured for {count} test & config files -> {path}")
        return 0

    if action == "verify":
        mode = getattr(args, "mode", "bugfix") or "bugfix"
        report = guard.verify(mode=mode, snapshot_path=getattr(args, "snapshot", None), base_ref=getattr(args, "base_ref", None))
        print("=" * 64)
        print("      Antigravity Guard — Test & Config Boundary Verification     ")
        print("=" * 64)
        print(f"Workspace      : {report.workspace_dir}")
        print(f"Baseline       : {report.baseline_source or 'n/a'}")
        print(f"Mode           : {report.mode.upper()}")
        print(f"Tracked Files  : {report.total_files}")
        print(f"Status         : {report.summary()}")
        if report.added:
            print(f"New test files : {', '.join(report.added)}")
        if report.extended:
            print(f"Extended files : {', '.join(report.extended)}")
        print("=" * 64)
        if report.violations:
            print("\nViolations Detected:")
            for v in report.violations:
                print(f"  [X] {v}")
            print("\n[BLOCKED] Delivery halted. Test or configuration mutation is prohibited.")
            return 1
        print("[PASS] Test trust boundary is intact. No unauthorized test mutations.")
        return 0

    if action == "run-reproducible":
        if not getattr(args, "cmd", None):
            print("Error: Specify test command using --cmd '<command>'")
            return 1
        passes = args.passes
        if passes < 2:
            print("Error: --passes must be >= 2 to verify reproducibility.", file=sys.stderr)
            return 1
        print(f"[REPRODUCIBILITY-GATE] Running command {passes} consecutive times: {args.cmd}")
        success, msg, codes = guard.run_reproducible(command=args.cmd, passes=passes)
        print(f"[{'PASS' if success else 'FAIL'}] {msg} (Exit Codes: {codes})")
        return 0 if success else 1
    return 0


def cmd_provenance(args: argparse.Namespace) -> int:
    tracker = RunProvenanceTracker(workspace_dir=getattr(args, "dir", None))
    action = getattr(args, "action", "status") or "status"
    if action == "generate":
        if getattr(args, "test_cmd", None) and args.passes < 2:
            print("Error: --passes must be >= 2 to verify reproducibility.", file=sys.stderr)
            return 1
        manifest = tracker.generate_manifest(
            mode=getattr(args, "mode", "bugfix") or "bugfix",
            test_command=getattr(args, "test_cmd", None),
            reproducibility_passes=args.passes,
        )
        print("=" * 64)
        print("        Antigravity Guard — Run Provenance Manifest Generated     ")
        print("=" * 64)
        print(manifest.to_markdown())
        print("=" * 64)
        print(f"Manifest written -> {tracker.output_file}")
        return 0
    if not tracker.output_file.exists():
        print("No provenance manifest found. Run 'provenance generate' first.")
        return 1
    try:
        data = json.loads(tracker.output_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"Error reading provenance manifest: {e}")
        return 1
    print("=" * 64)
    print("         Antigravity Guard — Active Provenance Manifest          ")
    print("=" * 64)
    print(f"Timestamp       : {data.get('session_timestamp')}")
    print(f"Base Commit     : {data.get('git_base_commit')}")
    print(f"Boundary Status : {'INTACT' if data.get('test_boundary_verified') else 'UNVERIFIED / VIOLATED'}")
    print(f"Reproducibility : {'VERIFIED' if data.get('reproducibility_verified') else 'UNVERIFIED'}")
    print(f"Modified Files  : {len(data.get('files_modified', []))}")
    print("=" * 64)
    return 0


def cmd_env(args: argparse.Namespace) -> int:
    registry = _registry(args)
    action = getattr(args, "action", "list") or "list"
    name = getattr(args, "name", None) or getattr(args, "target", None)

    if action == "list":
        print("=" * 64)
        print("          Antigravity Guard — Registered Environments          ")
        print("=" * 64)
        for item in registry.get_status_matrix():
            print(f"ID       : {item['id']}")
            print(f"Name     : {item['name']}")
            print(f"Platform : {item['platform']}")
            print(f"Root     : {item['root']}")
            print(f"Policy   : {item['policy']}")
            print(f"Shield   : {'[LOCKED]' if item['is_locked'] else '[UNLOCKED]'}")
            print(f"Seams    : {item['file_count']} existing governance entries")
            print("-" * 64)
        print(f"Registry : {registry.config_path}")
        return 0

    if action == "detect":
        workspace = Path(getattr(args, "path", None) or Path.cwd())
        discovered = registry.discover_environments(workspace_dir=workspace, register=not getattr(args, "dry_run", False))
        print(f"Discovered {len(discovered)} coding agent environment(s):")
        for env in discovered:
            paths = env.get_governance_paths(existing_only=True)
            print(f"  - {env.name} (id: {env.id}, platform: {env.platform_type}) -> {len(paths)} governance entries")
        if not getattr(args, "dry_run", False):
            print(f"\n[SAVED] Environments registered to {registry.config_path}")
        return 0

    if action == "add":
        path = getattr(args, "path", None)
        if not name or not path:
            print("Error: Specify environment name (--name) and path (--path) to add.", file=sys.stderr)
            return 1
        env = AgentEnvironment(
            id=re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-"),
            name=name,
            platform_type=getattr(args, "type", None) or "custom",
            root_path=str(Path(path).resolve()),
            policy=getattr(args, "policy", None) or "enforced",
        )
        registry.register_environment(env)
        print(f"[REGISTERED] Environment '{env.id}' added -> {env.root_path}")
        return 0

    if action == "remove":
        if not name:
            print("Error: Specify environment ID to remove.", file=sys.stderr)
            return 1
        if registry.unregister_environment(name):
            print(f"[REMOVED] Environment '{name}' removed from registry.")
            return 0
        print(f"Environment '{name}' not found (the global 'antigravity' environment cannot be removed).", file=sys.stderr)
        return 1

    if action == "policy":
        policy_val = getattr(args, "policy_val", None) or getattr(args, "value", None)
        if not name or not policy_val:
            print(f"Error: usage: agy-guard env policy <id> <{'|'.join(VALID_POLICIES)}>", file=sys.stderr)
            return 1
        try:
            if registry.set_policy(name, policy_val):
                print(f"[POLICY UPDATED] '{name}' policy set to '{policy_val}'")
                return 0
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        print(f"Environment '{name}' not found.", file=sys.stderr)
        return 1
    return 0


def cmd_request_unlock(args: argparse.Namespace) -> int:
    manager = LeaseManager(registry=_registry(args))
    success, msg, _ = manager.request_unlock(
        env_id=getattr(args, "env", None) or "antigravity",
        reason=getattr(args, "reason", None) or "Maintenance operation",
        duration_seconds=args.duration,
        interactive=not getattr(args, "non_interactive", False),
    )
    print(f"[{'AUTHORIZED' if success else 'REJECTED'}] {msg}")
    return 0 if success else 1


def cmd_lock_complete(args: argparse.Namespace) -> int:
    ok, msg = LeaseManager(registry=_registry(args)).complete_lease(env_id=getattr(args, "env", None))
    print(f"[{'LOCKED' if ok else 'ERROR'}] {msg}")
    return 0 if ok else 1


def cmd_lease_tick(args: argparse.Namespace) -> int:
    """Internal: waits, then expires every due lease (spawned by request-unlock)."""
    if args.wait:
        time.sleep(max(0, min(args.wait, MAX_LEASE_SECONDS + 5)))
    manager = LeaseManager(
        registry=_registry(args),
        lease_file=Path(args.lease_file) if getattr(args, "lease_file", None) else None,
    )
    expired = manager.check_and_expire_leases()
    remaining = manager.list_leases()
    print(f"[LEASE-TICK] expired {len(expired)} lease(s); {len(remaining)} still recorded.")
    return 0 if not any(l.state == "close_failed" for l in remaining) else 1


def cmd_drift(args: argparse.Namespace) -> int:
    registry = _registry(args)
    if getattr(args, "env", None):
        env, err = registry.resolve_environment(args.env)
        if not env:
            print(f"Error: {err}", file=sys.stderr)
            return 1
        targets = [env]
    else:
        targets = registry.list_environments()
    any_drift = False
    print("=" * 64)
    print("        Antigravity Guard — Multi-Environment Drift Analysis     ")
    print("=" * 64)
    for env in targets:
        report = _monitor(env, registry).verify()
        if report.is_intact:
            print(f"[INTACT] {env.name} ({env.id}): {report.total_files} governance entries verified.")
            continue
        any_drift = True
        print(f"\n[DRIFT] {env.name} ({env.id}): {report.summary()}")
        _print_report_details(report, indent="   ")
    print("=" * 64)
    return 1 if any_drift else 0


def _default_audit_root() -> Path:
    repo_root = Path(__file__).resolve().parent.parent
    if (repo_root / "skills").is_dir() and (repo_root / "GEMINI.md").is_file():
        return repo_root
    return config_dir()


def cmd_self_audit(args: argparse.Namespace) -> int:
    lib_root = str(Path(__file__).resolve().parent.parent)
    if lib_root not in sys.path:
        sys.path.insert(0, lib_root)
    try:
        from scripts.meta_audit import MetaAuditEngine
    except ImportError as e:
        print(f"Error: the self-audit engine (scripts/meta_audit.py) is not available in this build: {e}", file=sys.stderr)
        return 2
    root = Path(args.root).resolve() if getattr(args, "root", None) else _default_audit_root()
    engine = MetaAuditEngine(repo_root=root)
    findings = engine.run_all_passes()
    criticals = [f for f in findings if f.severity == "CRITICAL"]
    warnings = [f for f in findings if f.severity == "WARNING"]
    failed = bool(criticals) or (getattr(args, "strict", False) and bool(warnings))

    if getattr(args, "json", False):
        print(json.dumps({
            "root": str(root),
            "is_valid": not failed,
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }, indent=2))
        return 1 if failed else 0

    print("=" * 64)
    print("    Antigravity Guard — Harness Self-Audit       ")
    print("=" * 64)
    print(f"Audited root: {root}")
    for f in findings:
        print(f"[{f.severity}] {f.pass_name} -> {f.target}")
        print(f"   Message: {f.message}")
        print(f"   Fix    : {f.suggested_fix}\n")
    print("=" * 64)
    if failed:
        print("[FAIL] Self-audit violations detected.")
        return 1
    print("[PASS] Harness self-consistency checks passed.")
    return 0


def cmd_notify(args: argparse.Namespace) -> int:
    settings = load_settings()
    action = args.action
    if action == "status":
        print(f"Notifications: {'enabled' if settings['enabled'] else 'disabled'}; quiet mode: {'on' if settings['quiet'] else 'off'}")
        return 0
    enabled, quiet = settings["enabled"], settings["quiet"]
    if action == "enable":
        enabled = True
    elif action == "disable":
        enabled = False
    elif action == "quiet":
        quiet = True
    elif action == "normal":
        quiet = False
    path = save_settings(enabled, quiet)
    print(f"[NOTIFY] enabled={enabled} quiet={quiet} -> {path}")
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    from guard.gui import launch_gui
    return launch_gui()


# ----------------------------------------------------------------------
# Parser
# ----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agy-guard",
        description=f"Antigravity Guard v{__version__} - governance write protection, integrity monitoring and staging",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--registry", help=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    def env_opts(p, with_all: bool = False):
        p.add_argument("--env", "-e", help="Environment id (default: antigravity)")
        if with_all:
            p.add_argument("--all", "-a", action="store_true", help="Apply to all registered environments")

    p = subparsers.add_parser("status", help="Show write protection, integrity and lease status")
    env_opts(p)
    p.set_defaults(func=cmd_status)

    p = subparsers.add_parser("lock", help="Write-protect governance seams")
    env_opts(p, with_all=True)
    p.set_defaults(func=cmd_lock)

    p = subparsers.add_parser("unlock", help="Remove write protection (human confirmation required)")
    env_opts(p, with_all=True)
    p.set_defaults(func=cmd_unlock)

    p = subparsers.add_parser("verify", help="Run the File Integrity Monitor (FIM) check")
    env_opts(p, with_all=True)
    p.set_defaults(func=cmd_verify)

    p = subparsers.add_parser("rebaseline", help="Accept the current state as trusted (human confirmation required)")
    env_opts(p)
    p.set_defaults(func=cmd_rebaseline)

    p = subparsers.add_parser("snapshot", help="Manage governance snapshots")
    p.add_argument("action", choices=["create", "list", "restore", "prune"], help="Snapshot action")
    p.add_argument("--label", "-l", help="Label for snapshot create")
    p.add_argument("--id", help="Snapshot ID for restore")
    p.add_argument("--keep", type=int, default=5, help="Snapshots to retain per kind during prune")
    env_opts(p)
    p.set_defaults(func=cmd_snapshot)

    p = subparsers.add_parser("porter", help="Porter inspection and staging gate")
    p.add_argument("action", choices=["inspect", "stage"], help="Porter action")
    p.add_argument("source", help="Path to rule file or HTTP(S) URL")
    p.add_argument("--name", "-n", help="Override destination target name")
    p.add_argument("--force", "-f", action="store_true", help="Ingest despite constitutional violations (confirmation required)")
    p.add_argument("--expect-sha256", help="Only ingest if the source still has this content hash (from 'inspect')")
    p.set_defaults(func=cmd_porter)

    p = subparsers.add_parser("upstream", help="Check tracked upstream repositories")
    p.add_argument("action", choices=["check", "status"], default="check", nargs="?", help="Upstream action")
    p.set_defaults(func=cmd_upstream)

    p = subparsers.add_parser("startup", help="Manage the boot sentinel registration")
    p.add_argument("action", choices=["enable", "disable", "status"], default="status", nargs="?", help="Startup action")
    p.set_defaults(func=cmd_startup)

    p = subparsers.add_parser("boot-check", help="Headless boot verification and lock enforcement")
    p.set_defaults(func=cmd_boot_check)

    p = subparsers.add_parser("gui", help="Launch the desktop interface")
    p.set_defaults(func=cmd_gui)

    p = subparsers.add_parser("doctor", help="Health check (permissions, baseline, legacy state, risky grants)")
    p.add_argument("--fix", "--recover", action="store_true", dest="fix", help="Re-lock and establish a missing baseline")
    env_opts(p)
    p.set_defaults(func=cmd_doctor)

    p = subparsers.add_parser("test-boundary", help="Guard tests and runner configs as a trust boundary")
    p.add_argument("action", choices=["snapshot", "verify", "run-reproducible"], help="Test boundary action")
    p.add_argument("--mode", choices=["bugfix", "tdd"], default="bugfix", help="Verification mode (default: bugfix)")
    p.add_argument("--dir", help="Target workspace root directory")
    p.add_argument("--output", help="Snapshot output path")
    p.add_argument("--snapshot", help="Custom snapshot path to verify against")
    p.add_argument("--base-ref", help="Verify against a git ref (e.g. origin/main) instead of a stored snapshot")
    p.add_argument("--cmd", help="Target test command for run-reproducible")
    p.add_argument("--passes", type=int, default=2, help="Consecutive passes required (>= 2, default: 2)")
    p.set_defaults(func=cmd_test_boundary)

    p = subparsers.add_parser("provenance", help="Generate and inspect the execution provenance manifest")
    p.add_argument("action", choices=["generate", "status"], default="status", nargs="?", help="Provenance action")
    p.add_argument("--mode", choices=["bugfix", "tdd"], default="bugfix", help="Operating mode for boundary check")
    p.add_argument("--dir", help="Target workspace root directory")
    p.add_argument("--test-cmd", help="Optional test command to check reproducibility")
    p.add_argument("--passes", type=int, default=2, help="Reproducibility passes (>= 2, default: 2)")
    p.set_defaults(func=cmd_provenance)

    p = subparsers.add_parser("env", help="Manage multi-environment registration and policies")
    p.add_argument("action", choices=["list", "detect", "add", "remove", "policy"], default="list", nargs="?", help="Environment action")
    p.add_argument("target", nargs="?", help="Environment id (for remove/policy)")
    p.add_argument("value", nargs="?", help=f"Policy value for 'policy' ({'|'.join(VALID_POLICIES)})")
    p.add_argument("--name", "-n", help="Environment id or display name")
    p.add_argument("--path", "-p", help="Root path for 'add', workspace for 'detect'")
    p.add_argument("--type", "-t", choices=["antigravity", "claude", "codex", "cursor", "aider", "custom"], help="Platform type")
    p.add_argument("--policy", choices=VALID_POLICIES, help="Policy for 'add'")
    p.add_argument("--policy-val", choices=VALID_POLICIES, help="Policy for 'policy'")
    p.add_argument("--dry-run", action="store_true", help="Preview discovery without saving to registry")
    p.set_defaults(func=cmd_env)

    p = subparsers.add_parser("request-unlock", help="Request a time-bounded unlock (human approval, automatic relock)")
    p.add_argument("--env", "-e", default="antigravity", help="Environment id to unlock")
    p.add_argument("--reason", "-r", default="Maintenance operation", help="Reason for requesting unlock")
    p.add_argument("--duration", "-d", type=int, default=60,
                   help=f"Lease duration in seconds ({MIN_LEASE_SECONDS}-{MAX_LEASE_SECONDS}, default: 60)")
    p.add_argument("--non-interactive", action="store_true", help="Never prompt (the request is then rejected)")
    p.set_defaults(func=cmd_request_unlock)

    p = subparsers.add_parser("lock-complete", help="End maintenance early and re-lock immediately")
    p.add_argument("--env", "-e", help="Environment id (default: all active leases)")
    p.set_defaults(func=cmd_lock_complete)

    p = subparsers.add_parser("lease-tick", help="Internal: expire due leases (used by the auto-relock watcher)")
    p.add_argument("--wait", type=int, default=0, help="Seconds to wait before checking")
    p.add_argument("--lease-file", help=argparse.SUPPRESS)
    p.add_argument("--registry", help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_lease_tick)

    p = subparsers.add_parser("drift", help="Analyze drift across registered environments")
    p.add_argument("--env", "-e", help="Environment id to inspect (defaults to all)")
    p.set_defaults(func=cmd_drift)

    p = subparsers.add_parser("self-audit", help="Run the harness meta-consistency self-audit")
    p.add_argument("--json", action="store_true", help="Output findings as structured JSON")
    p.add_argument("--strict", action="store_true", help="Treat warnings as failures")
    p.add_argument("--root", help="Harness root to audit (default: this repository or ~/.gemini/config)")
    p.set_defaults(func=cmd_self_audit)

    p = subparsers.add_parser("notify", help="Configure desktop notifications")
    p.add_argument("action", choices=["status", "enable", "disable", "quiet", "normal"], default="status", nargs="?")
    p.set_defaults(func=cmd_notify)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    raw_args = sys.argv[1:] if argv is None else list(argv)
    args = parser.parse_args(raw_args)

    if not args.command:
        if not raw_args and sys.stdout.isatty() and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            return cmd_gui(args)
        parser.print_help()
        return 0

    try:
        if args.command not in ("lease-tick", "gui"):
            try:
                LeaseManager(registry=_registry(args)).check_and_expire_leases()
            except Exception as e:  # never let lease housekeeping block the requested command
                print(f"[WARN] Lease housekeeping failed: {e}", file=sys.stderr)
        return args.func(args)
    except RegistryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
