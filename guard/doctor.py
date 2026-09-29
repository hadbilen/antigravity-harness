"""
guard/doctor.py — Health diagnosis for an environment's governance scope (headless, testable).
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

The CLI (`agy-guard doctor`) only renders a DoctorReport; the checks live here so they can
be exercised without a terminal.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from guard.environment import AgentEnvironment, EnvironmentRegistry
from guard.integrity import FileIntegrityMonitor, IntegrityReport
from guard.notifier import load_settings
from guard.paths import state_dir


@dataclass
class DoctorReport:
    env: AgentEnvironment
    root: Path
    monitor: FileIntegrityMonitor
    issues: List[str]
    report: IntegrityReport
    warnings: List[str] = field(default_factory=list)
    infos: List[str] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not self.issues and self.report.is_intact and not self.warnings


def world_writable_ancestors(path: Path, depth: int = 3) -> List[str]:
    """Ancestors (up to `depth`) that any local user may write to (sticky dirs such as /tmp excluded)."""
    if os.name == "nt":
        return []  # st_mode carries no ACL information on Windows; every path would look world-writable
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


def grant_statistics(config_json: Path) -> Optional[dict]:
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


def diagnose(env: AgentEnvironment, registry: EnvironmentRegistry, sentinel_active: Optional[bool] = None) -> DoctorReport:
    """Runs every read-only health check for `env`. `sentinel_active` may be injected by callers/tests."""
    root = env.get_root()
    monitor = FileIntegrityMonitor.for_environment(env, os_adapter=registry.os_adapter)
    result = DoctorReport(env=env, root=root, monitor=monitor, issues=registry.protection_issues(env), report=monitor.verify())
    warnings, infos = result.warnings, result.infos

    if result.issues:
        warnings.append(f"Governance scope is not fully write-protected ({len(result.issues)} issue(s)); first: {result.issues[0]}")
    if not result.report.is_intact:
        warnings.append(f"Integrity: {result.report.summary()}")
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
        writable_sources.update(world_writable_ancestors(p))
    if writable_sources:
        warnings.append(f"World-writable locations hold governance content: {', '.join(sorted(writable_sources)[:5])}")
    if env.is_global:
        stats = grant_statistics(root / "config.json")
        if stats and (stats["governance_writes"] or stats["secret_like"]):
            warnings.append(
                f"Antigravity permission grants: {stats['total']} total, {stats['governance_writes']} persistent write grant(s) "
                f"to governance paths, {stats['secret_like']} containing secret-like values, {stats['unsandboxed']} unsandboxed. "
                f"Review them in Antigravity settings and rotate any exposed tokens."
            )
    watcher_log = state_dir() / "logs" / "lease-watcher.log"
    if watcher_log.is_file():
        try:
            tail = watcher_log.read_text(encoding="utf-8", errors="replace")[-4000:]
        except OSError:
            tail = ""
        if "RELOCK FAILED" in tail or "Traceback" in tail:
            warnings.append(f"The auto-relock watcher reported errors recently; see {watcher_log}.")
    if sentinel_active is None:
        from guard.startup import StartupManager
        sentinel_active = bool(StartupManager(root).status().get("active"))
    if not sentinel_active:
        infos.append("Boot sentinel is not enabled ('agy-guard startup enable').")
    if not load_settings().get("enabled", True):
        infos.append("Desktop notifications are disabled ('agy-guard notify enable'); security events still go to the audit log.")
    return result
