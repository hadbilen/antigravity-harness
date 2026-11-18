"""
Antigravity Guard (agy-guard) — OS-Level Governance, Write Protection, & Staging Suite.
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

__version__ = "2.2.0"
__author__ = "Antigravity Team & Contributors"

if TYPE_CHECKING:
    from guard.environment import AgentEnvironment, EnvironmentRegistry
    from guard.integrity import FileIntegrityMonitor
    from guard.lease import LeaseManager, UnlockLease
    from guard.notifier import GuardNotifier, NotificationSeverity
    from guard.os_adapter import OSProtectionAdapter
    from guard.porter_bridge import PorterBridge
    from guard.provenance import RunProvenanceTracker
    from guard.snapshot import SnapshotEngine
    from guard.startup import StartupManager
    from guard.test_boundary import TestBoundaryGuard
    from guard.upstream import UpstreamAuditorBridge

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "OSProtectionAdapter": ("guard.os_adapter", "OSProtectionAdapter"),
    "FileIntegrityMonitor": ("guard.integrity", "FileIntegrityMonitor"),
    "SnapshotEngine": ("guard.snapshot", "SnapshotEngine"),
    "PorterBridge": ("guard.porter_bridge", "PorterBridge"),
    "UpstreamAuditorBridge": ("guard.upstream", "UpstreamAuditorBridge"),
    "StartupManager": ("guard.startup", "StartupManager"),
    "TestBoundaryGuard": ("guard.test_boundary", "TestBoundaryGuard"),
    "RunProvenanceTracker": ("guard.provenance", "RunProvenanceTracker"),
    "AgentEnvironment": ("guard.environment", "AgentEnvironment"),
    "EnvironmentRegistry": ("guard.environment", "EnvironmentRegistry"),
    "GuardNotifier": ("guard.notifier", "GuardNotifier"),
    "NotificationSeverity": ("guard.notifier", "NotificationSeverity"),
    "LeaseManager": ("guard.lease", "LeaseManager"),
    "UnlockLease": ("guard.lease", "UnlockLease"),
}


def create_tray_adapter(*args: Any, **kwargs: Any) -> Any:
    from guard.tray import create_tray_adapter as _cta

    return _cta(*args, **kwargs)


__all__ = [
    "__version__",
    "OSProtectionAdapter",
    "FileIntegrityMonitor",
    "SnapshotEngine",
    "PorterBridge",
    "UpstreamAuditorBridge",
    "StartupManager",
    "TestBoundaryGuard",
    "RunProvenanceTracker",
    "AgentEnvironment",
    "EnvironmentRegistry",
    "GuardNotifier",
    "NotificationSeverity",
    "LeaseManager",
    "UnlockLease",
    "create_tray_adapter",
]


_LAZY_SUBMODULES: frozenset[str] = frozenset({
    "os_adapter",
    "integrity",
    "snapshot",
    "porter_bridge",
    "upstream",
    "startup",
    "test_boundary",
    "provenance",
    "environment",
    "notifier",
    "lease",
    "paths",
    "audit_log",
    "approval",
    "doctor",
    "cli",
    "tray",
})


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is not None:
        mod_name, attr_name = target
        mod = importlib.import_module(mod_name)
        val = getattr(mod, attr_name)
        globals()[name] = val
        return val
    if name in _LAZY_SUBMODULES:
        mod = importlib.import_module(f"guard.{name}")
        globals()[name] = mod
        return mod
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals().keys()) | set(__all__))
