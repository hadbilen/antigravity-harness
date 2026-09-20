"""
Antigravity Guard (agy-guard) — OS-Level Governance, Write Protection, & Staging Suite.
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

__version__ = "1.3.0"
__author__ = "Antigravity Team & Contributors"

from guard.os_adapter import OSProtectionAdapter
from guard.integrity import FileIntegrityMonitor
from guard.snapshot import SnapshotEngine
from guard.porter_bridge import PorterBridge
from guard.upstream import UpstreamAuditorBridge
from guard.startup import StartupManager
from guard.test_boundary import TestBoundaryGuard
from guard.provenance import RunProvenanceTracker
from guard.environment import AgentEnvironment, EnvironmentRegistry
from guard.notifier import GuardNotifier, NotificationSeverity
from guard.lease import LeaseManager, UnlockLease
def create_tray_adapter(*args, **kwargs):
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
