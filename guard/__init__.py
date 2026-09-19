"""
Antigravity Guard (agy-guard) — OS-Level Governance, Write Protection, & Staging Suite.
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

__version__ = "1.2.4"
__author__ = "Antigravity Team & Contributors"

from guard.os_adapter import OSProtectionAdapter
from guard.integrity import FileIntegrityMonitor
from guard.snapshot import SnapshotEngine
from guard.porter_bridge import PorterBridge
from guard.upstream import UpstreamAuditorBridge

__all__ = [
    "__version__",
    "OSProtectionAdapter",
    "FileIntegrityMonitor",
    "SnapshotEngine",
    "PorterBridge",
    "UpstreamAuditorBridge",
]
