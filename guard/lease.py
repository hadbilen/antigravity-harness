"""
guard/lease.py — Human-in-the-Loop (HITL) Time-Bounded Lease Unlock Protocol
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from guard.environment import AgentEnvironment, EnvironmentRegistry
from guard.integrity import FileIntegrityMonitor
from guard.notifier import GuardNotifier, NotificationSeverity


@dataclass
class UnlockLease:
    lease_id: str
    env_id: str
    env_name: str
    reason: str
    duration_seconds: int
    granted_at: float
    expires_at: float
    target_paths: List[str]
    is_active: bool = True

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.expires_at - time.time())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> UnlockLease:
        return cls(**data)


class LeaseManager:
    """
    Orchestrates time-bounded, human-authorized lease unlocking for AI agents.
    Guarantees atomic auto-relock when time expires or work completes.
    """

    def __init__(
        self,
        registry: Optional[EnvironmentRegistry] = None,
        notifier: Optional[GuardNotifier] = None,
        lease_file: Optional[Path] = None,
    ):
        self.registry = registry or EnvironmentRegistry()
        self.notifier = notifier or GuardNotifier()
        if lease_file is not None:
            self.lease_file = Path(lease_file).resolve()
        else:
            harness_dir = self.registry.workspace_dir / ".harness"
            if harness_dir.exists():
                self.lease_file = harness_dir / ".active_lease.json"
            else:
                self.lease_file = Path.home() / ".gemini" / ".active_lease.json"

    def get_active_lease(self) -> Optional[UnlockLease]:
        if not self.lease_file.exists():
            return None
        try:
            data = json.loads(self.lease_file.read_text(encoding="utf-8"))
            lease = UnlockLease.from_dict(data)
            if lease.is_active and lease.remaining_seconds > 0:
                return lease
            elif lease.is_active and lease.remaining_seconds <= 0:
                self.expire_lease(lease)
                return None
        except Exception:
            return None
        return None

    def request_unlock(
        self,
        env_id: str,
        reason: str,
        duration_seconds: int = 60,
        interactive: bool = True,
        auto_approve: bool = False,
    ) -> Tuple[bool, str, Optional[UnlockLease]]:
        """
        Processes an unlock request from an agent or developer.
        Dispatches high-urgency notifications and requires human confirmation.
        """
        env = self.registry.get_environment(env_id)
        if not env:
            return False, f"Target environment '{env_id}' is not recognized in registry.", None

        # Clean existing expired leases
        self.check_and_expire_leases()

        # Send immediate critical desktop notification to alert the operator
        self.notifier.notify(
            title="Antigravity Guard — Unlock Request",
            message=f"Agent requested {duration_seconds}s lease for {env.name}.\nReason: {reason}",
            severity=NotificationSeverity.CRITICAL,
            force=True,
        )

        approved = auto_approve
        if not approved and interactive:
            # Check if stdin is available for terminal interaction
            if sys.stdin and sys.stdin.isatty():
                prompt_msg = (
                    f"\n[ANTIGRAVITY GUARD — HUMAN APPROVAL REQUIRED]\n"
                    f"Agent Environment : {env.name} ({env.id})\n"
                    f"Requested Duration: {duration_seconds} seconds\n"
                    f"Operator Reason   : {reason}\n"
                    f"Authorize temporary unlock window? [y/N]: "
                )
                try:
                    choice = input(prompt_msg).strip().lower()
                    approved = choice in ("y", "yes")
                except (EOFError, KeyboardInterrupt):
                    approved = False
            else:
                # Non-interactive headless session: cannot prompt directly on TTY
                approved = False

        if not approved:
            return (
                False,
                f"Unlock rejected by operator or headless mode without approval. "
                f"Operator must manually run 'agy-guard unlock --env {env.id}' to authorize.",
                None,
            )

        # Unlock target environment governance paths
        ok, msg = self.registry.unlock(env.id)
        if not ok:
            return False, f"Failed to release OS write protection: {msg}", None

        now = time.time()
        active_paths = [str(p) for p in env.get_governance_paths(existing_only=True)]
        lease = UnlockLease(
            lease_id=str(uuid.uuid4())[:8],
            env_id=env.id,
            env_name=env.name,
            reason=reason,
            duration_seconds=duration_seconds,
            granted_at=now,
            expires_at=now + duration_seconds,
            target_paths=active_paths,
            is_active=True,
        )

        try:
            self.lease_file.parent.mkdir(parents=True, exist_ok=True)
            self.lease_file.write_text(json.dumps(lease.to_dict(), indent=2), encoding="utf-8")
        except Exception:
            pass

        return (
            True,
            f"Authorized! Granted {duration_seconds}s maintenance lease (ID: {lease.lease_id}) for {env.name}. "
            f"Auto-relock arms in {duration_seconds} seconds.",
            lease,
        )

    def expire_lease(self, lease: UnlockLease) -> Tuple[bool, str]:
        """Expires active lease, restores OS protection, and rebaselines FIM."""
        lease.is_active = False
        try:
            if self.lease_file.exists():
                self.lease_file.unlink(missing_ok=True)
        except Exception:
            pass

        # Relock target environment
        ok, msg = self.registry.lock(lease.env_id)

        # Update FIM baseline for tracked target paths
        env = self.registry.get_environment(lease.env_id)
        if env:
            monitor = FileIntegrityMonitor(
                target_dir=env.get_root(),
                target_paths=env.get_governance_paths(existing_only=True),
            )
            monitor.save_baseline()

        self.notifier.notify(
            title="Antigravity Guard — Lease Expired",
            message=f"Maintenance window for {lease.env_name} closed. Environment re-locked & integrity secured.",
            severity=NotificationSeverity.INFO,
            force=True,
        )
        return ok, f"Lease {lease.lease_id} expired. {msg}"

    def check_and_expire_leases(self) -> List[UnlockLease]:
        """Scans active leases and expires any that exceeded their allotted window."""
        expired = []
        if not self.lease_file.exists():
            return expired
        try:
            data = json.loads(self.lease_file.read_text(encoding="utf-8"))
            lease = UnlockLease.from_dict(data)
            if lease.is_active and lease.remaining_seconds <= 0:
                self.expire_lease(lease)
                expired.append(lease)
        except Exception:
            pass
        return expired

    def complete_lease(self, env_id: Optional[str] = None) -> Tuple[bool, str]:
        """Allows an agent or developer to signal early completion and immediately re-lock."""
        active = self.get_active_lease()
        if not active:
            # If no active lease file exists, ensure target is locked anyway
            ok, msg = self.registry.lock(env_id)
            return ok, f"Zero active lease found. Verified lock: {msg}"

        if env_id and active.env_id != env_id:
            ok, msg = self.registry.lock(env_id)
            return ok, f"Active lease was for {active.env_id}, locked requested {env_id}: {msg}"

        return self.expire_lease(active)
