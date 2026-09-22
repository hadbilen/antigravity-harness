"""
guard/lease.py — Human-in-the-Loop (HITL) Time-Bounded Lease Unlock Protocol
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Lifecycle: approve -> persist record (OPENING) -> unlock -> OPEN -> scheduled relock.
Closing relocks FIRST; only a successful relock writes a change report and a new
baseline and removes the record. A failed relock keeps the record (CLOSE_FAILED) and
raises a CRITICAL notification, so an open environment is never silently forgotten.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from guard.approval import ApprovalRequest, request_approval
from guard.environment import AgentEnvironment, EnvironmentRegistry
from guard.integrity import FileIntegrityMonitor
from guard.notifier import GuardNotifier, NotificationSeverity
from guard.paths import atomic_write_json, read_json, state_dir

MIN_LEASE_SECONDS = 1
MAX_LEASE_SECONDS = 3600

STATE_OPENING = "opening"
STATE_OPEN = "open"
STATE_CLOSE_FAILED = "close_failed"

Scheduler = Callable[["UnlockLease", "LeaseManager"], Tuple[bool, str]]
Approver = Callable[[ApprovalRequest], bool]


@dataclass
class UnlockLease:
    lease_id: str
    env_id: str
    env_name: str
    reason: str
    duration_seconds: int
    granted_at: float
    expires_at: float
    target_paths: List[str] = field(default_factory=list)
    is_active: bool = True
    state: str = STATE_OPEN
    scheduler_detail: str = ""

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.expires_at - time.time())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> UnlockLease:
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


def guard_command() -> List[str]:
    """argv prefix that runs this Guard installation's CLI."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, "-m", "guard.cli"]


def default_scheduler(lease: UnlockLease, manager: "LeaseManager") -> Tuple[bool, str]:
    """Spawns a detached watcher that relocks when the lease expires (cross-platform)."""
    wait = int(lease.remaining_seconds) + 1
    cmd = guard_command() + ["lease-tick", "--wait", str(wait), "--lease-file", str(manager.lease_file)]
    if manager.registry.config_path:
        cmd += ["--registry", str(manager.registry.config_path)]
    env = dict(os.environ)
    root = str(Path(__file__).resolve().parent.parent)
    env["PYTHONPATH"] = root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    kwargs: Dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
        "cwd": root,
        "env": env,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(cmd, **kwargs)
        at = datetime.fromtimestamp(lease.expires_at).strftime("%H:%M:%S")
        return True, f"auto-relock watcher pid {proc.pid} fires at {at}"
    except OSError as e:
        return False, f"could not start auto-relock watcher ({e})"


class LeaseManager:
    """
    Orchestrates time-bounded, human-authorized lease unlocking.
    Leases are tracked per environment in the per-user state directory.
    """

    def __init__(
        self,
        registry: Optional[EnvironmentRegistry] = None,
        notifier: Optional[GuardNotifier] = None,
        lease_file: Optional[Path] = None,
        scheduler: Optional[Scheduler] = None,
    ):
        self.registry = registry or EnvironmentRegistry()
        self.notifier = notifier or GuardNotifier()
        self.lease_file = Path(lease_file).resolve() if lease_file is not None else state_dir() / "leases.json"
        self.scheduler: Scheduler = scheduler or default_scheduler
        self.reports_dir = self.lease_file.parent / "lease_reports"

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    @contextmanager
    def _file_lock(self, timeout: float = 10.0) -> Iterator[None]:
        lock_path = self.lease_file.with_name(self.lease_file.name + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.time() + timeout
        fd = None
        while fd is None:
            try:
                fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                try:
                    if time.time() - lock_path.stat().st_mtime > 30:
                        lock_path.unlink(missing_ok=True)
                        continue
                except OSError:
                    pass
                if time.time() > deadline:
                    raise TimeoutError(f"Lease store is busy ({lock_path}).")
                time.sleep(0.05)
        try:
            yield
        finally:
            os.close(fd)
            try:
                lock_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _load(self) -> Dict[str, UnlockLease]:
        data = read_json(self.lease_file, default=None)
        if not data:
            return {}
        raw = data.get("leases") if isinstance(data, dict) and "leases" in data else {data.get("env_id", "unknown"): data}
        leases: Dict[str, UnlockLease] = {}
        for env_id, item in (raw or {}).items():
            try:
                lease = UnlockLease.from_dict(item)
            except (TypeError, KeyError):
                continue
            if lease.is_active:
                leases[lease.env_id or env_id] = lease
        return leases

    def _save(self, leases: Dict[str, UnlockLease]) -> None:
        if not leases:
            self.lease_file.unlink(missing_ok=True)
            return
        atomic_write_json(self.lease_file, {"version": 2, "leases": {k: v.to_dict() for k, v in leases.items()}})

    def list_leases(self) -> List[UnlockLease]:
        return list(self._load().values())

    def get_active_lease(self, env_id: Optional[str] = None) -> Optional[UnlockLease]:
        """Returns the active lease for `env_id` (or any), expiring overdue leases first."""
        self.check_and_expire_leases()
        leases = self._load()
        if env_id:
            lease = leases.get(env_id)
            return lease if lease and lease.state != STATE_CLOSE_FAILED else None
        for lease in leases.values():
            if lease.state == STATE_OPEN:
                return lease
        return None

    # ------------------------------------------------------------------
    # Request / grant
    # ------------------------------------------------------------------
    def request_unlock(
        self,
        env_id: str,
        reason: str,
        duration_seconds: int = 60,
        interactive: bool = True,
        approver: Optional[Approver] = None,
    ) -> Tuple[bool, str, Optional[UnlockLease]]:
        """
        Processes an unlock request. Approval comes from `approver` (GUI dialog) or, when
        interactive, from a human typing 'yes' in a terminal. Headless requests are rejected.
        """
        if not isinstance(duration_seconds, int) or not MIN_LEASE_SECONDS <= duration_seconds <= MAX_LEASE_SECONDS:
            return False, f"Lease duration must be between {MIN_LEASE_SECONDS} and {MAX_LEASE_SECONDS} seconds.", None

        env, err = self.registry.resolve_environment(env_id)
        if not env:
            return False, err, None

        self.check_and_expire_leases()
        existing = self._load().get(env.id)
        if existing:
            return False, (
                f"A lease for {env.name} is already {existing.state} (id {existing.lease_id}, "
                f"{int(existing.remaining_seconds)}s left). Run 'agy-guard lock-complete --env {env.id}' first."
            ), None

        details = [
            f"Environment : {env.name} ({env.id})",
            f"Duration    : {duration_seconds} seconds",
            f"Reason      : {reason}",
            f"Paths       : {len(env.get_governance_paths(existing_only=True))} governance entries",
        ]
        request = ApprovalRequest(action="request-unlock", summary="Authorize a temporary maintenance window?", details=details)
        if approver is not None:
            approved = bool(approver(request))
        elif interactive:
            approved = request_approval(request.action, request.summary, request.details)
        else:
            approved = False

        if not approved:
            self.notifier.notify(
                title="Antigravity Guard — Unlock Request Pending",
                message=f"An unlock of {env.name} was requested ({reason}). Approve it from an interactive terminal or the Guard GUI.",
                severity=NotificationSeverity.WARNING,
                key=f"lease-request-{env.id}",
            )
            return (
                False,
                "Unlock rejected: human approval is required. A human operator must run "
                "'agy-guard request-unlock' in an interactive terminal or approve the lease in the Guard GUI.",
                None,
            )

        now = time.time()
        lease = UnlockLease(
            lease_id=uuid.uuid4().hex[:8],
            env_id=env.id,
            env_name=env.name,
            reason=reason,
            duration_seconds=duration_seconds,
            granted_at=now,
            expires_at=now + duration_seconds,
            target_paths=[str(p) for p in env.get_governance_paths(existing_only=True)],
            is_active=True,
            state=STATE_OPENING,
        )

        # Persist BEFORE unlocking: an open environment must never exist without a record.
        try:
            with self._file_lock():
                leases = self._load()
                leases[env.id] = lease
                self._save(leases)
        except (OSError, TimeoutError) as e:
            return False, f"Could not persist the lease record ({e}); unlock aborted, nothing was changed.", None

        ok, msg = self.registry.unlock(env.id)
        if not ok:
            relock_ok, _ = self.registry.lock(env.id)
            with self._file_lock():
                leases = self._load()
                leases.pop(env.id, None)
                self._save(leases)
            return False, f"Failed to release OS write protection: {msg}" + ("" if relock_ok else " (re-lock also failed)"), None

        lease.state = STATE_OPEN
        sched_ok, sched_msg = self.scheduler(lease, self)
        lease.scheduler_detail = sched_msg
        with self._file_lock():
            leases = self._load()
            leases[env.id] = lease
            self._save(leases)

        relock_note = (
            f"Auto-relock scheduled: {sched_msg}."
            if sched_ok
            else f"WARNING: {sched_msg}. Run 'agy-guard lock-complete --env {env.id}' when finished."
        )
        self.notifier.notify(
            title="Antigravity Guard — Lease Granted",
            message=f"{env.name} unlocked for {duration_seconds}s ({reason}).",
            severity=NotificationSeverity.INFO,
            key=f"lease-granted-{lease.lease_id}",
        )
        return True, f"Authorized {duration_seconds}s maintenance lease (ID: {lease.lease_id}) for {env.name}. {relock_note}", lease

    # ------------------------------------------------------------------
    # Close
    # ------------------------------------------------------------------
    def _write_change_report(self, lease: UnlockLease, env: AgentEnvironment, monitor: FileIntegrityMonitor) -> Tuple[Optional[Path], int]:
        report = monitor.verify()
        if report.baseline_status == "ok":
            changes = len(report.modified) + len(report.added) + len(report.deleted)
        else:  # nothing to compare against: every file in scope is unreviewed
            changes = report.total_files
        payload = {
            "lease": lease.to_dict(),
            "closed_at": datetime.now(timezone.utc).isoformat(),
            "baseline_existed": monitor.state_file.exists(),
            "integrity": report.to_dict(),
        }
        path = self.reports_dir / f"{lease.lease_id}.json"
        try:
            atomic_write_json(path, payload)
            return path, changes
        except OSError:
            return None, changes

    def expire_lease(self, lease: UnlockLease) -> Tuple[bool, str]:
        """Relocks the environment; on success records a change report and a new baseline."""
        ok, msg = self.registry.lock(lease.env_id)
        env = self.registry.get_environment(lease.env_id)

        if not ok:
            first_failure = lease.state != STATE_CLOSE_FAILED
            with self._file_lock():
                leases = self._load()
                lease.state = STATE_CLOSE_FAILED
                leases[lease.env_id] = lease
                self._save(leases)
            self.notifier.notify(
                title="Antigravity Guard — RELOCK FAILED",
                message=f"{lease.env_name} could not be re-locked after lease {lease.lease_id}. It is still writable.",
                severity=NotificationSeverity.CRITICAL,
                key=f"relock-failed-{lease.lease_id}",
                cooldown_seconds=None if first_failure else 600,
                force=first_failure,
            )
            return False, f"Lease {lease.lease_id}: re-lock FAILED, environment remains writable. {msg}"

        report_note = ""
        if env:
            monitor = FileIntegrityMonitor.for_environment(env, os_adapter=self.registry.os_adapter)
            report_path, changes = self._write_change_report(lease, env, monitor)
            monitor.save_baseline()
            report_note = f" {changes} change(s) during the window" + (f" (report: {report_path})" if report_path else "") + "."

        with self._file_lock():
            leases = self._load()
            leases.pop(lease.env_id, None)
            self._save(leases)

        self.notifier.notify(
            title="Antigravity Guard — Lease Closed",
            message=f"Maintenance window for {lease.env_name} closed and re-locked.{report_note}",
            severity=NotificationSeverity.INFO,
            key=f"lease-closed-{lease.lease_id}",
        )
        return True, f"Lease {lease.lease_id} closed; environment re-locked.{report_note} {msg}"

    def check_and_expire_leases(self) -> List[UnlockLease]:
        """Expires every lease whose window has elapsed (and retries failed closes)."""
        expired: List[UnlockLease] = []
        try:
            due = [l for l in self._load().values() if l.remaining_seconds <= 0 or l.state == STATE_CLOSE_FAILED]
        except Exception:
            return expired
        for lease in due:
            ok, _ = self.expire_lease(lease)
            if ok:
                expired.append(lease)
        return expired

    def complete_lease(self, env_id: Optional[str] = None) -> Tuple[bool, str]:
        """Signals early completion and immediately re-locks."""
        leases = self._load()
        if env_id:
            env, err = self.registry.resolve_environment(env_id)
            if not env:
                return False, err
            lease = leases.get(env.id)
            if lease:
                return self.expire_lease(lease)
            ok, msg = self.registry.lock(env.id)
            return ok, f"No active lease for {env.id}. Verified lock: {msg}"

        if not leases:
            ok, msg = self.registry.lock("antigravity")
            return ok, f"Zero active leases found. Verified lock: {msg}"
        results = [self.expire_lease(lease) for lease in list(leases.values())]
        return all(ok for ok, _ in results), " | ".join(msg for _, msg in results)
