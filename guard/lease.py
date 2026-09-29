"""
guard/lease.py — Human-in-the-Loop (HITL) Time-Bounded Lease Unlock Protocol
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Lifecycle: approve -> persist record (OPENING) -> unlock -> OPEN -> scheduled relock.
Closing relocks FIRST; only a successful relock writes a change report and removes the
record. Changes made during the window are NOT silently trusted: an automatic expiry
records them as a candidate baseline "pending review" (accepted later with an approved
`agy-guard rebaseline`); a human closing the window interactively can accept them at once.
A failed relock keeps the record (CLOSE_FAILED), raises a CRITICAL notification and
schedules bounded retries, so an open environment is never silently forgotten. A lease
record is only ever removed by the close of that same lease (matched by lease id), and a
corrupt lease store fails closed (every enforced environment is re-locked).
"""

from __future__ import annotations

import errno
import os
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from guard.approval import ApprovalRequest, request_approval
from guard.audit_log import audit, error, warn
from guard.environment import AgentEnvironment, EnvironmentRegistry
from guard.integrity import FileIntegrityMonitor
from guard.notifier import GuardNotifier, NotificationSeverity
from guard.paths import CorruptStateError, atomic_write_json, file_lock, move_aside, read_json_strict, state_dir

MIN_LEASE_SECONDS = 1
MAX_LEASE_SECONDS = 3600

STATE_OPENING = "opening"
STATE_OPEN = "open"
STATE_CLOSING = "closing"
STATE_CLOSE_FAILED = "close_failed"

CLOSING_CLAIM_SECONDS = 120   # a close claimed by another process is honoured this long
RELOCK_RETRY_SECONDS = 60     # delay between automatic relock retries
MAX_RELOCK_RETRIES = 5

Scheduler = Callable[["UnlockLease", "LeaseManager"], Tuple[bool, str]]
RetryScheduler = Callable[["UnlockLease", "LeaseManager", int], Tuple[bool, str]]
Approver = Callable[[ApprovalRequest], bool]
Acceptor = Callable[[int, Optional[Path]], bool]


class LeaseStoreCorrupt(RuntimeError):
    """The lease store exists but cannot be parsed."""


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
    closing_started: float = 0.0
    relock_attempts: int = 0

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


def watcher_log_path() -> Path:
    return state_dir() / "logs" / "lease-watcher.log"


def _spawn_tick(manager: "LeaseManager", wait: int) -> Tuple[bool, str]:
    """Starts a detached `agy-guard lease-tick` that sleeps `wait` seconds, then expires due leases."""
    cmd = guard_command() + ["lease-tick", "--wait", str(max(1, int(wait))), "--lease-file", str(manager.lease_file)]
    if manager.registry.config_path:
        cmd += ["--registry", str(manager.registry.config_path)]
    env = dict(os.environ)
    root = str(Path(__file__).resolve().parent.parent)
    env["PYTHONPATH"] = root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    # The watcher's output goes to a log file, not /dev/null: a relock failure in a detached
    # process must leave a trace even when no desktop notification can be shown.
    log_file = None
    try:
        log_path = watcher_log_path()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a", encoding="utf-8")
    except OSError:
        log_file = None
    kwargs: Dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": log_file or subprocess.DEVNULL,
        "stderr": subprocess.STDOUT if log_file else subprocess.DEVNULL,
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
    except OSError as e:
        return False, f"could not start auto-relock watcher ({e})"
    finally:
        if log_file is not None:
            log_file.close()
    at = datetime.fromtimestamp(time.time() + wait).strftime("%H:%M:%S")
    return True, f"auto-relock watcher pid {proc.pid} fires at {at}"


def default_scheduler(lease: UnlockLease, manager: "LeaseManager") -> Tuple[bool, str]:
    """Spawns a detached watcher that relocks when the lease expires (cross-platform)."""
    return _spawn_tick(manager, int(lease.remaining_seconds) + 1)


def default_retry_scheduler(lease: UnlockLease, manager: "LeaseManager", delay: int) -> Tuple[bool, str]:
    """Schedules another relock attempt for a lease whose close failed."""
    return _spawn_tick(manager, delay)


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
        retry_scheduler: Optional[RetryScheduler] = None,
    ):
        self.registry = registry or EnvironmentRegistry()
        self.notifier = notifier or GuardNotifier()
        self.lease_file = Path(lease_file).resolve() if lease_file is not None else state_dir() / "leases.json"
        self.scheduler: Scheduler = scheduler or default_scheduler
        # Tests that stub the scheduler must not spawn real retry watchers either.
        if retry_scheduler is not None:
            self.retry_scheduler: RetryScheduler = retry_scheduler
        elif scheduler is None:
            self.retry_scheduler = default_retry_scheduler
        else:
            self.retry_scheduler = lambda lease, manager, delay: (False, "retry scheduling disabled")
        self.reports_dir = self.lease_file.parent / "lease_reports"

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _file_lock(self, timeout: float = 10.0):
        return file_lock(self.lease_file, timeout=timeout)

    def _load(self) -> Dict[str, UnlockLease]:
        """Active lease records by environment id. Raises LeaseStoreCorrupt for an unreadable store."""
        try:
            data = read_json_strict(self.lease_file)
        except CorruptStateError as e:
            raise LeaseStoreCorrupt(str(e)) from e
        except OSError as e:
            if e.errno in (errno.ENOENT, errno.ENOTDIR):
                return {}  # no store can exist at this path; persisting will report the problem
            raise LeaseStoreCorrupt(f"{self.lease_file} cannot be read ({e})") from e
        if not data:
            return {}
        if not isinstance(data, dict):
            raise LeaseStoreCorrupt(f"{self.lease_file} does not contain a lease mapping")
        raw = data.get("leases") if "leases" in data else {data.get("env_id", "unknown"): data}
        if not isinstance(raw, dict):
            raise LeaseStoreCorrupt(f"{self.lease_file}: 'leases' is not a mapping")
        leases: Dict[str, UnlockLease] = {}
        for env_id, item in raw.items():
            try:
                lease = UnlockLease.from_dict(item)
            except (TypeError, KeyError, AttributeError) as e:
                # A malformed record may describe an OPEN environment: fail closed.
                raise LeaseStoreCorrupt(f"{self.lease_file}: malformed record for '{env_id}' ({e})") from e
            if lease.is_active:
                leases[lease.env_id or env_id] = lease
        return leases

    def _save(self, leases: Dict[str, UnlockLease]) -> None:
        if not leases:
            self.lease_file.unlink(missing_ok=True)
            return
        atomic_write_json(self.lease_file, {"version": 2, "leases": {k: v.to_dict() for k, v in leases.items()}})

    def _fail_closed(self, reason: str) -> None:
        """Corrupt lease store: keep the evidence, re-lock every enforced environment, alert."""
        moved = move_aside(self.lease_file)
        ok, msg = self.registry.lock()
        error("lease.store_corrupt", reason=reason, moved_to=str(moved) if moved else "", relocked=ok, detail=msg[:1000])
        self.notifier.notify(
            title="Antigravity Guard — Lease Store Corrupt",
            message=(f"The lease store could not be read ({reason}). All enforced environments were re-locked"
                     + ("" if ok else " (SOME RE-LOCKS FAILED)") + ". Check 'agy-guard status'."),
            severity=NotificationSeverity.CRITICAL,
            key="lease-store-corrupt",
            force=True,
        )

    def list_leases(self) -> List[UnlockLease]:
        try:
            return list(self._load().values())
        except LeaseStoreCorrupt:
            return []

    def get_active_lease(self, env_id: Optional[str] = None) -> Optional[UnlockLease]:
        """Returns the active lease for `env_id` (or any), expiring overdue leases first."""
        self.check_and_expire_leases()
        try:
            leases = self._load()
        except LeaseStoreCorrupt:
            return None
        if env_id:
            lease = leases.get(env_id)
            return lease if lease and lease.state not in (STATE_CLOSE_FAILED, STATE_CLOSING) else None
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
        try:
            existing = self._load().get(env.id)
        except LeaseStoreCorrupt as e:
            return False, f"The lease store is corrupt ({e}); it was set aside and environments were re-locked. Retry.", None
        if existing:
            return False, self._already_leased_message(env, existing), None

        details = [
            f"Environment : {env.name} ({env.id})",
            f"Duration    : {duration_seconds} seconds",
            f"Reason      : {reason}",
            f"Paths       : {len(env.get_governance_paths(existing_only=True))} governance entries",
        ]
        request = ApprovalRequest(action="request-unlock", summary="Authorize a temporary maintenance window?", details=details)
        if approver is not None:
            approved = bool(approver(request))
            audit("approval.granted" if approved else "approval.refused", action="request-unlock", via="approver")
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
        # The existence check is repeated under the store lock, so two concurrent requests
        # can never both be granted for the same environment.
        try:
            with self._file_lock():
                leases = self._load()
                if env.id in leases:
                    return False, self._already_leased_message(env, leases[env.id]), None
                leases[env.id] = lease
                self._save(leases)
        except LeaseStoreCorrupt as e:
            return False, f"The lease store is corrupt ({e}); unlock aborted, nothing was changed.", None
        except (OSError, TimeoutError) as e:
            return False, f"Could not persist the lease record ({e}); unlock aborted, nothing was changed.", None

        ok, msg = self.registry.unlock(env.id)
        if not ok:
            relock_ok, _ = self.registry.lock(env.id)
            self._remove_record(lease)
            return False, f"Failed to release OS write protection: {msg}" + ("" if relock_ok else " (re-lock also failed)"), None

        lease.state = STATE_OPEN
        sched_ok, sched_msg = self.scheduler(lease, self)
        lease.scheduler_detail = sched_msg
        self._update_record(lease)

        audit("lease.granted", lease_id=lease.lease_id, env=env.id, seconds=duration_seconds, reason=reason,
              scheduler_ok=sched_ok, scheduler=sched_msg)
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

    @staticmethod
    def _already_leased_message(env: AgentEnvironment, existing: UnlockLease) -> str:
        return (
            f"A lease for {env.name} is already {existing.state} (id {existing.lease_id}, "
            f"{int(existing.remaining_seconds)}s left). Run 'agy-guard lock-complete --env {env.id}' first."
        )

    # ------------------------------------------------------------------
    # Record helpers (always matched by lease id)
    # ------------------------------------------------------------------
    def _update_record(self, lease: UnlockLease) -> bool:
        """Writes `lease` back only if the store still holds THIS lease for its environment."""
        with self._file_lock():
            leases = self._load()
            current = leases.get(lease.env_id)
            if current is not None and current.lease_id != lease.lease_id:
                return False
            leases[lease.env_id] = lease
            self._save(leases)
            return True

    def _remove_record(self, lease: UnlockLease) -> None:
        """Removes the record of THIS lease; a newer lease for the same environment is kept."""
        with self._file_lock():
            leases = self._load()
            current = leases.get(lease.env_id)
            if current is not None and current.lease_id == lease.lease_id:
                leases.pop(lease.env_id, None)
                self._save(leases)

    def _claim_close(self, lease: UnlockLease) -> Tuple[bool, str]:
        """Marks the lease as closing so two processes never close the same lease concurrently."""
        with self._file_lock():
            leases = self._load()
            current = leases.get(lease.env_id)
            if current is None or current.lease_id != lease.lease_id:
                return False, f"Lease {lease.lease_id} was already closed."
            if current.state == STATE_CLOSING and time.time() - current.closing_started < CLOSING_CLAIM_SECONDS:
                return False, f"Lease {lease.lease_id} is being closed by another process."
            current.state = STATE_CLOSING
            current.closing_started = time.time()
            leases[lease.env_id] = current
            self._save(leases)
            lease.state, lease.closing_started, lease.relock_attempts = current.state, current.closing_started, current.relock_attempts
            return True, ""

    # ------------------------------------------------------------------
    # Close
    # ------------------------------------------------------------------
    def _write_change_report(self, lease: UnlockLease, env: AgentEnvironment, monitor: FileIntegrityMonitor) -> Tuple[Optional[Path], int]:
        report = monitor.verify()
        if report.baseline_status in ("ok", "pending_review"):
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
        except OSError as e:
            warn("lease.report_write_failed", lease_id=lease.lease_id, error=str(e))
            return None, changes

    def expire_lease(self, lease: UnlockLease, acceptor: Optional[Acceptor] = None) -> Tuple[bool, str]:
        """
        Relocks the environment and records a change report. Changes made during the window are
        accepted into the trusted baseline only when `acceptor` (a human decision) returns True;
        otherwise they are recorded as a candidate baseline pending review.
        """
        claimed, claim_msg = self._claim_close(lease)
        if not claimed:
            return True, claim_msg

        env = self.registry.get_environment(lease.env_id)
        if env is not None and (not env.enabled or env.policy != "enforced"):
            # The policy was lowered while the window was open: nothing will be re-locked, and the
            # notification must say so instead of claiming the environment is protected again.
            self._remove_record(lease)
            warn("lease.closed_unlocked", lease_id=lease.lease_id, env=lease.env_id, policy=env.policy, enabled=env.enabled)
            self.notifier.notify(
                title="Antigravity Guard — Lease Closed WITHOUT Relock",
                message=f"{lease.env_name} stays writable: its policy is '{env.policy}'"
                        + ("" if env.enabled else " (disabled)") + ".",
                severity=NotificationSeverity.WARNING,
                key=f"lease-closed-unlocked-{lease.lease_id}",
            )
            return True, f"Lease {lease.lease_id} closed; {lease.env_name} was NOT re-locked (policy={env.policy})."

        ok, msg = self.registry.lock(lease.env_id)
        if not ok:
            first_failure = lease.relock_attempts == 0
            lease.state = STATE_CLOSE_FAILED
            lease.relock_attempts += 1
            try:
                self._update_record(lease)
            except (OSError, TimeoutError, LeaseStoreCorrupt) as e:
                error("lease.record_update_failed", lease_id=lease.lease_id, error=str(e))
            retry_note = ""
            if lease.relock_attempts <= MAX_RELOCK_RETRIES:
                r_ok, r_msg = self.retry_scheduler(lease, self, RELOCK_RETRY_SECONDS)
                retry_note = f" Retry {lease.relock_attempts}/{MAX_RELOCK_RETRIES}: {r_msg}." if r_ok else ""
            error("lease.relock_failed", lease_id=lease.lease_id, env=lease.env_id, attempt=lease.relock_attempts, detail=msg[:1000])
            self.notifier.notify(
                title="Antigravity Guard — RELOCK FAILED",
                message=f"{lease.env_name} could not be re-locked after lease {lease.lease_id}. It is still writable.",
                severity=NotificationSeverity.CRITICAL,
                key=f"relock-failed-{lease.lease_id}",
                cooldown_seconds=None if first_failure else 600,
                force=first_failure,
            )
            return False, f"Lease {lease.lease_id}: re-lock FAILED, environment remains writable. {msg}{retry_note}"

        report_note = ""
        if env:
            monitor = FileIntegrityMonitor.for_environment(env, os_adapter=self.registry.os_adapter)
            report_path, changes = self._write_change_report(lease, env, monitor)
            report_ref = f" (report: {report_path})" if report_path else " (report could not be written)"
            if changes == 0:
                report_note = f" 0 change(s) during the window{report_ref}."
            elif acceptor is not None and acceptor(changes, report_path):
                monitor.save_baseline()
                report_note = f" {changes} change(s) during the window accepted into the baseline{report_ref}."
            else:
                monitor.save_pending_baseline(f"lease {lease.lease_id}")
                report_note = (f" {changes} change(s) during the window await review{report_ref}; "
                               f"accept them with 'agy-guard rebaseline'.")

        self._remove_record(lease)
        audit("lease.closed", lease_id=lease.lease_id, env=lease.env_id, detail=report_note.strip())
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
            leases = self._load()
        except LeaseStoreCorrupt as e:
            self._fail_closed(str(e))
            return expired
        due = [l for l in leases.values() if l.remaining_seconds <= 0 or l.state == STATE_CLOSE_FAILED]
        for lease in due:
            try:
                ok, _ = self.expire_lease(lease)
            except (OSError, TimeoutError, LeaseStoreCorrupt) as e:
                error("lease.expire_error", lease_id=lease.lease_id, error=f"{type(e).__name__}: {e}")
                continue
            if ok:
                expired.append(lease)
        return expired

    def complete_lease(self, env_id: Optional[str] = None, approver: Optional[Approver] = None,
                       interactive: bool = False) -> Tuple[bool, str]:
        """
        Signals early completion and immediately re-locks. When a human is present (an explicit
        `approver`, or `interactive` with a terminal), they are asked whether the changes made
        during the window may be accepted into the trusted baseline; otherwise they stay pending.
        """
        def acceptor(changes: int, report_path: Optional[Path]) -> bool:
            details = [f"{changes} file change(s) were made during the maintenance window."]
            if report_path:
                details.append(f"Change report: {report_path}")
            request = ApprovalRequest(action="accept-window-changes",
                                      summary="Accept these changes into the trusted integrity baseline?", details=details)
            if approver is not None:
                return bool(approver(request))
            if interactive:
                return request_approval(request.action, request.summary, request.details)
            return False

        try:
            leases = self._load()
        except LeaseStoreCorrupt as e:
            self._fail_closed(str(e))
            return False, f"The lease store is corrupt ({e}); every enforced environment was re-locked."
        if env_id:
            env, err = self.registry.resolve_environment(env_id)
            if not env:
                return False, err
            lease = leases.get(env.id)
            if lease:
                return self.expire_lease(lease, acceptor=acceptor)
            ok, msg = self.registry.lock(env.id)
            return ok, f"No active lease for {env.id}. Verified lock: {msg}"

        if not leases:
            ok, msg = self.registry.lock("antigravity")
            return ok, f"Zero active leases found. Verified lock: {msg}"
        results = [self.expire_lease(lease, acceptor=acceptor) for lease in list(leases.values())]
        return all(ok for ok, _ in results), " | ".join(msg for _, msg in results)
