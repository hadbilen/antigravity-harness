"""
guard/approval.py — Human confirmation gate for Guard administration commands.
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Threat model (honest): the gate stops unattended/headless automation and accidental
invocations. A process running as the same OS user can still bypass any user-space
check; a real boundary requires root-owned files or host-enforced tool policies.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence


@dataclass
class ApprovalRequest:
    action: str
    summary: str
    details: List[str] = field(default_factory=list)


Approver = Callable[[ApprovalRequest], bool]

_approver_override: Optional[Approver] = None


def set_approver(approver: Optional[Approver]) -> None:
    """Installs an in-process approver (GUI dialogs, unit tests). None restores the TTY gate."""
    global _approver_override
    _approver_override = approver


def is_interactive() -> bool:
    try:
        return bool(sys.stdin and sys.stdin.isatty() and sys.stdout and sys.stdout.isatty())
    except (AttributeError, ValueError):
        return False


def tty_approver(request: ApprovalRequest) -> bool:
    """Requires an interactive terminal and an explicit typed 'yes'."""
    if not is_interactive():
        return False
    print(f"\n[ANTIGRAVITY GUARD — HUMAN CONFIRMATION REQUIRED: {request.action}]")
    print(request.summary)
    for line in request.details:
        print(f"  - {line}")
    try:
        answer = input("Type 'yes' to confirm: ")
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.strip().lower() == "yes"


def request_approval(action: str, summary: str, details: Sequence[str] = ()) -> bool:
    request = ApprovalRequest(action=action, summary=summary, details=list(details))
    approver = _approver_override or tty_approver
    try:
        return bool(approver(request))
    except Exception:
        return False


def refusal_message(action: str) -> str:
    return (
        f"'{action}' requires confirmation by a human operator in an interactive terminal "
        f"(or in the Guard GUI). The request was not approved; nothing was changed."
    )
