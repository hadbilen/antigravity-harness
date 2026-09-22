"""
tests/hermetic.py — Hermetic test environment for the Antigravity Harness suite.

Imported first by every test module. It redirects HOME and every per-user state location
into a throw-away directory (so tests never read or write the developer's real
~/.gemini, ~/.local/state or ~/.local/share), disables desktop notifications, and offers
helpers for approving administration prompts and removing write-protected trees.
"""

from __future__ import annotations

import atexit
import os
import shutil
import stat
import tempfile
from pathlib import Path

_ROOT = Path(tempfile.mkdtemp(prefix="agy-test-home-"))

os.environ["HOME"] = str(_ROOT)
os.environ["USERPROFILE"] = str(_ROOT)
os.environ["XDG_STATE_HOME"] = str(_ROOT / "state")
os.environ["XDG_DATA_HOME"] = str(_ROOT / "data")
os.environ["ANTIGRAVITY_CONFIG_DIR"] = str(_ROOT / ".gemini" / "config")
os.environ["AGY_GUARD_NOTIFY"] = "off"
for _var in ("ANTIGRAVITY_INTEGRITY_FILE", "AGY_GUARD_STATE_DIR", "AGY_GUARD_DATA_DIR", "UPSTREAM_STATE_FILE", "ANTIGRAVITY_MODEL"):
    os.environ.pop(_var, None)

HOME = _ROOT
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


def force_rmtree(path) -> None:
    """Removes a tree even if Guard left parts of it read-only."""
    path = Path(path)
    if not os.path.lexists(path):
        return
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            if not os.path.islink(p):
                try:
                    os.chmod(p, stat.S_IMODE(os.lstat(p).st_mode) | stat.S_IWUSR | stat.S_IRUSR | (stat.S_IXUSR if os.path.isdir(p) else 0))
                except OSError:
                    pass
    try:
        os.chmod(path, stat.S_IMODE(os.lstat(path).st_mode) | stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR)
    except OSError:
        pass
    shutil.rmtree(path, ignore_errors=True)


def approve_all() -> None:
    from guard import approval
    approval.set_approver(lambda request: True)


def deny_all() -> None:
    from guard import approval
    approval.set_approver(lambda request: False)


def reset_approver() -> None:
    from guard import approval
    approval.set_approver(None)


atexit.register(force_rmtree, _ROOT)
