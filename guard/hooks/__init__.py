"""
guard/hooks/__init__.py — Event-scoped lifecycle hook package header (ADR-0008).
Part of Plumbwork (https://github.com/tozhax/plumbwork)
Zero external dependencies: uses strictly the Python standard library.

Intentionally defines only `_ACTIVE_FACADE` (`ContextVar`) with zero eager submodule
imports so importing `guard.hooks.<event>` never loads sibling lifecycle modules.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any

_ACTIVE_FACADE: ContextVar[Any] = ContextVar("agy_hooks_active_facade", default=None)

__all__ = ()
