"""
guard/environment.py — Multi-Environment Governance & Protection Registry
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

The registry lives in the per-user state directory (never the current working
directory), so every invocation sees the same environments regardless of cwd.
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from guard.os_adapter import OSProtectionAdapter
from guard.paths import atomic_write_json, config_dir, path_key, read_json, state_dir

VALID_POLICIES = ("enforced", "monitored", "disabled")

# Governance seams of the Antigravity global customization root. Runtime state written by
# the Antigravity application itself (config.json, projects/, sidecars/, plugins/, cache)
# is deliberately NOT part of the protected scope.
ANTIGRAVITY_GOVERNANCE_SEAMS = [
    "GEMINI.md",
    "AGENTS.md",
    "DESIGN.md",
    "MISTAKES.md",
    "hooks.json",
    "mcp_config.json",
    "skills",
    "agents",
    "templates",
    ".harness",
]
ANTIGRAVITY_RUNTIME_ENTRIES = ["config.json", "projects", "sidecars", "plugins", "cache", ".git"]

KNOWN_PLATFORMS = {
    "antigravity": {"name": "Antigravity Harness", "governance_seams": ANTIGRAVITY_GOVERNANCE_SEAMS},
    "claude": {"name": "Claude Code", "governance_seams": ["CLAUDE.md", ".claude"]},
    "codex": {"name": "GPT Codex / Copilot", "governance_seams": ["AGENTS.md", "CODEX.md", ".codex"]},
    "cursor": {"name": "Cursor IDE", "governance_seams": [".cursorrules", ".cursor"]},
    "aider": {"name": "Aider", "governance_seams": [".aider.conf.yml", ".aiderignore"]},
}


class RegistryError(RuntimeError):
    """Raised when the registry cannot be persisted."""


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "workspace"


def make_env_id(prefix: str, workspace: Path) -> str:
    """Collision-resistant environment id: platform + folder name + short path hash."""
    ws = Path(workspace).resolve()
    return f"{prefix}-{_slug(ws.name)}-{path_key(ws)[:6]}"


@dataclass
class AgentEnvironment:
    """
    Represents a recognized coding agent runtime environment with an isolated
    Agent Governance Surface (governance seam).
    """
    id: str
    name: str
    platform_type: str
    root_path: str
    governance_paths: List[str] = field(default_factory=list)
    policy: str = "enforced"  # "enforced" | "monitored" | "disabled"
    is_global: bool = False
    enabled: bool = True
    protect_root: bool = False  # also strip write access from the root directory entry itself

    def get_root(self) -> Path:
        return Path(self.root_path).expanduser().resolve()

    def get_governance_paths(self, existing_only: bool = False) -> List[Path]:
        """Absolute governance paths. Symlinks are NOT resolved, so they stay visible to the lock."""
        root = self.get_root()
        resolved: List[Path] = []
        for rel in self.governance_paths:
            candidate = Path(rel).expanduser()
            p = candidate if candidate.is_absolute() else root / candidate
            p = Path(os.path.abspath(p))
            if not existing_only or os.path.lexists(p):
                resolved.append(p)
        return resolved

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AgentEnvironment:
        known = {f.name for f in fields(cls)}
        payload = {k: v for k, v in data.items() if k in known}
        payload.setdefault("name", data["id"])
        payload.setdefault("platform_type", "custom")
        return cls(**payload)


def default_antigravity_environment(root: Optional[Path] = None) -> AgentEnvironment:
    return AgentEnvironment(
        id="antigravity",
        name="Antigravity Global Config",
        platform_type="antigravity",
        root_path=str((root or config_dir())),
        governance_paths=list(ANTIGRAVITY_GOVERNANCE_SEAMS),
        policy="enforced",
        is_global=True,
        enabled=True,
        protect_root=True,
    )


class EnvironmentRegistry:
    """
    Manages multi-environment registration, auto-discovery, selective write protection,
    and integrity verification across all AI coding agent platforms.
    """

    def __init__(
        self,
        config_path: Optional[Path] = None,
        workspace_dir: Optional[Path] = None,
        os_adapter: Optional[OSProtectionAdapter] = None,
    ):
        self.workspace_dir = Path(workspace_dir or Path.cwd()).resolve()
        self.legacy_config_path: Optional[Path] = None
        if config_path is not None:
            self.config_path = Path(config_path).resolve()
        else:
            self.config_path = state_dir() / "environments.json"
            legacy = Path.home() / ".gemini" / ".environments.json"
            if not self.config_path.exists() and legacy.is_file():
                self.legacy_config_path = legacy

        self.os_adapter = os_adapter or OSProtectionAdapter()
        self._environments: Dict[str, AgentEnvironment] = {}
        self.load()

    def load(self) -> None:
        """Loads environment definitions from disk (or a legacy registry) and seeds defaults."""
        self._environments = {}
        source = self.config_path if self.config_path.exists() else self.legacy_config_path
        if source is not None:
            data = read_json(source, default={}) or {}
            for env_data in data.get("environments", []):
                try:
                    env = AgentEnvironment.from_dict(env_data)
                except (KeyError, TypeError):
                    continue
                self._environments[env.id] = env

        default_global = default_antigravity_environment()
        existing = self._environments.get("antigravity")
        if existing is None:
            self._environments["antigravity"] = default_global
        else:
            # The global root always follows the active configuration directory, and the
            # governance scope is upgraded with any seams introduced by newer releases.
            existing.root_path = default_global.root_path
            existing.is_global = True
            existing.protect_root = True
            for seam in ANTIGRAVITY_GOVERNANCE_SEAMS:
                if seam not in existing.governance_paths:
                    existing.governance_paths.append(seam)

    def save(self) -> None:
        """Persists the registry atomically; raises RegistryError with an actionable message."""
        from guard import __version__

        payload = {
            "version": __version__,
            "environments": [env.to_dict() for env in self._environments.values()],
        }
        try:
            atomic_write_json(self.config_path, payload)
        except OSError as e:
            raise RegistryError(
                f"Could not save the environment registry to {self.config_path}: {e}. "
                f"Check permissions of the state directory or pass an explicit registry path."
            ) from e

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def _find_existing(self, platform_type: str, root: Path) -> Optional[AgentEnvironment]:
        for env in self._environments.values():
            if env.platform_type == platform_type and not env.is_global and env.get_root() == root:
                return env
        return None

    def discover_environments(self, workspace_dir: Optional[Path] = None, register: bool = True) -> List[AgentEnvironment]:
        """
        Auto-detects coding agent governance seams in the workspace or home directories.
        Does not mutate user project files.
        """
        target_ws = Path(workspace_dir or self.workspace_dir).resolve()
        discovered: List[AgentEnvironment] = [self._environments["antigravity"]]

        candidates: List[Tuple[str, str, str, List[str]]] = []
        antigravity_root = self._environments["antigravity"].get_root()
        if target_ws != antigravity_root and ((target_ws / ".gemini").exists() or (target_ws / "GEMINI.md").exists()):
            seams = [s for s in ["GEMINI.md", "DESIGN.md", "MISTAKES.md", ".gemini", ".agents", ".harness"] if os.path.lexists(target_ws / s)]
            candidates.append(("antigravity", "antigravity-workspace", f"Antigravity Workspace ({target_ws.name})", seams or ["GEMINI.md"]))
        for platform_type in ("claude", "codex", "cursor", "aider"):
            seams_all = KNOWN_PLATFORMS[platform_type]["governance_seams"]
            seams = [s for s in seams_all if os.path.lexists(target_ws / s)]
            if seams:
                label = KNOWN_PLATFORMS[platform_type]["name"]
                candidates.append((platform_type, platform_type, f"{label} ({target_ws.name})", seams))

        for platform_type, prefix, name, seams in candidates:
            existing = self._find_existing(platform_type, target_ws)
            if existing:
                for seam in seams:
                    if seam not in existing.governance_paths:
                        existing.governance_paths.append(seam)
                discovered.append(existing)
                continue
            discovered.append(
                AgentEnvironment(
                    id=make_env_id(prefix, target_ws),
                    name=name,
                    platform_type=platform_type,
                    root_path=str(target_ws),
                    governance_paths=seams,
                    policy="enforced",
                    is_global=False,
                )
            )

        if register:
            for env in discovered:
                self._environments.setdefault(env.id, env)
            self.save()

        return discovered

    # ------------------------------------------------------------------
    # Lookup and mutation
    # ------------------------------------------------------------------
    def list_environments(self) -> List[AgentEnvironment]:
        return list(self._environments.values())

    def resolve_environment(self, env_id: str) -> Tuple[Optional[AgentEnvironment], str]:
        """Exact id, then a unique platform or unique id-prefix match. Ambiguity is an error."""
        if not env_id:
            return None, "No environment id given."
        if env_id in self._environments:
            return self._environments[env_id], ""
        by_platform = [e for e in self._environments.values() if e.platform_type == env_id]
        if len(by_platform) == 1:
            return by_platform[0], ""
        by_prefix = [e for eid, e in self._environments.items() if eid.startswith(env_id)]
        if len(by_prefix) == 1 and not by_platform:
            return by_prefix[0], ""
        matches = by_platform or by_prefix
        if matches:
            ids = ", ".join(sorted(e.id for e in matches))
            return None, f"Environment id '{env_id}' is ambiguous; use one of: {ids}"
        return None, f"Environment '{env_id}' is not registered."

    def get_environment(self, env_id: str) -> Optional[AgentEnvironment]:
        env, _ = self.resolve_environment(env_id)
        return env

    def register_environment(self, env: AgentEnvironment) -> None:
        if env.policy not in VALID_POLICIES:
            raise ValueError(f"Invalid policy '{env.policy}'. Must be one of {', '.join(VALID_POLICIES)}.")
        self._environments[env.id] = env
        self.save()

    def unregister_environment(self, env_id: str) -> bool:
        if env_id == "antigravity":
            return False
        if env_id in self._environments:
            del self._environments[env_id]
            self.save()
            return True
        return False

    def set_policy(self, env_id: str, policy: str) -> bool:
        if policy not in VALID_POLICIES:
            raise ValueError(f"Invalid policy '{policy}'. Must be one of {', '.join(VALID_POLICIES)}.")
        env = self.get_environment(env_id)
        if not env:
            return False
        env.policy = policy
        self.save()
        return True

    # ------------------------------------------------------------------
    # Protection
    # ------------------------------------------------------------------
    def _targets(self, env_id: Optional[str]) -> Tuple[List[AgentEnvironment], str]:
        if env_id:
            env, err = self.resolve_environment(env_id)
            return ([env] if env else []), err
        return self.list_environments(), ""

    def protection_issues(self, env: AgentEnvironment) -> List[str]:
        """Reasons why an environment is not fully write-protected (empty list = protected)."""
        issues: List[str] = []
        paths = env.get_governance_paths(existing_only=True)
        if paths:
            issues.extend(self.os_adapter.protection_issues(paths))
        if env.protect_root or not paths:
            issues.extend(self.os_adapter.protection_issues(env.get_root(), recursive=False))
        return issues

    def is_locked(self, env_id: Optional[str] = None) -> Dict[str, bool]:
        """Returns map of env_id -> is fully locked."""
        results: Dict[str, bool] = {}
        targets, _ = self._targets(env_id)
        for env in targets:
            if not env.enabled or env.policy == "disabled":
                results[env.id] = False
                continue
            paths = env.get_governance_paths(existing_only=True)
            locked = self.os_adapter.is_locked(paths) if paths else True
            if env.protect_root or not paths:
                locked = locked and self.os_adapter.is_locked(env.get_root(), recursive=False)
            results[env.id] = bool(locked)
        return results

    def lock(self, env_id: Optional[str] = None) -> Tuple[bool, str]:
        """Locks the targeted (or all enforced) environments' governance seams."""
        targets, err = self._targets(env_id)
        if env_id and not targets:
            return False, err
        details: List[str] = []
        all_ok = True
        for env in targets:
            if not env.enabled or env.policy != "enforced":
                details.append(f"Skipped {env.name} (policy={env.policy})")
                continue
            paths = env.get_governance_paths(existing_only=True)
            ok, msg = self.os_adapter.lock(paths) if paths else (True, "Zero active governance files found to lock.")
            if env.protect_root:
                ok_root, msg_root = self.os_adapter.lock(env.get_root(), recursive=False)
                ok = ok and ok_root
                msg = f"{msg}; root: {msg_root}"
            if not ok:
                all_ok = False
            details.append(f"[{env.name}] {msg}")
        return all_ok, "\n".join(details)

    def unlock(self, env_id: Optional[str] = None) -> Tuple[bool, str]:
        """Unlocks targeted (or all) environments' governance seams."""
        targets, err = self._targets(env_id)
        if env_id and not targets:
            return False, err
        details: List[str] = []
        all_ok = True
        for env in targets:
            if not env.enabled or env.policy == "disabled":
                continue
            ok, msg = True, ""
            if env.protect_root:
                ok, msg_root = self.os_adapter.unlock(env.get_root(), recursive=False)
                msg = f"root: {msg_root}; "
            paths = env.get_governance_paths(existing_only=True)
            if paths:
                ok_paths, msg_paths = self.os_adapter.unlock(paths)
                ok = ok and ok_paths
                msg += msg_paths
            else:
                msg += "Zero active governance files found to unlock."
            if not ok:
                all_ok = False
            details.append(f"[{env.name}] {msg}")
        return all_ok, "\n".join(details)

    def get_status_matrix(self) -> List[Dict[str, Any]]:
        """Returns aggregated status matrix for all registered environments."""
        lock_map = self.is_locked()
        matrix = []
        for env in self.list_environments():
            active_paths = env.get_governance_paths(existing_only=True)
            matrix.append({
                "id": env.id,
                "name": env.name,
                "platform": env.platform_type,
                "root": env.root_path,
                "policy": env.policy,
                "is_locked": lock_map.get(env.id, False),
                "is_global": env.is_global,
                "tracked_files": [str(p) for p in active_paths],
                "file_count": len(active_paths),
            })
        return matrix


class EnvironmentLocker:
    """Lock controller scoped to one environment's governance seams (used by snapshot/restore)."""

    def __init__(self, registry: EnvironmentRegistry, env_id: str):
        self.registry = registry
        self.env_id = env_id

    def is_locked(self) -> bool:
        return self.registry.is_locked(self.env_id).get(self.env_id, False)

    def unlock(self) -> Tuple[bool, str]:
        return self.registry.unlock(self.env_id)

    def lock(self) -> Tuple[bool, str]:
        return self.registry.lock(self.env_id)
