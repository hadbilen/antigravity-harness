"""
guard/environment.py — Multi-Environment Governance & Protection Registry
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

The registry lives in the per-user state directory (never the current working
directory), so every invocation sees the same environments regardless of cwd.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, List, Optional, Tuple

from guard.audit_log import audit
from guard.os_adapter import OSProtectionAdapter
from guard.paths import (
    CorruptStateError,
    atomic_write_json,
    config_dir,
    config_dir_symlink,
    data_dir,
    is_within,
    path_key,
    read_json_strict,
    state_dir,
)

VALID_POLICIES = ("enforced", "monitored", "disabled")
_LAUNCHER_MARKER = "antigravity-harness launcher"
CONSTITUTION_RULE_REL = "rules/antigravity-constitution.md"
CONSTITUTION_RULE_FRONTMATTER = (
    "---\n"
    "trigger: always_on\n"
    'description: "Antigravity Global Engineering & Behavioral Constitution (always-on invariants)."\n'
    "---\n\n"
)


def render_constitution_rule(gemini_src: Path, *, mode: str = "copy") -> str:
    """Renders GEMINI.md as an Antigravity rules/*.md file with trigger: always_on frontmatter."""
    if mode == "link":
        return f"{CONSTITUTION_RULE_FRONTMATTER}@[Antigravity Constitution]({gemini_src.resolve().as_posix()})\n"
    body = gemini_src.read_text(encoding="utf-8").replace("\r\n", "\n")
    return f"{CONSTITUTION_RULE_FRONTMATTER}{body.rstrip()}\n"


def is_harness_constitution_file(path: Path, source_root: Optional[Path] = None) -> bool:
    """True when `path` appears to be an earlier Antigravity Harness GEMINI.md installation."""
    if os.path.islink(path):
        if source_root is not None:
            try:
                return Path(os.path.realpath(path)) == (source_root / "GEMINI.md").resolve()
            except OSError:
                return False
        return False
    if not path.is_file():
        return False
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:256]
    except OSError:
        return False
    return "# Antigravity Global Engineering & Behavioral Constitution" in head


def has_constitution_file(root: Path) -> bool:
    """True when `root` contains either legacy `GEMINI.md` or migrated `rules/antigravity-constitution.md`."""
    return (root / "GEMINI.md").is_file() or (root / CONSTITUTION_RULE_REL).is_file()

# Governance seams of the Antigravity global customization root. Runtime state written by
# the Antigravity application itself (config.json, projects/, sidecars/, plugins/, cache)
# is deliberately NOT part of the protected scope.
ANTIGRAVITY_GOVERNANCE_SEAMS = [
    "GEMINI.md",
    "AGENTS.md",
    "DESIGN.md",
    "hooks.json",
    "mcp_config.json",
    "skills",
    "agents",
    "rules",
    "templates",
    ".harness",
]
ANTIGRAVITY_RUNTIME_ENTRIES = ["config.json", "projects", "sidecars", "plugins", "cache", ".git"]

# Other agents' seams are a file-level whitelist of RULE content only. Their configuration
# directories also hold runtime state the tools write themselves (Claude Code's
# settings.local.json, session and memory files; Cursor's state), which must never be
# write-protected: locking a whole `.claude` or `.cursor` directory breaks those tools.
KNOWN_PLATFORMS = {
    "antigravity": {"name": "Antigravity Harness", "governance_seams": ANTIGRAVITY_GOVERNANCE_SEAMS},
    "claude": {"name": "Claude Code", "governance_seams": ["CLAUDE.md", ".claude/agents", ".claude/commands", ".claude/skills"]},
    "codex": {
        "name": "GPT Codex / Copilot",
        "governance_seams": ["AGENTS.md", "CODEX.md", "CONVENTIONS.md", ".agents/skills", ".agents/rules"],
    },
    "cursor": {
        "name": "Cursor IDE",
        "governance_seams": [".cursorrules", ".cursor/rules", ".cursor/skills", ".cursor/agents"],
    },
    "aider": {
        "name": "Aider",
        "governance_seams": [".aider.conf.yml", ".aiderignore", "CONVENTIONS.md", ".aider/skills"],
    },
}

# Whole-directory seams registered by releases before 1.4.0 (or pre-2.0 workspace `.gemini`);
# replaced by rule-only whitelists so tool runtime state (`~/.gemini/antigravity/brain`, settings, caches) stays writable.
ANTIGRAVITY_WORKSPACE_SEAMS = [
    "GEMINI.md",
    "AGENTS.md",
    "DESIGN.md",
    "MISTAKES.md",
    ".gemini/GEMINI.md",
    ".gemini/AGENTS.md",
    ".gemini/rules",
    ".gemini/skills",
    ".gemini/agents",
    ".gemini/hooks.json",
    ".gemini/mcp_config.json",
    ".agents",
    ".harness",
]
LEGACY_BROAD_SEAMS = {
    "antigravity": {".gemini"},
    "claude": {".claude"},
    "codex": {".codex"},
    "cursor": {".cursor"},
}

# Other agents' environments are discovered as "monitored" (integrity reports, no chmod):
# write-protecting another tool's files is opt-in via `agy-guard env policy <id> enforced`.
DISCOVERED_DEFAULT_POLICY = {"antigravity": "enforced"}
POLICY_STRENGTH = {"disabled": 0, "monitored": 1, "enforced": 2}


class RegistryError(RuntimeError):
    """Raised when the registry cannot be persisted."""


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "workspace"


def make_env_id(prefix: str, workspace: Path) -> str:
    """Collision-resistant environment id: platform + folder name + short path hash."""
    ws = Path(workspace).resolve()
    return f"{prefix}-{_slug(ws.name)}-{path_key(ws)[:6]}"


def antigravity_external_governance_paths(existing_only: bool = False) -> List[Path]:
    """
    Returns external runtime (`data_dir() / "runtime"`) and CLI launcher paths belonging to
    the global Antigravity Harness installation so they share OS-lock and FIM protection.
    """
    runtime_root = Path(os.path.abspath(data_dir() / "runtime"))
    candidates: List[Path] = [runtime_root]
    if os.name == "nt":
        bin_dir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Programs" / "antigravity-guard"
        for name in ("agy-guard.cmd", "agy-porter.cmd", "agy-guard.exe"):
            candidates.append(Path(os.path.abspath(bin_dir / name)))
    else:
        bin_dir = Path.home() / ".local" / "bin"
        candidates.append(Path(os.path.abspath(bin_dir / "agy-guard")))
        candidates.append(Path(os.path.abspath(bin_dir / "agy-porter")))
        porter_alias = Path(os.path.abspath(bin_dir / "porter"))
        include_porter = False
        if not os.path.lexists(porter_alias) or os.path.islink(porter_alias):
            include_porter = True
        elif porter_alias.is_file():
            try:
                with open(porter_alias, "rb") as fh:
                    head = fh.read(512).decode("utf-8", errors="ignore")
                include_porter = _LAUNCHER_MARKER in head
            except OSError:
                include_porter = False
        if include_porter:
            candidates.append(porter_alias)
    return [p for p in candidates if not existing_only or os.path.lexists(p)]


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
        seen: set[str] = set()
        for rel in self.governance_paths:
            candidate = Path(rel).expanduser()
            p = candidate if candidate.is_absolute() else root / candidate
            p = Path(os.path.abspath(p))
            if not existing_only or os.path.lexists(p):
                resolved.append(p)
                seen.add(str(p))
        if self.is_global and self.id == "antigravity":
            for ext in antigravity_external_governance_paths(existing_only=existing_only):
                if str(ext) not in seen:
                    resolved.append(ext)
                    seen.add(str(ext))
        return resolved

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AgentEnvironment:
        if not isinstance(data, dict):
            raise TypeError("Environment entry must be a JSON object")
        env_id = data.get("id")
        root_path = data.get("root_path")
        if not isinstance(env_id, str) or not env_id.strip():
            raise TypeError("Environment 'id' must be a non-empty string")
        if not isinstance(root_path, str) or not root_path.strip():
            raise TypeError("Environment 'root_path' must be a non-empty string")
        known = {f.name for f in fields(cls)}
        payload = {k: v for k, v in data.items() if k in known}
        payload.setdefault("name", env_id)
        payload.setdefault("platform_type", "custom")
        if not isinstance(payload["name"], str) or not isinstance(payload["platform_type"], str):
            raise TypeError("Environment 'name' and 'platform_type' must be strings")
        gov_paths = payload.get("governance_paths", [])
        if not isinstance(gov_paths, list) or not all(isinstance(p, str) for p in gov_paths):
            raise TypeError("Environment 'governance_paths' must be a list of strings")
        policy = payload.get("policy", "enforced")
        if not isinstance(policy, str) or policy not in VALID_POLICIES:
            raise ValueError(f"Invalid environment policy {policy!r}")
        for bool_field in ("is_global", "enabled", "protect_root"):
            if bool_field in payload and not isinstance(payload[bool_field], bool):
                raise TypeError(f"Environment '{bool_field}' must be a boolean")
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
        # The root stays writable: Antigravity saves config.json by atomic replace (new file +
        # rename) in this directory, which a read-only root would break. Top-level governance
        # files are still protected against in-place edits; replacing one is detected by FIM.
        protect_root=False,
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
        self.last_discovery_note = ""
        self.load()

    def _fail_closed_default(self) -> None:
        default_global = default_antigravity_environment()
        self._environments = {"antigravity": default_global}
        try:
            self.lock("antigravity")
        except Exception:
            pass

    def load(self) -> None:
        """Loads environment definitions from disk (or a legacy registry) and seeds defaults."""
        self._environments = {}
        source = self.config_path if self.config_path.exists() else self.legacy_config_path
        if source is not None:
            try:
                data = read_json_strict(source)
            except CorruptStateError as e:
                self._fail_closed_default()
                raise RegistryError(f"Environment registry {source} is corrupt ({e})") from e
            except OSError as e:
                self._fail_closed_default()
                raise RegistryError(f"Environment registry {source} cannot be read ({e})") from e
            if data is not None:
                if not isinstance(data, dict):
                    self._fail_closed_default()
                    raise RegistryError(f"Environment registry {source} is not a JSON object.")
                raw_envs = data.get("environments", [])
                if not isinstance(raw_envs, list):
                    self._fail_closed_default()
                    raise RegistryError(f"Environment registry {source}: 'environments' must be a list.")
                for env_data in raw_envs:
                    try:
                        env = AgentEnvironment.from_dict(env_data)
                    except (KeyError, TypeError, ValueError) as e:
                        self._fail_closed_default()
                        raise RegistryError(
                            f"Environment registry {source} contains a malformed environment entry ({e})."
                        ) from e
                    self._migrate_broad_seams(env)
                    self._environments[env.id] = env

        default_global = default_antigravity_environment()
        existing = self._environments.get("antigravity")
        if existing is None:
            self._environments["antigravity"] = default_global
        else:
            # The global root always follows the active configuration directory, and the
            # governance scope is upgraded with any seams introduced by newer releases.
            existing.root_path = default_global.root_path
            existing.platform_type = default_global.platform_type
            existing.is_global = True
            existing.enabled = True
            existing.policy = "enforced"
            existing.protect_root = default_global.protect_root
            existing.governance_paths = [s for s in existing.governance_paths if s != "MISTAKES.md"]
            for seam in ANTIGRAVITY_GOVERNANCE_SEAMS:
                if seam not in existing.governance_paths:
                    existing.governance_paths.append(seam)

    @staticmethod
    def _migrate_broad_seams(env: AgentEnvironment) -> None:
        """Replaces pre-1.4.0 whole-directory seams (e.g. `.claude`, workspace `.gemini`) with the rule-file whitelist."""
        broad = LEGACY_BROAD_SEAMS.get(env.platform_type)
        if env.is_global or not broad or not broad.intersection(env.governance_paths):
            return
        kept = [s for s in env.governance_paths if s not in broad]
        replacement_seams = (
            ANTIGRAVITY_WORKSPACE_SEAMS
            if env.platform_type == "antigravity"
            else KNOWN_PLATFORMS[env.platform_type]["governance_seams"]
        )
        for seam in replacement_seams:
            if seam not in kept:
                kept.append(seam)
        env.governance_paths = kept

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
        self.last_discovery_note = ""

        # The home directory (or a filesystem root) is not a workspace: from there `.gemini`,
        # `.claude` and `.cursor` are the tools' own global runtime directories. A GUI started
        # from a desktop launcher runs with $HOME as its working directory.
        home = Path.home().resolve()
        if target_ws == home or target_ws == Path(target_ws.anchor) or home.is_relative_to(target_ws):
            self.last_discovery_note = (
                f"{target_ws} is the home directory (or one of its ancestors), not a project workspace; "
                f"only the global Antigravity environment was considered. Run discovery from a project "
                f"folder or pass --workspace <project>."
            )
            if register:
                self.save()
            return discovered

        candidates: List[Tuple[str, str, str, List[str]]] = []
        antigravity_root = self._environments["antigravity"].get_root()
        if target_ws != antigravity_root and (
            (target_ws / ".gemini").exists()
            or (target_ws / "GEMINI.md").exists()
            or (target_ws / ".harness").exists()
        ):
            seams = [s for s in ANTIGRAVITY_WORKSPACE_SEAMS if os.path.lexists(target_ws / s)]
            if seams:
                candidates.append(("antigravity", "antigravity-workspace", f"Antigravity Workspace ({target_ws.name})", seams))
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
                    policy=DISCOVERED_DEFAULT_POLICY.get(platform_type, "monitored"),
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
        if not env.id or env.id == "antigravity" or env.id in self._environments:
            raise ValueError(f"Environment ID '{env.id}' is reserved or already registered.")
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

    @staticmethod
    def is_weakening(current: str, new: str) -> bool:
        """True when `new` protects less than `current` (such changes need human approval)."""
        return POLICY_STRENGTH.get(new, 0) < POLICY_STRENGTH.get(current, 0)

    def set_policy(self, env_id: str, policy: str) -> bool:
        if policy not in VALID_POLICIES:
            raise ValueError(f"Invalid policy '{policy}'. Must be one of {', '.join(VALID_POLICIES)}.")
        env = self.get_environment(env_id)
        if not env:
            return False
        previous = env.policy
        env.policy = policy
        self.save()
        audit("registry.policy", env=env.id, previous=previous, policy=policy)
        return True

    # ------------------------------------------------------------------
    # Protection
    # ------------------------------------------------------------------
    def _targets(self, env_id: Optional[str]) -> Tuple[List[AgentEnvironment], str]:
        if env_id:
            env, err = self.resolve_environment(env_id)
            return ([env] if env else []), err
        return self.list_environments(), ""

    @staticmethod
    def symlinked_root_issue(env: AgentEnvironment) -> str:
        """Non-empty when the global root is itself a symlink (locking would protect its target)."""
        if not env.is_global or env.id != "antigravity":
            return ""
        link = config_dir_symlink()
        if link is None:
            return ""
        return (
            f"{link} is a symlink to {os.path.realpath(link)}; Guard refuses to lock it because that "
            f"would write-protect the link target. Reinstall in copy mode (python3 install.py)."
        )

    def protection_issues(self, env: AgentEnvironment) -> List[str]:
        """Reasons why an environment is not fully write-protected (empty list = protected)."""
        issues: List[str] = []
        root_issue = self.symlinked_root_issue(env)
        if root_issue:
            return [root_issue]
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
            if not env.enabled or env.policy == "disabled" or self.symlinked_root_issue(env):
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
                state = "disabled" if not env.enabled else f"policy={env.policy}"
                details.append(f"Skipped {env.name} ({state}): NOT write-protected")
                # Asking for one specific environment is a request to protect it: a skip is not
                # success (a lease relock or boot check must never report a writable tree as locked).
                if env_id:
                    all_ok = False
                continue
            root_issue = self.symlinked_root_issue(env)
            if root_issue:
                all_ok = False
                details.append(f"[{env.name}] {root_issue}")
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
        audit("registry.lock", target=env_id or "all", ok=all_ok, detail=" | ".join(details)[:2000])
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
        audit("registry.unlock", target=env_id or "all", ok=all_ok, detail=" | ".join(details)[:2000])
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

    def should_lock_after_restore(self) -> bool:
        env = self.registry.get_environment(self.env_id)
        return bool(env and env.enabled and env.policy == "enforced")


CONSOLIDATED_SKILL_SLUGS: Tuple[str, ...] = (
    "antislop-ui",
    "antislop-copywriting",
    "antislop-human",
    "antislop-layoutmobile",
    "antislop-code",
    "silk-design",
    "marathon",
    "unlazy",
    "architecture-decision-records",
    "mistake-proofing",
    "dependency-upgrade",
    "test-design",
    "visualizer",
    "security-review",
    "procoder",
)

RELOCATED_SKILL_SCRIPTS: Dict[str, str] = {
    "skills/antislop-human/contrast-mcp.py": "skills/antislop/scripts/contrast-mcp.py",
    "skills/antislop-human/contrast-check.py": "skills/antislop/scripts/contrast-check.py",
    "skills/antislop-copywriting/scripts/check_synthetic_markers.py": "skills/antislop/scripts/check_synthetic_markers.py",
}


def _is_within_lexically(path: Path, root: Path) -> bool:
    try:
        Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
        return True
    except ValueError:
        return False


def migrate_harness_mcp_config(
    target_dir: Path,
    source_dir: Path,
    *,
    dry_run: bool = False,
    python_executable: Optional[str] = None,
    backup_fn: Optional[Callable[[Path], Any]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> bool:
    """Repoints harness-owned MCP skill scripts (including ADR-0009 relocations) and pins bare python."""
    _emit = log_fn or (lambda _msg: None)
    mcp = target_dir / "mcp_config.json"
    if os.path.islink(mcp):
        _emit(f"[WARN] {mcp} is a symbolic link; skipping MCP path migration.")
        return False
    if not mcp.is_file():
        return False
    try:
        data = json.loads(mcp.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _emit(f"[WARN] Could not parse {mcp}: {exc}; skipping MCP path migration.")
        return False
    if not isinstance(data, dict):
        _emit(f"[WARN] {mcp} root is not a JSON object; skipping MCP path migration.")
        return False
    mcp_servers = data.get("mcpServers")
    if mcp_servers is not None and not isinstance(mcp_servers, dict):
        _emit(f"[WARN] {mcp} 'mcpServers' is not a JSON object; skipping MCP path migration.")
        return False

    repo_skills_dir = source_dir / "skills"
    target_skills_dir = target_dir / "skills"
    harness_skills: set[str] = set(CONSOLIDATED_SKILL_SLUGS)
    try:
        if repo_skills_dir.is_dir():
            harness_skills.update(p.name for p in repo_skills_dir.iterdir() if p.is_dir())
    except OSError as exc:
        _emit(f"[WARN] Could not scan {repo_skills_dir}: {exc}")

    try:
        target_dir_res: Optional[Path] = target_dir.resolve()
    except (OSError, RuntimeError, ValueError):
        target_dir_res = None
    try:
        source_dir_res: Optional[Path] = source_dir.resolve()
    except (OSError, RuntimeError, ValueError):
        source_dir_res = None
    try:
        target_skills_res: Optional[Path] = target_skills_dir.resolve()
    except (OSError, RuntimeError, ValueError):
        target_skills_res = None

    bare_python_names = {"python", "python3", "python.exe", "python3.exe"}
    if getattr(sys, "frozen", False) and (python_executable is None or python_executable == sys.executable):
        pin_exec = ""
    else:
        pin_exec = python_executable if python_executable is not None else sys.executable

    changed = False
    repointed = False
    pinned = False
    for server in (mcp_servers or {}).values():
        if not isinstance(server, dict):
            continue
        args = server.get("args") or []
        if not isinstance(args, list):
            continue
        is_harness_server = False
        for i, arg in enumerate(args):
            if not isinstance(arg, str) or not arg.strip() or "\x00" in arg:
                continue
            arg_str = arg.strip()
            expanded_str = os.path.expanduser(arg_str)
            raw_path = Path(expanded_str)
            arg_path: Optional[Path] = None
            if raw_path.is_absolute():
                if ".." in raw_path.parts or ".." in expanded_str.replace("\\", "/").split("/"):
                    continue
                arg_path = Path(os.path.abspath(raw_path))
                parts: Tuple[str, ...] = arg_path.parts
            elif expanded_str.startswith("/") and not expanded_str.startswith("//") and "\\" not in expanded_str:
                posix_path = PurePosixPath(expanded_str)
                if ".." in posix_path.parts:
                    continue
                parts = posix_path.parts
            else:
                continue
            skill_indices = [idx for idx, part in enumerate(parts) if part == "skills"]
            for skills_idx in reversed(skill_indices):
                skill_name = parts[skills_idx + 1] if (skills_idx + 1) < len(parts) else ""
                if skill_name not in harness_skills:
                    continue
                if Path(parts[-1]).suffix.lower() not in (".py", ".mjs", ".js", ".cjs", ".sh"):
                    continue
                prefix_res: Optional[Path] = None
                if arg_path is not None:
                    prefix_dir = Path(*parts[:skills_idx]) if skills_idx > 0 else Path("/")
                    try:
                        prefix_res = prefix_dir.resolve()
                    except (OSError, RuntimeError, ValueError):
                        prefix_res = None
                is_repo_tree = (
                    (skills_idx > 0 and parts[skills_idx - 1] == "antigravity-harness")
                    or (arg_path is not None and _is_within_lexically(arg_path, repo_skills_dir))
                    or (prefix_res is not None and source_dir_res is not None and prefix_res == source_dir_res)
                )
                is_target_tree = (
                    arg_path is not None and _is_within_lexically(arg_path, target_skills_dir)
                ) or (
                    prefix_res is not None and target_dir_res is not None and prefix_res == target_dir_res
                )
                raw_rel_posix = "/".join(parts[skills_idx:])
                mapped_rel_posix = RELOCATED_SKILL_SCRIPTS.get(raw_rel_posix, raw_rel_posix)
                mapped_rel = Path(*mapped_rel_posix.split("/"))
                if is_repo_tree or (is_target_tree and mapped_rel_posix != raw_rel_posix):
                    candidate = target_dir / mapped_rel
                    try:
                        cand_within = (
                            _is_within_lexically(candidate, target_skills_dir)
                            and not os.path.islink(candidate)
                            and target_skills_res is not None
                            and is_within(candidate.resolve(), target_skills_res)
                        )
                    except (OSError, RuntimeError, ValueError):
                        cand_within = False
                    if not cand_within:
                        _emit(f"[WARN] Skipping unsafe MCP target {candidate}; leaving argument unchanged.")
                        continue
                    src_candidate = source_dir / mapped_rel
                    try:
                        dest_ready = (not os.path.islink(candidate) and candidate.is_file()) or (
                            dry_run and not os.path.islink(src_candidate) and src_candidate.is_file()
                        )
                    except (OSError, RuntimeError, ValueError):
                        dest_ready = False
                    if dest_ready:
                        is_harness_server = True
                        if str(candidate) != arg:
                            args[i] = str(candidate)
                            changed = True
                            repointed = True
                    else:
                        _emit(f"[WARN] Relocated MCP script target {candidate} not found; leaving argument unchanged.")
                    break
                if is_target_tree:
                    is_harness_server = True
                    break

        if is_harness_server:
            cmd = server.get("command")
            if (
                bool(pin_exec)
                and isinstance(cmd, str)
                and cmd.strip().lower() in bare_python_names
                and cmd != pin_exec
            ):
                server["command"] = pin_exec
                changed = True
                pinned = True

    if changed:
        actions: List[str] = []
        if repointed:
            actions.append("repoint skill scripts")
        if pinned:
            actions.append(f"pin Python to {pin_exec}")
        summary = " & ".join(actions) or "update harness MCP entries"
        if dry_run:
            _emit(f"[DRY-RUN] Would update {mcp} ({summary})")
        else:
            if backup_fn is not None:
                backup_fn(mcp)
            atomic_write_json(mcp, data, mode=0o600)
            if repointed:
                _emit("[CONFIGURED] mcp_config.json now points to the protected skill copies")
            else:
                _emit(f"[CONFIGURED] Updated {mcp} ({summary})")
        return True
    return False
