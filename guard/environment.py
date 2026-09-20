"""
guard/environment.py — Multi-Environment Governance & Protection Registry
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from guard.os_adapter import OSProtectionAdapter

KNOWN_PLATFORMS = {
    "antigravity": {
        "name": "Antigravity Harness",
        "governance_seams": ["GEMINI.md", "DESIGN.md", "MISTAKES.md", "skills", "agents", ".harness"],
    },
    "claude": {
        "name": "Claude Code",
        "governance_seams": ["CLAUDE.md", ".claude/commands", ".claude"],
    },
    "codex": {
        "name": "GPT Codex / Copilot",
        "governance_seams": ["AGENTS.md", "CODEX.md", ".codex"],
    },
    "cursor": {
        "name": "Cursor IDE",
        "governance_seams": [".cursorrules", ".cursor/rules", ".cursor"],
    },
    "aider": {
        "name": "Aider",
        "governance_seams": [".aider.conf.yml", ".aiderignore"],
    },
}


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

    def get_root(self) -> Path:
        return Path(self.root_path).resolve()

    def get_governance_paths(self, existing_only: bool = False) -> List[Path]:
        root = self.get_root()
        resolved: List[Path] = []
        for rel in self.governance_paths:
            p = (root / rel).resolve() if not Path(rel).is_absolute() else Path(rel).resolve()
            if not existing_only or p.exists():
                resolved.append(p)
        return resolved

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AgentEnvironment:
        return cls(
            id=data["id"],
            name=data.get("name", data["id"]),
            platform_type=data.get("platform_type", "custom"),
            root_path=data["root_path"],
            governance_paths=data.get("governance_paths", []),
            policy=data.get("policy", "enforced"),
            is_global=data.get("is_global", False),
            enabled=data.get("enabled", True),
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
        if config_path is not None:
            self.config_path = Path(config_path).resolve()
        else:
            harness_config = self.workspace_dir / ".harness" / "environments.json"
            if harness_config.parent.exists():
                self.config_path = harness_config
            else:
                self.config_path = Path.home() / ".gemini" / ".environments.json"

        self.os_adapter = os_adapter or OSProtectionAdapter()
        self._environments: Dict[str, AgentEnvironment] = {}
        self.load()

    def load(self) -> None:
        """Loads environment definitions from disk or initializes defaults."""
        self._environments = {}
        if self.config_path.exists():
            try:
                data = json.loads(self.config_path.read_text(encoding="utf-8"))
                for env_data in data.get("environments", []):
                    env = AgentEnvironment.from_dict(env_data)
                    self._environments[env.id] = env
            except Exception:
                pass

        # If no default global environment is loaded, initialize Antigravity global
        if "antigravity" not in self._environments:
            global_config = (
                Path(os.environ["ANTIGRAVITY_CONFIG_DIR"]).resolve()
                if "ANTIGRAVITY_CONFIG_DIR" in os.environ
                else (Path.home() / ".gemini" / "config").resolve()
            )
            self._environments["antigravity"] = AgentEnvironment(
                id="antigravity",
                name="Antigravity Global Config",
                platform_type="antigravity",
                root_path=str(global_config),
                governance_paths=["GEMINI.md", "DESIGN.md", "MISTAKES.md", "skills", "agents", ".harness"],
                policy="enforced",
                is_global=True,
                enabled=True,
            )

    def save(self) -> None:
        """Saves current environment registry to disk."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": "1.3.0",
            "environments": [env.to_dict() for env in self._environments.values()],
        }
        self.config_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def discover_environments(self, workspace_dir: Optional[Path] = None, register: bool = True) -> List[AgentEnvironment]:
        """
        Auto-detects coding agent governance seams in the workspace or home directories.
        Does not mutate user project files.
        """
        target_ws = (workspace_dir or self.workspace_dir).resolve()
        discovered: List[AgentEnvironment] = []

        # 1. Antigravity Global Environment (Always verified)
        antigravity_env = self._environments.get("antigravity")
        if antigravity_env:
            discovered.append(antigravity_env)

        # 2. Workspace Antigravity
        ws_gemini_config = target_ws / ".gemini"
        ws_gemini_md = target_ws / "GEMINI.md"
        if (ws_gemini_config.exists() or ws_gemini_md.exists()) and target_ws != antigravity_env.get_root():
            env_id = f"antigravity-workspace-{target_ws.name}"
            governance = []
            if ws_gemini_md.exists():
                governance.append("GEMINI.md")
            if (target_ws / "DESIGN.md").exists():
                governance.append("DESIGN.md")
            if (target_ws / "MISTAKES.md").exists():
                governance.append("MISTAKES.md")
            if ws_gemini_config.exists():
                governance.append(".gemini")
            if (target_ws / ".harness").exists():
                governance.append(".harness")

            env = AgentEnvironment(
                id=env_id,
                name=f"Antigravity Workspace ({target_ws.name})",
                platform_type="antigravity",
                root_path=str(target_ws),
                governance_paths=governance or ["GEMINI.md"],
                policy="enforced",
                is_global=False,
            )
            discovered.append(env)

        # 3. Claude Code Workspace
        claude_md = target_ws / "CLAUDE.md"
        claude_dir = target_ws / ".claude"
        if claude_md.exists() or claude_dir.exists():
            env_id = f"claude-{target_ws.name}"
            seams = []
            if claude_md.exists():
                seams.append("CLAUDE.md")
            if claude_dir.exists():
                seams.append(".claude")
            env = AgentEnvironment(
                id=env_id,
                name=f"Claude Code ({target_ws.name})",
                platform_type="claude",
                root_path=str(target_ws),
                governance_paths=seams or ["CLAUDE.md"],
                policy="enforced",
                is_global=False,
            )
            discovered.append(env)

        # 4. GPT Codex / Copilot Workspace
        agents_md = target_ws / "AGENTS.md"
        codex_md = target_ws / "CODEX.md"
        codex_dir = target_ws / ".codex"
        if agents_md.exists() or codex_md.exists() or codex_dir.exists():
            env_id = f"codex-{target_ws.name}"
            seams = []
            if agents_md.exists():
                seams.append("AGENTS.md")
            if codex_md.exists():
                seams.append("CODEX.md")
            if codex_dir.exists():
                seams.append(".codex")
            env = AgentEnvironment(
                id=env_id,
                name=f"GPT Codex ({target_ws.name})",
                platform_type="codex",
                root_path=str(target_ws),
                governance_paths=seams or ["AGENTS.md"],
                policy="enforced",
                is_global=False,
            )
            discovered.append(env)

        # 5. Cursor Workspace
        cursor_rules_file = target_ws / ".cursorrules"
        cursor_dir = target_ws / ".cursor"
        if cursor_rules_file.exists() or cursor_dir.exists():
            env_id = f"cursor-{target_ws.name}"
            seams = []
            if cursor_rules_file.exists():
                seams.append(".cursorrules")
            if cursor_dir.exists():
                seams.append(".cursor")
            env = AgentEnvironment(
                id=env_id,
                name=f"Cursor ({target_ws.name})",
                platform_type="cursor",
                root_path=str(target_ws),
                governance_paths=seams or [".cursorrules"],
                policy="enforced",
                is_global=False,
            )
            discovered.append(env)

        # 6. Aider Workspace
        aider_conf = target_ws / ".aider.conf.yml"
        if aider_conf.exists() or (target_ws / ".aiderignore").exists():
            env_id = f"aider-{target_ws.name}"
            seams = [rel for rel in [".aider.conf.yml", ".aiderignore"] if (target_ws / rel).exists()]
            env = AgentEnvironment(
                id=env_id,
                name=f"Aider ({target_ws.name})",
                platform_type="aider",
                root_path=str(target_ws),
                governance_paths=seams or [".aider.conf.yml"],
                policy="enforced",
                is_global=False,
            )
            discovered.append(env)

        if register:
            for env in discovered:
                if env.id not in self._environments:
                    self._environments[env.id] = env
            self.save()

        return discovered

    def list_environments(self) -> List[AgentEnvironment]:
        return list(self._environments.values())

    def get_environment(self, env_id: str) -> Optional[AgentEnvironment]:
        # Direct lookup or match by platform prefix
        if env_id in self._environments:
            return self._environments[env_id]
        for eid, env in self._environments.items():
            if eid.startswith(env_id) or env.platform_type == env_id:
                return env
        return None

    def register_environment(self, env: AgentEnvironment) -> None:
        self._environments[env.id] = env
        self.save()

    def unregister_environment(self, env_id: str) -> bool:
        if env_id in self._environments:
            del self._environments[env_id]
            self.save()
            return True
        return False

    def set_policy(self, env_id: str, policy: str) -> bool:
        env = self.get_environment(env_id)
        if not env:
            return False
        if policy not in ("enforced", "monitored", "disabled"):
            raise ValueError(f"Invalid policy '{policy}'. Must be 'enforced', 'monitored', or 'disabled'.")
        env.policy = policy
        self.save()
        return True

    def is_locked(self, env_id: Optional[str] = None) -> Dict[str, bool]:
        """Returns map of env_id -> is_locked."""
        results: Dict[str, bool] = {}
        targets = [self.get_environment(env_id)] if env_id else self.list_environments()
        for env in targets:
            if not env or not env.enabled:
                continue
            if env.policy == "disabled":
                results[env.id] = False
                continue

            paths = env.get_governance_paths(existing_only=True)
            if not paths:
                # If no paths exist yet, check root directory
                results[env.id] = self.os_adapter.is_locked(env.get_root())
            else:
                results[env.id] = self.os_adapter.is_locked(paths)
        return results

    def lock(self, env_id: Optional[str] = None) -> Tuple[bool, str]:
        """Locks targeted or all enforced environments."""
        targets = [self.get_environment(env_id)] if env_id else self.list_environments()
        details: List[str] = []
        all_ok = True

        for env in targets:
            if not env:
                return False, f"Environment '{env_id}' not found."
            if not env.enabled or env.policy != "enforced":
                details.append(f"Skipped {env.name} (policy={env.policy})")
                continue

            paths = env.get_governance_paths(existing_only=True)
            if not paths:
                # Global environment fallback to full directory
                if env.is_global:
                    ok, msg = self.os_adapter.lock(env.get_root())
                else:
                    ok, msg = True, "Zero active governance files found to lock."
            else:
                ok, msg = self.os_adapter.lock(paths)

            if not ok:
                all_ok = False
            details.append(f"[{env.name}] {msg}")

        return all_ok, "\n".join(details)

    def unlock(self, env_id: Optional[str] = None) -> Tuple[bool, str]:
        """Unlocks targeted or all environments."""
        targets = [self.get_environment(env_id)] if env_id else self.list_environments()
        details: List[str] = []
        all_ok = True

        for env in targets:
            if not env:
                return False, f"Environment '{env_id}' not found."
            if not env.enabled or env.policy == "disabled":
                continue

            paths = env.get_governance_paths(existing_only=True)
            if not paths:
                if env.is_global:
                    ok, msg = self.os_adapter.unlock(env.get_root())
                else:
                    ok, msg = True, "Zero active governance files found to unlock."
            else:
                ok, msg = self.os_adapter.unlock(paths)

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
