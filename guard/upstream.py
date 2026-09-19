"""
guard/upstream.py — Bridge to Upstream Auditor Watchdog
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class UpstreamAuditorBridge:
    """
    Proactively checks the 7 tracked community repositories and active model status
    without requiring LLM token expenditure.
    """

    def __init__(self, target_dir: Optional[Path] = None):
        if target_dir is None:
            config_env = os.environ.get("ANTIGRAVITY_CONFIG_DIR")
            self.target_dir = Path(config_env).resolve() if config_env else Path.home() / ".gemini" / "config"
        else:
            self.target_dir = Path(target_dir).resolve()

        self.state_file = self.target_dir / "skills" / "upstream-auditor" / "upstream_state.json"

    def load_state(self) -> Dict[str, Any]:
        """Loads state from upstream_state.json or returns default tracked repo structure."""
        if self.state_file.is_file():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        # Default fallback tracked repositories
        return {
            "last_skills_audit_timestamp": None,
            "skills_audit_interval_hours": 72,
            "tracked_repositories": {
                "antislop": {"repo": "miqdadbadjuber/anti-slop", "branch": "main", "last_synced_commit": "d8529a6"},
                "chisle": {"repo": "JayPokale/Chisle", "branch": "main", "last_synced_commit": "47b7dd7"},
                "unlazy": {"repo": "Leonxlnx/unlazy", "branch": "main", "last_synced_commit": "1667149"},
                "procoder": {"repo": "azrtydxb/procoder", "branch": "main", "last_synced_commit": "f8c7fca"},
                "silk-design": {"repo": "bendrape1-byte/silk-design", "branch": "main", "last_synced_commit": "0f530f0"},
                "everything-claude-code": {"repo": "affaan-m/everything-claude-code", "branch": "main", "last_synced_commit": "b2279eb"},
                "skills": {"repo": "mattpocock/skills", "branch": "main", "last_synced_commit": "c55ee46"},
            },
        }

    def check_repositories(self, timeout: float = 3.0) -> List[Dict[str, Any]]:
        """Queries tracked repositories in parallel to detect upstream commit drift."""
        state = self.load_state()
        tracked = state.get("tracked_repositories", {})
        results: List[Dict[str, Any]] = []

        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not token:
            try:
                p = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=2)
                if p.returncode == 0 and p.stdout.strip():
                    token = p.stdout.strip()
            except Exception:
                pass

        def query_repo(name: str, info: dict) -> Dict[str, Any]:
            repo = info.get("repo", "")
            branch = info.get("branch", "main")
            local_sha = info.get("last_synced_commit", "")[:7]
            url = f"https://api.github.com/repos/{repo}/commits?sha={branch}&per_page=1"
            headers = {"User-Agent": "AntigravityGuard-Watchdog/1.2"}
            if token:
                headers["Authorization"] = f"token {token}"
            req = urllib.request.Request(url, headers=headers)

            remote_sha = ""
            status = "Unknown"
            commit_msg = ""

            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode())
                    if data and isinstance(data, list):
                        remote_sha = data[0]["sha"][:7]
                        commit_msg = data[0].get("commit", {}).get("message", "").splitlines()[0]
                        if local_sha and remote_sha:
                            status = "Up-to-date" if local_sha == remote_sha else "Updates Available"
                        else:
                            status = "Remote Found"
            except Exception as e:
                status = f"Network Error ({type(e).__name__})"

            return {
                "name": name,
                "repo": repo,
                "branch": branch,
                "local_sha": local_sha,
                "remote_sha": remote_sha,
                "status": status,
                "commit_message": commit_msg,
            }

        with ThreadPoolExecutor(max_workers=min(len(tracked) or 1, 7)) as executor:
            future_to_name = {executor.submit(query_repo, name, info): name for name, info in tracked.items()}
            for future in as_completed(future_to_name):
                try:
                    results.append(future.result())
                except Exception:
                    pass

        # Sort results deterministically by name
        results.sort(key=lambda x: x["name"])
        return results

    def get_model_drift_status(self) -> Dict[str, str]:
        """Detects active model environment status."""
        active_model = os.environ.get("ANTIGRAVITY_MODEL", "Gemini 3.8 Flash (High)")
        return {
            "active_model": active_model,
            "architecture": "Google DeepMind Multimodal Foundation Engine",
            "tier_support": "Tier 1 (Fast Path), Tier 2 (Harness/ADR), Tier 3 (Auditor Enforced)",
            "context_saturation_guard": "Enforced at 25 turns",
        }
