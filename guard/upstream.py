"""
guard/upstream.py — Bridge to Upstream Auditor Watchdog
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional


REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


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

        from guard.paths import state_dir

        default_state_dir = state_dir()
        state_file_env = os.environ.get("UPSTREAM_STATE_FILE")
        if state_file_env:
            self.state_file = Path(state_file_env).resolve()
        else:
            candidate_state = (default_state_dir / "upstream_state.json").resolve()
            skill_dir = self.target_dir / "skills" / "upstream-auditor"
            legacy_state = (skill_dir / "upstream_state.json").resolve()
            seed_state = (skill_dir / "upstream_state.seed.json").resolve()
            if candidate_state.is_file():
                self.state_file = candidate_state
            elif legacy_state.is_file():
                self.state_file = legacy_state
            elif seed_state.is_file():
                self.state_file = seed_state
            else:
                self.state_file = candidate_state

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

        from guard import __version__

        def query_repo(name: str, info: dict) -> Dict[str, Any]:
            repo = str(info.get("repo", ""))
            branch = str(info.get("branch", "main"))
            local_sha = str(info.get("last_synced_commit", ""))[:7]
            if not REPO_RE.match(repo):
                return {"name": name, "repo": repo, "branch": branch, "local_sha": local_sha,
                        "remote_sha": "", "status": "Invalid repository id", "commit_message": ""}
            query = urllib.parse.urlencode({"sha": branch, "per_page": 1})
            url = f"https://api.github.com/repos/{repo}/commits?{query}"
            headers = {"User-Agent": f"AntigravityGuard-Watchdog/{__version__}"}
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
        """Reports the active model ONLY when it is actually known; nothing here is inferred."""
        env_model = os.environ.get("ANTIGRAVITY_MODEL")
        state = self.load_state()
        recorded = state.get("last_audited_model")
        if env_model:
            active_model, source = env_model, "ANTIGRAVITY_MODEL environment variable"
        elif recorded:
            active_model, source = str(recorded), "last value recorded by the upstream watcher"
        else:
            active_model, source = "Unknown (not detected)", "none"
        tracked_count = len(state.get("tracked_repositories", {}))
        return {
            "active_model": active_model,
            "model_source": source,
            "context_saturation_guard": "Constitution rule (turn count is not measured by Guard)",
            "tracked_ecosystems": str(tracked_count),
        }
