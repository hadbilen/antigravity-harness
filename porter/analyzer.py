"""
porter/analyzer.py — Pre-flight suitability, adaptability, and redundancy analyzer.
Zero-dependency: strictly uses Python standard library.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from porter.models import SuitabilityIssue, SuitabilityReport
from porter.sanitizer import ConstitutionalSanitizer


class SuitabilityAnalyzer:
    """Evaluates external rules for compatibility, safety, and ecosystem fit before any file is written."""

    def __init__(self, harness_root: Optional[Path] = None):
        self.harness_root = harness_root or Path(__file__).resolve().parent.parent
        self.known_skills = self._load_known_skills()
        self.known_agents = self._load_known_agents()

    def _load_known_skills(self) -> Dict[str, str]:
        """Discovers existing skills in the harness to detect overlap."""
        skills_dir = self.harness_root / "skills"
        skills = {}
        if skills_dir.is_dir():
            for item in skills_dir.iterdir():
                if item.is_dir():
                    skill_file = item / "SKILL.md"
                    desc = ""
                    if skill_file.is_file():
                        try:
                            content = skill_file.read_text(encoding="utf-8", errors="ignore")
                            match = re.search(r"description:\s*([^\n\r]+)", content)
                            if match:
                                desc = match.group(1).strip()
                        except Exception:
                            pass
                    skills[item.name.lower()] = desc
        return skills

    def _load_known_agents(self) -> Dict[str, str]:
        """Discovers existing subagents in the harness."""
        agents_dir = self.harness_root / "agents"
        agents = {}
        if agents_dir.is_dir():
            for item in agents_dir.glob("*.md"):
                desc = ""
                try:
                    content = item.read_text(encoding="utf-8", errors="ignore")
                    match = re.search(r"description:\s*([^\n\r]+)", content)
                    if match:
                        desc = match.group(1).strip()
                except Exception:
                    pass
                agents[item.stem.lower()] = desc
        return agents

    def detect_format(self, content: str, filename: str = "") -> str:
        """Determines the origin format of the rule."""
        lower_fn = filename.lower()
        if lower_fn.endswith(".mdc"):
            return "cursor_mdc"
        if "claude.md" in lower_fn or ".claude" in lower_fn:
            return "claude_md"
        if "agents.md" in lower_fn:
            return "agents_md"
        if "conventions.md" in lower_fn:
            return "aider_conventions"

        # Content heuristics
        if re.search(r"^---\s*\nglobs:\s*", content, re.MULTILINE):
            return "cursor_mdc"
        if re.search(r"^---\s*\nname:\s*", content, re.MULTILINE):
            return "harness_skill_or_agent"

        return "generic_markdown"

    def classify_target_type(self, content: str, filename: str) -> Tuple[str, str]:
        """Decides whether content should be a skill, subagent, or project rule."""
        lower = content.lower() + " " + filename.lower()

        # Check if it defines a persona / subagent / auditor
        if any(term in lower for term in ["subagent", "auditor", "verifier", "hunter", "you are an agent"]):
            name_match = re.search(r"(?i)\b([a-z0-9_-]+)-(auditor|verifier|hunter|agent|resolver)\b", lower)
            name = name_match.group(0) if name_match else Path(filename).stem or "imported-agent"
            return "agent", name

        # Default to modular skill
        base_name = Path(filename).stem or "imported-rule"
        base_name = re.sub(r"[^a-zA-Z0-9_-]", "-", base_name).strip("-").lower()
        if not base_name or base_name in ["cursorrules", "claude", "agents", "rules"]:
            # Derive name from first heading
            heading = re.search(r"^#+\s*([a-zA-Z0-9\s_-]+)", content, re.MULTILINE)
            if heading:
                base_name = re.sub(r"\s+", "-", heading.group(1).strip().lower())
            else:
                base_name = "custom-skill"
        return "skill", base_name

    def find_redundancies(self, content: str, name: str) -> List[Dict[str, str]]:
        """Identifies any overlap with our existing modular skills and autonomous subagents."""
        redundancies = []
        lower_content = content.lower()
        lower_name = name.lower()

        # Check skills
        for s_name, s_desc in self.known_skills.items():
            if s_name in lower_name or (len(s_name) > 4 and s_name in lower_content):
                redundancies.append({
                    "name": s_name,
                    "type": "Skill",
                    "reason": f"Semantic overlap with existing skill `{s_name}` ({s_desc[:60]}...)"
                })

        # Check agents
        for a_name, a_desc in self.known_agents.items():
            if a_name in lower_name or (len(a_name) > 4 and a_name in lower_content):
                redundancies.append({
                    "name": a_name,
                    "type": "Agent",
                    "reason": f"Role overlap with existing subagent `{a_name}`"
                })

        return redundancies

    def analyze(self, content: str, source_identifier: str = "unnamed_source") -> SuitabilityReport:
        """Executes full pre-flight inspection and returns SuitabilityReport."""
        detected_format = self.detect_format(content, source_identifier)
        target_type, rec_name = self.classify_target_type(content, source_identifier)

        # Audit constitutional alignment
        issues = ConstitutionalSanitizer.audit_content(content)

        # Calculate Constitutional Score (100 base)
        const_score = 100
        for issue in issues:
            if issue.severity == "CRITICAL":
                const_score -= 35
            elif issue.severity == "WARNING":
                const_score -= 15
            elif issue.severity == "INFO":
                const_score -= 5
        const_score = max(0, min(100, const_score))

        # Calculate Adaptability Score
        adapt_score = 90
        if detected_format == "cursor_mdc":
            adapt_score = 95  # Easy YAML frontmatter translation
        elif detected_format == "generic_markdown":
            adapt_score = 80  # Needs frontmatter generation
        if len(content) < 50:
            adapt_score -= 20  # Under-specified
        adapt_score = max(0, min(100, adapt_score))

        # Check redundancy
        redundancies = self.find_redundancies(content, rec_name)

        # Determine import safety
        is_safe = const_score >= 60 and not any(i.severity == "CRITICAL" for i in issues)

        sanitized = ConstitutionalSanitizer.sanitize_for_import(content)

        return SuitabilityReport(
            source_target=source_identifier,
            detected_format=detected_format,
            recommended_type=target_type,
            recommended_name=rec_name,
            constitutional_score=const_score,
            adaptability_score=adapt_score,
            is_safe_to_import=is_safe,
            issues=issues,
            redundancies=redundancies,
            sanitized_content=sanitized
        )
