"""
porter/analyzer.py — Pre-flight suitability, adaptability, and redundancy analyzer.
Zero-dependency: strictly uses Python standard library.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from porter.frontmatter import FrontmatterError, frontmatter_description, parse_frontmatter, split_frontmatter
from porter.manifest import default_harness_root
from porter.models import SuitabilityIssue, SuitabilityReport
from porter.sanitizer import ConstitutionalSanitizer

_AGENT_NAME_RE = re.compile(r"(?i)\b([a-z0-9_]+(?:-[a-z0-9_]+)*-(?:auditor|verifier|hunter|agent|resolver|reviewer))\b")
_PERSONA_RE = re.compile(r"(?i)\byou\s+are\s+(?:an?\s+)?(?:autonomous\s+|expert\s+|independent\s+|read-only\s+)*"
                         r"(?:sub-?agent|auditor|verifier|reviewer|agent)\b")
_MUTATING_AGENT_TOOLS = frozenset({
    "bash", "write", "edit", "multiedit", "notebookedit",
    "run_command", "write_file", "edit_file", "write_to_file",
    "replace_file_content", "multi_replace_file_content",
    "execute", "shell", "rm", "chmod", "killshell", "bashoutput",
})


class SuitabilityAnalyzer:
    """Evaluates external rules for compatibility, safety, and ecosystem fit before any file is written."""

    def __init__(self, harness_root: Optional[Path] = None):
        self.harness_root = Path(harness_root) if harness_root else default_harness_root()
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
                            desc = frontmatter_description(skill_file.read_text(encoding="utf-8", errors="ignore"))
                        except OSError:
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
                    desc = frontmatter_description(item.read_text(encoding="utf-8", errors="ignore"))
                except OSError:
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
        """
        Decides whether content should be a skill, subagent, or project rule. A document is
        an agent only if it DEFINES a persona near its top ("You are an ... auditor") or its
        frontmatter/file name says so — merely mentioning "auditor" is not enough.
        """
        head = "\n".join(content.splitlines()[:25])
        declared_kind = ""
        try:
            meta, _ = parse_frontmatter(content)
            declared_kind = str(meta.get("kind") or meta.get("type") or "").lower()
        except FrontmatterError:
            meta = {}
        stem = Path(filename).stem.lower()
        name_hit = _AGENT_NAME_RE.search(stem) or _AGENT_NAME_RE.search(head)
        if declared_kind in ("agent", "subagent") or _PERSONA_RE.search(head) or _AGENT_NAME_RE.fullmatch(stem or "-"):
            name = (name_hit.group(1).lower() if name_hit else "") or str(meta.get("name") or "") or stem or "imported-agent"
            return "agent", re.sub(r"[^a-z0-9_-]", "-", name).strip("-") or "imported-agent"

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

    @staticmethod
    def _references(content: str, name: str) -> bool:
        """True when `name` is referenced as an identifier (heading, `code`, /command, skills/<name>)."""
        n = re.escape(name)
        patterns = [
            rf"(?im)^#+\s.*\b{n}\b",
            rf"`{n}`",
            rf"(?<![\w/])/{n}\b",
            rf"\b(?:skills|agents)/{n}\b",
        ]
        if "-" in name:
            patterns.append(rf"\b{n}\b")
        return any(re.search(p, content) for p in patterns)

    def find_redundancies(self, content: str, name: str) -> List[Dict[str, str]]:
        """Identifies overlap with existing skills/subagents (identifier references, not plain words)."""
        redundancies = []
        lower_name = name.lower()
        for kind, known, label in (("Skill", self.known_skills, "skill"), ("Agent", self.known_agents, "subagent")):
            for k_name, k_desc in known.items():
                if k_name == lower_name or self._references(content, k_name):
                    redundancies.append({
                        "name": k_name,
                        "type": kind,
                        "reason": f"Overlap with existing {label} `{k_name}` ({k_desc[:60]}...)",
                    })
        return redundancies

    @staticmethod
    def _audit_frontmatter_privileges(content: str) -> List[SuitabilityIssue]:
        """Flags non-read-only `access:` or mutating `tools:` declarations in external frontmatter."""
        reasons: List[str] = []
        meta: Optional[Dict[str, object]] = None
        try:
            parsed, _ = parse_frontmatter(content)
            meta = dict(parsed)
        except FrontmatterError:
            try:
                raw_fm, _ = split_frontmatter(content)
            except FrontmatterError:
                raw_fm = None
            if raw_fm:
                m_acc = re.search(r"(?im)^access\s*:\s*['\"]?([^\s'\"#]+)", raw_fm)
                if m_acc and m_acc.group(1).strip().lower() != "read-only":
                    reasons.append(f"Frontmatter declares non-read-only access ({m_acc.group(1)!r})")
                m_tools = re.search(r"(?im)^tools\s*:\s*(.+)$", raw_fm)
                if m_tools:
                    toks = [t.strip(" []'\"") for t in re.split(r"[,\s]+", m_tools.group(1)) if t.strip(" []'\"")]
                    bad = [t for t in toks if t.lower() in _MUTATING_AGENT_TOOLS]
                    if bad:
                        reasons.append(f"Frontmatter declares mutating tools ({', '.join(bad)})")

        if meta is not None:
            if "access" in meta:
                acc_raw = meta.get("access")
                acc_norm = str(acc_raw).strip().lower() if isinstance(acc_raw, str) else ""
                if acc_norm != "read-only":
                    reasons.append(f"Frontmatter declares non-read-only access ({acc_raw!r})")
            if "tools" in meta:
                raw_tools = meta.get("tools")
                tokens: List[str] = []
                if isinstance(raw_tools, list):
                    tokens = [str(item).strip() for item in raw_tools if str(item).strip()]
                elif isinstance(raw_tools, str):
                    tokens = [tok.strip() for tok in re.split(r"[,\s]+", raw_tools) if tok.strip()]
                bad_tools = [tok for tok in tokens if tok.lower() in _MUTATING_AGENT_TOOLS]
                if bad_tools:
                    reasons.append(f"Frontmatter declares mutating tools ({', '.join(bad_tools)})")
            ew = meta.get("EnableWriteTools")
            if ew is True or (isinstance(ew, str) and ew.strip().lower() == "true"):
                reasons.append("Frontmatter enables write tools (EnableWriteTools: true)")

        if not reasons:
            return []
        return [
            SuitabilityIssue(
                severity="WARNING",
                category="TOOL_LEAK",
                message="; ".join(reasons) + " — custom subagents in Antigravity must remain read-only.",
                suggested_fix="Clamp imported agent frontmatter to 'access: read-only' and strip mutating 'tools:' keys.",
            )
        ]

    def analyze(self, content: str, source_identifier: str = "unnamed_source") -> SuitabilityReport:
        """Executes full pre-flight inspection and returns SuitabilityReport."""
        detected_format = self.detect_format(content, source_identifier)
        target_type, rec_name = self.classify_target_type(content, source_identifier)

        # Audit constitutional alignment
        issues = ConstitutionalSanitizer.audit_content(content)
        issues.extend(self._audit_frontmatter_privileges(content))

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
