"""
porter/models.py — Data structures for the Porter ecosystem bridge.
Zero-dependency: strictly uses Python standard library dataclasses.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class HarnessRule:
    """Represents an extracted or synthesized engineering rule."""
    name: str
    description: str
    content: str
    globs: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    target_type: str = "rule"  # "rule", "skill", "agent", "constitution"


@dataclass
class HarnessSkill:
    """Represents a modular harness skill."""
    name: str
    description: str
    content: str
    subfiles: Dict[str, str] = field(default_factory=dict)


@dataclass
class HarnessAgent:
    """Represents an autonomous subagent definition."""
    name: str
    description: str
    content: str


@dataclass
class SuitabilityIssue:
    """An issue detected during constitutional and suitability analysis."""
    severity: str  # "CRITICAL", "WARNING", "INFO"
    category: str  # "TEST_INVARIANT", "SYCOPHANCY", "AI_SLOP", "TOOL_LEAK", "OVERLAP"
    message: str
    suggested_fix: str


@dataclass
class SuitabilityReport:
    """Comprehensive pre-flight report evaluated before any file mutation."""
    source_target: str
    detected_format: str  # "cursor_mdc", "claude_md", "agents_md", "generic_markdown", "unknown"
    recommended_type: str  # "skill", "agent", "rule", "convention"
    recommended_name: str
    constitutional_score: int  # 0 to 100
    adaptability_score: int    # 0 to 100
    is_safe_to_import: bool
    issues: List[SuitabilityIssue] = field(default_factory=list)
    redundancies: List[Dict[str, str]] = field(default_factory=list)
    sanitized_content: str = ""

    def to_markdown(self) -> str:
        """Renders report in clean GitHub-flavored markdown for user inspection."""
        status_badge = "✅ SAFE TO IMPORT" if self.is_safe_to_import else "⚠️ CAUTION / CONSTITUTIONAL ISSUES"
        lines = [
            f"# Porter Suitability & Adaptability Report",
            f"",
            f"**Target:** `{self.source_target}`",
            f"**Status:** {status_badge}",
            f"**Detected Format:** `{self.detected_format}`",
            f"**Recommended Classification:** `{self.recommended_type}` (Name: `{self.recommended_name}`)",
            f"**Constitutional Alignment Score:** `{self.constitutional_score}/100`",
            f"**Ecosystem Adaptability Score:** `{self.adaptability_score}/100`",
            f"",
            f"---",
            f"",
            f"### 1. Constitutional & Hygiene Findings",
        ]

        if not self.issues:
            lines.append("Zero constitutional violations or AI-slop detected. Clean import candidate.")
        else:
            for issue in self.issues:
                prefix = "🚨 [CRITICAL]" if issue.severity == "CRITICAL" else "⚠️ [WARNING]" if issue.severity == "WARNING" else "ℹ️ [INFO]"
                lines.append(f"- {prefix} **{issue.category}**: {issue.message}")
                lines.append(f"  *Fix:* {issue.suggested_fix}")

        lines.extend([
            f"",
            f"### 2. Redundancy & Existing Ecosystem Overlap",
        ])
        if not self.redundancies:
            lines.append("No direct overlap with existing custom skills or subagents.")
        else:
            for red in self.redundancies:
                lines.append(f"- **Matches `{red.get('name')}`** ({red.get('type')}): {red.get('reason')}")

        lines.extend([
            f"",
            f"### 3. Sanitized Action Plan",
            f"- Recommended action: Convert into `skills/{self.recommended_name}/SKILL.md`" if self.recommended_type == "skill" else f"- Recommended action: Add as `{self.recommended_type}` definition",
            f"- Antislop and constitutional de-slop applied: Ready for user approval gate.",
        ])

        return "\n".join(lines)


@dataclass
class UniversalManifest:
    """
    Lossless canonical machine-readable representation of the entire harness.
    Guarantees zero information decay across multi-hop migrations (A -> B -> C).
    """
    version: str = "1.3.0"
    schema_version: str = "1.0.0"
    generated_at: str = ""
    constitution: Dict[str, Any] = field(default_factory=dict)
    design_contract: Dict[str, Any] = field(default_factory=dict)
    skills: List[Dict[str, Any]] = field(default_factory=list)
    agents: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
