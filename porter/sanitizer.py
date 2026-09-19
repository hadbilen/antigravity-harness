"""
porter/sanitizer.py — Constitutional de-slop, sycophancy filter, and invariant protector.
Zero-dependency: uses Python standard library re and string manipulation.
"""

from __future__ import annotations

import re
from typing import List, Tuple
from porter.models import SuitabilityIssue


# Patterns indicating test weakening (Strictly prohibited by Goodhart's Invariant)
TEST_WEAKENING_PATTERNS = [
    (r"(?i)\b(skip|ignore)\b.*\btests?\b", "Directives suggesting skipping or ignoring tests"),
    (r"(?i)\b(relax|loosen|modify)\b.*\bassertions?\b", "Directives suggesting weakening assertions"),
    (r"(?i)\bcomment\s+out\b.*\btest", "Directives suggesting commenting out failing tests"),
    (r"(?i)\bchange\s+the\s+test\s+to\s+pass\b", "Directives suggesting modifying tests to pass gates"),
]

# Patterns indicating conversational sycophancy and anti-engineering flattery
SYCOPHANCY_PATTERNS = [
    (r"(?i)\balways\s+agree\s+with\s+the\s+user\b", "Rules forcing automatic agreement with user premises"),
    (r"(?i)\bapologize\s+(profusely|always|sincerely)\b", "Forced apologetic conversational filler"),
    (r"(?i)\bnever\s+(disagree|refuse|contradict)\b", "Prohibition on objective technical disagreement"),
    (r"(?i)\bvalidate\s+the\s+user'?s?\s+feelings\b", "Emotional validation over objective technical facts"),
]

# Patterns indicating AI-slop visual tropes (Prohibited by antislop contract)
AI_SLOP_PATTERNS = [
    (r"(?i)\bpurple\s+gradients?\b", "Generic purple SaaS gradient trope"),
    (r"(?i)\bglow\s+effects?\b", "Unjustified aesthetic glow slop"),
    (r"(?i)\b10,?000\+\s+happy\s+users\b", "Unverified fake marketing placeholder"),
    (r"(?i)\blight\s+gray\s+text\b", "Low-contrast WCAG AA violation hazard"),
]

# Antigravity-specific internal runtime markers to strip or abstract during export
AGY_INTERNAL_MARKERS = [
    r"<RULE\[.*?\]>",
    r"</RULE\[.*?\]>",
    r"<appDataDir>/brain/[^/\s`]+",
    r"default_api:\w+",
    r"\binvoke_subagent\b",
    r"\bmanage_task\b",
]


class ConstitutionalSanitizer:
    """Audits text against constitutional invariants and de-slops external rules."""

    @classmethod
    def audit_content(cls, content: str) -> List[SuitabilityIssue]:
        """Scans content and returns list of constitutional issues."""
        issues: List[SuitabilityIssue] = []

        # 1. Test Invariant Check
        for pattern, desc in TEST_WEAKENING_PATTERNS:
            if re.search(pattern, content):
                issues.append(
                    SuitabilityIssue(
                        severity="CRITICAL",
                        category="TEST_INVARIANT",
                        message=desc,
                        suggested_fix="Remove assertion relaxing directives; enforce 'source fixes test, never test fixes source'."
                    )
                )

        # 2. Sycophancy Check
        for pattern, desc in SYCOPHANCY_PATTERNS:
            if re.search(pattern, content):
                issues.append(
                    SuitabilityIssue(
                        severity="CRITICAL",
                        category="SYCOPHANCY",
                        message=desc,
                        suggested_fix="Strip flattery directives; enforce direct first-line answer and objective evaluation."
                    )
                )

        # 3. AI-Slop Check
        for pattern, desc in AI_SLOP_PATTERNS:
            if re.search(pattern, content):
                issues.append(
                    SuitabilityIssue(
                        severity="WARNING",
                        category="AI_SLOP",
                        message=desc,
                        suggested_fix="Replace with functional justification, WCAG AA contrast (zinc/slate), and intentional visual hierarchy."
                    )
                )

        return issues

    @classmethod
    def sanitize_for_import(cls, content: str) -> str:
        """Sanitizes external rule content for seamless ingestion into Antigravity."""
        sanitized = content

        # Remove forced conversational apologies / flattery
        sanitized = re.sub(r"(?i)^.*(always apologize|never contradict the user).*$\n?", "", sanitized, flags=re.MULTILINE)

        # Normalize multiple excessive empty lines
        sanitized = re.sub(r"\n{3,}", "\n\n", sanitized)

        return sanitized.strip()

    @classmethod
    def sanitize_for_export(cls, content: str, target: str = "generic") -> str:
        """
        Strips Antigravity-specific tags and translates tool references to target equivalents.
        """
        text = content

        # Remove XML rule tags (<RULE[...]>)
        text = re.sub(r"<RULE\[[^\]]+\]>", "", text)
        text = re.sub(r"</RULE\[[^\]]+\]>", "", text)

        # Abstract artifact brain paths
        text = re.sub(r"<appDataDir>/brain/<conversation-id>/", ".harness/artifacts/", text)
        text = re.sub(r"<appDataDir>/brain/[^/\s`]+/", ".harness/artifacts/", text)

        # Replace subagent tool references depending on target
        if target == "claude":
            text = re.sub(r"invoke_subagent\b", "isolated Claude sub-process or command execution", text)
        elif target in ("cursor", "windsurf"):
            text = re.sub(r"invoke_subagent\b", "specialized audit rule checklist", text)
        else:
            text = re.sub(r"invoke_subagent\b", "independent audit agent or verification task", text)

        # Clean trailing whitespace and extra blank lines
        lines = [line.rstrip() for line in text.splitlines()]
        cleaned = "\n".join(lines)
        return re.sub(r"\n{3,}", "\n\n", cleaned).strip()
