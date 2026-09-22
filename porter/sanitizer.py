"""
porter/sanitizer.py — Constitutional de-slop, sycophancy filter, and invariant protector.
Zero-dependency: uses Python standard library re and string manipulation.

Detection is negation-aware: "Never skip tests" or "Skipping tests is forbidden" are
PROTECTIVE rules and are kept; "Skip the failing tests" or "Mark flaky tests as xfail"
are weakening directives and are neutralised. Matching also runs over whole paragraphs
so a directive split across line breaks is still caught. This is a pattern filter, not
semantic understanding: every result is shown to a human before anything is written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern, Sequence, Set, Tuple

from porter.models import SuitabilityIssue

_VERBS = (
    r"skip|skipping|skipped|ignore|ignoring|disable|disabling|remove|removing|delete|deleting|"
    r"drop|dropping|bypass|bypassing|comment\s+out|commenting\s+out"
)
_OBJECTS = (
    r"(?:failing|failed|flaky|broken|red)\s+(?:tests?|test\s+cases?|cases?|specs?|checks?)|"
    r"tests?|test\s+cases?|test\s+suites?|test\s+files?|specs?|assertions?"
)
_GAP_PREPOSITIONS = re.compile(r"(?i)\b(from|in|within|inside|of|for|to|into|about|near|around)\b|:")

# (pattern, description, needs_gap_check)
TEST_WEAKENING_PATTERNS: List[Tuple[str, str, bool]] = [
    (rf"(?i)\b(?:{_VERBS})\b(?P<gap>[^.\n;]{{0,60}}?)\b(?:{_OBJECTS})\b",
     "Directive to skip, disable, delete or comment out tests", True),
    (r"(?i)\b(?:relax|relaxing|loosen|loosening|weaken|weakening|soften|softening|modify|modifying|change|changing|"
     r"edit|editing|adjust|adjusting|rewrite|rewriting)\b(?P<gap>[^.\n;]{0,40}?)\b(?:assertions?|asserts?|expectations?|"
     r"expected\s+(?:values?|outputs?|results?)|test\s+thresholds?|tolerances?)\b",
     "Directive to weaken assertions or expectations", True),
    (r"(?i)\bmark(?:ing)?\b[^.\n;]{0,40}?\b(?:tests?|specs?|cases?)\b[^.\n;]{0,20}?\bas\s+(?:skipped|skip|xfail|"
     r"expected\s+to\s+fail|pending|flaky)\b",
     "Directive to mark tests as skipped / expected failures", False),
    (r"@pytest\.mark\.(?:skip|xfail)\b|\b(?:it|test|describe)\.skip\s*\(|\bx(?:it|describe)\s*\(|\bt\.Skip\(|"
     r"@(?:Disabled|Ignore)\b|\bxfail\b",
     "Instruction to use skip / xfail test markers", False),
    (r"(?i)\bchange\s+the\s+tests?\s+to\s+(?:make\s+it\s+)?pass\b|\bmake\s+the\s+tests?\s+pass\s+by\s+"
     r"(?:changing|editing|modifying)\s+(?:the\s+)?tests?\b",
     "Directive to modify tests to pass gates", False),
    (r"(?i)\b(?:testleri|testi|testler)\s+(?:atla|atlay[ıi]n|ge[çc]|ge[çc]in|sil|silin|devre\s+d[ıi][şs][ıi]\s+b[ıi]rak(?:[ıi]n)?|"
     r"kapat(?:[ıi]n)?|yorum\s+sat[ıi]r[ıi]na\s+al(?:[ıi]n)?)\b",
     "Turkish directive to skip, delete or disable tests", False),
    (r"(?i)\b(?:assert(?:ion)?(?:lar[ıi]|leri|u|ü)?|do[ğg]rulamalar[ıi])\s+(?:gev[şs]et|zay[ıi]flat|de[ğg]i[şs]tir|kald[ıi]r)(?:in|[ıi]n)?\b",
     "Turkish directive to weaken assertions", False),
]

SYCOPHANCY_PATTERNS: List[Tuple[str, str, bool]] = [
    (r"(?i)\balways\s+(?:agree|side)\s+with\s+the\s+user\b", "Rules forcing automatic agreement with user premises", True),
    (r"(?i)\bapologi[sz]e\s+(?:profusely|always|sincerely|often)\b|\balways\s+apologi[sz]e\b", "Forced apologetic conversational filler", True),
    (r"(?i)\b(?:never|do\s+not|don'?t|must\s+not)\s+(?:disagree|refuse|contradict|challenge|push\s+back)\b"
     r"(?!\s+(?:with|on|against)\s+(?:verified\s+|established\s+|the\s+)?(?:facts?|evidence|data|tests?|spec(?:ification)?s?))",
     "Prohibition on objective technical disagreement", False),
    (r"(?i)\bvalidate\s+the\s+user'?s?\s+feelings\b", "Emotional validation over objective technical facts", True),
    (r"(?i)\bthe\s+user\s+is\s+always\s+right\b", "Rules asserting the user is always right", True),
]

AI_SLOP_PATTERNS: List[Tuple[str, str, bool]] = [
    (r"(?i)\bpurple\s+gradients?\b", "Generic purple SaaS gradient trope", True),
    (r"(?i)\bglow\s+effects?\b", "Unjustified aesthetic glow slop", True),
    (r"(?i)\b10,?000\+\s+happy\s+users\b", "Unverified fake marketing placeholder", False),
    (r"(?i)\blight\s+gray\s+text\b", "Low-contrast WCAG AA violation hazard", True),
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

_NEGATION_BEFORE = re.compile(
    r"(?i)\b(never|not|no|don'?t|do\s+not|does\s+not|must\s+not|mustn'?t|shall\s+not|should\s+not|shouldn'?t|"
    r"cannot|can'?t|avoid|avoiding|refrain\s+from|without|forbid|forbidden|prohibit|prohibited|ban|banned|"
    r"stop|asla|yasak|yasakt[ıi]r)\b"
)
_PROHIBITION_AFTER = re.compile(
    r"(?i)\b(is|are|remains?|stays?)\s+(strictly\s+|absolutely\s+|always\s+)?(forbidden|prohibited|not\s+allowed|"
    r"disallowed|banned|unacceptable|not\s+permitted)\b|\byasakt[ıi]r\b|\byap[ıi]lmamal[ıi]d[ıi]r\b|"
    r"\bwithout\s+(?:explicit\s+|prior\s+|written\s+)?(?:user\s+|human\s+)?(?:authori[sz]ation|approval|consent|confirmation)\b|"
    r"\bblocks?\s+(?:the\s+)?delivery\b|\bis\s+never\s+(?:allowed|acceptable)\b|"
    r"\brequires?\s+(?:explicit\s+|prior\s+)?(?:user\s+|human\s+)?(?:authori[sz]ation|approval|consent|confirmation)\b"
)
_SENTENCE_BREAK = re.compile(r"[.!?;]\s|[.!?;]$")

MARKER_TEST = "# [SANITIZED BY HARNESS: Test weakening directive suppressed per Goodhart's Invariant]"
MARKER_SYCOPHANCY = "# [SANITIZED BY HARNESS: Sycophancy directive suppressed per Rule 7]"


@dataclass
class Directive:
    category: str
    description: str
    line_start: int
    line_end: int
    text: str


def _compile(patterns: Sequence[Tuple[str, str, bool]]) -> List[Tuple[Pattern[str], str, bool]]:
    return [(re.compile(p), d, g) for p, d, g in patterns]


_WEAKENING = _compile(TEST_WEAKENING_PATTERNS)
_SYCOPHANCY = _compile(SYCOPHANCY_PATTERNS)
_SLOP = _compile(AI_SLOP_PATTERNS)


def _sentence_bounds(text: str, start: int, end: int) -> Tuple[int, int]:
    s = 0
    for m in _SENTENCE_BREAK.finditer(text, 0, start):
        s = m.end()
    m2 = _SENTENCE_BREAK.search(text, end)
    e = m2.start() + 1 if m2 else len(text)
    return s, e


def is_prohibitive(text: str, start: int, end: int) -> bool:
    """True when the matched directive is negated/forbidden in its own sentence."""
    s, e = _sentence_bounds(text, start, end)
    prefix = text[s:start]
    suffix = text[end:e]
    return bool(_NEGATION_BEFORE.search(prefix) or _PROHIBITION_AFTER.search(suffix))


def _matches(text: str, compiled, negation_aware: bool = True):
    for regex, desc, gap_check in compiled:
        for m in regex.finditer(text):
            if gap_check and "gap" in regex.groupindex and m.group("gap") and _GAP_PREPOSITIONS.search(m.group("gap")):
                continue
            if negation_aware and (regex.pattern not in _NEGATION_INHERENT) and is_prohibitive(text, m.start(), m.end()):
                continue
            yield m, desc


_NEGATION_INHERENT = {SYCOPHANCY_PATTERNS[2][0]}


def _paragraphs(lines: List[str]) -> List[Tuple[int, int]]:
    spans, start = [], None
    for idx, line in enumerate(lines):
        if line.strip() and not line.strip().startswith("```"):
            if start is None:
                start = idx
        elif start is not None:
            spans.append((start, idx - 1))
            start = None
    if start is not None:
        spans.append((start, len(lines) - 1))
    return spans


def find_directives(content: str) -> List[Directive]:
    """Locates weakening and sycophancy directives (line- and paragraph-level)."""
    lines = content.splitlines()
    found: List[Directive] = []
    seen: Set[Tuple[str, int]] = set()
    for category, compiled in (("TEST_INVARIANT", _WEAKENING), ("SYCOPHANCY", _SYCOPHANCY)):
        for idx, line in enumerate(lines):
            for m, desc in _matches(line, compiled):
                if (category, idx) not in seen:
                    seen.add((category, idx))
                    found.append(Directive(category, desc, idx, idx, line.strip()))
        for start, end in _paragraphs(lines):
            if start == end:
                continue
            joined = " ".join(l.strip() for l in lines[start:end + 1])
            offsets = []
            pos = 0
            for i in range(start, end + 1):
                offsets.append((pos, i))
                pos += len(lines[i].strip()) + 1
            for m, desc in _matches(joined, compiled):
                covered = [i for off, i in offsets if off <= m.end() and off + len(lines[i].strip()) >= m.start()]
                if any((category, i) in seen for i in covered):
                    continue
                for i in covered:
                    seen.add((category, i))
                found.append(Directive(category, desc, covered[0], covered[-1], m.group(0)))
    return sorted(found, key=lambda d: (d.line_start, d.category))


class ConstitutionalSanitizer:
    """Audits text against constitutional invariants and de-slops external rules."""

    @classmethod
    def audit_content(cls, content: str) -> List[SuitabilityIssue]:
        """Scans content and returns one issue per detected directive kind."""
        issues: List[SuitabilityIssue] = []
        reported: Set[Tuple[str, str]] = set()
        for d in find_directives(content):
            if (d.category, d.description) in reported:
                continue
            reported.add((d.category, d.description))
            if d.category == "TEST_INVARIANT":
                fix = "Remove the directive; enforce 'source fixes test, never test fixes source'."
            else:
                fix = "Strip flattery directives; enforce direct first-line answers and objective evaluation."
            issues.append(SuitabilityIssue(
                severity="CRITICAL",
                category=d.category,
                message=f"{d.description} (line {d.line_start + 1}: \"{d.text[:80]}\")",
                suggested_fix=fix,
            ))

        for idx, line in enumerate(content.splitlines()):
            for m, desc in _matches(line, _SLOP):
                if ("AI_SLOP", desc) in reported:
                    continue
                reported.add(("AI_SLOP", desc))
                issues.append(SuitabilityIssue(
                    severity="WARNING",
                    category="AI_SLOP",
                    message=f"{desc} (line {idx + 1})",
                    suggested_fix="Replace with functional justification, WCAG AA contrast, and intentional hierarchy.",
                ))
        return issues

    @classmethod
    def neutralize_directives(cls, content: str) -> str:
        """Replaces weakening / sycophancy directive lines with explicit harness markers."""
        lines = content.splitlines()
        replacements = {}
        for d in find_directives(content):
            marker = MARKER_TEST if d.category == "TEST_INVARIANT" else MARKER_SYCOPHANCY
            for i in range(d.line_start, d.line_end + 1):
                replacements.setdefault(i, marker)
        out = []
        for idx, line in enumerate(lines):
            if idx in replacements:
                indent = re.match(r"^\s*", line).group(0)
                bullet = "- " if line.strip().startswith(("- ", "* ", "+ ")) else ""
                out.append(f"{indent}{bullet}{replacements[idx]}")
            else:
                out.append(line)
        return "\n".join(out)

    @classmethod
    def sanitize_for_import(cls, content: str) -> str:
        """
        Sanitizes external rule content for ingestion into Antigravity:
        1. Neutralizes test-weakening and sycophancy directives with visible markers.
        2. Replaces fake marketing metrics with placeholders.
        3. Normalizes excessive blank lines.
        """
        text = cls.neutralize_directives(content)
        text = re.sub(r"(?i)\b10,?000\+\s+happy\s+users\b", "[Verified Metrics Placeholder]", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    @classmethod
    def sanitize_for_export(cls, content: str, target: str = "generic") -> str:
        """
        Applies the same directive filter as import, strips Antigravity-specific tags and
        translates tool references to target equivalents.
        """
        text = cls.neutralize_directives(content)

        text = re.sub(r"<RULE\[[^\]]+\]>", "", text)
        text = re.sub(r"</RULE\[[^\]]+\]>", "", text)
        text = re.sub(r"<appDataDir>/brain/<conversation-id>/", ".harness/artifacts/", text)
        text = re.sub(r"<appDataDir>/brain/[^/\s`]+/", ".harness/artifacts/", text)

        if target == "claude":
            text = re.sub(r"invoke_subagent\b", "a Claude Code subagent (.claude/agents/)", text)
        elif target in ("cursor", "windsurf"):
            text = re.sub(r"invoke_subagent\b", "the matching agent rule in .cursor/rules/", text)
        else:
            text = re.sub(r"invoke_subagent\b", "an independent audit agent or verification task", text)

        lines = [line.rstrip() for line in text.splitlines()]
        return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
