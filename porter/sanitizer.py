"""
porter/sanitizer.py — Constitutional de-slop, sycophancy filter, and invariant protector.
Zero-dependency: uses Python standard library re and string manipulation.

Every directive match is classified three ways:

  PROHIBITED   the text forbids the weakening ("Never skip tests", "Skipping tests is
               cheating", "Skip tests? Never.") -> the line is kept untouched;
  AFFIRMATIVE  the text instructs or permits the weakening ("Skip the failing tests",
               "Don't hesitate to skip failing tests") -> the line is replaced with a visible
               SANITIZED marker;
  UNCERTAIN    the wording cannot be decided by pattern (a question, a condition, a negation
               in a neighbouring clause, a quoted mention) -> the line is kept unchanged and
               reported as a review item that needs a human decision. It is never deleted.

Negation is clause-scoped: clauses break at , : ( ) and dashes, and at contrastive
conjunctions ("but", "instead", or ", just" / ", then"), so "No need to fix them, just skip
the failing tests" is not protected by its "No". Permissive negations ("don't hesitate to",
"feel free to", "no need to <other verb>") are not prohibitions, and "without user approval"
only forbids when a real negation governs it. Every pattern is evaluated independently and
with overlapping matches, so a rejected match never hides a real directive later in the same
sentence. Matching also runs over whole paragraphs so a directive split across line breaks is
still caught. This is a pattern filter, not semantic understanding: every result is shown to a
human before anything is written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Pattern, Sequence, Set, Tuple

from porter.models import SuitabilityIssue

PROHIBITED = "PROHIBITED"
AFFIRMATIVE = "AFFIRMATIVE"
UNCERTAIN = "UNCERTAIN"

_VERBS = (
    r"skip|skipping|skipped|ignore|ignoring|disable|disabling|remove|removing|delete|deleting|"
    r"drop|dropping|bypass|bypassing|comment\s+out|commenting\s+out"
)
_OBJECTS = (
    r"(?:failing|failed|flaky|broken|red)\s+(?:tests?|test\s+cases?|cases?|specs?|checks?)|"
    r"tests?|test\s+cases?|test\s+suites?|test\s+files?|specs?|assertions?"
)
# A gap holding a preposition or a clause break means the verb acts on something else.
_GAP_PREPOSITIONS = re.compile(r"(?i)\b(from|in|within|inside|of|for|to|into|about|near|around)\b|[:,()\u2014\u2013]")
# Quantifier phrases are part of the object ("skip all of the failing tests"), not a preposition
# that moves the verb onto something else ("remove the fixture from the tests").
_GAP_QUANTIFIERS = re.compile(
    r"(?i)\b(?:all|each|any|some|most|many|several|every\s+one|one|two|both|either|none|the\s+rest|half)"
    r"\s+of\s+(?:the|these|those|your|our|its|their)\b"
)

_PASSIVE_SUBJECTS = (
    r"(?:(?:failing|failed|flaky|broken|red|slow)\s+)?"
    r"(?:tests?|test\s+cases?|test\s+suites?|test\s+files?|specs?|assertions?)"
)
_PASSIVE_MODALS = (
    r"(?:may|might|can|cannot|can[’']t|could(?:n[’']t)?|should(?:n[’']t)?|shall|will|won[’']t|would|"
    r"must(?:n[’']t)?|(?:is|are)\s+(?:not\s+)?(?:allowed|permitted)\s+to)"
)
_PASSIVE_VERBS = (
    r"skipped|disabled|removed|deleted|ignored|dropped|bypassed|commented\s+out|xfail(?:ed)?|"
    r"weakened|relaxed|loosened|softened"
)

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
    (rf"(?i)\b{_PASSIVE_SUBJECTS}\s+(?P<interior>{_PASSIVE_MODALS}(?:\s+(?:not|never|always|safely|simply|just|"
     rf"freely|also|then|now|only)){{0,2}}\s+(?:be|get))\s+(?:{_PASSIVE_VERBS})\b",
     "Permission for tests to be skipped, disabled or removed (passive form)", False),
    (r"(?<![\w-])--no-verify\b",
     "Directive to bypass commit / verification hooks (--no-verify)", False),
    (r"(?i)\b(?:disable|disabling|turn(?:ing)?\s+off|switch(?:ing)?\s+off|bypass|bypassing|skip|skipping|"
     r"silence|silencing)\b(?P<gap>[^.\n;]{0,30}?)\b(?:linters?|linting|lint\s+(?:checks?|rules?|errors?|warnings?)|"
     r"type[\s-]?check(?:s|ing|er|ers)?)\b",
     "Directive to disable linting or type checking", True),
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

PROMPT_INJECTION_PATTERNS: List[Tuple[str, str, bool]] = [
    (r"(?i)\b(?:ignore|ignoring|disregard|disregarding|forget|forgetting|override|overriding)\s+(?:all\s+|any\s+)?"
     r"(?:(?:the|your|my|of\s+the)\s+)?(?:previous|prior|above|earlier|preceding|former|system)\s+"
     r"(?:instructions?|rules?|prompts?|directives?|guidelines?)\b",
     "Instruction-override directive (ignore previous instructions)", False),
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
    r"(?i)\b(?:never|not|no|nor|neither|none|nothing|cannot|avoid|avoiding|without|forbid|forbids|forbidden|"
    r"prohibit|prohibits|prohibited|ban|bans|banned|stop|refrain\s+from|refuse\s+to|instead\s+of|rather\s+than|"
    r"dont|cant|wont|mustnt|shouldnt|doesnt|asla|yasak|yasakt[ıi]r)\b|\b\w+n[’']t\b"
)
# Negation that sits INSIDE the matched span ("skip no tests", "tests must not be skipped").
_INTERIOR_NEGATION = re.compile(r"(?i)\b(?:no|none|not|never|nothing|cannot)\b(?!-)|n[’']t\b")
# Negated verbs that do not negate the directive: they encourage it.
_PERMISSIVE = re.compile(
    r"(?i)\b(?:(?:do\s+not|don[’']?t|never)\s+(?:hesitate|be\s+afraid|forget)\s+to|feel\s+free\s+to|why\s+not|"
    r"(?:do\s+not|don[’']?t)\s+worry(?:\s+about(?:\s+it)?)?|"
    r"without\s+(?:(?:explicit|prior|written|any|the|asking\s+for)\s+)*(?:(?:user|human|operator|maintainer)(?:[’']s)?\s+)?"
    r"(?:approval|authori[sz]ation|consent|confirmation|permission|asking|sign-?off))"
)
_NO_NEED = re.compile(r"(?i)\b(?:there\s+is\s+)?no\s+need\s+(?:to|for)\b(?:\s+\w+)?")
_NO_NEED_GOVERNS = re.compile(r"(?i)\bno\s+need\s+to\s*$")
_PROHIBITION_AFTER = re.compile(
    r"(?i)\b(?:is|are|remains?|stays?|was|will\s+be|would\s+be|counts?\s+as|constitutes?)\s+"
    r"(?:strictly\s+|absolutely\s+|always\s+|considered\s+|treated\s+as\s+)?"
    r"(?:forbidden|prohibited|not\s+allowed|disallowed|banned|blocked|unacceptable|not\s+acceptable|not\s+permitted|"
    r"never\s+(?:ok|okay|allowed|acceptable|permitted|fine|an\s+option)|not\s+(?:ok|okay|fine|an\s+option)|"
    r"off[\s-]limits|out\s+of\s+the\s+question|cheating|(?:test\s+)?tampering|"
    r"(?:an?\s+)?(?:\w+\s+)?(?:offen[cs]e|violation|breach))\b"
    r"|\byasakt[ıi]r\b|\byap[ıi]lmamal[ıi]d[ıi]r\b"
    r"|\bblocks?\s+(?:the\s+)?(?:delivery|release|merge)\b"
    r"|\b(?:requires?|needs?)\s+(?:explicit\s+|prior\s+|written\s+)?(?:user\s+|human\s+)?"
    r"(?:authori[sz]ation|approval|consent|confirmation|sign-?off)\b"
)
# A clause that opens with a bare prohibition right after the directive ("Skipping tests: forbidden.").
_PROHIBITION_LEAD = re.compile(
    r"(?i)^\s*(?:[,:—–]|-{1,2})\s*(?:(?:which|that|this|it)\s+)?(?:(?:is|are)\s+|[’']s\s+)?"
    r"(?:strictly\s+|absolutely\s+)?(?:forbidden|prohibited|banned|never|no|not\s+allowed|not\s+permitted|"
    r"disallowed|off[\s-]limits|not\s+ok(?:ay)?|not\s+an\s+option|cheating|unacceptable)\b"
)
_APPROVAL = (
    r"(?:(?:explicit|prior|written)\s+)?(?:(?:the|a)\s+)?(?:(?:user|human|maintainer|owner|operator)(?:[’']s)?\s+)?"
    r"(?:approval|authori[sz]ation|consent|confirmation|sign-?off|permission)"
)
_HUMAN = r"(?:(?:an?|the)\s+)?(?:humans?|users?|maintainers?|owners?|operators?|persons?|people|reviewers?)"
# "Only a human may disable tests", "only with explicit user approval", "only if the user approves".
_RESTRICTION = re.compile(
    rf"(?i)\bonly\s+{_HUMAN}\b|\bonly\b[^.;:\n]{{0,40}}?\b(?:with|after|upon|following)\s+{_APPROVAL}\b|"
    rf"\bonly\b[^.;:\n]{{0,40}}?\bby\s+{_HUMAN}\b|"
    r"\bonly\s+(?:if|when|once|after)\s+(?:the\s+|a\s+)?(?:user|human|maintainer|owner|operator)s?\s+(?:explicitly\s+)?"
    r"(?:approves?|authori[sz]es?|allows?|confirms?|consents?|asks?|requests?)\b"
)
_SUBORDINATOR = re.compile(r"(?i)\b(?:if|unless|when|whenever|once|in\s+case|whether)\b")
_SUBORDINATE_START = re.compile(
    r"(?i)^\s*(?:[-*+>]\s+|\d+[.)]\s+)?(?:\*\*|__)?\s*(?:if|unless|when|whenever|once|in\s+case|whether|because|"
    r"since|as\s+long\s+as|while|although|though|even\s+if)\b"
)
_CONSEQUENCE = re.compile(
    r"(?i)\b(?:blocked|blocks?|fails?|failed|rejected|reverted|halts?|halted|aborts?|aborted|refused|revoked|"
    r"forbidden|prohibited|violat\w*|cheating|not\s+(?:be\s+)?merged|not\s+ship\w*|escalat\w*)\b"
)
_DANGLING_NEGATION = re.compile(
    r"(?i)(?:\b(?:do|does|must|should|shall|may|can|will|would)\s+not|\b\w+n[’']t|\bnever|\bcannot)\s*(?:\*\*|__)?\s*$"
)
_BARE_NEGATION = re.compile(
    r"(?i)^\s*(?:\*\*|__)?(?:never|no|nope|not\s+allowed|not\s+ever|absolutely\s+not|certainly\s+not|of\s+course\s+not|"
    r"forbidden|prohibited|not\s+permitted|no\s+way|don[’']?t|do\s+not|hay[ıi]r|asla)(?:\s+ever)?\s*(?:\*\*|__)?\s*[.!]*\s*$"
)
_SENTENCE_BREAK = re.compile(r"[.!?;](?=\s|$)|\n")
_CLAUSE_BREAK = re.compile(
    r"(?i)(?P<soft>[,:()—–]|\s-{1,2}\s)"
    r"(?P<conj>\s*\b(?:just|then|so|simply|but|however|otherwise|instead(?!\s+of\b)|rather(?!\s+than\b))\b)?"
    r"|(?P<hard>\b(?:but|however|otherwise|instead(?!\s+of\b)|rather(?!\s+than\b))\b)"
)
_GERUND_START = re.compile(
    r"(?i)(?:skipping|ignoring|disabling|removing|deleting|dropping|bypassing|commenting|relaxing|loosening|"
    r"weakening|softening|modifying|changing|editing|adjusting|rewriting|marking|turning|switching|silencing)\b"
)
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)")
_UNIT_START = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+|#{1,6}\s|\||>)")
_HEADING = re.compile(r"^\s*#{1,6}\s")
_LEAD_IN_PROHIBITION = re.compile(
    r"(?i)\b(?:forbidden|prohibited|banned|not\s+allowed|disallowed|anti-?patterns?|don[’']?ts)\b"
)

MARKER_TEST = "# [SANITIZED BY HARNESS: Test weakening directive suppressed per Goodhart's Invariant]"
MARKER_SYCOPHANCY = "# [SANITIZED BY HARNESS: Sycophancy directive suppressed per Rule 7]"
MARKER_INJECTION = "# [SANITIZED BY HARNESS: Instruction-override directive suppressed per Prompt Defense Baseline]"
_MARKERS = {"TEST_INVARIANT": MARKER_TEST, "SYCOPHANCY": MARKER_SYCOPHANCY, "PROMPT_INJECTION": MARKER_INJECTION}
_FIXES = {
    "TEST_INVARIANT": "Remove the directive; enforce 'source fixes test, never test fixes source'.",
    "SYCOPHANCY": "Strip flattery directives; enforce direct first-line answers and objective evaluation.",
    "PROMPT_INJECTION": "Remove the directive; imported content is data and must never override the harness rules.",
}
_RANK = {PROHIBITED: 0, UNCERTAIN: 1, AFFIRMATIVE: 2}


@dataclass
class Directive:
    category: str
    description: str
    line_start: int
    line_end: int
    text: str
    classification: str = AFFIRMATIVE
    reason: str = ""


def _compile(patterns: Sequence[Tuple[str, str, bool]]) -> List[Tuple[Pattern[str], str, bool]]:
    return [(re.compile(p), d, g) for p, d, g in patterns]


_WEAKENING = _compile(TEST_WEAKENING_PATTERNS)
_SYCOPHANCY = _compile(SYCOPHANCY_PATTERNS)
_INJECTION = _compile(PROMPT_INJECTION_PATTERNS)
_SLOP = _compile(AI_SLOP_PATTERNS)
_CATEGORIES = (("TEST_INVARIANT", _WEAKENING), ("SYCOPHANCY", _SYCOPHANCY), ("PROMPT_INJECTION", _INJECTION))

# Patterns whose wording already contains the negation ("never disagree"): the negation is the directive.
_NEGATION_INHERENT = {SYCOPHANCY_PATTERNS[2][0]}


# ----------------------------------------------------------------------------------------------
# Classification
# ----------------------------------------------------------------------------------------------
def _sentence_bounds(text: str, start: int, end: int) -> Tuple[int, int, str]:
    """(sentence start, sentence end, terminator) around text[start:end]."""
    s = 0
    for m in _SENTENCE_BREAK.finditer(text):
        if m.end() > start:
            break
        s = m.end()
    m2 = _SENTENCE_BREAK.search(text, end)
    if m2:
        return s, m2.start(), text[m2.start()]
    return s, len(text), ""


def _clause_context(text: str, s: int, start: int) -> Tuple[int, List[str]]:
    """Start of the clause holding `start`, and the earlier clauses up to the last hard break."""
    prefix = text[s:start]
    segments: List[str] = []
    last = 0
    for b in _CLAUSE_BREAK.finditer(prefix):
        hard = bool(b.group("hard") or b.group("conj"))
        segments = [] if hard else segments + [prefix[last:b.start()]]
        last = b.end()
    return s + last, segments


def _suffix_bounds(text: str, end: int, e: int) -> Tuple[int, int]:
    """(end of the directive's own clause, end of the clause chain before the next hard break)."""
    own = hard = e
    for b in _CLAUSE_BREAK.finditer(text, end, e):
        if own == e:
            own = b.start()
        if b.group("hard") or b.group("conj"):
            hard = b.start()
            break
    return own, hard


def _strip_permissive(segment: str, governs_directive: bool = False) -> Tuple[str, bool]:
    """Removes permissive negations. Returns (cleaned text, 'no need to' directly governs the directive)."""
    governed = governs_directive and bool(_NO_NEED_GOVERNS.search(segment))
    cleaned = _PERMISSIVE.sub(" ", segment)
    if not governed:
        cleaned = _NO_NEED.sub(" ", cleaned)
    return cleaned, governed


def _next_sentence(text: str, e: int) -> str:
    rest = text[e + 1:]
    m = _SENTENCE_BREAK.search(rest)
    return rest[:m.end()] if m else rest


def _in_quotes(sentence: str, a: int, b: int) -> bool:
    """True when sentence[a:b] sits inside a double-quoted span (a mention, not an instruction)."""
    if sentence[:a].count('"') % 2 == 1 and '"' in sentence[b:]:
        return True
    return sentence[:a].count("“") > sentence[:a].count("”") and "”" in sentence[b:]


def _classify(text: str, start: int, end: int, interior: Sequence[str] = (), inherent: bool = False) -> Tuple[str, str]:
    """Classifies text[start:end] as PROHIBITED, AFFIRMATIVE or UNCERTAIN, with a short reason."""
    if inherent:
        return AFFIRMATIVE, "the negation is part of the directive"
    if any(_INTERIOR_NEGATION.search(part or "") for part in interior):
        return PROHIBITED, "negated inside the directive"
    s, e, term = _sentence_bounds(text, start, end)
    sentence = text[s:e]
    cs, earlier = _clause_context(text, s, start)
    clause_prefix = text[cs:start]
    cleaned, no_need = _strip_permissive(clause_prefix, governs_directive=True)
    if no_need or _NEGATION_BEFORE.search(cleaned):
        return PROHIBITED, "negated in its own clause"
    if _RESTRICTION.search(sentence):
        return PROHIBITED, "restricted to a human or to explicit approval"
    own_end, chain_end = _suffix_bounds(text, end, e)
    # A gerund directive is a subject ("Relaxing assertions, skipping tests, ... is forbidden"): its
    # predicate may follow a list of soft-separated siblings. An imperative's may not.
    gerund = bool(_GERUND_START.match(text[start:end]))
    if (_PROHIBITION_AFTER.search(text[end:own_end]) or _PROHIBITION_LEAD.match(text[end:chain_end])
            or (gerund and _PROHIBITION_AFTER.search(text[end:chain_end]))):
        return PROHIBITED, "declared forbidden after the directive"
    if _SUBORDINATOR.search(clause_prefix):
        if _CONSEQUENCE.search(text[end:chain_end]):
            return PROHIBITED, "condition with a blocking consequence"
        return UNCERTAIN, "appears inside a condition, not as an instruction"
    if term == "?":
        if _BARE_NEGATION.match(_next_sentence(text, e)):
            return PROHIBITED, "question answered with a bare negation"
        return UNCERTAIN, "phrased as a question"
    for seg in earlier:
        if _SUBORDINATE_START.match(seg):
            continue
        seg_clean, _ = _strip_permissive(seg)
        if _DANGLING_NEGATION.search(seg_clean):
            return PROHIBITED, "governed by a preceding negation"
        if _NEGATION_BEFORE.search(seg_clean):
            return UNCERTAIN, "a negation in a neighbouring clause may govern it"
    if _in_quotes(sentence, start - s, end - s):
        return UNCERTAIN, "quoted mention"
    return AFFIRMATIVE, "instructs or permits the weakening"


def classify_match(text: str, start: int, end: int) -> str:
    """Public classification of text[start:end] (PROHIBITED, AFFIRMATIVE or UNCERTAIN)."""
    return _classify(text, start, end)[0]


def is_prohibitive(text: str, start: int, end: int) -> bool:
    """True when the matched directive is forbidden by its own sentence."""
    return classify_match(text, start, end) == PROHIBITED


def _gap_rejected(m: "re.Match[str]") -> bool:
    if "gap" not in m.re.groupindex:
        return False
    gap = _GAP_QUANTIFIERS.sub(" ", m.group("gap") or "")
    return bool(_GAP_PREPOSITIONS.search(gap))


def _iter_matches(text: str, compiled) -> Iterator[Tuple["re.Match[str]", str, bool]]:
    """Every match of every pattern, overlapping: a rejected match never hides a later one."""
    for regex, desc, gap_check in compiled:
        inherent = regex.pattern in _NEGATION_INHERENT
        pos = 0
        while pos <= len(text):
            m = regex.search(text, pos)
            if not m:
                break
            pos = m.start() + 1
            if gap_check and _gap_rejected(m):
                continue
            yield m, desc, inherent


def _interior(m: "re.Match[str]") -> List[str]:
    return [m.group(g) or "" for g in ("gap", "interior") if g in m.re.groupindex]


# ----------------------------------------------------------------------------------------------
# Paragraph assembly
# ----------------------------------------------------------------------------------------------
def _fence_flags(lines: List[str]) -> List[bool]:
    flags, inside = [], False
    for line in lines:
        if line.strip().startswith(("```", "~~~")):
            inside = not inside
            flags.append(True)
        else:
            flags.append(inside)
    return flags


def _paragraphs(lines: List[str]) -> List[Tuple[int, int]]:
    spans, start = [], None
    for idx, line in enumerate(lines):
        if line.strip() and not line.strip().startswith(("```", "~~~")):
            if start is None:
                start = idx
        elif start is not None:
            spans.append((start, idx - 1))
            start = None
    if start is not None:
        spans.append((start, len(lines) - 1))
    return spans


def _join(lines: List[str], span: Tuple[int, int], fenced: List[bool]) -> Tuple[str, List[Tuple[int, int, int]]]:
    """Joins a paragraph for analysis. List items, headings, table rows and code lines stay separate units."""
    parts: List[str] = []
    offsets: List[Tuple[int, int, int]] = []
    pos = 0
    prev = ""
    for i in range(span[0], span[1] + 1):
        line = lines[i].strip()
        if i > span[0]:
            separate = fenced[i] or _UNIT_START.match(lines[i]) or _HEADING.match(prev) or prev.startswith("|")
            parts.append("\n" if separate else " ")
            pos += 1
        offsets.append((pos, i, len(line)))
        parts.append(line)
        pos += len(line)
        prev = line
    return "".join(parts), offsets


def _lead_in(lines: List[str], idx: int, fenced: List[bool]) -> Optional[str]:
    """The line introducing the list that holds lines[idx] (a heading or a line ending in ':')."""
    if fenced[idx] or not _LIST_ITEM.match(lines[idx]):
        return None
    for j in range(idx - 1, max(-1, idx - 60), -1):
        raw = lines[j]
        stripped = raw.strip()
        if not stripped or _LIST_ITEM.match(raw) or (raw[:1].isspace() and not _HEADING.match(raw)):
            continue
        bare = stripped.rstrip("*_ ")
        if _HEADING.match(raw) or bare.endswith(":"):
            return stripped
        return None
    return None


def _lead_in_prohibits(lead: str) -> bool:
    cleaned, _ = _strip_permissive(lead)
    return bool(_NEGATION_BEFORE.search(cleaned) or _LEAD_IN_PROHIBITION.search(cleaned))


def review_directives(content: str) -> List[Directive]:
    """
    Every weakening / sycophancy / instruction-override finding with its classification
    (PROHIBITED, AFFIRMATIVE or UNCERTAIN). Lines replaced because of an AFFIRMATIVE finding do not
    also carry weaker findings.
    """
    lines = content.splitlines()
    fenced = _fence_flags(lines)
    best: Dict[Tuple[str, int], Directive] = {}
    for span in _paragraphs(lines):
        text, offsets = _join(lines, span, fenced)
        for category, compiled in _CATEGORIES:
            for m, desc, inherent in _iter_matches(text, compiled):
                covered = [i for off, i, ln in offsets if off < m.end() and off + ln > m.start()]
                if not covered:
                    continue
                cls, reason = _classify(text, m.start(), m.end(), _interior(m), inherent)
                if cls == AFFIRMATIVE and not inherent:
                    lead = _lead_in(lines, covered[0], fenced)
                    if lead and _lead_in_prohibits(lead):
                        cls, reason = PROHIBITED, "listed under a prohibiting lead-in"
                shown = lines[covered[0]].strip() if len(covered) == 1 else m.group(0)
                d = Directive(category, desc, covered[0], covered[-1], shown, cls, reason)
                key = (category, covered[0])
                if key not in best or _RANK[cls] > _RANK[best[key].classification]:
                    best[key] = d
    sanitized: Set[int] = set()
    for d in best.values():
        if d.classification == AFFIRMATIVE:
            sanitized.update(range(d.line_start, d.line_end + 1))
    out = [d for d in best.values()
           if d.classification == AFFIRMATIVE or not sanitized.intersection(range(d.line_start, d.line_end + 1))]
    return sorted(out, key=lambda d: (d.line_start, d.category))


def find_directives(content: str) -> List[Directive]:
    """Locates weakening, sycophancy and instruction-override directives that will be sanitized."""
    return [d for d in review_directives(content) if d.classification == AFFIRMATIVE]


class ConstitutionalSanitizer:
    """Audits text against constitutional invariants and de-slops external rules."""

    @classmethod
    def audit_content(cls, content: str) -> List[SuitabilityIssue]:
        """
        Scans content and returns one issue per detected directive kind. AFFIRMATIVE findings are
        CRITICAL; UNCERTAIN findings are WARNING 'NEEDS_REVIEW' items listing every affected line,
        because they are kept unchanged and need a human decision.
        """
        issues: List[SuitabilityIssue] = []
        reported: Set[Tuple[str, str]] = set()
        review: Dict[str, List[Directive]] = {}
        for d in review_directives(content):
            if d.classification == UNCERTAIN:
                review.setdefault(d.description, []).append(d)
                continue
            if d.classification != AFFIRMATIVE or (d.category, d.description) in reported:
                continue
            reported.add((d.category, d.description))
            issues.append(SuitabilityIssue(
                severity="CRITICAL",
                category=d.category,
                message=f"{d.description} (line {d.line_start + 1}: \"{d.text[:80]}\")",
                suggested_fix=_FIXES.get(d.category, _FIXES["TEST_INVARIANT"]),
            ))

        for desc, items in review.items():
            shown = "; ".join(f"line {d.line_start + 1}: \"{d.text[:80]}\" ({d.reason})" for d in items[:5])
            more = f"; +{len(items) - 5} more" if len(items) > 5 else ""
            issues.append(SuitabilityIssue(
                severity="WARNING",
                category="NEEDS_REVIEW",
                message=f"Ambiguous wording, kept unchanged and needs a human decision — {desc.lower()} ({shown}{more})",
                suggested_fix="Decide whether each line forbids or instructs the weakening; rephrase it as an explicit "
                              "prohibition or delete it before relying on the import.",
            ))

        for idx, line in enumerate(content.splitlines()):
            for m, desc, inherent in _iter_matches(line, _SLOP):
                if ("AI_SLOP", desc) in reported:
                    continue
                if _classify(line, m.start(), m.end(), _interior(m), inherent)[0] != AFFIRMATIVE:
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
        """Replaces AFFIRMATIVE directive lines with explicit harness markers (UNCERTAIN lines are kept)."""
        lines = content.splitlines()
        replacements = {}
        for d in find_directives(content):
            marker = _MARKERS.get(d.category, MARKER_TEST)
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
        1. Neutralizes test-weakening, sycophancy and instruction-override directives with visible markers.
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
        # Templates are exported to <output>/templates/, not the Antigravity config directory.
        text = re.sub(r"~/\.gemini/config/templates/", "templates/", text)

        if target == "claude":
            text = re.sub(r"invoke_subagent\b", "a Claude Code subagent (.claude/agents/)", text)
        elif target in ("cursor", "windsurf"):
            text = re.sub(r"invoke_subagent\b", "the matching agent rule in .cursor/rules/", text)
        else:
            text = re.sub(r"invoke_subagent\b", "an independent audit agent or verification task", text)

        lines = [line.rstrip() for line in text.splitlines()]
        return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
