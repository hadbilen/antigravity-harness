#!/usr/bin/env python3
"""
skills/antislop-copywriting/scripts/check_synthetic_markers.py — Deterministic scanner for signs of machine-generated prose
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Python standard library only; runs on Python 3.10 and later.

Rule families (IDs are stable and match the purifier catalogue):
  1.1–1.8   content signs        (inflated significance, promotional tone, vague attribution ...)
  2.1–2.6   language and grammar (AI vocabulary clusters, copula avoidance, negative parallelism ...)
  3.1–3.8   formatting           (Title Case headings, bold overuse, em dashes, tiny tables ...)
  4.1–4.3   chat leftovers       (assistant phrasing, knowledge-cutoff hedging, placeholders)
  5.1–5.2   older-model habits   (didactic filler, summary openers)
  6.1–6.6   antislop copy rules  (fake candour, signposting, staccato drama, shouting ...)
  TR-1–TR-6 Turkish mode         (negative parallelism, brochure vocabulary, chat leftovers ...)

Before scanning, YAML frontmatter, fenced and inline code, HTML comments and tags, link
targets, Markdown blockquotes and (for content rules 1.x, 2.x, TR-1–TR-4 and 3.4) quotations
of five or more words are blanked out character by character, so reported line numbers
always point at the original file.

Usage:
  python3 scripts/check_synthetic_markers.py PATH [PATH ...]      # files or directories (.md .txt .html)
  cat draft.md | python3 scripts/check_synthetic_markers.py -     # read standard input
  python3 scripts/check_synthetic_markers.py PATH --summary       # per-rule table and density
  python3 scripts/check_synthetic_markers.py PATH --json          # machine-readable output
  python3 scripts/check_synthetic_markers.py PATH --lang auto|en|tr
  python3 scripts/check_synthetic_markers.py PATH --strict        # also report sub-threshold singletons
  python3 scripts/check_synthetic_markers.py PATH --profile technical   # engineering docs
  python3 scripts/check_synthetic_markers.py PATH --source human       # em dashes by cluster only

Exit codes: 0 clean (or below cluster thresholds), 1 findings, 2 read or argument error.
"""

from __future__ import annotations

import argparse
import bisect
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Sequence, Tuple

# ---------------------------------------------------------------------------
# Rule catalogue
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    category: str
    severity: str  # "high" | "medium" | "low"
    fix_hint: str
    lang: str  # "en" | "tr" | "any"


RULES: Dict[str, RuleInfo] = {}


def _register(rule_id: str, category: str, severity: str, fix_hint: str, lang: str) -> None:
    RULES[rule_id] = RuleInfo(rule_id, category, severity, fix_hint, lang)


_register("1.1", "Inflated significance or legacy", "medium",
          "Cut the significance claim, or replace it with the concrete fact that shows it.", "en")
_register("1.2", "Canned notability claim", "medium",
          "Say what the subject did instead of listing who covered it.", "en")
_register("1.3", "Trailing -ing commentary", "medium",
          "End the sentence before the -ing clause; if the point matters, give it its own sentence and evidence.", "en")
_register("1.4", "Promotional or brochure tone", "medium",
          "Drop the selling adjectives; state a specific feature, number or location.", "en")
_register("1.5", "Vague attribution", "medium",
          "Name the source, or delete the claim.", "en")
_register("1.6", "Challenges-and-prospects formula", "medium",
          "State the real problem plainly and drop the upbeat 'continues to thrive' ending.", "en")
_register("1.7", "Title-defining lead", "low",
          "Open with what the subject is ('X is ...') rather than defining its name.", "en")
_register("1.8", "Formulaic paired heading", "low",
          "Use a heading that names what this section actually covers.", "en")
_register("2.1", "AI vocabulary", "medium",
          "Use the ordinary word, or delete the filler sentence.", "en")
_register("2.2", "Copula avoidance", "low",
          "Use a plain 'is', 'are' or 'has'.", "en")
_register("2.3", "Vague association", "low",
          "Name the actual relationship (for example 'was CEO of').", "en")
_register("2.4", "Negative parallelism", "medium",
          "State the positive claim directly; nobody raised the view being corrected.", "en")
_register("2.5", "Rule-of-three overuse", "low",
          "Break the triplet rhythm; keep a list of three only when there are exactly three real items.", "en")
_register("2.6", "Elegant variation", "low",
          "Repeat the same clear noun, or use a pronoun, instead of cycling synonyms.", "en")
_register("3.1", "Title Case heading", "low",
          "Use sentence case in headings.", "en")
_register("3.2", "Boldface overuse", "low",
          "Remove bold from body text; keep at most one key term per paragraph.", "any")
_register("3.3", "Bold inline-header list items", "low",
          "Drop the bold lead-ins; write the items as plain list entries or as a paragraph.", "any")
_register("3.4", "Em dash", "medium",
          "Rewrite with a period, comma, colon or parentheses (not an en dash).", "any")
_register("3.5", "Emoji as formatting", "low",
          "Remove emoji from headings and from the start of list items.", "any")
_register("3.6", "Tiny table", "low",
          "Turn the small table into one plain sentence.", "any")
_register("3.7", "Mixed curly and straight quotes", "low",
          "Use one quote style (straight or curly) throughout the text.", "any")
_register("3.8", "Thematic breaks before headings", "low",
          "Remove the horizontal rules; the headings already separate the sections.", "any")
_register("4.1", "Chat assistant leftover", "high",
          "Delete the assistant phrasing; the text is not a conversation.", "en")
_register("4.2", "Knowledge-cutoff hedging", "high",
          "State once, concretely, what is unknown; do not speculate about gaps.", "en")
_register("4.3", "Unfilled placeholder", "high",
          "Fill in or remove the leftover template placeholder.", "en")
_register("5.1", "Didactic filler", "low",
          "Delete the filler and state the fact ('in order to' becomes 'to').", "en")
_register("5.2", "Summary opener", "medium",
          "Delete the summary opener and end on the last concrete point.", "en")
_register("6.1", "Fake-candid opener", "medium",
          "Delete the staged candour and start with the point.", "en")
_register("6.2", "Signposting announcement", "medium",
          "Skip the announcement and give the information.", "en")
_register("6.3", "Aphorism formula", "medium",
          "Replace the aphorism template with a concrete explanation.", "en")
_register("6.4", "Staccato fragments", "medium",
          "Merge the short dramatic fragments into one ordinary sentence.", "any")
_register("6.5", "Shouting capitals or scare quotes", "low",
          "Build emphasis with sentence structure, not capital letters or quote marks.", "any")
_register("6.6", "Human verb on an inanimate subject", "low",
          "Say what the thing actually does; do not give it a mind.", "en")
_register("TR-1", "Turkish negative parallelism", "medium",
          "Drop the 'not X, but Y' frame and state the positive claim directly.", "tr")
_register("TR-2", "Turkish inflated significance", "medium",
          "Replace 'plays a key role' or 'hosts' phrasing with the concrete effect or a plain 'vardır/içerir'.", "tr")
_register("TR-3", "Turkish brochure vocabulary", "medium",
          "Replace the brochure wording with specific information.", "tr")
_register("TR-4", "Turkish trailing converb commentary", "medium",
          "Cut the -erek/-arak commentary tacked onto the end of the sentence.", "tr")
_register("TR-5", "Turkish didactic filler or summary opener", "medium",
          "Delete the filler lead-in or the summary opener.", "tr")
_register("TR-6", "Turkish chat leftover", "high",
          "Delete the assistant sentence.", "tr")

RULE_ORDER = {rid: i for i, rid in enumerate(RULES)}

EM_DASH_AGENT_CATEGORY = "Em dash in agent-written copy (R-02)"
EM_DASH_AGENT_FIX = ("Agent-written copy must not contain em dashes (R-02): use a period, comma, colon "
                     "or parentheses instead, not an en dash.")
EM_DASH_HUMAN_CATEGORY = "Em dash overuse"
EM_DASH_HUMAN_FIX = ("Flag to the author; do not rewrite deliberate style silently. If they agree, use a "
                     "period, comma, colon or parentheses.")

# Markdown-structure rules that fire on ordinary engineering documentation.
TECHNICAL_DISABLED = frozenset({"3.1", "3.2", "3.3", "3.5", "3.6", "3.8"})
# Rules whose patterns are evaluated on text with long quotations blanked out.
QUOTE_EXEMPT_PREFIXES = ("1.", "2.", "TR-1", "TR-2", "TR-3", "TR-4")

CLUSTER_WINDOW_WORDS = 500


@dataclass
class RuleMatch:
    rule_id: str
    category: str
    severity: str
    line_number: int
    excerpt: str
    matched_span: str
    fix_hint: str


@dataclass
class FileReport:
    path: str
    words: int
    language: str
    findings: List[RuleMatch] = field(default_factory=list)

    @property
    def density(self) -> float:
        return (len(self.findings) * 1000.0 / self.words) if self.words else 0.0

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "words": self.words,
            "language": self.language,
            "density": round(self.density, 2),
            "findings": [asdict(f) for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

def _ci(*patterns: str) -> List[Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


def _cs(*patterns: str) -> List[Pattern[str]]:
    return [re.compile(p) for p in patterns]


WORD_RE = re.compile(r"[^\W_]+(?:['’\-][^\W_]+)*")

# Phrase rules: rule id -> (text variant, patterns). "content" blanks long quotations.
PHRASE_RULES: Dict[str, Tuple[str, List[Pattern[str]]]] = {
    "1.1": ("content", _ci(
        r"\b(?:stands|serves) as a\b",
        r"\bis a (?:testament|reminder) to\b",
        r"\b(?:crucial|pivotal|vital|significant|key) (?:role|moment|turning point)\b",
        r"\b(?:underscores|highlights) its (?:importance|significance)\b",
        r"\breflects broader\b",
        r"\bsymboli[sz]ing its (?:ongoing|enduring|lasting)\b",
        r"\bsetting the stage for\b",
        r"\bmarks a shift\b",
        r"\bevolving landscape\b",
        r"\bindelible mark\b",
        r"\bdeeply rooted\b",
        r"\b(?:generated debate|prompted broader reflection) (?:about|on)\b",
    )),
    "1.2": ("content", _ci(
        r"\bindependent coverage\b",
        r"\b(?:local|national) media outlets\b",
        r"\b(?:featured|profiled) in\b",
        r"\bcited in (?:(?:the|major|leading|several|numerous|various|national|international|local)\s+)?"
        r"(?:media|press|news|newspapers?|magazines?|outlets|publications?)\b",
        r"\bwritten by a leading expert\b",
        r"\bmaintains an active social media presence\b",
    )),
    "1.3": ("content", _ci(
        r"\bvaluable insights\b",
        r"\b(?:align|resonate) with\b",
    )),
    "1.4": ("content", _ci(
        r"\bboasts an?\b",
        r"\bnestled (?:in|among)\b",
        r"\bin the heart of\b",
        r"\bdiverse array of\b",
        r"\bcommitment to (?:quality|excellence|innovation)\b",
        r"\bnatural beauty\b",
        r"\b(?:world-class|state-of-the-art|groundbreaking|breathtaking|stunning)\b",
        r"\bexemplifies\b",
        r"\bseamless(?:ly)?\b",
    )),
    "1.5": ("content", _ci(
        r"\bindustry reports (?:suggest|indicate|show)\b",
        r"\bobservers (?:have cited|note)\b",
        r"\b(?:experts|some critics) (?:argue|say|believe)\b",
        r"\bstudies show\b",
        r"\bwidely regarded as\b",
    )),
    "1.6": ("content", _ci(
        r"\bDespite its\b[^.!?]+,\s*[^.!?]+?\bfaces? (?:several |many |significant )?challenges\b",
        r"\bDespite these challenges,\s*[^.!?]+?\bcontinues? to (?:thrive|grow|remain)\b",
    )),
    "2.2": ("content", _ci(
        r"\b(?:serves|stands|functions|operates) as\b",
        r"\b(?:boasts|features|maintains|offers) an?\b",
        r"\bventured into\b",
        r"\bbegan (?:his|her|their|its) career as\b",
        r"\brepresents an?\b",
    )),
    "2.3": ("content", _ci(
        r"\b(?:was|is) associated with\b",
        r"\bin connection with\b",
        r"\bconnected to the leadership of\b",
    )),
    "2.4": ("content", _ci(
        r"\bnot only\b[^.!?]+?\bbut\b(?:\s+also\b)?",
        r"\bit['’]?s not (?:just|merely|only)\b[^,;.!?]+,\s*it['’]?s\b",
        r"\bthis isn['’]?t\b[^,;.!?]+,\s*it['’]?s\b",
        r"\bno\s+\w+,\s*no\s+\w+,\s*just\b",
        r"\bis not an?\s+\w+\s+but an?\s+\w+\b",
    )),
    "4.1": ("struct", _ci(
        r"\bI hope this helps\b",
        r"\bCertainly!",
        r"\bGreat question\b",
        r"\bLet me know if you['’]?d like\b",
        r"\bWould you like me to\b",
        r"\bIn this section,? we will\b",
        r"\bHere is (?:a|an|your)\b",
    )),
    "4.2": ("struct", _ci(
        r"\bAs of my last (?:update|knowledge cutoff)\b",
        r"\bWhile specific details are limited\b",
        r"\bnot widely (?:documented|disclosed)\b",
        r"\bbased on available information\b",
        r"\bmaintains a low profile\b",
    )),
    "4.3": ("struct", _ci(
        r"\[(?:Your Name|Company Name|Insert [^\]\n]{1,60}|Describe [^\]\n]{1,60})\]",
        r"\bINSERT_URL\b",
        r"\b20\d\d-XX-XX\b",
    ) + _cs(
        # Case-sensitive, and never a real link or a reference definition.
        r"(?<!\])\[(?:Link|URL)\](?![(\[:])",
    )),
    "5.1": ("struct", _ci(
        r"\bIt(?:['’]?s| is) important to (?:note|remember|consider)\b",
        r"\bIt is worth noting\b",
        r"\bkeep in mind that\b",
        r"\bdue to the fact that\b",
    )),
    "6.2": ("struct", _ci(
        r"\bLet['’]?s dive in(?:to)?\b",
        r"\bHere['’]?s what you need to know\b",
        r"\bWithout further ado\b",
    )),
    "6.3": ("struct", _ci(
        r"\bis the (?:language|currency|lifeblood|backbone|cornerstone) of\b",
        r"\bbecomes a trap when\b",
    )),
    "6.6": ("struct", _ci(
        r"\bThe (?:dashboard|platform|system|data|roadmap|design|interface|software)\s+"
        r"(?:understands|knows|decides|wants|believes|cares)\b",
    )),
    "TR-1": ("content", _ci(
        r"\b(?:sadece|yalnızca)\b[^,;.!?]+\bdeğil[,;]\s*aynı zamanda\b",
        r"\bbir\s+\w+\s+olmaktan öte\b",
        # "X değil, (bir) Y'dir": a word, "değil,", up to four words, the last carrying a copula.
        r"\b\w+\s+değil,\s*(?:\w+\s+){0,3}?\w+?['’]?(?:dır|dir|dur|dür|tır|tir|tur|tür)(?:lar|ler)?\b",
    )),
    "TR-2": ("content", _ci(
        r"\b(?:kritik|hayati|kilit) bir rol oyna(?:maktadır|r|yan)\b",
        r"\badeta bir\b[^.!?]+\bniteliğinde(?:dir)?\b",
        r"\bkanıtı olarak karşımıza çık(?:maktadır|ıyor)\b",
        r"\bev sahipliği yapmaktadır\b",
        r"\bmihenk taşı\w*",
    )),
    "TR-3": ("content", _ci(
        r"\bgeniş bir yelpaze(?:de|si|ye)?\b",
        r"\b(?:zengin|kültürel) mozai[kğ]\w*",
        r"\b(?:tarihi|zengin) doku(?:su|suyla|sunu)?\b",
        r"\bharmanlayan\b",
        r"\bbütüncül bir yaklaşım\w*",
        r"\bkusursuz bir deneyim\w*",
        r"\bkalbinde yer alan\b",
        r"\bkapılarını arala(?:maktadır|r)\b",
    )),
    "TR-5": ("struct", _ci(
        r"\b(?:Unutmamak|Belirtmek|Vurgulamak) gerekir ki\b",
    )),
    "TR-6": ("struct", _ci(
        r"\bUmarım bu (?:yardımcı olur|işinize yarar)\b",
        r"\bBaşka bir sorunuz olursa\b",
        r"\bHarika bir soru\b",
        r"\bİşte\b[^.!?]+?\bhakkında bilmeniz gerekenler\b",
    )),
}

_SENTENCE_END = r"(?:[.!?][\"'”’)\]]*)?$"
TRAILING_ING_RE = re.compile(
    r",\s+(?:highlighting|underscoring|emphasi[sz]ing|ensuring|reflecting|symboli[sz]ing|contributing to|"
    r"cultivating|fostering|encompassing|enhancing|showcasing)\b[^.!?]{0,80}" + _SENTENCE_END,
    re.IGNORECASE)
TR_CONVERB_RE = re.compile(
    r",\s*[^.!?]{0,40}\b(?:önemini vurgulayarak|deneyim[iu]? sunarak|katkı sağlayarak|gözler önüne sererek|"
    r"pekiştirerek)\b[^.!?]*" + _SENTENCE_END,
    re.IGNORECASE)
FAKE_CANDID_RE = re.compile(r"^(?:Honestly\?|Let['’]?s be honest,|Here['’]?s the thing:|Real talk:)", re.IGNORECASE)
SUMMARY_OPENER_RE = re.compile(r"^(?:In conclusion|In summary|To summarize|Overall|Ultimately),\s", re.IGNORECASE)
TR_SUMMARY_OPENER_RE = re.compile(
    r"^(?:Sonuç olarak|Özetle|Özetlemek gerekirse|Genel olarak değerlendirildiğinde),\s", re.IGNORECASE)
# Case-sensitive on purpose: the capital letter is the signal.
TITLE_DEFINING_RE = re.compile(r"^[A-Z][\w\s-]{1,40}\s+refers to\b")
CURATED_RE = re.compile(r"\bis a curated compilation of\b", re.IGNORECASE)
PAIRED_HEADING_RE = re.compile(
    r"\b(?:Awards and recognition|Challenges and future prospects|Impact and legacy|History and background)\b",
    re.IGNORECASE)
AI_VOCAB_RE = re.compile(
    r"\b(?:additionally|delv(?:e|es|ed|ing)|tapestr(?:y|ies)|crucial(?:ly)?|pivotal|meticulous(?:ly)?|"
    r"intricate(?:ly)?|intricacies|interplay|garner(?:s|ed|ing)?|bolster(?:s|ed|ing)?|underscor(?:e|es|ed|ing)|"
    r"fostering|showcasing|vibrant|enduring|"
    r"(?:evolving|changing|ever-changing|shifting|competitive|digital|political|regulatory|media|technological|"
    r"business|cultural|economic|security|threat|research|funding|investment|market|industry)\s+landscapes?|"
    r"landscapes?\s+of)\b",
    re.IGNORECASE)
AI_VOCAB_ALWAYS_RE = re.compile(r"^(?:delv|tapestr)", re.IGNORECASE)
RATHER_THAN_RE = re.compile(r"\brather than\b", re.IGNORECASE)
TRIAD_RE = re.compile(r"\b[A-Za-z]+,\s+[A-Za-z]+,?\s+and\s+[A-Za-z]+\b")
TRIAD_CLICHE_RE = re.compile(r"\b(?:fast, reliable,? and secure|learn, connect,? and grow)\b", re.IGNORECASE)
THE_NOUN_RE = re.compile(r"^The ([a-z]+)\s")  # case-sensitive
FILLER_CLUSTER_RE = re.compile(r"\b(?:in order to|may vary)\b", re.IGNORECASE)
EM_DASH_RE = re.compile(r"—|(?<=\s)--(?=\s)")
EMOJI_CLASS = "[\U0001F300-\U0001FAFF☀-➿⭐⭕]"
EMOJI_RE = re.compile(EMOJI_CLASS)
LIST_EMOJI_RE = re.compile(r"^\s*(?:[-*+]|\d{1,9}[.)])\s+(?:[*_]{1,2})?\s*" + EMOJI_CLASS)
BOLD_RE = re.compile(r"\*\*(?=\S)[^*\n]+?(?<=\S)\*\*|__(?=\S)[^_\n]+?(?<=\S)__")
INLINE_HEADER_RE = re.compile(
    r"^\s*(?:[-*+]|\d{1,9}[.)])\s+\*\*[^*]{2,40}?:\*\*|^\s*(?:[-*+]|\d{1,9}[.)])\s+\*\*[^*]{2,40}?\*\*:\s+")
# Case-sensitive on purpose (Turkish capitals included).
ALL_CAPS_RUN_RE = re.compile(r"\b[A-ZÇĞİÖŞÜ]{2,}(?:\s+[A-ZÇĞİÖŞÜ]{2,}){2,}\b")
QUOTED_RE = re.compile(r"“(?:[^“”\n]|\n(?![ \t]*\n))*”|\"(?:[^\"\n]|\n(?![ \t]*\n))*\"")
CURLY_QUOTE_RE = re.compile(r"[“”‘’]")
STRAIGHT_QUOTE_RE = re.compile(r"[\"']")

TITLE_SMALL_WORDS = frozenset(
    "a an and as at but by for from in into nor of on or over per the to up via vs with".split())

# ---------------------------------------------------------------------------
# Masking (line numbers are preserved: every masked character becomes a space)
# ---------------------------------------------------------------------------

_FENCE_OPEN_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_FENCE_CLOSE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*$")
_BLOCKQUOTE_RE = re.compile(r"^ {0,3}>")
_INLINE_CODE_RE = re.compile(r"(`+)(?!`)(.+?)(?<!`)\1(?!`)")
_HTML_TAG_RE = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*(?:\s[^<>\n]*)?/?>")
_LINK_DEST_RE = re.compile(r"(?<=\]\()[^()\s]*(?:\s+\"[^\"\n]*\")?(?=\))")
_URL_RE = re.compile(r"<?\b(?:https?|ftp)://[^\s<>)\]]+>?")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def _blank(s: str) -> str:
    return re.sub(r"[^\n]", " ", s)


def _blank_match(m: "re.Match[str]") -> str:
    return _blank(m.group(0))


def _mask_inline(line: str) -> str:
    line = _INLINE_CODE_RE.sub(_blank_match, line)
    line = _HTML_TAG_RE.sub(_blank_match, line)
    line = _LINK_DEST_RE.sub(_blank_match, line)
    return _URL_RE.sub(_blank_match, line)


def mask_markdown(text: str, frontmatter: bool = True) -> str:
    """Blanks frontmatter, fenced code, blockquotes, inline code, HTML tags/comments and URLs."""
    lines = text.split("\n")
    out = list(lines)
    n = len(lines)
    i = 0
    if frontmatter and n and lines[0].strip() == "---":
        for j in range(1, n):
            if lines[j].strip() in ("---", "..."):
                for k in range(j + 1):
                    out[k] = _blank(lines[k])
                i = j + 1
                break
    fence = ""
    while i < n:
        line = lines[i]
        if fence:
            out[i] = _blank(line)
            close = _FENCE_CLOSE_RE.match(line)
            if close and close.group(1)[0] == fence[0] and len(close.group(1)) >= len(fence):
                fence = ""
        else:
            opener = _FENCE_OPEN_RE.match(line)
            if opener and not (opener.group(1)[0] == "`" and "`" in opener.group(2)):
                fence = opener.group(1)
                out[i] = _blank(line)
            elif _BLOCKQUOTE_RE.match(line):
                out[i] = _blank(line)
            else:
                out[i] = _mask_inline(line)
        i += 1
    return _HTML_COMMENT_RE.sub(_blank_match, "\n".join(out))


def mask_quotations(text: str, min_words: int = 5) -> str:
    """Blanks quotations of `min_words` or more words (a real person's or a source's words)."""
    def repl(m: "re.Match[str]") -> str:
        inner = m.group(0)[1:-1]
        return _blank(m.group(0)) if len(WORD_RE.findall(inner)) >= min_words else m.group(0)
    return QUOTED_RE.sub(repl, text)


# ---------------------------------------------------------------------------
# HTML → Markdown-shaped text (line map keeps original line numbers)
# ---------------------------------------------------------------------------

class _HtmlProse(HTMLParser):
    _SKIP = frozenset({"script", "style", "code", "pre", "template", "svg", "math", "noscript", "head", "title",
                       "blockquote", "textarea", "select"})
    _BREAK = frozenset({"p", "div", "section", "article", "header", "footer", "main", "aside", "nav", "ul", "ol",
                        "dl", "dt", "dd", "figure", "figcaption", "form", "fieldset", "details", "summary",
                        "address", "body", "html"})
    _HEADINGS = {"h1": 1, "h2": 2, "h3": 3, "h4": 4, "h5": 5, "h6": 6}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._lines: List[List[str]] = [[]]
        self._srcs: List[Optional[int]] = [None]
        self._skip_tag = ""
        self._skip_depth = 0
        self._flatten = 0  # inside a heading or table cell: keep content on one line
        self._tables: List[List[int]] = []  # per open table: [rows seen, cells in current row]

    # -- output helpers --------------------------------------------------
    def _add(self, text: str, from_data: bool = False) -> None:
        src = self.getpos()[0]
        for k, part in enumerate(text.split("\n")):
            if k:
                self._lines.append([])
                self._srcs.append(None)
                if from_data:
                    src += 1
            if part:
                self._lines[-1].append(part)
                if self._srcs[-1] is None and part.strip():
                    self._srcs[-1] = src

    def _current_has_text(self) -> bool:
        return any(p.strip() for p in self._lines[-1])

    def _line_break(self) -> None:
        if self._current_has_text():
            self._add("\n")

    def _block_break(self) -> None:
        if self._current_has_text():
            self._add("\n\n")
        elif len(self._lines) >= 2 and any(p.strip() for p in self._lines[-2]):
            self._add("\n")

    # -- parser callbacks ------------------------------------------------
    def handle_starttag(self, tag: str, attrs) -> None:
        if self._skip_depth:
            if tag == self._skip_tag:
                self._skip_depth += 1
            elif self._skip_tag == "head" and tag == "body":
                self._skip_depth = 0
                self._block_break()
            return
        if tag in self._SKIP:
            if tag == "blockquote":
                self._block_break()
            self._skip_tag, self._skip_depth = tag, 1
            return
        if tag in self._HEADINGS:
            self._block_break()
            self._add("#" * self._HEADINGS[tag] + " ")
            self._flatten += 1
        elif tag == "li":
            self._line_break()
            self._add("- ")
        elif tag == "table":
            self._block_break()
            self._tables.append([0, 0])
        elif tag == "tr":
            self._line_break()
            self._add("|")
            if self._tables:
                self._tables[-1][1] = 0
        elif tag in ("td", "th"):
            if self._tables and self._tables[-1][1]:
                self._add(" |")
            self._add(" ")
            if self._tables:
                self._tables[-1][1] += 1
            self._flatten += 1
        elif tag in ("strong", "b"):
            self._add("**")
        elif tag == "q":
            self._add('"')
        elif tag == "hr":
            self._block_break()
            self._add("---")
            self._block_break()
        elif tag == "br":
            self._line_break()
        elif tag in self._BREAK:
            self._block_break()

    def handle_endtag(self, tag: str) -> None:
        if self._skip_depth:
            if tag == self._skip_tag:
                self._skip_depth -= 1
            return
        if tag in self._HEADINGS:
            self._flatten = max(0, self._flatten - 1)
            self._block_break()
        elif tag in ("td", "th"):
            self._flatten = max(0, self._flatten - 1)
        elif tag == "tr":
            self._add(" |")
            if self._tables:
                state = self._tables[-1]
                state[0] += 1
                if state[0] == 1:
                    self._line_break()
                    self._add("|" + "---|" * max(state[1], 1))
        elif tag == "table":
            if self._tables:
                self._tables.pop()
            self._block_break()
        elif tag in ("strong", "b"):
            self._add("**")
        elif tag == "q":
            self._add('"')
        elif tag in self._BREAK:
            self._block_break()

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        data = re.sub(r"[ \t\r\f\v]+", " ", data)
        if not data.strip():
            if self._lines[-1] and not self._lines[-1][-1].endswith(" "):
                self._add(" ")
            return
        data = re.sub(r" *\n *", "\n", data)
        if self._flatten:
            data = data.replace("\n", " ")
        self._add(data, from_data=True)

    def result(self) -> Tuple[str, List[int]]:
        srcs: List[int] = []
        last = 1
        for s in self._srcs:
            last = s if s is not None else last
            srcs.append(last)
        return "\n".join("".join(parts) for parts in self._lines), srcs


def html_to_markdown(html: str) -> Tuple[str, List[int]]:
    """Returns (markdown-shaped prose, line_map) where line_map[i] is the source line of output line i."""
    parser = _HtmlProse()
    parser.feed(html)
    parser.close()
    return parser.result()


# ---------------------------------------------------------------------------
# Sentence splitting
# ---------------------------------------------------------------------------

_ABBREV_ALWAYS = frozenset({"mr", "mrs", "ms", "dr", "prof", "e.g", "i.e", "vs", "etc", "st", "jr", "sr", "cf"})
_ABBREV_BEFORE_NUMBER = frozenset({"no", "fig", "vol", "pp", "p", "sec", "ch"})
_BOUNDARY_RE = re.compile(r"[.!?]+[\"'”’)\]]*(?=\s|$)")
_TOKEN_BEFORE_RE = re.compile(r"([^\s(\[\"'“‘]+)$")


def sentence_spans(text: str) -> List[Tuple[int, int]]:
    """Returns (start, end) spans of sentences. Abbreviations, initials and decimals never split."""
    spans: List[Tuple[int, int]] = []
    start = 0
    for m in _BOUNDARY_RE.finditer(text):
        end = m.end()
        rest = text[end:].lstrip()
        if rest and rest[0].islower():
            continue
        if m.group(0).rstrip("\"'”’)]") == ".":
            token = _TOKEN_BEFORE_RE.search(text[start:m.start()])
            word = token.group(1) if token else ""
            lower = word.lower()
            if lower in _ABBREV_ALWAYS:
                continue
            if lower in _ABBREV_BEFORE_NUMBER and rest[:1].isdigit():
                continue
            if len(word) == 1 and word.isalpha() and word.isupper():
                continue  # an initial such as "J. R. Smith"
        spans.append((start, end))
        start = end
    if text[start:].strip():
        spans.append((start, len(text)))
    trimmed = []
    for s, e in spans:
        seg = text[s:e]
        lead = len(seg) - len(seg.lstrip())
        tail = len(seg) - len(seg.rstrip())
        if seg.strip():
            trimmed.append((s + lead, e - tail))
    return trimmed


def split_sentences(text: str) -> List[str]:
    return [text[s:e] for s, e in sentence_spans(text)]


# ---------------------------------------------------------------------------
# Document model
# ---------------------------------------------------------------------------

_ATX_RE = re.compile(r"^ {0,3}(#{1,6})(?=[ \t]|$)")
_ATX_TRAIL_RE = re.compile(r"[ \t]+#+[ \t]*$")
_SETEXT_RE = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
_HR_RE = re.compile(r"^ {0,3}(?:(?:-[ \t]*){3,}|(?:\*[ \t]*){3,}|(?:_[ \t]*){3,})$")
_LIST_RE = re.compile(r"^[ \t]*(?:[-*+]|\d{1,9}[.)])[ \t]+")
_TABLE_SEP_RE = re.compile(r"^[ \t]*\|?[ \t]*:?-{3,}:?[ \t]*(?:\|[ \t]*:?-{3,}:?[ \t]*)*\|?[ \t]*$")


@dataclass
class Block:
    kind: str  # "para" | "heading" | "list" | "table" | "hr"
    start: int  # first line index
    end: int  # exclusive line index
    offset: int  # character offset of the first line
    length: int
    prefix_ranges: List[Tuple[int, int]] = field(default_factory=list)  # block-relative, blanked in bodies


@dataclass
class Document:
    path: str
    display: str  # the text line numbers refer to (for HTML: the converted text)
    structural: str  # code, frontmatter, blockquotes, tags and URLs blanked
    content: str  # structural plus long quotations blanked
    line_map: Optional[List[int]] = None


def build_document(text: str, path: str = "<text>", kind: str = "markdown") -> Document:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if text.startswith("﻿"):
        text = text[1:]
    line_map = None
    if kind == "html":
        text, line_map = html_to_markdown(text)
        structural = mask_markdown(text, frontmatter=False)
    else:
        structural = mask_markdown(text)
    return Document(path, text, structural, mask_quotations(structural), line_map)


def _is_blank(line: str) -> bool:
    return not line.strip()


def _starts_table(lines: Sequence[str], i: int) -> bool:
    line = lines[i]
    if "|" not in line:
        return False
    if line.lstrip().startswith("|"):
        return True
    return i + 1 < len(lines) and "|" in lines[i + 1] and bool(_TABLE_SEP_RE.match(lines[i + 1]))


def build_blocks(lines: Sequence[str]) -> List[Block]:
    offsets = []
    pos = 0
    for line in lines:
        offsets.append(pos)
        pos += len(line) + 1
    blocks: List[Block] = []

    def add(kind: str, start: int, end: int, prefixes: List[Tuple[int, int]]) -> None:
        length = offsets[end - 1] + len(lines[end - 1]) - offsets[start]
        blocks.append(Block(kind, start, end, offsets[start], length, prefixes))

    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if _is_blank(line):
            i += 1
            continue
        atx = _ATX_RE.match(line)
        if atx:
            prefixes = [(0, atx.end())]
            trail = _ATX_TRAIL_RE.search(line)
            if trail:
                prefixes.append((trail.start(), len(line)))
            add("heading", i, i + 1, prefixes)
            i += 1
            continue
        if _HR_RE.match(line):
            add("hr", i, i + 1, [])
            i += 1
            continue
        if _starts_table(lines, i):
            j = i + 1
            while j < n and not _is_blank(lines[j]) and "|" in lines[j]:
                j += 1
            add("table", i, j, [])
            i = j
            continue
        marker = _LIST_RE.match(line)
        if marker:
            j = i + 1
            while (j < n and not _is_blank(lines[j]) and not _LIST_RE.match(lines[j])
                   and not _ATX_RE.match(lines[j]) and not _HR_RE.match(lines[j])):
                j += 1
            add("list", i, j, [(0, marker.end())])
            i = j
            continue
        j = i + 1
        kind = "para"
        while j < n and not _is_blank(lines[j]):
            if _SETEXT_RE.match(lines[j]):
                kind = "heading"
                j += 1
                break
            if (_ATX_RE.match(lines[j]) or _HR_RE.match(lines[j]) or _LIST_RE.match(lines[j])
                    or _starts_table(lines, j)):
                break
            j += 1
        prefixes = []
        if kind == "heading":
            underline_start = offsets[j - 1] - offsets[i]
            prefixes.append((underline_start, underline_start + len(lines[j - 1])))
        add(kind, i, j, prefixes)
        i = j
    return blocks


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

_TR_CHARS_RE = re.compile(r"[çğışöüÇĞİŞÖÜ]")
_TR_WORDS = frozenset(
    "ve bir bu için ile da de olarak değil çok daha gibi olan ise veya ancak ama her kadar sonra göre şu ki "
    "mi mı olduğu üzere yani ayrıca bile".split())
_EN_WORDS = frozenset(
    "the and of to is in that it for with as was on are be this by an or not you we from at".split())


def detect_language(text: str) -> str:
    tr = en = 0
    for word in WORD_RE.findall(text):
        lower = word.lower()
        if lower in _EN_WORDS:
            en += 1
        if lower in _TR_WORDS or _TR_CHARS_RE.search(word):
            tr += 1
    return "tr" if tr > en else "en"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@dataclass
class _Hit:
    rule_id: str
    offset: int
    end: int
    span: str
    category: Optional[str] = None
    severity: Optional[str] = None
    fix_hint: Optional[str] = None


def _dense_indices(word_positions: Sequence[int], k: int, window: int = CLUSTER_WINDOW_WORDS) -> set:
    """Indices of hits that fall in some run of k hits spanning fewer than `window` words."""
    order = sorted(range(len(word_positions)), key=lambda i: word_positions[i])
    flagged = set()
    for a in range(len(order) - k + 1):
        if word_positions[order[a + k - 1]] - word_positions[order[a]] < window:
            flagged.update(order[a:a + k])
    return flagged


class _Scanner:
    def __init__(self, doc: Document, lang: str, profile: str, source: str, strict: bool) -> None:
        self.doc = doc
        self.lang = lang
        self.profile = profile
        self.source = source
        self.strict = strict
        self.lines = doc.structural.split("\n")
        self.blocks = build_blocks(self.lines)
        self.word_starts = [m.start() for m in WORD_RE.finditer(doc.structural)]
        self.hits: List[_Hit] = []
        self._bodies: Dict[Tuple[int, str], str] = {}
        self._sentences: Dict[Tuple[int, str], List[Tuple[int, str]]] = {}

    # -- helpers ---------------------------------------------------------
    def enabled(self, rule_id: str) -> bool:
        info = RULES[rule_id]
        if self.profile == "technical" and rule_id in TECHNICAL_DISABLED:
            return False
        return info.lang == "any" or info.lang == self.lang

    def body(self, index: int, variant: str) -> str:
        key = (index, variant)
        if key not in self._bodies:
            block = self.blocks[index]
            source = self.doc.content if variant == "content" else self.doc.structural
            text = source[block.offset:block.offset + block.length]
            for s, e in block.prefix_ranges:
                text = text[:s] + " " * (e - s) + text[e:]
            self._bodies[key] = text
        return self._bodies[key]

    def sentences(self, index: int, variant: str) -> List[Tuple[int, str]]:
        """Absolute offset and text of each sentence in a block."""
        key = (index, variant)
        if key not in self._sentences:
            text = self.body(index, variant)
            base = self.blocks[index].offset
            self._sentences[key] = [(base + s, text[s:e]) for s, e in sentence_spans(text)]
        return self._sentences[key]

    def word_index(self, offset: int) -> int:
        return bisect.bisect_left(self.word_starts, offset)

    def add(self, rule_id: str, offset: int, span: str, **overrides) -> None:
        clean = " ".join(span.split())
        self.hits.append(_Hit(rule_id, offset, offset + len(span), clean, **overrides))

    def block_indices(self, *kinds: str) -> List[int]:
        return [i for i, b in enumerate(self.blocks) if not kinds or b.kind in kinds]

    # -- rule runners ----------------------------------------------------
    def run(self) -> List[_Hit]:
        for rule_id, (variant, patterns) in PHRASE_RULES.items():
            if self.enabled(rule_id):
                self._phrases(rule_id, variant, patterns)
        for rule_id, method in (
            ("1.3", self._r1_3), ("1.7", self._r1_7), ("1.8", self._r1_8), ("2.1", self._r2_1),
            ("2.4", self._r2_4_rather_than), ("2.5", self._r2_5), ("2.6", self._r2_6), ("3.1", self._r3_1),
            ("3.2", self._r3_2), ("3.3", self._r3_3), ("3.4", self._r3_4), ("3.5", self._r3_5),
            ("3.6", self._r3_6), ("3.7", self._r3_7), ("3.8", self._r3_8), ("5.1", self._r5_1_cluster),
            ("5.2", self._r5_2), ("6.1", self._r6_1), ("6.4", self._r6_4), ("6.5", self._r6_5),
            ("TR-4", self._tr_4), ("TR-5", self._tr_5_opener),
        ):
            if self.enabled(rule_id):
                method()
        return self.hits

    def _phrases(self, rule_id: str, variant: str, patterns: List[Pattern[str]]) -> None:
        for i in self.block_indices("para", "heading", "list", "table"):
            text = self.body(i, variant)
            base = self.blocks[i].offset
            for pattern in patterns:
                for m in pattern.finditer(text):
                    self.add(rule_id, base + m.start(), m.group(0))

    def _sentence_rule(self, rule_id: str, variant: str, pattern: Pattern[str], kinds=("para", "list")) -> None:
        for i in self.block_indices(*kinds):
            for offset, sentence in self.sentences(i, variant):
                m = pattern.search(sentence)
                if m:
                    self.add(rule_id, offset + m.start(), m.group(0))

    def _r1_3(self) -> None:
        self._sentence_rule("1.3", "content", TRAILING_ING_RE)

    def _r1_7(self) -> None:
        seen = 0
        for i in self.block_indices("para"):
            for offset, sentence in self.sentences(i, "content"):
                for pattern in (TITLE_DEFINING_RE, CURATED_RE):
                    m = pattern.search(sentence)
                    if m:
                        self.add("1.7", offset + m.start(), m.group(0))
                seen += 1
                if seen >= 3:
                    return

    def _r1_8(self) -> None:
        for i in self.block_indices("heading"):
            for m in PAIRED_HEADING_RE.finditer(self.body(i, "content")):
                self.add("1.8", self.blocks[i].offset + m.start(), m.group(0))

    def _r2_1(self) -> None:
        found = []  # (offset, text, block index, always)
        for i in self.block_indices("para", "heading", "list", "table"):
            text = self.body(i, "content")
            for m in AI_VOCAB_RE.finditer(text):
                word = m.group(0)
                always = bool(AI_VOCAB_ALWAYS_RE.match(word))
                if word.lower() == "additionally":
                    before = text[:m.start()].rstrip()
                    after = text[m.end():m.end() + 1]
                    if after == "," and (not before or before[-1] in ".!?:\"'”’)"):
                        always = True
                found.append((self.blocks[i].offset + m.start(), word, i, always))
        per_block: Dict[int, int] = {}
        for _, _, i, _ in found:
            per_block[i] = per_block.get(i, 0) + 1
        dense = _dense_indices([self.word_index(o) for o, _, _, _ in found], 3)
        for n, (offset, word, i, always) in enumerate(found):
            if self.strict or always or per_block[i] >= 2 or n in dense:
                self.add("2.1", offset, word)

    def _r2_4_rather_than(self) -> None:
        found = []
        for i in self.block_indices("para", "heading", "list", "table"):
            for m in RATHER_THAN_RE.finditer(self.body(i, "content")):
                found.append((self.blocks[i].offset + m.start(), m.group(0)))
        dense = _dense_indices([self.word_index(o) for o, _ in found], 2)
        for n, (offset, span) in enumerate(found):
            if self.strict or n in dense:
                self.add("2.4", offset, span)

    def _r2_5(self) -> None:
        found = []
        for i in self.block_indices("para", "heading", "list", "table"):
            text = self.body(i, "content")
            base = self.blocks[i].offset
            for m in TRIAD_CLICHE_RE.finditer(text):
                self.add("2.5", base + m.start(), m.group(0))
            for m in TRIAD_RE.finditer(text):
                if not TRIAD_CLICHE_RE.match(m.group(0)):
                    found.append((base + m.start(), m.group(0)))
        # Engineering docs enumerate real triples ("Linux, macOS and Windows") all the time, so the
        # technical profile only reports generic triads at twice the prose density; clichés always fire.
        threshold = 6 if self.profile == "technical" else 3
        dense = _dense_indices([self.word_index(o) for o, _ in found], threshold)
        for n, (offset, span) in enumerate(found):
            if self.strict or n in dense:
                self.add("2.5", offset, span)

    def _r2_6(self) -> None:
        for i in self.block_indices("para"):
            run: List[Tuple[int, str, str]] = []
            for offset, sentence in self.sentences(i, "content") + [(-1, "")]:
                m = THE_NOUN_RE.match(sentence)
                if m:
                    run.append((offset, m.group(1), m.group(0).strip()))
                    continue
                nouns = [noun for _, noun, _ in run]
                if len(run) >= 3 and len(set(nouns)) == len(nouns):
                    self.add("2.6", run[0][0], " / ".join(lead for _, _, lead in run))
                run = []

    def _r3_1(self) -> None:
        for i in self.block_indices("heading"):
            text = self.body(i, "struct")
            tokens = []
            for raw in text.split():
                token = raw.strip("*_`\"'“”‘’()[]{}:;,.!?")
                if not token or token[0].isdigit() or not any(c.isalpha() for c in token):
                    continue
                tokens.append(token)
            if len(tokens) < 4:
                continue
            significant = [t for t in tokens[1:] if t.lower() not in TITLE_SMALL_WORDS]
            titled = [t for t in significant if len(t) > 1 and t[0].isupper() and t[1:].islower()]
            if len(significant) >= 2 and len(titled) >= 2 and all(t[0].isupper() for t in significant):
                first = text.strip()
                self.add("3.1", self.blocks[i].offset + text.index(first), first)

    def _r3_2(self) -> None:
        for i in self.block_indices("para"):
            text = self.body(i, "struct")
            bolds = list(BOLD_RE.finditer(text))
            if len(bolds) >= 3:
                span = ", ".join(m.group(0) for m in bolds[:3]) + (f" (+{len(bolds) - 3} more)" if len(bolds) > 3 else "")
                self.hits.append(_Hit("3.2", self.blocks[i].offset + bolds[0].start(),
                                      self.blocks[i].offset + bolds[-1].end(), span))

    def _r3_3(self) -> None:
        run: List[int] = []

        def flush() -> None:
            if len(run) >= 2:
                for idx in run:
                    b = self.blocks[idx]
                    line = self.lines[b.start]
                    m = INLINE_HEADER_RE.match(line)
                    self.add("3.3", b.offset + len(line) - len(line.lstrip()), m.group(0).strip() if m else line.strip())
            run.clear()

        for i, block in enumerate(self.blocks):
            if block.kind == "list" and INLINE_HEADER_RE.match(self.lines[block.start]):
                run.append(i)
            else:
                flush()
        flush()

    def _r3_4(self) -> None:
        found = []
        for i in self.block_indices("para", "heading", "list", "table"):
            for m in EM_DASH_RE.finditer(self.body(i, "content")):
                found.append((self.blocks[i].offset + m.start(), m.group(0), i))
        if self.source == "agent":
            for offset, dash, _ in found:
                self.hits.append(_Hit("3.4", offset, offset + len(dash), self._dash_context(offset, dash),
                                      EM_DASH_AGENT_CATEGORY, "high", EM_DASH_AGENT_FIX))
            return
        per_block: Dict[int, int] = {}
        for _, _, i in found:
            per_block[i] = per_block.get(i, 0) + 1
        dense = _dense_indices([self.word_index(o) for o, _, _ in found], 3)
        for n, (offset, dash, i) in enumerate(found):
            if self.strict or per_block[i] >= 2 or n in dense:
                self.hits.append(_Hit("3.4", offset, offset + len(dash), self._dash_context(offset, dash),
                                      EM_DASH_HUMAN_CATEGORY, None, EM_DASH_HUMAN_FIX))

    def _dash_context(self, offset: int, dash: str) -> str:
        """The dash with up to two words on each side, for the Matched line."""
        text = self.doc.display
        left = text[max(0, offset - 40):offset].split("\n")[-1].split()
        right = text[offset + len(dash):offset + len(dash) + 40].split("\n")[0].split()
        return " ".join(left[-2:] + [dash] + right[:2])

    def _r3_5(self) -> None:
        for i in self.block_indices("heading", "list"):
            block = self.blocks[i]
            if block.kind == "heading":
                m = EMOJI_RE.search(self.body(i, "struct"))
                if m:
                    self.add("3.5", block.offset + m.start(), m.group(0))
            else:
                line = self.lines[block.start]
                m = LIST_EMOJI_RE.match(line)
                if m:
                    self.add("3.5", block.offset + m.end() - 1, m.group(0)[-1])

    def _r3_6(self) -> None:
        for i in self.block_indices("table"):
            block = self.blocks[i]
            rows = self.lines[block.start:block.end]
            if len(rows) < 2 or not _TABLE_SEP_RE.match(rows[1]) or "|" not in rows[1]:
                continue
            header = rows[0].strip().strip("|")
            columns = len(re.split(r"(?<!\\)\|", header))
            data_rows = len(rows) - 2
            if 2 <= data_rows <= 3 and columns <= 2:
                self.add("3.6", block.offset + len(rows[0]) - len(rows[0].lstrip()),
                         f"{columns}-column table with {data_rows} data rows")

    def _r3_7(self) -> None:
        text = self.doc.structural
        curly = list(CURLY_QUOTE_RE.finditer(text))
        straight = list(STRAIGHT_QUOTE_RE.finditer(text))
        if not curly or not straight:
            return
        minority = curly if len(curly) <= len(straight) else straight
        first = minority[0]
        style = "curly" if minority is curly else "straight"
        self.hits.append(_Hit("3.7", first.start(), first.end(),
                              f"{first.group(0)} ({style}; {len(curly)} curly vs {len(straight)} straight)"))

    def _r3_8(self) -> None:
        breaks = [i for i, b in enumerate(self.blocks)
                  if b.kind == "hr" and i + 1 < len(self.blocks) and self.blocks[i + 1].kind == "heading"]
        if len(breaks) >= 3:
            for i in breaks:
                self.add("3.8", self.blocks[i].offset, self.lines[self.blocks[i].start].strip())

    def _r5_1_cluster(self) -> None:
        found = []
        for i in self.block_indices("para", "heading", "list", "table"):
            for m in FILLER_CLUSTER_RE.finditer(self.body(i, "struct")):
                found.append((self.blocks[i].offset + m.start(), m.group(0), i))
        if self.profile != "technical":
            for offset, span, _ in found:
                self.add("5.1", offset, span)
            return
        per_block: Dict[int, int] = {}
        for _, _, i in found:
            per_block[i] = per_block.get(i, 0) + 1
        dense = _dense_indices([self.word_index(o) for o, _, _ in found], 3)
        for n, (offset, span, i) in enumerate(found):
            if self.strict or per_block[i] >= 2 or n in dense:
                self.add("5.1", offset, span)

    def _paragraph_opener(self, rule_id: str, pattern: Pattern[str]) -> None:
        for i in self.block_indices("para"):
            text = self.body(i, "struct")
            stripped = text.lstrip()
            m = pattern.match(stripped)
            if m:
                self.add(rule_id, self.blocks[i].offset + len(text) - len(stripped), m.group(0).rstrip())

    def _r5_2(self) -> None:
        self._paragraph_opener("5.2", SUMMARY_OPENER_RE)

    def _r6_1(self) -> None:
        self._sentence_rule("6.1", "struct", FAKE_CANDID_RE)

    def _r6_4(self) -> None:
        for i in self.block_indices("para"):
            run: List[Tuple[int, str]] = []
            for offset, sentence in self.sentences(i, "struct") + [(-1, "")]:
                words = len(WORD_RE.findall(sentence))
                if 1 <= words <= 4:
                    run.append((offset, sentence))
                    continue
                if len(run) >= 3:
                    self.add("6.4", run[0][0], " ".join(s for _, s in run))
                run = []

    def _r6_5(self) -> None:
        for i in self.block_indices("para", "heading", "list", "table"):
            text = self.body(i, "struct")
            base = self.blocks[i].offset
            for m in ALL_CAPS_RUN_RE.finditer(text):
                self.add("6.5", base + m.start(), m.group(0))
            scare = []
            for m in QUOTED_RE.finditer(text):
                inner = m.group(0)[1:-1]
                count = len(WORD_RE.findall(inner))
                if 1 <= count <= 3 and len(inner) <= 30 and "\n" not in inner:
                    scare.append(m)
            if self.strict or len(scare) >= 3:
                for m in scare:
                    self.add("6.5", base + m.start(), m.group(0))

    def _tr_4(self) -> None:
        self._sentence_rule("TR-4", "content", TR_CONVERB_RE)

    def _tr_5_opener(self) -> None:
        self._paragraph_opener("TR-5", TR_SUMMARY_OPENER_RE)


# Where two rules describe the same words, keep the more specific one.
SUPERSEDED_BY = {"2.2": ("1.1", "1.4")}


def _dedupe(hits: List[_Hit], text: str) -> List[_Hit]:
    """Merges overlapping hits of one rule into a single span and drops superseded duplicates."""
    hits = sorted(hits, key=lambda h: (h.offset, -(h.end - h.offset), RULE_ORDER[h.rule_id]))
    kept: List[_Hit] = []
    open_hit: Dict[str, _Hit] = {}
    for h in hits:
        prev = open_hit.get(h.rule_id)
        if prev is not None and h.offset < prev.end:
            if h.end > prev.end and prev.rule_id in PHRASE_RULES:
                prev.end = h.end
                prev.span = " ".join(text[prev.offset:prev.end].split())
            continue
        kept.append(h)
        open_hit[h.rule_id] = h
    final = []
    for h in kept:
        stronger = SUPERSEDED_BY.get(h.rule_id, ())
        if any(o.rule_id in stronger and o.offset < h.end and h.offset < o.end for o in kept):
            continue
        final.append(h)
    return final


def _excerpt(line: str, column: int, width: int = 90) -> str:
    stripped = line.strip()
    lead = len(line) - len(line.lstrip())
    column = max(0, column - lead)
    if len(stripped) <= width:
        return stripped
    start = max(0, min(column - 30, len(stripped) - width))
    if start > 0 and stripped[start - 1] != " " and " " in stripped[start:column]:
        start = stripped.index(" ", start) + 1  # do not open the excerpt mid-word
    stop = start + width
    if stop < len(stripped) and stripped[stop] != " " and " " in stripped[max(column, start):stop]:
        stop = stripped.rindex(" ", max(column, start), stop)
    snippet = stripped[start:stop].strip()
    return ("..." if start > 0 else "") + snippet + ("..." if stop < len(stripped) else "")


def scan_document(doc: Document, lang: str = "auto", profile: str = "prose", source: str = "agent",
                  strict: bool = False) -> FileReport:
    language = detect_language(doc.structural) if lang == "auto" else lang
    scanner = _Scanner(doc, language, profile, source, strict)
    hits = _dedupe(scanner.run(), doc.structural)
    display_lines = doc.display.split("\n")
    line_starts = []
    pos = 0
    for line in doc.structural.split("\n"):
        line_starts.append(pos)
        pos += len(line) + 1
    findings = []
    for h in hits:
        idx = bisect.bisect_right(line_starts, h.offset) - 1
        column = h.offset - line_starts[idx]
        info = RULES[h.rule_id]
        number = doc.line_map[idx] if doc.line_map else idx + 1
        findings.append((idx, column, RULE_ORDER[h.rule_id], RuleMatch(
            rule_id=h.rule_id,
            category=h.category or info.category,
            severity=h.severity or info.severity,
            line_number=number,
            excerpt=_excerpt(display_lines[idx] if idx < len(display_lines) else "", column),
            matched_span=h.span,
            fix_hint=h.fix_hint or info.fix_hint,
        )))
    findings.sort(key=lambda t: (t[0], t[1], t[2]))
    return FileReport(doc.path, len(scanner.word_starts), language, [f for _, _, _, f in findings])


def scan_text(text: str, path: str = "<text>", kind: str = "markdown", lang: str = "auto",
              profile: str = "prose", source: str = "agent", strict: bool = False) -> FileReport:
    return scan_document(build_document(text, path, kind), lang, profile, source, strict)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

SCAN_SUFFIXES = frozenset({".md", ".markdown", ".txt", ".html", ".htm"})
HTML_SUFFIXES = frozenset({".html", ".htm"})
SKIP_DIRS = frozenset({"node_modules", "__pycache__"})


def _collect(paths: Sequence[str], errors: List[str]) -> List[Tuple[str, Optional[Path]]]:
    targets: List[Tuple[str, Optional[Path]]] = []
    for raw in paths:
        if raw == "-":
            targets.append(("<stdin>", None))
            continue
        p = Path(raw)
        if p.is_dir():
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in SKIP_DIRS)
                for name in sorted(filenames):
                    f = Path(dirpath) / name
                    if f.suffix.lower() in SCAN_SUFFIXES:
                        targets.append((str(f), f))
        elif p.is_file():
            targets.append((raw, p))
        else:
            errors.append(f"{raw}: no such file or directory")
    return targets


def _read(label: str, path: Optional[Path]) -> Tuple[str, str]:
    data = sys.stdin.buffer.read() if path is None else path.read_bytes()
    text = data.decode("utf-8-sig")
    if path is None:
        kind = "html" if re.match(r"\s*<(?:!doctype\s+html|html)\b", text, re.IGNORECASE) else "markdown"
    else:
        kind = "html" if path.suffix.lower() in HTML_SUFFIXES else "markdown"
    return text, kind


def _print_standard(report: FileReport) -> None:
    print(f"=== {report.path} (Words: {report.words} | Language: {report.language} | "
          f"AI Density: {report.density:.1f}/1k words) ===")
    print()
    if not report.findings:
        print("No synthetic markers found.")
        print()
        return
    for f in report.findings:
        print(f"[{f.rule_id}] {f.category} ({f.severity})")
        print(f"  Line {f.line_number}: \"{f.excerpt}\"")
        print(f"  Matched: \"{f.matched_span}\"")
        print(f"  Fix: {f.fix_hint}")
        print()


def _print_summary(report: FileReport) -> None:
    print(f"=== AI Writing Scan Summary: {report.path} ===")
    print(f"Total Words: {report.words} | Total Flags: {len(report.findings)} | "
          f"Density Score: {report.density:.2f} flags / 1,000 words")
    print("Status: FAIL (Action Required)" if report.findings else "Status: PASS (Clean)")
    print()
    if not report.findings:
        return
    counts: Dict[Tuple[str, str], int] = {}
    for f in report.findings:
        counts[(f.rule_id, f.category)] = counts.get((f.rule_id, f.category), 0) + 1
    print(f"{'Sign':<7}{'Category':<45}{'Count':>5}")
    print("-" * 57)
    for (rule_id, category), count in sorted(counts.items(), key=lambda kv: RULE_ORDER[kv[0][0]]):
        print(f"{rule_id:<7}{category[:44]:<45}{count:>5}")
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_synthetic_markers",
        description="Deterministic scanner for signs of AI-generated prose (Markdown, text, HTML).")
    parser.add_argument("paths", nargs="+", help="files or directories (.md .txt .html); '-' reads standard input")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--summary", action="store_true", help="per-rule counts and density per 1,000 words")
    output.add_argument("--json", action="store_true", help="machine-readable JSON output")
    parser.add_argument("--lang", choices=("auto", "en", "tr"), default="auto", help="rule language (default: auto)")
    parser.add_argument("--strict", action="store_true", help="also report singletons that clustering would suppress")
    parser.add_argument("--profile", choices=("prose", "technical"), default="prose",
                        help="'technical' turns off Markdown-structure rules that fire on engineering docs")
    parser.add_argument("--source", choices=("agent", "human"), default="agent",
                        help="'agent' flags every em dash (R-02); 'human' flags em dashes only in clusters")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2

    errors: List[str] = []
    reports: List[FileReport] = []
    for label, path in _collect(args.paths, errors):
        try:
            text, kind = _read(label, path)
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"{label}: cannot read: {exc}")
            continue
        reports.append(scan_document(build_document(text, label, kind), args.lang, args.profile,
                                     args.source, args.strict))

    total = sum(len(r.findings) for r in reports)
    if args.json:
        print(json.dumps({"files": [r.to_dict() for r in reports], "total_findings": total}, indent=2))
    else:
        for report in reports:
            (_print_summary if args.summary else _print_standard)(report)
        if len(reports) > 1:
            print(f"=== Total: {total} finding(s) in {len(reports)} file(s) ===")
    for message in errors:
        print(f"check_synthetic_markers: error: {message}", file=sys.stderr)
    if errors:
        return 2
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
