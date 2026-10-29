#!/usr/bin/env python3
"""
guard/agy_hooks.py — Native Antigravity 2.0 Lifecycle Hooks (PreInvocation, PreToolUse, Stop)
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Implements three deterministic lifecycle gates following the Antigravity 2.0 camelCase
protojson hook contract:
  1. pre-invocation (skill-suggest + crash/resume recovery gate):
     Inspects the user's prompt (excluding pasted blocks and fenced code), matches bilingual
     (TR/EN) skill intent patterns, deduplicates per conversationId, detects interrupted
     in-flight sessions (`flight_recorder.json`) or unfinished `HANDOFF.md` / `tasks.md` state
     in the workspace, and returns an ephemeralMessage step via injectSteps.
  2. pre-tool-use (bashguard + governance-shield + customization-model-gate + workflow-shield + flight-recorder):
     Blocks direct writes to ~/.gemini/config, blocks mutations to customization or governance
     files unless the active runtime model and effort match the catalog's top reasoning model
     and highest effort (skills/upstream-auditor/upstream_state.seed.json, GEMINI.md Rule 17),
     inspects `run_workflow` scripts (`Script`, `ScriptPath`, `Args`) against child-process
     escapes, direct filesystem mutations, governance writes, and downgraded `agent()` model
     tiers (GEMINI.md Rule 15e), blocks agent execution of human-only agy-guard administration
     commands and git hook bypasses (--no-verify), prompts (force_ask) on destructive shell/git
     operations or unpinned remote script execution, and records an atomic pre-write flight
     record + non-destructive git baseline (`refs/harness/pre-edit`). Returns {"decision": "allow"}
     on pass-through (required by Antigravity 2.0 PreToolUse).
  3. stop (completion-gate + flight-recorder reconciliation):
     Defers when the assistant is asking the user a clarifying question; otherwise inspects
     the workspace git diff for tautological assertions, test-runner detection in production
     code (GEMINI.md Rule 9 C9), unapproved test skips, malformed structured files (.json,
     .toml, .svg), and broken workspace-local Markdown links, reconciling the workspace
     flight record (`turn_complete` or `in_progress_blocked`). Enforces a 3-strike circuit
     breaker per conversationId (GEMINI.md Rule 13) so the agent never loops infinitely.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    import tomllib  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guard.paths import (  # noqa: E402
    HOOK_LOCK_TIMEOUT,
    CorruptStateError,
    atomic_write_json,
    config_dir,
    configured_config_dir,
    data_dir,
    file_lock,
    is_within,
    move_aside,
    read_json,
    read_json_strict,
    state_dir,
)

MAX_HINTS = 2
MAX_STRIKES = 3
MIN_PROMPT_CHARS = 15
REHINT_TURN_GAP = 8

CONTINUATION_WORDS = frozenset({
    "devam",
    "devam et",
    "evet",
    "hayır",
    "hayir",
    "tamam",
    "peki",
    "olur",
    "ok",
    "okay",
    "yes",
    "no",
    "proceed",
    "continue",
    "go ahead",
    "uygula",
    "başla",
    "basla",
    "onaylıyorum",
    "onayliyorum",
})

_FENCE_RE = re.compile(r"(?ms)^[ \t]{0,3}(`{3,}(?!`)|~{3,}(?!~)).*?^[ \t]{0,3}\1[ \t]*$")
_PASTED_RE = re.compile(r"(?s)<pasted_content\b[^<>]*>.*?</pasted_content[^<>]*>")
_INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
_INLINE_TAG_CODE_RE = re.compile(r"`[^`\n]*[<>][^`\n]*`")
_USER_REQUEST_TAG_RE = re.compile(r"(?is)<user_request\b[^<>]*>(.*?)</user_request\b[^<>]*>")
_SLASH_PRE = r"(?=[/\$])(?:^|(?<=[\s(\[\"'«“]))"
_SLASH_POST = r"(?=$|[\s,!?;:)\]>\"'»”]|\.(?![A-Za-z0-9_]))"
_PATH_WORD_PRE = r"(?=[\w.$])(?<![/\w\\-])(?<!(?<!\.\.)\.)"
_PATH_WORD_POST = r"(?![/\w\\-])(?!\.[A-Za-z0-9_])"
_EXPLICIT_CMD_TOKEN_RE = re.compile(
    rf"{_SLASH_PRE}[/\$][a-zA-Z][a-zA-Z0-9_-]{{1,63}}{_SLASH_POST}"
)
_VIABLE_HINT_TOKEN_RE = re.compile(r"(?=[\w.$])(?<![/\w\\-])")

# Bilingual (EN + TR) skill suggestion table: (skill_name, skill_rel_path, compiled_regex, summary)
SKILL_HINTS: Tuple[Tuple[str, str, re.Pattern[str], str], ...] = (
    (
        "diagnosing-bugs",
        "skills/diagnosing-bugs/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/diagnosing-bugs{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"bug|regression|crash(?:es|ed|ing)?|traceback|stack\s*trace|segfault|"
            r"failing\s+tests?|flaky\s+tests?|intermittent\s+failure|bisect|"
            r"hata\s+var|çalışmıyor|calismiyor|patlıyor|patliyor|bozuldu|neden\s+hata"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "7-phase root-cause analysis before editing code",
    ),
    (
        "test-design",
        "skills/test-design/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/test-design{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"test\s+design|design\s+tests?|coverage\s+gaps?|property[- ]based\s+test|"
            r"boundary[- ]value|equivalence\s+partition|parametrize[d]?\s+tests?|"
            r"test\s+yaz|test\s+ekle|regresyon\s+testi|"
            r"test\s+tasar(?:ımı|imi|la)|test\s+senaryo(?:su|ları)|kapsama\s+boşlu(?:ğu|gu)|"
            r"sınır\s+değer\s+test"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "behaviour-first test design, boundary analysis & anti-tautology checks",
    ),
    (
        "mistake-proofing",
        "skills/mistake-proofing/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/mistake-proofing{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"poka[- ]?yoke|mistake[- ]proof(?:ing)?|parse[,\s]+don'?t\s+validate|"
            r"boolean\s+trap|primitive\s+obsession|illegal\s+state\s+unrepresentable|"
            r"yine\s+aynı\s+hata|bir\s+daha\s+olmasın|tekrar\s+etti|"
            r"hata\s+önleme|yanlış\s+kullanımı\s+engelle|tip\s+güvenli(?:ği|gi)\s+ile\s+koru"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "compile/parse-time structural mistake-proofing (poka-yoke) for APIs & schemas",
    ),
    (
        "refactoring",
        "skills/refactoring/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/refactoring{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"refactor(?:ing)?|extract\s+(?:function|method|class|module)|"
            r"split\s+(?:file|module|class)|decouple|code\s+smell|dead\s+code|"
            r"refactor\s+et|yeniden\s+düzenle|sadeleştir|parçala|kod\s+tekrarını\s+kaldır|"
            r"yeniden\s+yapılandır|kod\s+kokusu|modüllere\s+ayır|fonksiyon\s+çıkar"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "behaviour-preserving step-by-step refactoring with red-green test seams",
    ),
    (
        "dependency-upgrade",
        "skills/dependency-upgrade/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/dependency-upgrade{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"upgrade\s+(?:dependenc(?:y|ies)|packages?)|bump\s+version|version\s+bump|major\s+upgrade|"
            r"lockfile\s+update|cve\s+fix|dependenc(?:y|ies)\s+migration|"
            r"sürümü\s+yükselt|bağımlılıkları\s+güncelle|"
            r"paket\s+güncelle|bağımlılık\s+güncelle|sürüm\s+yükselt"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "compatibility matrix, changelog review & lockfile-safe dependency upgrades",
    ),
    (
        "renew",
        "skills/renew/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/renew{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"(?:moderniz(?:e|ing)|reviv(?:e|ing)|port(?:ing)?|remaster(?:ing)?)\s+(?:(?:this|the|an?|our|my)\s+)*(?:old|legacy|classic|obsolete|unbuildable|abandoned|win32|winforms|mfc|delphi|vb6|flash|dos|j2me|sdl1?|pygame|python\s*2)\b(?:\s+[\w.-]+){0,4}\s+(?:app(?:lication)?s?|programs?|software|codebases?|projects?|tools?|games?)|"
            r"remaster(?:ing)?\s+(?:(?:this|the|an?|our|my|old|classic|legacy|retro)\s+)*(?:games?|app(?:lication)?s?|programs?|titles?)|"
            r"legacy\s+(?:software|app(?:lication)?|codebase|program|game)\s+(?:modernization|revival|remaster(?:ing)?|port(?:ing)?)|"
            r"(?:eski|klasik|atıl|çalışmayan|derlenmeyen)\s+(?:bir\s+)?(?:[\wçğıöşüÇĞİÖŞÜ.-]+\s+){0,3}(?:program\w*|yazılım\w*|uygulama\w*|oyun\w*|kod\s+taban\w*|araç\w*|arac\w*|proje\w*)(?:\s+[\wçğıöşüÇĞİÖŞÜ-]+){0,3}\s+(?:yenile\w*|modernize\s+et\w*|dirilt\w*|remaster\s+yap\w*|(?:güncel|modern)\s+(?:sistem\w*|ortam\w*|çalışma\s+zaman\w*)\s+(?:taşı\w*|uyarla\w*))|"
            r"(?:güncel|modern)\s+(?:sistem\w*|çalışma\s+zaman\w*)\s+(?:taşı\w*|uyarla\w*)|"
            r"(?:oyun\w*|program\w*|yazılım\w*|uygulama\w*)\s+remaster\s+yap\w*"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "5-stage legacy app & classic game modernization (autopsy, contract, golden-master oracle, strangler cutover & security sanitization)",
    ),
    (
        "rustify",
        "skills/rustify/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/rustify{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"rustify\w*(?!\.(?:rs|py|c|cc|cpp|cxx|h|hh|hpp|hxx|go|js|ts|md|json|toml|yaml|yml)\b)|"
            r"(?<!bump\s)(?<!upgrade\s)(?<!update\s)(?:cbindgen|bindgen|cxx\s+bridge|#?\[?cxx::bridge\]?|pyo3)(?!\s+(?:from|to|in)\s+[\dv]|[^\n]{0,30}\bcargo\.toml\b)|"
            r"(?:port(?:ing)?|migrat(?:e|ing)|rewrit(?:e|ing)|convert(?:ing)?|translat(?:e|ing)|bridg(?:e|ing))\s+(?!this\s+unsafe\b|unsafe\s+(?:rust|helper|fn|function|block|code|impl|trait)\b)(?:(?:[\w+/.-]+,*|,+)\s+){0,8}(?:to|into)\s+(?:(?:idiomatic|memory[- ]safe|compiler[- ]verified|zero[- ]panic|safe|pure),?\s+)*rust\b(?!\s*(?:edition\s*)?20\d{2}\b|\s+1\.\d+\b)|"
            r"(?:c(?:\+\+|/c\+\+)?|cpp|go|golang|python)'?(?:dan|den|tan|ten)\s+rust'?(?:a|ya)\b|"
            r"rust'?(?:a|ya)\s*(?:çevir\w*|cevir\w*|taşı\w*|tasi\w*|dönüştür\w*|donustur\w*|geçir\w*|gecir\w*|aktar\w*|port\s+et\w*)"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "5-stage C/C++/Go/Python -> memory-safe Rust migration, ABI/FFI bridges (bindgen/cbindgen/cxx/PyO3) & Miri/sanitizer/Kani verification",
    ),
    (
        "retro",
        "skills/retro/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/retro{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"retrospective|sprint\s+retro|post[- ]?mortem|"
            r"retrospektif\w*|tekrarlayan\s+hata\w*"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "read-only retrospective over MISTAKES.md, plan outcomes & 3-strike rule promotion",
    ),
    (
        "deep-grill",
        "skills/deep-grill/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/deep-grill{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"deep[- ]grill|grill\s+me|design\s+interview|stress[- ]test\s+requirements|"
            r"edge[- ]case\s+interview|mülakat\s+yap\w*|uç\s+durumlar\w*\s+sorgula\w*|beni\s+sorgula\w*"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "adversarial requirement & architecture boundary interview before coding",
    ),
    (
        "audit",
        "skills/audit/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/audit{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"security\s+audit|consistency\s+audit|boundary\s+audit|spec\s+gap\s+audit|"
            r"güvenlik\s+denetim\w*|tutarlılık\s+denetim\w*|mimari\s+denetim\w*|sınır\s+denetim\w*"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "read-only multi-pass consistency, specification-gap & security boundary audit",
    ),
    (
        "technical-writing",
        "skills/technical-writing/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/technical-writing{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"technical\s+writing|documentation\s+architecture|diataxis|diátaxis|"
            r"api\s+reference\s+docs?|write\s+(?:a\s+)?(?:tutorial|runbook|release\s+notes)|"
            r"teknik\s+dokümantasyon|teknik\s+yazarlık|kullanım\s+kılavuzu|sürüm\s+notları|doküman\s+yaz"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "Diataxis mode separation, executable snippet verification & changelog discipline",
    ),
    (
        "data-analysis",
        "skills/data-analysis/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/data-analysis{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"data\s+analysis|exploratory\s+data\s+analysis|jupyter\s+notebooks?|data\s+leakage|"
            r"train[/-]test\s+split|feature\s+engineering|statistical\s+analysis|"
            r"veri\s+analizi|veri\s+bilimi|istatistiksel\s+analiz|veri\s+sızıntısı"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "row-count/drop accounting, train/test split anti-leakage & honest chart scaling",
    ),
    (
        "game-engineering",
        "skills/game-engineering/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/game-engineering{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"game\s+loop|fixed\s+timestep|game\s+dev(?:elopment)?|canvas\s+game|webgl\s+game|"
            r"browser\s+game|arcade\s+game|"
            r"collision\s+detection|sprite\s+sheet|game\s+physics|entity\s+state\s+machine|"
            r"oyun\s+geliştir(?:me)?|oyun\s+motoru|fizik\s+döngüsü|canvas\s+oyun|tarayıcı\s+oyunu|2d\s+oyun|3d\s+oyun"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "fixed-timestep simulation loop, zero per-frame allocation, seeded PRNG & MODE: GAME vitality",
    ),
    (
        "media-studio",
        "skills/media-studio/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/media-studio{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"(?:audio|video|sound|voice|music|track|song|photo|image|media)\s+(?:mastering|remaster(?:ing)?|restoration|salvage|upscal(?:e|ing)|super[- ]resolution|denois(?:e|ing)|editing|transcod(?:e|ing)|synthesis)|"
            r"(?:salvage|restore|repair|upscale|uncorrupt)\s+(?:(?:this|the|an?|old|damaged|corrupted|broken|truncated|scanned|low[- ]res(?:olution)?|blurry|noisy|archival)\s+)*(?:audio|video|sound|voice|photo(?:graph)?|image|picture|footage|recording|mp4|mkv|wav|flac|mp3|jpe?g|png|tiff?)\b|"
            r"ebu\s*r128|loudness\s+normalization|lufs|deband(?:ing)?|jpeg\s+(?:blocking|artifacts?)|animated\s+(?:webp|gif|apng|visuals?)|"
            r"ffmpeg\s+filter(?:graph)?|(?:audio|video|image|photo)\s+quality\s+(?:fix|repair|gate|enhancement|upscal(?:e|ing))|"
            r"(?:bozuk|hasarlı|kırık|eski|düşük\s+kaliteli|bulanık|cızırtılı)\s+(?:bir\s+)?(?:(?!session\w*)ses\w*|video\w*|görüntü\w*|fotoğraf\w*|fotograf\w*|görsel\w*|(?:(?!session\w*)ses|video|görüntü|ekran|kamera|mikrofon)\s+(?:kayıt\w*|kayd\w*)|wav|mp4|mkv|mp3|jpe?g|png)(?:\s+[\wçğıöşüÇĞİÖŞÜ-]+){0,5}\s+(?:düzelt\w*|onar\w*|kurtar\w*|temizle\w*|iyileştir\w*|yükselt\w*|artır\w*)|"
            r"(?:(?!session\w*)ses\w*|video\w*|görüntü\w*|fotoğraf\w*|fotograf\w*)\s+(?:üret(?:im|me)?|düzenle(?:me)?|kurgu(?:la|su)?|kurtar\w*|onar(?:ım|ma)?|mastering|remaster(?:\s+yap\w*)?|kalite\w*(?:\s+[\wçğıöşüÇĞİÖŞÜ-]+){0,3}\s+(?:düzelt\w*|artır\w*|yükselt\w*|iyileştir\w*))|"
            r"(?:(?:(?!session\w*)ses|müzik|şarkı)(?:\s+kayıt\w*|\s+kayd\w*)?)\s+remaster(?:\s+yap\w*)?|"
            r"(?:fotoğraf\w*|fotograf\w*|görüntü\w*|(?!session\w*)ses\w*|video\w*)\s+[\wçğıöşüÇĞİÖŞÜ-]+\s+temizle\w*|"
            r"gürültü\s+temizle(?:me)?|ses\s+seviyesi(?:ni)?\s+dengele|hareketli\s+görsel(?:\s+üret)?"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "4-stage Probe->Plan->Process->Verify media pipeline, container salvage, photo/AV restoration, fidelity upscaling & media_qc.py gate",
    ),
    (
        "marathon",
        "skills/marathon/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/marathon{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"marathon\s+plan|multi[- ]window\s+(?:plan|rework|build)|split\s+into\s+windows|"
            r"maraton\s+başlat|maraton\s+plan(?:ı|la)|pencerelere\s+böl"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "proactive multi-window goal planning, model/effort routing & HANDOFF.md orchestration",
    ),
    (
        "sweetspot",
        "skills/sweetspot/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/(?:sweetspot|optimize){_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"sweetspot|sweet[- ]spot\s+optimization|"
            r"optimize\s+(?:startup|latency|frame\s+rate|fps|performance|memory|ram|disk\s+space|binary\s+size|bundle\s+size|footprint|network|bandwidth|download|upload)|"
            r"optimize\s+(?:this\s+|the\s+)?(?:game|app|application|software|project|codebase|program|service|backend|script|tool|system|library|binary|package)|"
            r"(?:reduce|shrink)\s+(?:memory|ram|disk|binary|bundle|network|bandwidth|download|upload|round[- ]trip)\s+(?:usage|footprint|size|traffic|latency|payload)|"
            r"sweetspot\s+analizi|tatlı\s+nokta\s+optimizasyonu|performans\s+optimizasyonu|(?:bellek|ram|disk|ağ|bant\s+genişliği)\s+optimizasyonu|"
            r"optimize\s+et|"
            r"(?:bellek|ram|bant\s+genişliği)\s+kullanımını\s+(?:düşür|azalt)|(?:disk\s+alanını|dosya\s+boyutunu|paket\s+boyutunu|indirme\s+(?:ve\s+yükleme\s+)?boyutunu|yükleme\s+boyutunu|boyutunu)\s+küçült|"
            r"hızlandır|"
            r"(?:ağ\s+)?gecikme(?:yi|sini)\s+(?:düşür|azalt)|(?:fps|kare\s+hızını)\s+artır"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "controlled behavior-preserving speed, memory (RAM), disk & network optimization (3-Zone Sweet-Spot Gate)",
    ),
    (
        "vibecoder",
        "skills/vibecoder/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/vibecoder?{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"vibecoder|vibercoder|vibe\s*coding|rapid\s+prototyp(?:e|ing)|single[- ]file\s+(?:html\s+)?prototyp(?:e|ing)|"
            r"game\s+prototype|interactive\s+(?:prototype|sandbox)|(?:audio|sound|visual)\s+synthesizer|creative\s+studio\s+prototype|"
            r"fikrim\s+var|hızlı\s+prototip|oyun\s+prototipi|etkileşimli\s+kum\s+havuzu|ses\s+sentezleyici|"
            r"yaratıcı\s+stüdyo\s+prototip(?:i)?|tek\s+dosya(?:lık)?\s+(?:html|prototip|oyun|stüdyo)|prototip\s+üret"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "3-question Vibe-Grill & zero-friction single-file rich HTML app, game & creative sandbox prototyping",
    ),
    (
        "antislop",
        "skills/antislop/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/antislop{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"anti[- ]?slop|ui\s+delivery\s+gate|ai\s+slop|design\s+quality\s+gate|"
            r"arayüz\s+kalite(?:si)?|tasarım\s+denetimi|yapay\s+zeka\s+klişe(?:si|leri)"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "38-rule design/copy quality filter, Liveliness Toolkit & UI Delivery Gate",
    ),
    (
        "antislop-ui",
        "skills/antislop-ui/SKILL.md",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"antislop[- ]ui|visual\s+slop\s+audit|audit\s+ui\s+components?|anti[- ]boxification|sibling\s+symmetry|"
            r"görsel\s+slop|bileşen\s+denetimi|kart\s+simetrisi"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "Anti-Boxification, Sibling Symmetry Cap, Typographic Scale Lock & HUD vitality",
    ),
    (
        "antislop-copywriting",
        "skills/antislop-copywriting/SKILL.md",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"antislop[- ]copy(?:writing)?|write\s+copy|de[- ]ai\s+(?:prose|text|copy)|synthetic\s+markers?|anti[- ]ai\s+tone|"
            r"metin\s+yazımı|pazarlama\s+metni|yapay\s+zeka\s+dili(?:ni)?\s+temizle"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "de-AI prose rewrites, tone calibration & EN/TR synthetic-marker scanning",
    ),
    (
        "antislop-human",
        "skills/antislop-human/SKILL.md",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"antislop[- ]human|check\s+contrast|wcag\s+contrast|accessibility\s+audit|a11y\s+audit|color\s+contrast\s+ratio|"
            r"renk\s+kontrast(?:ı|i)|erişilebilirlik\s+denetimi|wcag\s+uyumu"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "WCAG AA contrast verification, keyboard navigation & 5 component states",
    ),
    (
        "antislop-layoutmobile",
        "skills/antislop-layoutmobile/SKILL.md",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"antislop[- ]layoutmobile|mobile\s+layout|fix\s+overflow|horizontal\s+overflow|tap[- ]target\s+siz(?:e|ing)|responsive\s+check|"
            r"mobil\s+yerleşim|yatay\s+taşma|mobil\s+uyumluluk|dokunma\s+hedefi"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "mobile horizontal-overflow elimination, 44px tap targets & responsive reflow",
    ),
    (
        "antislop-code",
        "skills/antislop-code/SKILL.md",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"antislop[- ]code|clean\s+comments|comment\s+hygiene|remove\s+slop\s+comments|"
            r"yorum\s+temizli(?:ği|gi)|gereksiz\s+yorumlar(?:ı|i)\s+(?:sil|temizle|kaldır)"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "code-comment hygiene: strips AI-slop comments while preserving why/contract notes",
    ),
    (
        "silk-design",
        "skills/silk-design/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/silk-design{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"silk[- ]design|kinetic\s+(?:motion|typography)|smooth[- ]scroll(?:ing)?|motion\s+3|lenis\s+scroll|"
            r"kinetik\s+tasarım|akıcı\s+kaydırma|vitrin\s+sayfası\s+tasarla"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "physics-based kinetic motion (MOTION 3), fluid typography & showcase landing pages",
    ),
    (
        "visualizer",
        "skills/visualizer/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/visualizer{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"visualize\s+(?:architecture|workflow|state|codebase|journey)|architecture\s+diagram|mermaid\s+diagram|sequence\s+diagram|"
            r"mimari(?:yi)?\s+görselleştir|diyagram\s+çiz|akış\s+şeması\s+oluştur|şematize\s+et"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "4-lens visual structure routing (Mermaid for static, generative_ui for interactive)",
    ),
    (
        "porter",
        "skills/porter/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/porter{_SLASH_POST}|"
            r"@\[[^\]\r\n[]{0,256}(?:Downloads|İndirilenler|/tmp/)[^\]\r\n[]{0,256}(?:SKILL|CLAUDE|AGENTS|CONVENTIONS|RULES)\.md\]|"
            r"@\[[^\]\r\n[]{0,256}(?:CLAUDE|CONVENTIONS)\.md\]|"
            rf"(?<![/\w\\-])\.cursorrules{_PATH_WORD_POST}|"
            rf"{_PATH_WORD_PRE}(?:"
            r"transpile\s+rules?|"
            r"(?:import|adapt|port|evaluate)\s+(?:external|cursor|claude|windsurf|aider|codex|copilot|cline)\s+(?:rules?|skills?|prompts?)|"
            r"(?:adapt|import|borrow)\s+useful\s+(?:rules?|parts?|ideas?)\s+from\b|"
            r"export\s+to\s+(?:claude|cursor|aider|codex|windsurf|copilot)|"
            r"kural(?:lar\w*|ı)?\s+(?:aktar\w*|dönüştür\w*|port\s+et\w*|içe\s+aktar\w*)|başka\s+ajana\s+uyarla\w*|"
            r"(?:bu|dış\w*|harici)\s+(?:[\w-]+\s+)?(?:beceri\w*|skill(?:\.md)?|kural\w*)\b[^\n.?!]{0,80}\b(?:özelleştir\w*|faydalı|uyarla\w*|içe\s+aktar\w*|adapte\s+et\w*|alabileceğ\w*)"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "bidirectional rule/skill suitability analyzer, sanitizer & ecosystem transpiler",
    ),
    (
        "database-migrations",
        "skills/database-migrations/SKILL.md",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"schema\s+migration|database\s+migration|zero[- ]downtime\s+migration|database\s+rollback|alter\s+table|"
            r"veritabanı\s+göç\w*|şema\s+göç\w*|migrasyon\s+yaz\w*"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "expand-migrate-contract schema changes, lock timeouts & rollback safety",
    ),
    (
        "architecture-decision-records",
        "skills/architecture-decision-records/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/adr{_SLASH_POST}|(?<![/\w\\-])docs/adr(?![\w-])|{_PATH_WORD_PRE}(?:"
            r"record\s+adr|architecture\s+decision\s+records?|write\s+an\s+adr|"
            r"mimari\s+karar\s+kayd\w*|adr\s+(?:yaz\w*|oluştur\w*|kaydet\w*)"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "weighted trade-off matrix & structured Architecture Decision Records in docs/adr/",
    ),
    (
        "security-review",
        "skills/security-review/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/security-review{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"security\s+review\s+checklist|pre[- ]deployment\s+security|transport\s+security\s+headers|"
            r"dağıtım\s+öncesi\s+güvenlik\w*|güvenlik\s+kontrol\s+liste\w*"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "pre-deployment security checklist for secrets, transport headers & cloud boundaries",
    ),
    (
        "chisle",
        "skills/chisle/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/chisle{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"chisle\s+mode|activate\s+chisle|chislify"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "terse zero-fluff prose & YAGNI/ladder-first engineering mode",
    ),
    (
        "harness",
        "skills/harness/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/(?:harness|verify|gate|run-gate){_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"harness\s+verification\s+gate|run\s+verification\s+gate|doğrulama\s+kapıs\w*"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "strict computational verification gates, artifact-driven task lifecycle & auditor handoffs",
    ),
    (
        "procoder",
        "skills/procoder/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/procoder{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"procoder\s+(?:backlog|sprint|release)"
            rf"){_PATH_WORD_POST}|(?<![/\w\\-])\.procoder/)",
            re.IGNORECASE,
        ),
        "spec, plan, todo, backlog & sprint governance for .procoder/ repositories",
    ),
    (
        "unlazy",
        "skills/unlazy/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}[/\$]unlazy{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"tree\s+\d+|do\s+not\s+stop\s+until\s+it\s+is\s+done|bitene\s+kadar\s+durma"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "Tier-3 deep completion engine with Depth Tree & reverification gates",
    ),
    (
        "upstream-auditor",
        "skills/upstream-auditor/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/audit-upstream{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"upstream[- ]auditor|model\s+drift\s+audit|upstream\s+skill\s+sync"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "upstream model catalog, runtime & tracked repository synchronization auditor",
    ),
    (
        "reverse-engineer-anything",
        "plugins/rea/skills/reverse-engineer-anything/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/rea{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"reverse[- ]engineer(?:ing)?|decompile\s+(?:binary|apk|elf|macho|jar|wasm)|disassemble\s+binary|"
            r"inspect\s+(?:apk|elf|macho|firmware|pcap)|frida\s+(?:hook|session|trace)|rizin\s+debug|"
            r"tersine\s+mühendislik|binary\s+analiz(?:i)?|apk\s+incele|decompile\s+et|ikili\s+dosya\s+analiz"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "evidence-backed binary, APK/IPA/ELF, firmware, PCAP & Electron/JS reverse engineering",
    ),
)

# Bilingual (EN + TR) Subagent, MCP Server & Plugin routing hints: (route_key, compiled_regex, directive)
ECOSYSTEM_ROUTING_HINTS: Tuple[Tuple[str, re.Pattern[str], str], ...] = (
    (
        "route:mcp:rea_rea",
        re.compile(
            rf"(?:{_SLASH_PRE}/rea{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"reverse[- ]engineer(?:ing)?|decompile|disassemble|inspect\s+(?:apk|elf|macho|firmware|pcap)|"
            r"frida\s+(?:hook|session|trace)|rizin\s+debug|jeb\s+project|"
            r"tersine\s+mühendislik|binary\s+analiz(?:i)?|apk\s+incele|decompile\s+et|ikili\s+dosya\s+analiz"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "MCP Server `rea_rea` & Plugin `rea` (`call_mcp_tool` with `ServerName=\"rea_rea\"` + read `plugins/rea/skills/reverse-engineer-anything/SKILL.md`)",
    ),
    (
        "route:mcp:antislop-contrast",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"check\s+contrast|wcag\s+contrast|color\s+contrast(?:\s+ratio)?|contrast\s+ratio|"
            r"renk\s+kontrast(?:ı|i)|kontrast\s+oran(?:ı|i)"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "MCP Server `antislop-contrast` (`call_mcp_tool` with `ServerName=\"antislop-contrast\"`, `ToolName=\"check_contrast\"`)",
    ),
    (
        "route:subagent:security-silent",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"authentication\s+boundary|authorization\s+boundary|jwt\s+(?:token|auth)|oauth2?\s+flow|"
            r"cryptograph(?:y|ic)|payment\s+processing|storage\s+integrity|secret\s+boundary|"
            r"kimlik\s+doğrulama|yetkilendirme\s+sınır(?:ı|i)|kriptografi|ödeme\s+altyapısı|depolama\s+bütünlüğü"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "Subagents `security-boundary-verifier` & `silent-failure-hunter` (`invoke_subagent` before delivery per GEMINI.md §3 Critical Exceptions)",
    ),
    (
        "route:subagent:contract-test",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"public\s+api\s+contract|breaking\s+contract\s+change|wire\s+protocol\s+change|openapi\s+schema\s+change|"
            r"public\s+interface\s+migration|"
            r"sözleşme\s+değişikliği|api\s+kontrat(?:ı|i)|public\s+arayüz\s+değişikliği|kırıcı\s+şema\s+değişikliği"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "Subagents `contract-change-auditor` & `test-adequacy-auditor` (`invoke_subagent` before delivering public contract/schema changes)",
    ),
    (
        "route:subagent:spec-consistency",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"formal\s+specification|multi[- ]volume\s+spec|state\s+machine\s+invariant|safety\s+core\s+spec|"
            r"resmi\s+spesifikasyon|güvenlik\s+çekirdeği\s+spesifikasyonu|aksiyomatik\s+tutarlılık"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "Subagents `consistency-auditor` & `specification-gap-auditor` (`invoke_subagent` per GEMINI.md §3 Critical Exceptions)",
    ),
    (
        "route:subagent:research",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"external\s+documentation|official\s+sdk\s+docs|research\s+library\s+api|"
            r"dış\s+dokümantasyon\s+araştır|resmi\s+kütüphane\s+dokümanı"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "Subagent `research` (`invoke_subagent` to isolate >50 KB documentation or broad codebase exploration per GEMINI.md Rule 11)",
    ),
    (
        "route:subagent:build-error-resolver",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"compiler\s+error\s+trace|typescript\s+build\s+error|typecheck\s+failure\s+log|"
            r"uzun\s+derleme\s+hatası|tip\s+hatası\s+izini\s+çöz"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "Subagent `build-error-resolver` (`invoke_subagent` on >500-line traces or after 2 consecutive failed compiler/type fix attempts)",
    ),
    (
        "route:builtin:generative_ui",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"generative[_ ]ui|agent-embed|inline\s+(?:interactive\s+)?widget|interactive\s+chat\s+widget|"
            r"sohbet\s+içinde\s+(?:interaktif|etkileşimli)\s+widget|interaktif\s+widget|canlı\s+kontrol\s+paneli\s+göm\w*"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "Built-in Skill `generative_ui` (read `~/.gemini/antigravity/builtin/skills/generative_ui/SKILL.md`; use host theme variables and allowlisted `gstatic` Tailwind solely inside isolated widgets per GEMINI.md Rule 15c)",
    ),
    (
        "route:builtin:automation",
        re.compile(
            rf"(?:{_SLASH_PRE}/automation{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"scheduled\s+background\s+automation|recurring\s+scheduled\s+task|background\s+cron\s+automation|"
            r"zamanlanmış\s+görev|arka\s+plan\s+otomasyonu|tekrarlayan\s+otomasyon"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "Built-in Skill `automation` (read `~/.gemini/antigravity/builtin/skills/automation/SKILL.md`; obey GEMINI.md Rule 15a/15b: never write to governance seams in `~/.gemini/config/`, route runtime sidecars only to `~/.gemini/config/sidecars/` or `~/.gemini/antigravity/sidecars/`, default to the native `schedule` tool, and report progress via `toolAction`/`toolSummary`)",
    ),
    (
        "route:builtin:antigravity-guide",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"antigravity\s+(?:ide|cli|sdk|keybindings?|slash\s+commands?|2\.0)|agy\s+cli|"
            r"antigravity\s+(?:kısayol\w*|ayar\w*|nasıl\s+kullanıl\w*)|agy\s+komut\s+satır\w*"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "Built-in Skill `antigravity-guide` (read `~/.gemini/antigravity/builtin/skills/antigravity_guide/SKILL.md` for Antigravity 2.0, `agy` CLI, IDE keybindings, slash commands & Python SDK reference)",
    ),
    (
        "route:builtin:agy-customizations",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"agy[- ]customizations|"
            r"antigravity\s+customization\w*|"
            r"customization\s+(?:system|loading\s+priority|discovery|precedence)|"
            r"antigravity\s+özelleştir\w*|"
            r"yerleşik\s+(?:antigravity\s+)?özelleştir\w*|"
            r"keşif\s+önceliğ\w*\s+ve\s+kanca\s+yapı\w*|"
            r"(?:hint|ipucu)\s+mekanizma\w*"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "Built-in Skill `agy-customizations` (read `~/.gemini/antigravity/builtin/skills/agy-customizations/SKILL.md`; obey GEMINI.md Rule 15a: `~/.gemini/config/` is read-only, author repo-managed changes in the source checkout)",
    ),
    (
        "route:builtin:plugin",
        re.compile(
            rf"(?:{_SLASH_PRE}/plugin{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"antigravity\s+plugin|package\s+into\s+a\s+plugin|install\s+or\s+uninstall\s+a\s+plugin|"
            r"eklenti\s+paketi\s+olarak\s+paketle\w*|antigravity\s+eklentisi\s+(?:oluştur|kur|kaldır)\w*"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "Built-in Skill `plugin` (read `~/.gemini/antigravity/builtin/skills/plugin/SKILL.md`; obey GEMINI.md Rule 15a: never write directly to `~/.gemini/config/` outside runtime `plugins/`)",
    ),
    (
        "route:subagent:meta-auditor",
        re.compile(
            rf"(?:{_SLASH_PRE}/audit\s+--(?:meta|self){_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"meta[- ]auditor|"
            r"harness\s+(?:self[- ]audit|meta[- ]consistency|meta[- ]audit)|"
            r"porter\s+parity\s+audit|"
            r"harness\s+(?:öz[- ]?denetim\w*|meta[- ]?tutarlılık\w*|iç\s+tutarlılık\w*)|"
            r"(?:beceri|kanca|anayasa)\s+tutarlılık\s+denetim\w*"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "Subagent `meta-auditor` (`invoke_subagent` with `TypeName=\"meta-auditor\"` + `python3 scripts/meta_audit.py --strict` for harness, skill, hook & Porter meta-consistency verification per GEMINI.md Rule 17)",
    ),
    (
        "route:subagent:image-generator",
        re.compile(
            rf"{_PATH_WORD_PRE}(?:"
            r"generate\s+(?:an\s+)?(?:illustration|raster\s+image|hero\s+image)|image[- ]generator\s+subagent|"
            r"özel\s+bir\s+illüstrasyon\s+ve\s+görsel\s+üret\w*|illüstrasyon\s+üret\w*|görsel\s+varlık\s+üret\w*"
            rf"){_PATH_WORD_POST}",
            re.IGNORECASE,
        ),
        "Built-in Subagent `image-generator` (`invoke_subagent` with `TypeName=\"image-generator\"` after obtaining explicit user approval for asset creation per `antislop` R-23; never use for logical diagrams per `visualizer`)",
    ),
)

_SKILL_SLASH_ALIASES: Dict[str, Tuple[str, ...]] = {
    "architecture-decision-records": ("adr", "architecture-decision-records"),
    "sweetspot": ("sweetspot", "optimize"),
    "vibecoder": ("vibecoder", "vibecode"),
    "harness": ("harness", "verify", "gate", "run-gate"),
    "upstream-auditor": ("audit-upstream", "upstream-auditor"),
    "reverse-engineer-anything": ("rea", "reverse-engineer-anything"),
}

_ROUTE_SLASH_ALIASES: Dict[str, Tuple[str, ...]] = {
    "route:mcp:rea_rea": ("rea",),
    "route:builtin:automation": ("automation",),
    "route:builtin:plugin": ("plugin",),
}

# File-mutating tool names in Antigravity 2.0 and portable agent environments
WRITE_TOOL_NAMES = frozenset({
    "write_to_file",
    "write_file",
    "replace_file_content",
    "multi_replace_file_content",
    "edit_file",
    "create_file",
    "write",
    "edit",
    "multiedit",
    "notebookedit",
})

COMMAND_TOOL_NAMES = frozenset({
    "run_command",
    "bash",
    "execute_command",
    "shell",
    "send_command_input",
    "manage_task",
})

HIGH_RISK_MCP_TOOL_NAMES = frozenset({
    "execute_rizin_command",
    "gdb_console",
    "rizin_debug_command",
    "cutter_command",
    "instrument_with_frida",
    "load_frida_script",
})

PRE_TOOL_USE_MATCHER_TOOLS: Tuple[str, ...] = (
    "run_command",
    "bash",
    "execute_command",
    "shell",
    "send_command_input",
    "manage_task",
    "run_workflow",
    "invoke_subagent",
    "call_mcp_tool",
    "mcp_.*",
    "write_to_file",
    "write_file",
    "replace_file_content",
    "multi_replace_file_content",
    "edit_file",
    "create_file",
    "write",
    "edit",
    "multiedit",
    "notebookedit",
)
PRE_TOOL_USE_MATCHER: str = "|".join(PRE_TOOL_USE_MATCHER_TOOLS)

_PY_INTERP_OPTS = r"(?:-(?![A-Za-z0-9]*[mc]\b)(?:[WXx]\s+\S+|[A-Za-z0-9]+(?:=\S+)?)\s+)*"
_SINGLE_WRAPPER_PAT = (
    r"(?:[^\s;|&`]*/)?"
    r"(?:"
    r"timeout(?:\s+(?:-[ks]\s+\S+|--(?:signal|kill-after)(?:=\S+|\s+\S+)|-[A-Za-z0-9-]+))*\s+\d+(?:\.\d+)?[smhd]?|"
    r"nice(?:\s+(?:-n\s+-?\d+|--adjustment(?:=-?\d+|\s+-?\d+)|-\d+))*|"
    r"ionice(?:\s+(?:-[cnpt]\s+\S+|--[a-z-]+(?:=\S+|\s+\S+)|-[A-Za-z0-9]+))*|"
    r"chrt(?:\s+-[A-Za-z0-9-]+)*(?:\s+\d+)?|"
    r"taskset(?:\s+(?:-c\s+\S+|--cpu-list(?:=\S+|\s+\S+)|-[A-Za-z0-9]+))*\s+\S+|"
    r"stdbuf(?:\s+(?:-[ioe]\S*|--(?:input|output|error)(?:=\S+|\s+\S+)))+|"
    r"setsid(?:\s+-[A-Za-z0-9-]+)*|"
    r"nohup|"
    r"time(?:\s+-[pP])*|"
    r"sudo(?:\s+(?:-[uUgCp]\s+\S+|--(?:user|group|chdir|other-user)(?:=\S+|\s+\S+)|-[A-Za-z0-9-]+))*|"
    r"env(?:\s+(?:-[uC]\s+\S+|--(?:unset|chdir|split-string)(?:=\S+|\s+\S+)|-[A-Za-z0-9-]+|[A-Za-z_][A-Za-z0-9_]*=\S*))*|"
    r"exec(?:\s+(?:-a\s+\S+|-[cl]))*|"
    r"command(?:\s+-p)*(?!\s+-[A-Za-z]*[vV]\b)|"
    r"xargs(?:\s+(?:-[IinLPsdE]\s*\S+|--[a-z-]+(?:=\S+|\s+\S+)|-[A-Za-z0-9]+))*"
    r")"
)
_CMD_WRAPPER_PREFIX = rf"(?:{_SINGLE_WRAPPER_PAT}\s+)*(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*(?:{_SINGLE_WRAPPER_PAT}\s+)*"
_SUBPARSER_OPTS = (
    r"(?:\s+--?[A-Za-z0-9_-]+"
    r"(?:=\S+|\s+(?!snapshot\b|restore\b|prune\b|stage\b|import\b|policy\b|add\b|remove\b|enable\b|disable\b)--?[^\s;|`]+|\s+(?!snapshot\b|restore\b|prune\b|stage\b|import\b|policy\b|add\b|remove\b|enable\b|disable\b)[^\s;|`-]\S*)?)*"
)

# Human-only Guard administration subcommands (GEMINI.md Rule 12)
_GUARD_ADMIN_RE = re.compile(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}"
    r"(?:"
    rf"(?:(?:[^\s;|&`]*/)?python3?(?:\.\d+)?\s+{_PY_INTERP_OPTS}(?:-[A-Za-z0-9]*m\s+guard(?:\.cli)?\b|(?:[^\s;|&`]*/)?(?:guard\.py|guard/cli\.py))|(?:[^\s;|&`]*/)?(?:guard\.py|guard/cli\.py|agy-guard))\s+"
    r"(?:--(?:env|registry)(?:\s+\S+|=\S+)\s+)*"
    r"(?:"
    r"unlock\b|"
    r"rebaseline\b|"
    rf"test-boundary{_SUBPARSER_OPTS}\s+snapshot\b|"
    r"test-boundary\b[^\n;|&`]*\s--authorize(?:\b|=)|"
    r"provenance\b[^\n;|&`]*\s--authorize(?:\b|=)|"
    rf"snapshot{_SUBPARSER_OPTS}\s+(?:restore|prune)\b|"
    rf"porter{_SUBPARSER_OPTS}\s+(?:stage\b|import\b[^\n;|&`]*\s--force\b)|"
    rf"env{_SUBPARSER_OPTS}\s+remove\b|"
    rf"env{_SUBPARSER_OPTS}\s+add\b[^\n;|&`]*--policy(?:=|\s+)(?!enforced\b)\S+|"
    rf"env{_SUBPARSER_OPTS}\s+policy\b(?!(?![^\n;|&`]*\b(?:monitored|disabled|relaxed)\b)(?:[^\n;|&`]*\s+\S+\s+enforced\s*(?:$|[;&|()\n`])|[^\n;|&`]*--policy-val(?:=|\s+)enforced\b))|"
    rf"startup{_SUBPARSER_OPTS}\s+(?:enable|disable)\b|"
    rf"notify{_SUBPARSER_OPTS}\s+disable\b|"
    r"doctor\b[^\n;|&`]*\s--(?:fix|recover)\b|"
    r"init\b(?!(?![^\n;|&`]*--uninstall\b)[^\n;|&`]*(?:--dry-run\b|--help\b|-h\b))"
    r")|"
    rf"(?:(?:[^\s;|&`]*/)?python3?(?:\.\d+)?\s+{_PY_INTERP_OPTS}(?:-[A-Za-z0-9]*m\s+porter\b|(?:[^\s;|&`]*/)?porter\.py)|(?:[^\s;|&`]*/)?(?:porter\.py|(?:agy-)?porter)){_SUBPARSER_OPTS}\s+(?:stage\b|import\b[^\n;|&`]*\s--force\b)|"
    rf"(?:(?:[^\s;|&`]*/)?python3?(?:\.\d+)?\s+{_PY_INTERP_OPTS}(?:-[A-Za-z0-9]*m\s+scripts\.verify_invariants\b|(?:[^\s;|&`]*/)?verify_invariants\.py)|(?:[^\s;|&`]*/)?verify_invariants\.py)\b[^\n;|&`]*\s--authorize(?:\b|=)"
    r")",
    re.IGNORECASE,
)

_GUARD_API_TOKEN_PAT = (
    r"(?:"
    r"\b(?:OSProtectionAdapter|PorterBridge|Installer)\b|"
    r"\bguard\.(?:os_adapter|porter_bridge|cli)\b|"
    r"\binstall\.main\s*\(|"
    r"\bauthorized_modifications\s*=|"
    r"\.(?:unlock|save_baseline|snapshot|restore_snapshot|prune_snapshots|stage_and_ingest|set_policy|register_environment|unregister_environment|remove_environment)\s*\("
    r")"
)

# Inline or piped Python (`python -c`, `python -uc`, heredoc, or `... | python3`) invoking human-only Guard or Installer APIs directly
_GUARD_INLINE_PY_RE = re.compile(
    r"(?:"
    rf"\bpython3?(?:\.\d+)?\b[^\n;|&`]*(?:\s-[A-Za-z0-9]*c\b|<<-?\s*['\"]?[A-Za-z0-9_]+['\"]?)[\s\S]*?{_GUARD_API_TOKEN_PAT}|"
    rf"{_GUARD_API_TOKEN_PAT}[\s\S]*?\|\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?python3?(?:\.\d+)?\b"
    r")",
    re.IGNORECASE,
)

# Direct execution of install.py without --dry-run or --help (GEMINI.md Rule 12).
# Anchored to the start of a simple command (or interpreter invocation) so passing `install.py`
# as a path argument to read-only commands (`git diff ... install.py`, `grep ... install.py`) is allowed.
_INSTALL_PY_RE = re.compile(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}"
    r"(?:(?:[^\s;|&`]*/)?(?:python3?(?:\.\d+)?|py|(?:ba|z|da|k)?sh)\s+(?:-[^\s;|&`]+\s+)*(?:[^\s;|&`]*/)?|(?:[^\s;|&`]*/)?)"
    r"install\.py\b(?![^\n;|&`]*(?:--dry-run|--help|-h\b))",
    re.IGNORECASE,
)

_WORKFLOW_INSTALL_EXEC_RE = re.compile(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}"
    r"(?:(?:[^\s;|&`]*/)?(?:python3?(?:\.\d+)?|py|(?:ba|z|da|k)?sh)\s+(?:-[^\s;|&`]+\s+)*(?:[^\s;|&`]*/)?|(?:\./|/[^\s;|&`]*/))"
    r"install\.py\b(?![^\n;|&`]*(?:--dry-run|--help|-h\b))",
    re.IGNORECASE,
)

_QUOTED_SPAN_RE = re.compile(r"'[^']*'|\"(?:\\.|[^\"\\])*\"")
_BACKTICK_SPAN_RE = re.compile(r"`((?:\\.|[^`\\])+)`")
_SHELL_C_EXTRACT_RE = re.compile(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}"
    r"(?:(?:[^\s;|&`]*/)?(?:ba|z|da|k)?sh\b[^\n;|&`]*?\s-(?:[A-Za-z0-9]+\s+)*[A-Za-z0-9]*c[A-Za-z0-9]*|eval)\s+"
    r"(?:'([^']*)'|\"((?:\\.|[^\"\\])*)\")",
    re.IGNORECASE,
)
_SCRIPT_C_EXTRACT_RE = re.compile(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?script\b[^\n;|&`]*?"
    r"(?:\s-(?:[A-Za-z0-9]+\s+)*[A-Za-z0-9]*c\s*|\s--command(?:=|\s+))"
    r"(?:'([^']*)'|\"((?:\\.|[^\"\\])*)\"|([^\s;|&`'\"]+))",
    re.IGNORECASE,
)
_PIPE_TO_SH_EXTRACT_RE = re.compile(
    rf"(?:^|[;&|()\n`])\s*(?:echo|printf)\b(?:\s+-[neE]+)*\s+"
    r"(?:'([^']*)'|\"((?:\\.|[^\"\\])*)\")\s*\|\s*"
    rf"{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?(?:ba|z|da|k)?sh\b",
    re.IGNORECASE,
)
_FIND_EXEC_EXTRACT_RE = re.compile(
    r"\bfind\b[^\n;|&]*?\s-(?:exec|execdir|ok|okdir)\s+([^\n;|]+?)(?:\s+(?:\\;|;|\+))?(?=$|[;&|\n])",
    re.IGNORECASE,
)
# Owners whose `-c`-style flag never takes a shell command line (counters, compilers, SQL clients, archivers,
# network tools) or whose code payload is inspected separately (`_GUARD_INLINE_PY_RE`, `_EXEC_CALL_ARGV_RE`).
_NON_SHELL_C_FLAG_OWNERS = frozenset({
    "grep", "egrep", "fgrep", "rg", "ag", "ack", "git", "jq", "yq", "wc", "tar", "gzip", "gunzip", "bzip2",
    "xz", "zstd", "gcc", "g++", "cc", "c++", "clang", "clang++", "ld", "as", "psql", "mysql", "sqlite3",
    "mongo", "mongosh", "redis-cli", "curl", "wget", "ssh", "scp", "sftp", "rsync", "sort", "uniq", "head",
    "tail", "cut", "awk", "sed", "diff", "cmp", "python", "python3", "py", "node", "nodejs", "deno", "bun",
    "perl", "ruby", "php", "lua", "java", "docker", "podman", "kubectl", "make", "cmake", "npm", "pnpm",
    "yarn", "pip", "pip3", "cargo", "go",
})
# Launch wrappers skipped while locating the real owner of a `-c` flag (`env -u X /tmp/s -qc '...'`).
_C_FLAG_LAUNCH_WRAPPERS = frozenset({
    "env", "sudo", "doas", "nohup", "setsid", "nice", "ionice", "timeout", "stdbuf", "time", "command",
    "exec", "builtin", "unbuffer", "chrt", "taskset",
})
_SHELL_PUNCT_CHARS = ";&|()"
# Terminal multiplexers spawn commands (`tmux new-window '...'`); every argument after the multiplexer
# is treated as a candidate command line. Anchors are matched outside quoted spans only.
_TERMINAL_MUX_SEGMENT_RE = re.compile(
    r"(?:^|[;&|()\n`])\s*(?:[^\s;|&`]*/)?(?:tmux|screen|byobu|tmate|dtach|abduco|zellij)\b([^\n;|&`]*)",
    re.IGNORECASE,
)
# Keystroke or buffer injection into a multiplexer runs arbitrary commands outside `PreToolUse` inspection.
_TERMINAL_INJECTION_RE = re.compile(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}(?:[^\s;|&`]*/)?(?:"
    r"(?:tmux|byobu|tmate)\b[^\n;|&`]*\s(?:send-keys|send|paste-buffer|pasteb|load-buffer|loadb|set-buffer|setb)\b|"
    r"screen\b[^\n;|&`]*\s-X\s+(?:stuff|paste|readbuf|register)\b|"
    r"zellij\b[^\n;|&`]*\s(?:write-chars|write)\b"
    r")",
    re.IGNORECASE,
)
# Exec-like calls whose argv is a string list/tuple (`pty.spawn(['agy-guard', 'unlock'])`,
# `subprocess.run(("python3", "install.py"))`) or a single command string (`os.system('...')`).
_EXEC_CALL_ARGV_RE = re.compile(
    r"\b(?:system|popen|run|call|check_call|check_output|getoutput|getstatusoutput|Popen|spawn|spawnSync|"
    r"execSync|execFile|execFileSync|exec[lv]p?e?|spawn[lv]p?e?)\s*\(\s*"
    r"(?:[\[(]\s*((?:'[^'\n]*'|\"[^\"\n]*\")(?:\s*,\s*(?:'[^'\n]*'|\"[^\"\n]*\"))*)\s*,?\s*[\])]"
    r"|('[^'\n]*'|\"[^\"\n]*\"))"
)
_STR_ARGV_TOKEN_RE = re.compile(r"'([^'\n]*)'|\"([^\"\n]*)\"")


def _blank_quoted_spans(cmd: str) -> str:
    """Returns `cmd` with every quoted span's interior replaced by spaces (same length, quotes kept)."""
    return _QUOTED_SPAN_RE.sub(lambda m: m.group(0)[0] + " " * (len(m.group(0)) - 2) + m.group(0)[-1], cmd)


def _extract_c_flag_payloads(cmd: str) -> List[str]:
    """Returns payloads of `-c`/`--command` flags owned by shells, renamed PTY wrappers, or unknown binaries."""
    import shlex

    text = re.sub(r"\$'", "'", _expand_simple_shell_vars(cmd))
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=_SHELL_PUNCT_CHARS)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return []
    payloads: List[str] = []
    owner: Optional[str] = None
    in_wrapper: Optional[str] = None
    skip_next = False
    for idx, tok in enumerate(tokens):
        if tok and set(tok) <= set(_SHELL_PUNCT_CHARS):
            owner, in_wrapper, skip_next = None, None, False
            continue
        if owner is None:
            if skip_next:
                skip_next = False
                continue
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tok, re.DOTALL):
                continue
            if in_wrapper is not None:
                if tok.startswith("-"):
                    if in_wrapper == "env" and tok in ("-u", "--unset", "-C", "--chdir", "-S", "--split-string"):
                        skip_next = True
                    continue
                if re.fullmatch(r"\d+(?:\.\d+)?[smhd]?", tok):
                    continue
            base = os.path.basename(tok).lower()
            if base in _C_FLAG_LAUNCH_WRAPPERS:
                in_wrapper = base
                continue
            owner = base
            continue
        if owner in _NON_SHELL_C_FLAG_OWNERS:
            continue
        nxt = tokens[idx + 1] if idx + 1 < len(tokens) else ""
        if (re.fullmatch(r"-[A-Za-z0-9]*c[A-Za-z0-9]*", tok) or tok == "--command") and nxt and not (
            set(nxt) <= set(_SHELL_PUNCT_CHARS)
        ):
            payloads.append(nxt)
        elif tok.startswith("--command="):
            payloads.append(tok.split("=", 1)[1])
    return payloads


def _extract_indirect_exec_payloads(cmd: str) -> List[str]:
    """Returns command lines driven indirectly via `-c` flag payloads, terminal multiplexers, or exec-call argv."""
    found: List[str] = []

    def _add(text: str) -> None:
        stripped = text.strip()
        if stripped and stripped != cmd.strip() and stripped not in found:
            found.append(stripped)

    for payload in _extract_c_flag_payloads(cmd):
        _add(payload)
    blanked = _blank_quoted_spans(cmd)
    for m in _TERMINAL_MUX_SEGMENT_RE.finditer(blanked):
        rest = cmd[m.start(1) : m.end(1)]
        tokens = [
            tm.group(1)
            if tm.group(1) is not None
            else (_unescape_dq_payload(tm.group(2)) if tm.group(2) is not None else (tm.group(3) or ""))
            for tm in _QUOTED_ARG_TOKEN_RE.finditer(rest)
        ][:64]
        # `screen -X stuff` / `tmux send-keys -l` encode Enter as a literal `\n` or `\r` escape.
        tokens = [re.sub(r"\\[nr]", " ", tok) for tok in tokens]
        # Every token suffix is a candidate command line (`new-window agy-guard unlock` -> `agy-guard unlock`).
        for idx in range(len(tokens)):
            _add(" ".join(tokens[idx:]))
    for m in _EXEC_CALL_ARGV_RE.finditer(cmd):
        argv_src = m.group(1) if m.group(1) is not None else (m.group(2) or "")
        parts = [
            tm.group(1) if tm.group(1) is not None else (tm.group(2) or "")
            for tm in _STR_ARGV_TOKEN_RE.finditer(argv_src)
        ]
        _add(" ".join(parts))
    return found


_QUOTED_ARG_TOKEN_RE = re.compile(r"'([^']*)'|\"((?:\\.|[^\"\\])*)\"|([^\s'\"]+)")


def _join_shell_line_continuations(cmd: str) -> str:
    """Joins POSIX backslash-newline (`\\` + LF/CRLF) continuations outside single-quoted strings."""
    if "\\" not in cmd or ("\n" not in cmd and "\r" not in cmd):
        return cmd
    out: List[str] = []
    in_sq = False
    i = 0
    n = len(cmd)
    while i < n:
        ch = cmd[i]
        if in_sq:
            out.append(ch)
            if ch == "'":
                in_sq = False
            i += 1
            continue
        if ch == "'":
            in_sq = True
            out.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            if cmd[i + 1] == "\n":
                i += 2
                continue
            if cmd[i + 1] == "\r" and i + 2 < n and cmd[i + 2] == "\n":
                i += 3
                continue
            out.append(ch)
            out.append(cmd[i + 1])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _extract_dollar_paren_payloads(cmd: str) -> List[str]:
    """Extracts command/process substitutions (`$(...)`, `<(...)`, `>(...)`) outside single quotes."""
    results: List[str] = []
    in_sq = False
    in_dq = False
    i = 0
    n = len(cmd)
    while i < n:
        ch = cmd[i]
        if in_sq:
            if ch == "'":
                in_sq = False
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch == "'" and not in_dq:
            in_sq = True
            i += 1
            continue
        if ch == '"':
            in_dq = not in_dq
            i += 1
            continue
        is_cmd_sub = ch == "$" and i + 1 < n and cmd[i + 1] == "("
        is_proc_sub = not in_dq and ch in "<>" and i + 1 < n and cmd[i + 1] == "("
        if is_cmd_sub or is_proc_sub:
            if is_cmd_sub and i + 2 < n and cmd[i + 2] == "(":
                i += 3
                continue
            start = i + 2
            depth = 1
            j = start
            sub_sq = False
            sub_dq = False
            while j < n and depth > 0:
                cj = cmd[j]
                if sub_sq:
                    if cj == "'":
                        sub_sq = False
                    j += 1
                    continue
                if cj == "\\" and j + 1 < n:
                    j += 2
                    continue
                if cj == "'" and not sub_dq:
                    sub_sq = True
                    j += 1
                    continue
                if cj == '"':
                    sub_dq = not sub_dq
                    j += 1
                    continue
                if cj == "(":
                    depth += 1
                elif cj == ")":
                    depth -= 1
                    if depth == 0:
                        inner = cmd[start:j].strip()
                        if inner and inner not in results:
                            results.append(inner)
                        break
                j += 1
            i = start
            continue
        i += 1
    return results


def _strip_unquoted_shell_comments(cmd: str) -> str:
    """Strips unquoted POSIX shell `# ...` comments (at start-of-line or after whitespace/operators)."""
    out: List[str] = []
    in_sq = False
    in_dq = False
    i = 0
    n = len(cmd)
    while i < n:
        ch = cmd[i]
        if in_sq:
            out.append(ch)
            if ch == "'":
                in_sq = False
            i += 1
            continue
        if in_dq:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(cmd[i + 1])
                i += 2
                continue
            if ch == '"':
                in_dq = False
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(ch)
            out.append(cmd[i + 1])
            i += 2
            continue
        if ch == "'":
            in_sq = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_dq = True
            out.append(ch)
            i += 1
            continue
        if ch == "#" and (i == 0 or cmd[i - 1] in " \t\r\n;&|(`"):
            nl = cmd.find("\n", i)
            if nl == -1:
                break
            i = nl
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _unquote_single_tokens(cmd: str) -> str:
    """Unquotes whitespace-free quoted tokens (`"agy-guard"`, `agy-""guard`, `'--no-verify'`) while preserving multi-word quoted prose."""
    parts: List[str] = []
    last = 0
    for m in _QUOTED_SPAN_RE.finditer(cmd):
        outside = cmd[last : m.start()]
        parts.append(re.sub(r"\\([A-Za-z0-9_./~-])", r"\1", outside))
        span = m.group(0)
        inner = span[1:-1]
        if inner == "":
            adjacent = (m.start() > 0 and not cmd[m.start() - 1].isspace()) or (
                m.end() < len(cmd) and not cmd[m.end()].isspace()
            )
            parts.append("" if adjacent else span)
        elif not re.search(r"[\s\\;|&()<>`]", inner):
            parts.append(inner)
        else:
            parts.append(span)
        last = m.end()
    parts.append(re.sub(r"\\([A-Za-z0-9_./~-])", r"\1", cmd[last:]))
    return "".join(parts)


def _unescape_dq_payload(raw_dq: str) -> str:
    return (
        raw_dq.replace('\\"', '"')
        .replace("\\$", "$")
        .replace("\\`", "`")
        .replace("\\\\", "\\")
    )


def _extract_shell_c_payloads(cmd: str, max_depth: int = 5) -> List[str]:
    """Recursively extracts inner shell scripts from `sh -c`, `eval`, `script -c`, `$(...)`, `<(...)`, backticks, `find -exec`, and `| sh`."""
    max_candidates = 256
    extracted: List[str] = []
    seen: set[str] = set()

    def _record(candidate: str, bucket: List[str]) -> None:
        if candidate and candidate not in seen and len(extracted) < max_candidates:
            seen.add(candidate)
            extracted.append(candidate)
            bucket.append(candidate)

    frontier = [_join_shell_line_continuations(cmd)]
    for _ in range(max_depth):
        if len(extracted) >= max_candidates:
            break
        next_frontier: List[str] = []
        for item in frontier:
            joined_item = _join_shell_line_continuations(item)
            if joined_item != item:
                _record(joined_item, next_frontier)
            for m in _SHELL_C_EXTRACT_RE.finditer(joined_item):
                inner = m.group(1) if m.group(1) is not None else _unescape_dq_payload(m.group(2) or "")
                _record(inner.strip(), next_frontier)
            for sm in _SCRIPT_C_EXTRACT_RE.finditer(joined_item):
                inner_s = (
                    sm.group(1)
                    if sm.group(1) is not None
                    else (_unescape_dq_payload(sm.group(2)) if sm.group(2) is not None else (sm.group(3) or ""))
                )
                _record(inner_s.strip(), next_frontier)
            for pm in _PIPE_TO_SH_EXTRACT_RE.finditer(joined_item):
                inner_p = pm.group(1) if pm.group(1) is not None else _unescape_dq_payload(pm.group(2) or "")
                _record(inner_p.strip(), next_frontier)
            for fm in _FIND_EXEC_EXTRACT_RE.finditer(joined_item):
                _record(fm.group(1).strip(), next_frontier)
            for dp_inner in _extract_dollar_paren_payloads(joined_item):
                _record(dp_inner, next_frontier)
            for ind_inner in _extract_indirect_exec_payloads(joined_item):
                _record(ind_inner, next_frontier)
            no_sq = re.sub(r"'[^']*'", "", joined_item)
            for bm in _BACKTICK_SPAN_RE.finditer(no_sq):
                _record(bm.group(1).strip(), next_frontier)
            if len(extracted) >= max_candidates:
                break
        if not next_frontier:
            break
        frontier = next_frontier
    return extracted


def _mask_quoted_operators(cmd: str) -> str:
    """Replaces shell operators and flags inside multi-word quoted string literals so quoted prose never triggers false positives."""
    uncommented = _strip_unquoted_shell_comments(_join_shell_line_continuations(cmd))
    unquoted = _unquote_single_tokens(uncommented)
    return _QUOTED_SPAN_RE.sub(lambda m: re.sub(r"[;&|()\-`]", "_", m.group(0)), unquoted)


_GIT_OPT_ARG = r"(?:(?:'[^']*'|\"(?:\\.|[^\"\\])*\"|[^\s;|&()'\"])+)"
_GIT_GLOBAL_OPTS = (
    rf"(?:\s+(?:-[Cc](?:\s+{_GIT_OPT_ARG}|{_GIT_OPT_ARG})"
    rf"|--(?:git-dir|work-tree|namespace|config-env|super-prefix|list-cmds)(?:={_GIT_OPT_ARG}|\s+{_GIT_OPT_ARG})"
    rf"|--exec-path(?:={_GIT_OPT_ARG})?"
    r"|--(?:no-pager|bare|literal-pathspecs|glob-pathspecs|noglob-pathspecs|icase-pathspecs|"
    r"no-optional-locks|no-advice|no-replace-objects|no-lazy-fetch|paginate)"
    r"|-[pP]))*"
)

# Git hook bypass flags (--no-verify, git commit -n, core.hooksPath, --config-env=core.hooksPath, HUSKY=0, LEFTHOOK=0)
_GIT_HOOK_BYPASS_RE = re.compile(
    r"(?:"
    r"\bgit\b[^\n;|&]*\s--no-verify\b|"
    rf"\bgit{_GIT_GLOBAL_OPTS}\s+commit\b[^\n;|&]*\s-(?!-)[a-zA-Z]*n[a-zA-Z]*\b|"
    r"\bgit\b[^\n;|&]*(?:\s-c\s*|--config-env(?:=|\s+))['\"]?(?i:core\.hookspath)\s*=|"
    r"\b(?:HUSKY|LEFTHOOK)\s*=\s*(?:0|(?i:false))\b"
    r")"
)

_REMOTE_INTERPRETER_PAT = (
    r"(?:(?:[^\s;|&]*/)?(?:(?:ba|z|da|k|tc|c|fi)?sh|python3?(?:\.\d+)?|py|node|nodejs|deno|bun|perl|ruby|php))"
)

# Destructive shell/git operations that require explicit human confirmation (force_ask)
_DESTRUCTIVE_CMD_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(rf"\bgit{_GIT_GLOBAL_OPTS}\s+reset\b[^\n;|&]*--hard\b"),
        "Destructive git operation (`git reset --hard`) discards uncommitted work (GEMINI.md Rule 12).",
    ),
    (
        re.compile(
            rf"\bgit{_GIT_GLOBAL_OPTS}\s+(?:checkout\s+(?:--\s+)?\.|restore\s+(?:(?:--worktree|--staged|-[sSW]+)\s+)*(?:--\s+)?\.)(?:\s|$|[;&|])"
        ),
        "Destructive git operation discards workspace modifications across the tree (GEMINI.md Rule 12).",
    ),
    (
        re.compile(rf"\bgit{_GIT_GLOBAL_OPTS}\s+clean\b[^\n;|&]*(?:--force\b|\s-(?!-)[a-zA-Z]*f)"),
        "Destructive git operation (`git clean -f`) permanently deletes untracked files (GEMINI.md Rule 12).",
    ),
    (
        re.compile(
            rf"\bgit{_GIT_GLOBAL_OPTS}\s+push\b[^\n;|&]*(?:\s--force(?![-a-zA-Z])|\s-(?!-)[a-zA-Z]*f[a-zA-Z]*\b|\s['\"]?\+[A-Za-z0-9_./:-]+)"
        ),
        "Force-pushing (`git push --force` / `+refspec`) rewrites remote history (GEMINI.md Rule 12).",
    ),
    (
        re.compile(
            r"\brm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r|--recursive)\b\s+"
            r"(?:/(?:\s|$|[;&|])|~(?:/|\s|$|[;&|])|\$HOME\b|\.\.(?:/|\s|$|[;&|])|\*(?:\s|$|[;&|]))"
        ),
        "High-risk recursive deletion (`rm -rf` on root, home, parent, or wildcard) requires confirmation (GEMINI.md Rule 12).",
    ),
    (
        re.compile(
            rf"(?:"
            rf"\b(?:curl|wget)\b[^\n|]*\|\s*{_CMD_WRAPPER_PREFIX}{_REMOTE_INTERPRETER_PAT}\b|"
            rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}(?:{_REMOTE_INTERPRETER_PAT}|source|\.)\b[^\n;|&]*(?:<\(|\$\()\s*(?:[^\s;|&]*/)?(?:curl|wget)\b"
            rf")",
            re.IGNORECASE,
        ),
        "Executing remote scripts directly via a shell or language interpreter is forbidden by supply-chain policy (GEMINI.md Rule 12).",
    ),
    (
        re.compile(r"\b(?:npx|bunx|pnpm\s+dlx|uvx)\b[^\n;|&]*@latest\b"),
        "Executing unpinned `@latest` packages (`npx/bunx/uvx @latest`) violates supply-chain pinning rules (GEMINI.md Rule 12).",
    ),
)

_EXACT_NPM_VER_RE = re.compile(r"^(?:\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?|[0-9a-fA-F]{40})$")
_EXACT_PY_PIN_RE = re.compile(r"(?:==\s*\d+\.\d+(?:\.\d+)?[0-9A-Za-z._+-]*|@\s*git\+[^\s@]+@[0-9a-fA-F]{40})$")
_NPX_SEGMENT_RE = re.compile(
    rf"(?:^|[;&|()\n`])\s*{_CMD_WRAPPER_PREFIX}"
    r"(?:[^\s;|&`]*/)?(?P<runner>npx|bunx|pnpm\s+dlx|uvx|pipx\s+run)\b(?P<rest>[^\n;|&`]*)",
    re.IGNORECASE,
)


def _is_pinned_npm_spec(spec: str) -> bool:
    s = spec.strip().strip("'\"")
    if not s or s.startswith(("./", "../", "/", "~/")) or s.startswith("file:"):
        return True
    if s.startswith("@"):
        slash_idx = s.find("/")
        if slash_idx == -1:
            return False
        at_idx = s.find("@", slash_idx + 1)
        if at_idx == -1:
            return False
        ver = s[at_idx + 1 :]
    else:
        if "@" not in s:
            return False
        ver = s.split("@", 1)[1]
    return bool(_EXACT_NPM_VER_RE.match(ver))


def _is_pinned_py_spec(spec: str) -> bool:
    s = spec.strip().strip("'\"")
    if not s or s.startswith(("./", "../", "/", "~/")):
        return True
    if "," in s:
        return False
    return bool(_EXACT_PY_PIN_RE.search(s))


def _detect_unpinned_package_exec(cmd: str) -> Optional[str]:
    """Detects unpinned remote package execution (`npx -y pkg`, `bunx pkg`, `pnpm dlx pkg`, `uvx pkg`)."""
    for m in _NPX_SEGMENT_RE.finditer(cmd):
        runner = re.sub(r"\s+", " ", m.group("runner").strip().lower())
        rest = m.group("rest").strip()
        if not rest:
            continue
        raw_tokens = [tok.strip("'\"") for tok in re.findall(r"'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+", rest)]
        if runner in ("npx", "bunx", "pnpm dlx"):
            if "--no-install" in raw_tokens or any(t in ("-h", "--help", "-v", "--version") for t in raw_tokens):
                continue
            pkg_specs: List[str] = []
            first_pos: Optional[str] = None
            idx = 0
            while idx < len(raw_tokens):
                tok = raw_tokens[idx]
                if tok == "--":
                    if idx + 1 < len(raw_tokens) and first_pos is None:
                        first_pos = raw_tokens[idx + 1]
                    break
                if tok in ("-p", "--package"):
                    if idx + 1 < len(raw_tokens):
                        pkg_specs.append(raw_tokens[idx + 1])
                    idx += 2
                    continue
                if tok.startswith("--package="):
                    pkg_specs.append(tok.split("=", 1)[1])
                    idx += 1
                    continue
                if tok in ("-c", "--call", "--shell", "--cache", "--userconfig"):
                    idx += 2
                    continue
                if tok.startswith("-"):
                    idx += 1
                    continue
                first_pos = tok
                break
            targets = pkg_specs if pkg_specs else ([first_pos] if first_pos else [])
            if any(not _is_pinned_npm_spec(t) for t in targets):
                return (
                    f"Executing unpinned package via `{runner}` without an exact `pkg@X.Y.Z` version "
                    "(or `--no-install`) violates supply-chain pinning rules (GEMINI.md Rule 12)."
                )
        else:
            if any(t in ("-h", "--help", "-V", "--version", "--offline", "--no-index") for t in raw_tokens):
                continue
            py_specs: List[str] = []
            first_py: Optional[str] = None
            idx = 0
            while idx < len(raw_tokens):
                tok = raw_tokens[idx]
                if tok == "--":
                    if idx + 1 < len(raw_tokens) and first_py is None:
                        first_py = raw_tokens[idx + 1]
                    break
                if tok in ("--from", "--with"):
                    if idx + 1 < len(raw_tokens):
                        py_specs.append(raw_tokens[idx + 1])
                    idx += 2
                    continue
                if tok.startswith(("--from=", "--with=")):
                    py_specs.append(tok.split("=", 1)[1])
                    idx += 1
                    continue
                if tok in ("-p", "--python", "--index-url", "--extra-index-url"):
                    idx += 2
                    continue
                if tok.startswith("-"):
                    idx += 1
                    continue
                first_py = tok
                break
            targets = py_specs if py_specs else ([first_py] if first_py else [])
            if any(not _is_pinned_py_spec(t) for t in targets):
                return (
                    f"Executing unpinned package via `{runner}` without an exact `pkg==X.Y.Z` version "
                    "violates supply-chain pinning rules (GEMINI.md Rule 12)."
                )
    return None


# Stop-gate diff inspection regexes
_TAUTOLOGY_PY_RE = re.compile(
    r"^\+\s*(?:"
    r"assert\s+([A-Za-z0-9_.]+)\s*==\s*\1(?:\s|$|,|#)|"
    r"assert\s+True(?:\s|$|,|#)|"
    r"self\.assertEqual\(\s*([A-Za-z0-9_.]+)\s*,\s*\2\s*\)|"
    r"self\.assertTrue\(\s*True\s*\)"
    r")"
)
_TAUTOLOGY_JS_RE = re.compile(
    r"^\+\s*expect\(\s*([A-Za-z0-9_.]+)\s*\)\.(?:toBe|toEqual|toStrictEqual)\(\s*\1\s*\)"
)
_COMMENT_ADDED_LINE_RE = re.compile(r"^\+\s*(?:#|//)")
_TEST_RUNNER_SNIFF_RE = re.compile(
    r"^\+.*?(?:"
    r"PYTEST_CURRENT_TEST|"
    r"UNITTEST_RUNNING|"
    r"sys\.modules(?:\.get\s*\(|\s*\[)\s*['\"](?:unittest|pytest)['\"]|"
    r"['\"](?:unittest|pytest)['\"]\s+in\s+sys\.modules|"
    r"NODE_ENV\s*===\s*['\"]test['\"]|"
    r"NODE_ENV\s*==\s*['\"]test['\"]|"
    r"process\.env\.JEST_WORKER_ID|"
    r"process\.env\.VITEST"
    r")"
)
_TEST_SKIP_RE = re.compile(
    r"^\+\s*(?:"
    r"@pytest\.mark\.(?:skip(?:if)?|xfail)\b|"
    r"@unittest\.(?:skip(?:If|Unless)?|expectedFailure)\b|"
    r"pytest\.(?:skip|xfail)\s*\(|"
    r"self\.skipTest\s*\(|"
    r"unittest\.SkipTest\s*\(|"
    r"(?:it|test|describe)\.(?:skip|todo)\s*\(|"
    r"(?:xit|xtest|xdescribe)\s*\("
    r")"
)

# Files inside the harness repo that legitimately mention test-runner env vars as scanner patterns
_SCANNER_EXEMPT_SUFFIXES = (
    "guard/agy_hooks.py",
    "porter/sanitizer.py",
    "scripts/verify_invariants.py",
    ".harness/manifest.json",
)


def _conversation_id(payload: Dict[str, Any]) -> str:
    for key in ("conversationId", "conversation_id", "sessionId", "session_id", "trajectoryId"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return "default"


def _safe_int(val: Any, default: int = 0) -> int:
    """Parses an integer safely while rejecting booleans, NaN/Inf, and malformed strings."""
    if isinstance(val, bool) or val is None:
        return default
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        try:
            return int(val)
        except (ValueError, OverflowError):
            return default
    if isinstance(val, str):
        stripped = val.strip()
        if not stripped:
            return default
        try:
            return int(stripped)
        except ValueError:
            return default
    return default


def _strip_non_user_prose(text: str) -> str:
    """Removes pasted blocks, fenced code blocks, and inline code from user text before matching."""
    cleaned = _PASTED_RE.sub(" ", text or "")
    cleaned = _FENCE_RE.sub(" ", cleaned)
    cleaned = _INLINE_CODE_RE.sub(" ", cleaned)
    return cleaned


def _extract_user_request_prose(raw_prompt: str) -> str:
    """Strips pasted/fenced/inline-code blocks before extracting `<USER_REQUEST>` user prose."""
    sanitized = _strip_non_user_prose(raw_prompt or "")
    blocks = _USER_REQUEST_TAG_RE.findall(sanitized)
    return _strip_non_user_prose("\n".join(blocks)) if blocks else sanitized


_DISTINCTIVE_SKILL_SLUGS = frozenset({
    "porter",
    "sweetspot",
    "vibecoder",
    "antislop",
    "chisle",
    "procoder",
    "unlazy",
    "marathon",
    "rustify",
})


def _has_explicit_slash_command(cleaned: str, aliases: Sequence[str]) -> bool:
    """Returns True when `cleaned` contains an explicit `/alias` or `$alias` command outside file paths."""
    if not aliases:
        return False
    joined = "|".join(re.escape(alias) for alias in aliases)
    pattern = re.compile(
        rf"{_SLASH_PRE}[/\$](?:{joined}){_SLASH_POST}",
        re.IGNORECASE,
    )
    return bool(pattern.search(cleaned))


def _has_explicit_slug_mention(cleaned: str, slug: str) -> bool:
    """Returns True when a distinctive or hyphenated skill/agent slug is named directly in prose outside paths."""
    if "-" not in slug and slug not in _DISTINCTIVE_SKILL_SLUGS:
        return False
    pattern = re.compile(
        rf"(?:^|(?<=[\s(\[\"'«“])){re.escape(slug)}{_SLASH_POST}",
        re.IGNORECASE,
    )
    return bool(pattern.search(cleaned))


def _load_conv_hint_state(raw_entry: Any) -> Tuple[Dict[str, int], int, str]:
    """Normalizes persisted `hook_hints.json` state (legacy `list[str]` or turn-indexed `dict`)."""
    if isinstance(raw_entry, list):
        seen = {
            str(k): 1
            for k in raw_entry
            if isinstance(k, str) and k not in ("__turn__", "__last_sig__")
        }
        return seen, (1 if seen else 0), ""
    if isinstance(raw_entry, dict):
        turn = max(0, _safe_int(raw_entry.get("__turn__"), default=0))
        raw_sig = raw_entry.get("__last_sig__", "")
        last_sig = str(raw_sig) if isinstance(raw_sig, str) else ""
        seen = {
            str(k): (parsed if (parsed := _safe_int(v, default=0)) > 0 else 1)
            for k, v in raw_entry.items()
            if isinstance(k, str) and k not in ("__turn__", "__last_sig__")
        }
        return seen, max(turn, 1 if seen else 0), last_sig
    return {}, 0, ""


def _extract_latest_user_prompt(payload: Dict[str, Any]) -> Tuple[str, int]:
    """
    Returns (user_text, step_idx) from explicit payload fields or from transcriptPath JSONL.
    """
    step_raw = payload.get("stepIdx")
    if step_raw is None:
        step_raw = payload.get("initialNumSteps")
    explicit_step = max(0, _safe_int(step_raw, default=0))

    for key in ("prompt", "userPrompt", "userMessage", "user_prompt"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()[:131072], explicit_step

    transcript = payload.get("transcriptPath") or payload.get("transcript_path")
    if isinstance(transcript, str) and transcript.strip():
        path = Path(transcript).expanduser()
        if path.is_file():
            try:
                # Read up to the last 128 KB of transcript to stay fast on long conversations
                with path.open("rb") as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - 131072), os.SEEK_SET)
                    lines = f.read().decode("utf-8", errors="replace").splitlines()
                for raw in reversed(lines):
                    raw = raw.strip()
                    if not raw.startswith("{"):
                        continue
                    try:
                        entry = json.loads(raw)
                    except ValueError:
                        continue
                    step_type = str(entry.get("type", "")).upper()
                    source = str(entry.get("source", "")).upper()
                    if step_type == "USER_INPUT" or source == "USER_EXPLICIT":
                        content = entry.get("content")
                        if isinstance(content, str) and content.strip():
                            raw_entry_step = entry.get("step_index")
                            if raw_entry_step is None:
                                raw_entry_step = entry.get("stepIdx")
                            idx = max(0, _safe_int(raw_entry_step, default=explicit_step))
                            return content.strip()[:131072], idx
            except OSError:
                pass
    return "", 0


def _extract_latest_assistant_message(payload: Dict[str, Any]) -> str:
    """Returns the latest assistant response text from payload or transcriptPath JSONL."""
    for key in ("lastAssistantMessage", "assistantMessage", "response"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()

    transcript = payload.get("transcriptPath") or payload.get("transcript_path")
    if isinstance(transcript, str) and transcript.strip():
        path = Path(transcript).expanduser()
        if path.is_file():
            try:
                with path.open("rb") as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - 131072), os.SEEK_SET)
                    lines = f.read().decode("utf-8", errors="replace").splitlines()
                for raw in reversed(lines):
                    raw = raw.strip()
                    if not raw.startswith("{"):
                        continue
                    try:
                        entry = json.loads(raw)
                    except ValueError:
                        continue
                    if str(entry.get("type", "")).upper() == "PLANNER_RESPONSE":
                        content = entry.get("content")
                        if isinstance(content, str) and content.strip():
                            return content.strip()
            except OSError:
                pass
    return ""


_HEX_OID_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
_HANDOFF_IN_PROGRESS_RE = re.compile(r"(?im)^\s*(?:\*\*Status:\*\*|Status:)\s*\[IN-PROGRESS\]\s*$")
_TASKS_PENDING_RE = re.compile(r"(?m)^\s*-\s*\[\s\]\s+\S")
_TASKS_PARTIAL_RE = re.compile(r"(?m)^\s*(?:-\s*\[~\]|\|[^\n]*\[~\])")
_TASKS_BLOCKED_RE = re.compile(r"(?m)^\s*(?:-\s*\[!\]|\|[^\n]*\[!\])")
_UNRECOVERED_FLIGHT_STATES = frozenset({"in_flight", "interrupted_notified", "in_progress_blocked"})


def _flight_recorder_file() -> Path:
    return state_dir() / "flight_recorder.json"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_ledger_safe(path: Path) -> Dict[str, Any]:
    """Reads a JSON dict ledger, quarantining (`move_aside`) corrupt state rather than silently wiping it."""
    try:
        data = read_json_strict(path)
    except (CorruptStateError, UnicodeDecodeError):
        move_aside(path, tag="corrupt")
        return {}
    except OSError:
        return {}
    if data is None:
        return {}
    if not isinstance(data, dict):
        move_aside(path, tag="corrupt")
        return {}
    return data


def _read_bounded_markdown(path: Path, limit: int = 262144) -> str:
    """Reads up to `limit` bytes from a non-symlink regular file without skipping large logs."""
    try:
        if path.is_symlink() or not path.is_file():
            return ""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(path), flags)
        with os.fdopen(fd, "rb") as f:
            return f.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _capture_git_baseline(workspace: Path) -> Tuple[str, str]:
    """
    Captures `(base_head, pre_edit_stash)` for `workspace` before the first write of a session.
    If the working tree has pre-existing uncommitted tracked modifications, `git stash create`
    produces a commit object without mutating the working tree, index, or `refs/stash`, and
    pins it at `refs/harness/pre-edit` so `git gc` preserves it across crashes.
    """
    base_head = ""
    pre_edit_stash = ""
    try:
        head_res = subprocess.run(
            ["git", "-C", str(workspace), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            stdin=subprocess.DEVNULL,
        )
        if head_res.returncode == 0:
            candidate = head_res.stdout.strip()
            if _HEX_OID_RE.match(candidate):
                base_head = candidate
    except (OSError, subprocess.SubprocessError):
        return "", ""

    if not base_head:
        return "", ""

    try:
        stash_res = subprocess.run(
            ["git", "-C", str(workspace), "stash", "create"],
            capture_output=True,
            text=True,
            timeout=2,
            stdin=subprocess.DEVNULL,
        )
        if stash_res.returncode == 0:
            candidate_stash = stash_res.stdout.strip()
            if _HEX_OID_RE.match(candidate_stash):
                ref_res = subprocess.run(
                    ["git", "-C", str(workspace), "update-ref", "refs/harness/pre-edit", candidate_stash],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    stdin=subprocess.DEVNULL,
                )
                if ref_res.returncode == 0:
                    pre_edit_stash = candidate_stash
    except (OSError, subprocess.SubprocessError):
        pass

    return base_head, pre_edit_stash


def _record_flight_pre_write(
    payload: Dict[str, Any],
    workspace: Optional[Path],
    tool_name: str,
    target_path_str: str,
) -> None:
    """
    Records an in-flight file mutation in `state_dir() / "flight_recorder.json"` (`fsync` +
    `os.replace`) before a workspace file-write tool executes. If the session is cut off by
    quota exhaustion, network loss, or power failure before `handle_stop` runs, the status
    remains `"in_flight"` on disk so the next `PreInvocation` surfaces a recovery directive.
    """
    if (
        workspace is None
        or not target_path_str
        or "\x00" in target_path_str
        or not target_path_str.strip()
    ):
        return
    try:
        if not workspace.is_dir():
            return
    except (OSError, ValueError):
        return

    expanded = Path(os.path.expanduser(target_path_str.strip()))
    candidate = (workspace / expanded) if not expanded.is_absolute() else expanded
    try:
        ws_resolved = workspace.resolve()
        cand_resolved = candidate.resolve()
    except (OSError, RuntimeError, ValueError):
        return

    if not is_within(cand_resolved, ws_resolved):
        return

    try:
        rel_target = str(cand_resolved.relative_to(ws_resolved)).replace("\\", "/")
    except ValueError:
        rel_target = target_path_str.strip().replace("\\", "/")
    if not rel_target or rel_target == ".":
        return

    ws_key = str(ws_resolved)
    conv_id = _conversation_id(payload)
    flight_file = _flight_recorder_file()

    try:
        with file_lock(flight_file, timeout=HOOK_LOCK_TIMEOUT):
            ledger = _read_ledger_safe(flight_file)
            prev = ledger.get(ws_key) if isinstance(ledger.get(ws_key), dict) else {}
            preserve_lineage = (
                prev.get("conversation_id") == conv_id
                or str(prev.get("status") or "") in _UNRECOVERED_FLIGHT_STATES
            )

            if preserve_lineage:
                base_head = str(prev.get("base_head") or "")
                pre_edit_stash = str(prev.get("pre_edit_stash") or "")
                touched: List[str] = [
                    str(x) for x in (prev.get("touched_files") or []) if isinstance(x, str) and x
                ]
            else:
                base_head, pre_edit_stash = _capture_git_baseline(ws_resolved)
                touched = []

            if rel_target not in touched:
                touched.append(rel_target)
            touched = touched[-30:]
            seq = _safe_int(prev.get("seq"), default=0) + 1

            if ws_key in ledger:
                del ledger[ws_key]
            ledger[ws_key] = {
                "workspace": ws_key,
                "conversation_id": conv_id,
                "status": "in_flight",
                "seq": seq,
                "updated_at": _utc_now_iso(),
                "base_head": base_head,
                "pre_edit_stash": pre_edit_stash,
                "last_tool": tool_name,
                "last_target": rel_target,
                "touched_files": touched,
                "last_stop_findings_count": _safe_int(prev.get("last_stop_findings_count"), default=0),
            }
            while len(ledger) > 50:
                oldest = next(iter(ledger))
                del ledger[oldest]
            atomic_write_json(flight_file, ledger)
    except (OSError, TimeoutError):
        pass


def _record_flight_stop(
    workspace: Optional[Path],
    conv_id: str,
    findings_count: int,
    *,
    workspace_clean: bool = False,
    deferred_question: bool = False,
    create_if_missing: bool = False,
) -> None:
    """
    Reconciles the workspace flight record when a turn reaches `handle_stop` normally,
    transitioning `status` from `"in_flight"` to `"turn_complete"` (`0` findings) or
    `"in_progress_blocked"` (`>0` findings), without allowing a read-only turn in a new
    conversation to erase an unrecovered crash/blocked state on a still-dirty workspace.
    """
    if workspace is None or not workspace.is_dir():
        return
    flight_file = _flight_recorder_file()
    if not flight_file.is_file() and not (create_if_missing and findings_count > 0):
        return
    try:
        ws_key = str(workspace.resolve())
        with file_lock(flight_file, timeout=HOOK_LOCK_TIMEOUT):
            ledger = _read_ledger_safe(flight_file)
            entry = ledger.get(ws_key)
            if not isinstance(entry, dict):
                if not (create_if_missing and findings_count > 0):
                    return
                ledger[ws_key] = {
                    "workspace": ws_key,
                    "conversation_id": conv_id,
                    "status": "in_progress_blocked",
                    "seq": 1,
                    "updated_at": _utc_now_iso(),
                    "base_head": "",
                    "pre_edit_stash": "",
                    "last_tool": "stop",
                    "last_target": "(workspace diff)",
                    "touched_files": [],
                    "last_stop_findings_count": _safe_int(findings_count, default=0),
                }
                while len(ledger) > 50:
                    oldest = next(iter(ledger))
                    del ledger[oldest]
                atomic_write_json(flight_file, ledger)
                return
            prev_conv = str(entry.get("conversation_id") or "")
            prev_status = str(entry.get("status") or "")

            if deferred_question:
                if prev_conv != conv_id or prev_status != "in_flight":
                    return
                prior_findings = _safe_int(entry.get("last_stop_findings_count"), default=0)
                updated = dict(entry)
                updated["status"] = "in_progress_blocked" if prior_findings > 0 else "turn_complete"
                updated["updated_at"] = _utc_now_iso()
                ledger[ws_key] = updated
                atomic_write_json(flight_file, ledger)
                return

            if (
                findings_count == 0
                and prev_conv != conv_id
                and not workspace_clean
                and prev_status in _UNRECOVERED_FLIGHT_STATES
            ):
                return

            updated = dict(entry)
            updated["conversation_id"] = conv_id
            updated["status"] = "turn_complete" if findings_count == 0 else "in_progress_blocked"
            updated["last_stop_findings_count"] = _safe_int(findings_count, default=0)
            updated["updated_at"] = _utc_now_iso()
            ledger[ws_key] = updated
            atomic_write_json(flight_file, ledger)
    except (OSError, RuntimeError, TimeoutError):
        pass


def _acknowledge_interrupted_flight(workspace: Path, expected_seq: int) -> None:
    """Marks an `"in_flight"` crash record as `"interrupted_notified"` once its recovery hint is committed."""
    flight_file = _flight_recorder_file()
    if not flight_file.is_file():
        return
    try:
        ws_key = str(workspace.resolve())
        with file_lock(flight_file, timeout=HOOK_LOCK_TIMEOUT):
            ledger = _read_ledger_safe(flight_file)
            entry = ledger.get(ws_key)
            if (
                isinstance(entry, dict)
                and entry.get("status") == "in_flight"
                and _safe_int(entry.get("seq"), default=0) == expected_seq
            ):
                updated_entry = dict(entry)
                updated_entry["status"] = "interrupted_notified"
                ledger[ws_key] = updated_entry
                atomic_write_json(flight_file, ledger)
    except (OSError, RuntimeError, TimeoutError):
        pass


def _detect_workspace_recovery_hint(
    workspace: Optional[Path],
    conv_id: str,
    first_turn_in_conv: bool,
) -> Tuple[bool, Optional[Tuple[str, str, Optional[int]]]]:
    """
    Inspects `state_dir() / "flight_recorder.json"`, `HANDOFF.md`, and `tasks.md` to detect:
      1. Mid-turn interruptions (`status == "in_flight"`, where a write tool ran and `Stop`
         never executed due to quota exhaustion, network disconnect, or power loss),
      2. Cross-session blocked or interrupted turns (`status in ("in_progress_blocked", "interrupted_notified")`
         from a prior session),
      3. Active `HANDOFF.md` (`Status: [IN-PROGRESS]`) or unfinished `tasks.md` (`[ ]`, `[~]`, `[!]`)
         on the opening turn of a new conversation.
    Returns `(inspect_ok, (dedup_key, recovery_message, ack_in_flight_seq) | None)`.
    """
    if workspace is None or not workspace.is_dir():
        return True, None

    try:
        ws_key = str(workspace.resolve())
    except (OSError, RuntimeError):
        return False, None

    flight_entry: Dict[str, Any] = {}
    flight_alert_reason = ""
    ack_seq: Optional[int] = None
    inspect_ok = True
    flight_file = _flight_recorder_file()
    if flight_file.is_file():
        try:
            with file_lock(flight_file, timeout=HOOK_LOCK_TIMEOUT):
                ledger = _read_ledger_safe(flight_file)
                if isinstance(ledger.get(ws_key), dict):
                    flight_entry = dict(ledger[ws_key])
                    status = str(flight_entry.get("status") or "")
                    rec_conv = str(flight_entry.get("conversation_id") or "")
                    if status == "in_flight":
                        flight_alert_reason = "in_flight"
                        ack_seq = _safe_int(flight_entry.get("seq"), default=0)
                    elif first_turn_in_conv and rec_conv != conv_id and status in (
                        "in_progress_blocked",
                        "interrupted_notified",
                    ):
                        flight_alert_reason = status
        except (OSError, TimeoutError):
            inspect_ok = False

    handoff_in_progress = False
    pending_count = 0
    partial_count = 0
    blocked_count = 0

    if first_turn_in_conv or flight_alert_reason:
        raw_handoff = _read_bounded_markdown(workspace / "HANDOFF.md")
        if raw_handoff:
            htext = _FENCE_RE.sub(" ", raw_handoff)
            if _HANDOFF_IN_PROGRESS_RE.search(htext):
                handoff_in_progress = True

        raw_tasks = _read_bounded_markdown(workspace / "tasks.md")
        if raw_tasks:
            ttext = _FENCE_RE.sub(" ", raw_tasks)
            pending_count = len(_TASKS_PENDING_RE.findall(ttext))
            partial_count = len(_TASKS_PARTIAL_RE.findall(ttext))
            blocked_count = len(_TASKS_BLOCKED_RE.findall(ttext))

    has_unfinished_tasks = (pending_count + partial_count + blocked_count) > 0
    if not flight_alert_reason and not (first_turn_in_conv and (handoff_in_progress or has_unfinished_tasks)):
        return inspect_ok, None

    details: List[str] = []
    last_target = str(flight_entry.get("last_target") or "")
    last_tool = str(flight_entry.get("last_tool") or "")
    touched = [str(x) for x in (flight_entry.get("touched_files") or []) if isinstance(x, str) and x]
    base_head = str(flight_entry.get("base_head") or "")
    pre_edit_stash = str(flight_entry.get("pre_edit_stash") or "")
    updated_at = str(flight_entry.get("updated_at") or "")
    seq_val = _safe_int(flight_entry.get("seq"), default=0)
    stop_findings = _safe_int(flight_entry.get("last_stop_findings_count"), default=0)

    if flight_alert_reason == "in_flight":
        details.append(
            f"an interrupted turn terminated mid-flight after `{last_tool}` on `{last_target}` "
            f"(at `{updated_at}`, before the `Stop` verification gate could run)"
        )
    elif flight_alert_reason == "in_progress_blocked":
        details.append(
            f"the previous session ended with `{stop_findings}` unresolved `Stop` gate finding(s) "
            f"(last touched `{last_target}`)"
        )
    elif flight_alert_reason == "interrupted_notified":
        details.append(
            f"a prior session experienced an unrecovered mid-flight interruption on `{last_target}`"
        )

    if touched and (flight_alert_reason or handoff_in_progress or has_unfinished_tasks):
        files_summary = ", ".join(f"`{p}`" for p in touched[:5])
        if len(touched) > 5:
            files_summary += f" (+{len(touched) - 5} more)"
        details.append(f"recorded session writes: {files_summary}")

    if pre_edit_stash:
        details.append(
            f"pre-edit dirty baseline snapshot: `{pre_edit_stash[:12]}` (`refs/harness/pre-edit`, `HEAD` `{base_head[:8]}`)"
        )
    elif base_head and (flight_alert_reason or touched):
        details.append(f"pre-edit git baseline `HEAD`: `{base_head[:8]}`")

    if handoff_in_progress:
        details.append("`HANDOFF.md` has `Status: [IN-PROGRESS]`")
    if has_unfinished_tasks:
        counts = []
        if pending_count:
            counts.append(f"{pending_count} `[ ]` pending")
        if partial_count:
            counts.append(f"{pending_count and '' or ''}{partial_count} `[~]` partial".lstrip())
        if blocked_count:
            counts.append(f"{blocked_count} `[!]` blocked")
        details.append(f"`tasks.md` has unfinished items ({', '.join(counts)})")

    fingerprint_raw = (
        f"{ws_key}|{flight_alert_reason}|{seq_val}|{updated_at}|{last_target}|"
        f"{handoff_in_progress}|{pending_count}|{partial_count}|{blocked_count}"
    )
    fp_hash = hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()[:12]
    dedup_key = f"recovery:{fp_hash}"
    msg = (
        f"[Harness Recovery & Continuity Gate] Unfinished or interrupted workspace state detected: "
        f"{'; '.join(details)}. Before making new edits, inspect `git status`/`git diff`, `tasks.md`, "
        "and `HANDOFF.md` (if present) to reconcile any half-finished modifications and resume deterministically."
    )
    return inspect_ok, (dedup_key, msg, ack_seq)


def _workspaces_from_payload(payload: Dict[str, Any]) -> List[Path]:
    """Returns all valid workspace directories from multi-root or single-root hook payloads."""
    found: List[Path] = []
    seen: set[str] = set()

    def _add_ws(raw: Any) -> None:
        if not isinstance(raw, str) or not raw.strip():
            return
        candidate = Path(raw.strip()).expanduser()
        try:
            if not candidate.is_dir():
                return
            key = str(candidate.resolve())
        except (OSError, RuntimeError, ValueError):
            return
        if key not in seen:
            seen.add(key)
            found.append(candidate)

    paths = payload.get("workspacePaths") or payload.get("workspace_paths")
    if isinstance(paths, list):
        for entry in paths:
            _add_ws(entry)
    for key in ("workspacePath", "workspace_path", "cwd", "workspace"):
        _add_ws(payload.get(key))
    return found


def _workspace_from_payload(payload: Dict[str, Any]) -> Optional[Path]:
    workspaces = _workspaces_from_payload(payload)
    return workspaces[0] if workspaces else None


def _workspace_for_target(
    target_path_str: str,
    workspaces: Sequence[Path],
    fallback: Optional[Path] = None,
) -> Optional[Path]:
    """Selects the workspace root that owns `target_path_str` in multi-root sessions."""
    if not workspaces:
        return fallback
    if not target_path_str or not target_path_str.strip() or "\x00" in target_path_str:
        return fallback if fallback is not None else workspaces[0]
    expanded = Path(os.path.expanduser(target_path_str.strip()))
    if expanded.is_absolute():
        for ws in workspaces:
            if is_within(expanded, ws):
                return ws
            try:
                if is_within(expanded.resolve(), ws.resolve()):
                    return ws
            except (OSError, RuntimeError, ValueError):
                continue
        return fallback if fallback is not None else workspaces[0]
    if fallback is not None:
        return fallback
    for ws in workspaces:
        try:
            if (ws / expanded).exists():
                return ws
        except (OSError, ValueError):
            continue
    return workspaces[0]


def _optional_plugin_skill_available(rel_path: str, workspaces: Sequence[Path]) -> bool:
    """Checks disk existence for optional `plugins/...` skill files so uninstalled plugins are not hinted."""
    if not rel_path.startswith("plugins/"):
        return True
    cfg = configured_config_dir()
    roots: List[Path] = [
        cfg,
        config_dir(),
        REPO_ROOT,
        Path("/usr/share/antigravity-harness"),
    ]
    for ws in workspaces:
        roots.append(ws)
        roots.append(ws / ".gemini" / "config")
    for root in roots:
        try:
            if (root / rel_path).is_file():
                return True
        except (OSError, ValueError):
            continue
    init_markers = ("GEMINI.md", "skills", "plugins", "hooks.json")
    try:
        if any((cfg / m).exists() for m in init_markers):
            return False
    except OSError:
        return False
    if os.environ.get("ANTIGRAVITY_CONFIG_DIR"):
        return True
    home_cfg = Path.home() / ".gemini" / "config"
    try:
        if (home_cfg / rel_path).is_file():
            return True
        if any((home_cfg / m).exists() for m in init_markers):
            return False
    except OSError:
        return False
    return True


# ----------------------------------------------------------------------
# 1. PreInvocation: Skill, Subagent, MCP Server, Plugin & Recovery Hook
# ----------------------------------------------------------------------
def handle_pre_invocation(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw_prompt, step_idx = _extract_latest_user_prompt(payload)
    if not raw_prompt:
        return {}

    cleaned = _extract_user_request_prose(raw_prompt).strip()
    scan_text = cleaned[:16384]
    normalized = re.sub(r"[.!?,;:]+$", "", scan_text.lower()).strip()
    has_explicit_cmd = bool(_EXPLICIT_CMD_TOKEN_RE.search(scan_text))
    is_short_or_continuation = (not has_explicit_cmd) and (
        len(scan_text) < MIN_PROMPT_CHARS or normalized in CONTINUATION_WORDS
    )
    workspaces = _workspaces_from_payload(payload)

    if is_short_or_continuation and not workspaces:
        return {}

    conv_id = _conversation_id(payload)
    hints_file = state_dir() / "hook_hints.json"
    recovery_msgs: List[str] = []
    pending_acks: List[Tuple[Path, int]] = []
    matched: List[Tuple[str, str, str]] = []
    matched_routes: List[Tuple[str, str]] = []
    prompt_hash = hashlib.sha256(scan_text.encode("utf-8")).hexdigest()[:12]
    current_sig = f"{step_idx}:{prompt_hash}"

    with file_lock(hints_file, timeout=HOOK_LOCK_TIMEOUT):
        ledger = _read_ledger_safe(hints_file)
        seen_turns, turn_num, last_sig = _load_conv_hint_state(ledger.get(conv_id))
        first_turn_in_conv = "__workspace_checked__" not in seen_turns
        is_new_user_turn = (not is_short_or_continuation) and (current_sig != last_sig)
        state_dirty = False
        if is_new_user_turn:
            turn_num += 1
            last_sig = current_sig
            state_dirty = True
        active_turn = max(turn_num, 1)
        new_keys: set[str] = set()

        if workspaces:
            all_inspect_ok = True
            for ws in workspaces:
                inspect_ok, recovery = _detect_workspace_recovery_hint(
                    ws,
                    conv_id,
                    first_turn_in_conv=first_turn_in_conv,
                )
                if not inspect_ok:
                    all_inspect_ok = False
                if recovery is not None:
                    rec_key, rec_text, ack_seq = recovery
                    if rec_key not in seen_turns and rec_key not in new_keys:
                        recovery_msgs.append(rec_text)
                        new_keys.add(rec_key)
                        if ack_seq is not None:
                            pending_acks.append((ws, ack_seq))
            if first_turn_in_conv and all_inspect_ok:
                new_keys.add("__workspace_checked__")

        if not is_short_or_continuation:
            has_viable_token = has_explicit_cmd or bool(_VIABLE_HINT_TOKEN_RE.search(scan_text))
            skill_candidates: List[Tuple[int, int, str, str, str]] = []
            for table_idx, (skill_name, rel_path, pattern, summary) in enumerate(SKILL_HINTS):
                if not has_viable_token and "@\\[" not in pattern.pattern:
                    continue
                if not pattern.search(scan_text):
                    continue
                if not _optional_plugin_skill_available(rel_path, workspaces):
                    continue
                aliases = _SKILL_SLASH_ALIASES.get(skill_name, (skill_name,))
                explicit_slash = _has_explicit_slash_command(scan_text, aliases)
                if skill_name in seen_turns:
                    if not is_new_user_turn:
                        continue
                    if not explicit_slash and (active_turn - seen_turns[skill_name]) < REHINT_TURN_GAP:
                        continue
                priority = (
                    2
                    if explicit_slash
                    else (1 if _has_explicit_slug_mention(scan_text, skill_name) else 0)
                )
                skill_candidates.append((-priority, table_idx, skill_name, rel_path, summary))
            skill_candidates.sort(key=lambda item: (item[0], item[1]))
            matched = [(s, r, d) for _p, _i, s, r, d in skill_candidates[:MAX_HINTS]]

            route_candidates: List[Tuple[int, int, str, str]] = []
            for table_idx, (route_key, pattern, directive) in enumerate(ECOSYSTEM_ROUTING_HINTS):
                if not has_viable_token and "@\\[" not in pattern.pattern:
                    continue
                if not pattern.search(scan_text):
                    continue
                if route_key == "route:mcp:rea_rea":
                    mcp_rea_dir = Path.home() / ".gemini" / "antigravity" / "mcp" / "rea_rea"
                    if not _optional_plugin_skill_available(
                        "plugins/rea/skills/reverse-engineer-anything/SKILL.md", workspaces
                    ) and not mcp_rea_dir.is_dir():
                        continue
                route_aliases = _ROUTE_SLASH_ALIASES.get(route_key, ())
                explicit_route_slash = _has_explicit_slash_command(scan_text, route_aliases)
                if route_key == "route:subagent:meta-auditor" and re.search(
                    rf"{_SLASH_PRE}/audit\s+--(?:meta|self){_SLASH_POST}",
                    scan_text,
                    re.IGNORECASE,
                ):
                    explicit_route_slash = True
                if route_key in seen_turns:
                    if not is_new_user_turn:
                        continue
                    if not explicit_route_slash and (active_turn - seen_turns[route_key]) < REHINT_TURN_GAP:
                        continue
                priority = 2 if explicit_route_slash else 0
                route_candidates.append((-priority, table_idx, route_key, directive))
            route_candidates.sort(key=lambda item: (item[0], item[1]))
            matched_routes = [(rk, d) for _p, _i, rk, d in route_candidates[:MAX_HINTS]]

        new_keys |= {m[0] for m in matched} | {r[0] for r in matched_routes}
        for key in new_keys:
            seen_turns[key] = active_turn

        hints_persisted = True
        if new_keys or state_dirty:
            serialized: Dict[str, Any] = {k: seen_turns[k] for k in sorted(seen_turns)}
            serialized["__turn__"] = turn_num
            serialized["__last_sig__"] = last_sig
            # Bound ledger size to the 50 most recent conversations
            if conv_id in ledger:
                del ledger[conv_id]
            ledger[conv_id] = serialized
            while len(ledger) > 50:
                oldest = next(iter(ledger))
                del ledger[oldest]
            try:
                atomic_write_json(hints_file, ledger)
            except OSError:
                hints_persisted = False

        if pending_acks and hints_persisted:
            for ack_ws, ack_seq_val in pending_acks:
                _acknowledge_interrupted_flight(ack_ws, ack_seq_val)

        if not recovery_msgs and not matched and not matched_routes:
            return {}

    parts: List[str] = list(recovery_msgs)
    if matched:
        items = "; ".join(f"`{name}` ({rel} — {desc})" for name, rel, desc in matched)
        parts.append(
            f"[Harness Skill Hint] Relevant skill(s) for this request: {items}. "
            "Read the corresponding SKILL.md if it fits the task; set this hint aside if not applicable."
        )
    if matched_routes:
        routes = "; ".join(directive for _key, directive in matched_routes)
        parts.append(
            f"[Harness Ecosystem Routing] Relevant subagent(s) / MCP server(s): {routes}. "
            "Invoke or call them automatically when the task touches these boundaries."
        )
    return {"injectSteps": [{"ephemeralMessage": " ".join(parts)}]}


# ----------------------------------------------------------------------
# 2. PreToolUse: Governance Shield & Bash Guard
# ----------------------------------------------------------------------
_BROAD_RUNTIME_DOTDIR_SEAMS: Dict[str, Tuple[str, ...]] = {
    ".gemini": (
        ".gemini/GEMINI.md",
        ".gemini/AGENTS.md",
        ".gemini/rules",
        ".gemini/skills",
        ".gemini/agents",
        ".gemini/hooks.json",
        ".gemini/mcp_config.json",
    ),
    ".claude": ("CLAUDE.md", ".claude/agents", ".claude/commands", ".claude/skills"),
    ".codex": ("AGENTS.md", "CODEX.md", "CONVENTIONS.md", ".agents/skills", ".agents/rules"),
    ".cursor": (".cursorrules", ".cursor/rules", ".cursor/skills", ".cursor/agents"),
}


def _custom_enforced_governance_roots() -> List[Path]:
    """Loads custom `policy == 'enforced'` governance seams from `state_dir() / 'environments.json'`."""
    out: List[Path] = []
    env_file = state_dir() / "environments.json"
    if not env_file.is_file():
        return out
    data = read_json(env_file, default={})
    if not isinstance(data, dict):
        return out
    raw_envs = data.get("environments")
    if isinstance(raw_envs, list):
        entries = raw_envs
    elif isinstance(raw_envs, dict):
        entries = list(raw_envs.values())
    else:
        return out
    home_abs = Path(os.path.abspath(Path.home()))
    home_dot_gemini_abs = Path(os.path.abspath(home_abs / ".gemini"))

    def _append_custom_seam(candidate: Path) -> None:
        cand_abs = Path(os.path.abspath(candidate))
        # `$HOME` (or an ancestor) is never a workspace governance tree; `~/.gemini` holds
        # Antigravity's runtime `antigravity/brain` state while `~/.gemini/config` is protected globally.
        if cand_abs == home_abs or home_abs.is_relative_to(cand_abs):
            return
        if cand_abs == home_dot_gemini_abs:
            for rel in _BROAD_RUNTIME_DOTDIR_SEAMS[".gemini"]:
                narrowed = home_abs / rel
                if narrowed not in out:
                    out.append(narrowed)
            return
        if candidate not in out:
            out.append(candidate)

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("enabled", True) is False:
            continue
        if str(entry.get("policy") or "").strip().lower() != "enforced":
            continue
        env_id = str(entry.get("id") or "").strip().lower()
        if env_id == "antigravity":
            continue
        is_global_entry = entry.get("is_global") is True
        raw_root = entry.get("root_path")
        root_p = (
            Path(os.path.expanduser(raw_root.strip()))
            if isinstance(raw_root, str) and raw_root.strip()
            else None
        )
        gov_paths = entry.get("governance_paths")
        if root_p is not None and (not isinstance(gov_paths, list) or not gov_paths):
            _append_custom_seam(root_p)
        if isinstance(gov_paths, list):
            for gp in gov_paths:
                if isinstance(gp, str) and gp.strip():
                    gp_clean = gp.strip()
                    gp_norm = gp_clean.rstrip("/\\")
                    if not is_global_entry and gp_norm in _BROAD_RUNTIME_DOTDIR_SEAMS and root_p is not None:
                        for rel_seam in _BROAD_RUNTIME_DOTDIR_SEAMS[gp_norm]:
                            _append_custom_seam(root_p / rel_seam)
                        continue
                    gp_path = Path(os.path.expanduser(gp_clean))
                    if not gp_path.is_absolute() and root_p is not None:
                        gp_path = root_p / gp_path
                    _append_custom_seam(gp_path)
    return out


def _config_root_candidates() -> List[Path]:
    out: List[Path] = []
    for cand in (
        configured_config_dir(),
        config_dir(),
        Path(os.path.abspath(Path.home() / ".gemini" / "config")),
    ):
        if cand not in out:
            out.append(cand)
    return out


def _state_root_candidates() -> List[Path]:
    home = Path.home()
    out: List[Path] = []
    for cand in (
        state_dir(),
        Path(os.path.abspath(home / ".local" / "state" / "antigravity-harness")),
        Path(os.path.abspath(home / ".local" / "state" / "antigravity-guard")),
    ):
        if cand not in out:
            out.append(cand)
    return out


def _governance_roots() -> List[Path]:
    roots: List[Path] = []
    home = Path.home()
    candidates: List[Path] = [
        *_config_root_candidates(),
        *_state_root_candidates(),
        data_dir(),
        data_dir() / "runtime",
        data_dir() / "snapshots",
        home / ".local" / "bin" / "agy-guard",
        home / ".local" / "bin" / "agy-porter",
    ]
    porter_bin = home / ".local" / "bin" / "porter"
    try:
        if not porter_bin.exists():
            candidates.append(porter_bin)
        elif porter_bin.is_file():
            porter_head = porter_bin.read_text(encoding="utf-8", errors="ignore")[:512].lower()
            if "antigravity-harness launcher" in porter_head or "antigravity harness cli launcher" in porter_head:
                candidates.append(porter_bin)
    except OSError:
        candidates.append(porter_bin)
    if os.name == "nt":
        local_app = Path(os.environ.get("LOCALAPPDATA") or (home / "AppData" / "Local"))
        candidates.append(local_app / "Programs" / "antigravity-guard")
    else:
        candidates.extend([
            Path("/usr/bin/agy-guard"),
            Path("/usr/bin/agy-porter"),
            Path("/usr/lib/antigravity-guard"),
            Path("/usr/share/antigravity-harness"),
        ])
    candidates.extend(_custom_enforced_governance_roots())
    for candidate in candidates:
        if candidate not in roots:
            roots.append(candidate)
    return roots


_RUNTIME_CONFIG_SUBDIRS = ("plugins", "sidecars", "projects", "cache")
_PLUGIN_GOVERNANCE_SEGMENTS = frozenset({
    "skills",
    "agents",
    "rules",
    "hooks",
    "scripts",
    "bin",
    "hooks.json",
    "mcp_config.json",
    ".mcp.json",
})
_PLUGIN_EXEC_SUFFIXES = (
    ".md",
    ".mdc",
    ".py",
    ".pyc",
    ".pyo",
    ".pyw",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ksh",
    ".pl",
    ".rb",
    ".php",
    ".ps1",
    ".bat",
    ".cmd",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".wasm",
)


def _is_plugin_governance_path(candidate: Path, plugin_root: Path) -> bool:
    rel_part_sets: List[Tuple[str, ...]] = []
    try:
        rel_part_sets.append(candidate.relative_to(plugin_root).parts)
    except ValueError:
        pass
    try:
        rel_part_sets.append(candidate.resolve().relative_to(plugin_root.resolve()).parts)
    except (OSError, RuntimeError, ValueError):
        pass
    for rel_parts in rel_part_sets:
        if any(part.lower() in _PLUGIN_GOVERNANCE_SEGMENTS for part in rel_parts):
            return True
        if rel_parts and rel_parts[-1].lower().endswith(_PLUGIN_EXEC_SUFFIXES):
            return True
    return False


def _is_runtime_config_subdir(candidate: Path, root: Path) -> bool:
    if root in _state_root_candidates():
        staging_path = root / "staging"
        within_staging = is_within(candidate, staging_path)
        if not within_staging:
            return False
        try:
            resolved_cand = candidate.resolve()
            resolved_staging = staging_path.resolve()
            resolved_within = is_within(resolved_cand, resolved_staging)
        except (OSError, RuntimeError, ValueError):
            return False
        return bool(within_staging and resolved_within)

    if root not in _config_root_candidates():
        return False
    for sub in _RUNTIME_CONFIG_SUBDIRS:
        sub_path = root / sub
        within = is_within(candidate, sub_path)
        if not within:
            continue
        try:
            resolved_cand = candidate.resolve()
            resolved_sub = sub_path.resolve()
            resolved_within = is_within(resolved_cand, resolved_sub)
        except (OSError, RuntimeError, ValueError):
            return False
        if not resolved_within:
            return False
        if sub == "plugins" and _is_plugin_governance_path(candidate, sub_path):
            return False
        return True
    return False


def _targets_governance_dir(target_path_str: str, base_dir: Optional[Path] = None) -> bool:
    if not target_path_str:
        return False
    cleaned = target_path_str.split("\x00", 1)[0].strip()
    if not cleaned:
        return False
    expanded = Path(os.path.expanduser(cleaned))
    if not expanded.is_absolute() and base_dir is not None:
        expanded = base_dir / expanded
    if any(
        _is_runtime_config_subdir(expanded, rt_root)
        for rt_root in (*_config_root_candidates(), *_state_root_candidates())
    ):
        return False
    for root in _governance_roots():
        if _is_runtime_config_subdir(expanded, root):
            continue
        if is_within(expanded, root):
            return True
        try:
            if is_within(expanded.resolve(), root.resolve()):
                return True
        except (OSError, RuntimeError, ValueError):
            pass
    return False


def _normalize_shell_paths(cmd: str) -> str:
    """Normalizes duplicate slashes, current-directory `.` segments, and parent-directory `..` segments inside shell command text."""
    norm = cmd.replace("${HOME}", "$HOME")
    norm = re.sub(r"(?<!:)/{2,}", "/", norm)
    for _ in range(16):
        collapsed_dot = re.sub(r"/\.(?=/|\s|$|[;&|'\"()])", "", norm)
        if collapsed_dot == norm:
            break
        norm = collapsed_dot
    for _ in range(32):
        collapsed = re.sub(
            r"/(?!\.\.?(?:/|\s|$|[;&|'\"()]))[^/\s;|&'\"()]+/\.\.(?=/|\s|$|[;&|'\"()])",
            "",
            norm,
        )
        if collapsed == norm:
            break
        norm = collapsed
    norm = re.sub(r"(?<!:)/{2,}", "/", norm)
    return norm


_SIMPLE_VAR_ASSIGN_RE = re.compile(
    r"(?:^|[;&|()\n\s])([A-Za-z_][A-Za-z0-9_]*)=(?:'([^']*)'|\"([^\"\\]*)\"|([^\s;|&'\"()]+))"
)


def _expand_simple_shell_vars(cmd: str) -> str:
    """Expands simple shell variable assignments (`D=...; ... "$D/..."`) within a command string."""
    var_map: Dict[str, str] = {}
    for m in _SIMPLE_VAR_ASSIGN_RE.finditer(cmd):
        name = m.group(1)
        if name in ("HOME", "PATH", "PWD", "OLDPWD", "IFS"):
            continue
        val = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else (m.group(4) or ""))
        if val:
            var_map[name] = val
    if not var_map:
        return cmd
    expanded = cmd
    for _ in range(4):
        prev = expanded
        for name, val in var_map.items():
            expanded = re.sub(rf"\$\{{{re.escape(name)}\}}|\${re.escape(name)}(?![A-Za-z0-9_])", lambda _m, v=val: v, expanded)
        if expanded == prev:
            break
    return expanded


def _normalize_governance_globs(cmd: str) -> str:
    """Canonicalizes wildcard-obfuscated governance path prefixes (`~/.gem*/config`, `~/.local/bin/agy-*`)."""
    out = re.sub(r"(?:~|\$HOME)/\.gem[^\s;|&'\"/]*/conf[^\s;|&'\"/]*", "~/.gemini/config", cmd)
    out = re.sub(
        r"(?:~|\$HOME)/\.local/(state|share)/antigravity-[^\s;|&'\"/]*",
        r"~/.local/\1/antigravity-harness",
        out,
    )
    out = re.sub(r"(?:~|\$HOME)/\.local/bin/agy-[^\s;|&'\"/]*", "~/.local/bin/agy-guard", out)
    out = re.sub(r"(?:~|\$HOME)/\.local/bin/por\?ter|(?:~|\$HOME)/\.local/bin/por\*[^\s;|&'\"/]*", "~/.local/bin/porter", out)
    return out


_SHELL_MUTATION_INDICATOR_RE = re.compile(
    r"(?:"
    r">{1,2}\|?|"
    r"\b(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip)\b|"
    r"\bfind\b[^\n;|&]*\s-(?:delete|exec|execdir|ok)\b|"
    r"\bsed\b[^\n;|&]*\s-(?:[A-Za-z]*i\S*|-in-place(?:=\S*)?)\b|"
    r"\b(?:curl|wget)\b[^\n;|&]*\s-(?:o|O)\b|"
    r"\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*(?:\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*)\b|<<)"
    r")"
)
_SHELL_DOTDOT_TOKEN_RE = re.compile(r"(?:^|[\s/'\"=])\.\.(?:$|[\s/'\";&|()])")


def _command_mutates_governance(cmd: str) -> bool:
    """Detects shell commands that write, copy, move, delete, or chmod inside protected governance or Guard state/runtime trees."""
    unquoted_expanded = _normalize_governance_globs(_unquote_single_tokens(_expand_simple_shell_vars(cmd)))
    norm_cmd = _normalize_shell_paths(unquoted_expanded)
    has_dotdot_escape = bool(_SHELL_DOTDOT_TOKEN_RE.search(norm_cmd))

    # Catch inline/heredoc/piped interpreter scripts constructing home-relative governance paths (`Path.home() / '.gemini' / 'config'`)
    if re.search(
        r"(?:\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*(?:\s-(?:[A-Za-z0-9]*c|e)\b|<<)|\|\s*(?:[A-Za-z0-9_./-]*\s+)*(?:python3?(?:\.\d+)?|node|ruby|perl)\b)",
        cmd,
    ):
        inline_cmd = cmd
        if not has_dotdot_escape and "symlink" not in cmd:
            inline_cmd = re.sub(
                r"(?:['\"]\.local['\"]\s*/\s*['\"]state['\"]\s*/\s*['\"]antigravity-(?:harness|guard)['\"]\s*/\s*['\"]staging['\"]|"
                rf"(?:~|\$HOME|{re.escape(str(state_dir()))}|[^\s'\"/]+/\.local/state)/antigravity-(?:harness|guard)/staging(?=/|['\"\s,)]))",
                "__RUNTIME_STAGING__",
                inline_cmd,
            )
        if re.search(
            r"(?:['\"]\.gemini['\"]\s*/\s*['\"]config['\"]|\.gemini/config|antigravity-(?:harness|guard)|['\"]\.local['\"]\s*/\s*['\"]bin['\"]\s*/\s*['\"]agy-|\.local/bin/agy-)",
            inline_cmd,
        ) and re.search(
            r"(?:write_text|write_bytes|\.write\s*\(|\bopen\s*\([^)]*['\"][wa+x]|unlink|remove|rmtree|rename|replace|chmod|symlink|shutil\.(?:copy|move|rmtree))",
            cmd,
        ):
            return True

    home = Path.home()
    cfg_roots = list(
        dict.fromkeys(
            [*(str(p) for p in _config_root_candidates()), "~/.gemini/config", "$HOME/.gemini/config"]
        )
    )
    state_roots = list(
        dict.fromkeys(
            [
                *(str(p) for p in _state_root_candidates()),
                "~/.local/state/antigravity-harness",
                "$HOME/.local/state/antigravity-harness",
                "~/.local/state/antigravity-guard",
                "$HOME/.local/state/antigravity-guard",
            ]
        )
    )
    custom_root_tokens: List[str] = []
    for c_root in _custom_enforced_governance_roots():
        custom_root_tokens.append(str(c_root))
        try:
            rel_home = c_root.relative_to(home).as_posix()
            if rel_home and rel_home != ".":
                custom_root_tokens.append(f"~/{rel_home}")
                custom_root_tokens.append(f"$HOME/{rel_home}")
        except ValueError:
            pass
    guard_roots = list(
        dict.fromkeys(
            state_roots
            + [
                str(data_dir()),
                str(data_dir() / "runtime"),
                str(data_dir() / "snapshots"),
                "~/.local/share/antigravity-harness",
                "$HOME/.local/share/antigravity-harness",
                "~/.local/share/antigravity-guard",
                "$HOME/.local/share/antigravity-guard",
                str(home / ".local" / "bin" / "agy-guard"),
                str(home / ".local" / "bin" / "agy-porter"),
                "~/.local/bin/agy-guard",
                "$HOME/.local/bin/agy-guard",
                "~/.local/bin/agy-porter",
                "$HOME/.local/bin/agy-porter",
                "/usr/bin/agy-guard",
                "/usr/bin/agy-porter",
                "/usr/lib/antigravity-guard",
                "/usr/share/antigravity-harness",
                *(
                    [
                        str(home / ".local" / "bin" / "porter"),
                        "~/.local/bin/porter",
                        "$HOME/.local/bin/porter",
                    ]
                    if (home / ".local" / "bin" / "porter") in _governance_roots()
                    else []
                ),
                *custom_root_tokens,
            ]
        )
    )
    roots = list(dict.fromkeys(cfg_roots + guard_roots))
    if not any(tok in norm_cmd for tok in roots):
        return False
    # Strip references to non-governance runtime subdirectories under ~/.gemini/config
    # ONLY when no `..` traversal, link creation (`ln`), or archive extraction (`tar`/`unzip`) is present.
    scrubbed = norm_cmd
    has_dotdot_escape = bool(_SHELL_DOTDOT_TOKEN_RE.search(norm_cmd))
    if not has_dotdot_escape and not re.search(r"\b(?:ln|tar|unzip)\b", scrubbed):
        for root in cfg_roots:
            esc_root = re.escape(root)
            for sub in _RUNTIME_CONFIG_SUBDIRS:
                if sub == "plugins":
                    scrubbed = re.sub(
                        rf"{esc_root}/plugins(?=/|\s|$|[;&|'\"()])(?![^\s;|&'\"]*(?:/(?:skills|agents|rules|hooks|scripts|bin|hooks\.json|mcp_config\.json|\.mcp\.json)\b|\.(?:mdc?|py[cow]?|m?js|cjs|tsx?|jsx|sh|bash|zsh|fish|ksh|pl|rb|php|ps1|bat|cmd|so|dylib|dll|exe|wasm)\b))",
                        "__RUNTIME_SUBDIR__",
                        scrubbed,
                        flags=re.IGNORECASE,
                    )
                else:
                    scrubbed = re.sub(
                        rf"{esc_root}/{re.escape(sub)}(?=/|\s|$|[;&|'\"()])",
                        "__RUNTIME_SUBDIR__",
                        scrubbed,
                    )
        for st_root in state_roots:
            esc_st = re.escape(st_root)
            scrubbed = re.sub(
                rf"{esc_st}/staging(?=/|\s|$|[;&|'\"()])",
                "__RUNTIME_SUBDIR__",
                scrubbed,
            )
    if not any(tok in scrubbed for tok in roots):
        return False
    # Read-only commands are permitted only when not redirecting or running mutating flags/interpreters
    for root in roots:
        escaped = re.escape(root)
        if re.search(rf">{{1,2}}\|?\s*['\"]?{escaped}", scrubbed):
            return True
        if re.search(rf"\b(?:cd|pushd)\s+['\"]?{escaped}", scrubbed) and _SHELL_MUTATION_INDICATOR_RE.search(scrubbed):
            return True
        if re.search(
            rf"\b(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip)\b[^\n;|&]*{escaped}",
            scrubbed,
        ):
            return True
        if re.search(
            rf"{escaped}[^\n;&]*\|\s*(?:{_CMD_WRAPPER_PREFIX})*xargs\b[^\n;&]*\b(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip|sed|python3?(?:\.\d+)?|node|ruby|perl|(?:ba|z|da|k)?sh)\b",
            scrubbed,
        ):
            return True
        if re.search(rf"\bfind\b[^\n;|&]*{escaped}[^\n;|&]*\s-(?:delete|exec|execdir|ok)\b", scrubbed):
            return True
        if re.search(
            rf"\bsed\b[^\n;|&]*(?:\s-(?:[A-Za-z]*i\S*|-in-place(?:=\S*)?)\b[^\n;|&]*{escaped}|{escaped}[^\n;|&]*\s-(?:[A-Za-z]*i\S*|-in-place(?:=\S*)?)\b)",
            scrubbed,
        ):
            return True
        if re.search(rf"\b(?:curl|wget)\b[^\n;|&]*\s-(?:o|O)\b[^\n;|&]*{escaped}", scrubbed):
            return True
        if re.search(
            rf"(?:\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*)\b[^\n;|&]*{escaped}|{escaped}[^\n;|&]*\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*)\b)",
            scrubbed,
        ):
            return True
        if re.search(r"\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*<<", scrubbed) and re.search(
            r"(?:write|open\s*\(|unlink|remove|rmtree|rename|replace|chmod|symlink|shutil|fs\.)",
            scrubbed,
        ):
            return True
    return False


_CUSTOMIZATION_BASENAMES = frozenset({
    "gemini.md",
    "agents.md",
    "claude.md",
    "design.md",
    "hooks.json",
    "mcp_config.json",
    "skills.json",
    "plugins.json",
    ".cursorrules",
    "skill.md",
})

_CUSTOMIZATION_DIR_SEGMENTS = frozenset({
    ".agents",
    ".agent",
    "_agents",
    "_agent",
    ".claude",
    ".cursor",
    ".harness",
})

_HARNESS_SOURCE_TOP_DIRS = frozenset({
    "skills",
    "agents",
    "guard",
    "porter",
    "templates",
    ".harness",
})

_HARNESS_SOURCE_FILES = frozenset({
    "gemini.md",
    "agents.md",
    "design.md",
    "hooks.json",
    "guard.py",
    "porter.py",
    "install.py",
    "scripts/meta_audit.py",
    "scripts/verify_invariants.py",
})

_ALLOWED_TOP_EFFORT_VALUES = frozenset({
    "high",
    "max",
    "maximum",
    "1",
    "1.0",
    "1.00",
    "100%",
})

_SETTINGS_MODEL_RE = re.compile(
    r"changed\s+setting\s+`?Model\s+Selection`?\s+from\s+[^\n]+?\s+to\s+([^\n]+?)\.(?=\s|$)",
    re.IGNORECASE,
)
_SETTINGS_EFFORT_RE = re.compile(
    r"changed\s+setting\s+`?(?:Effort(?:\s+Level)?|Thinking\s+Level|Reasoning\s+Effort)`?\s+from\s+[^\n]+?\s+to\s+([^\n]+?)\.(?=\s|$)",
    re.IGNORECASE,
)
_SETTINGS_KV_MODEL_RE = re.compile(
    r"(?:^|[\n,{])\s*['\"`]?(?:modelName|model_name|model|Model\s+Selection)['\"`]?\s*:\s*['\"`]?([^\n,\"'`\}]+)",
    re.IGNORECASE,
)
_SETTINGS_KV_EFFORT_RE = re.compile(
    r"(?:^|[\n,{])\s*['\"`]?(?:effort|effortLevel|effort_level|thinkingLevel|thinking_level|reasoningEffort|Effort(?:\s+Level)?)['\"`]?\s*:\s*['\"`]?([A-Za-z0-9.%_-]+)",
    re.IGNORECASE,
)
_MODEL_EMBEDDED_EFFORT_RE = re.compile(
    r"(?:\(\s*(high|max|maximum|medium|med|low|minimal|min)\s*\)\s*$|"
    r"-(high|max|maximum|medium|low|minimal)$)",
    re.IGNORECASE,
)
_USER_REQUEST_BLOCK_RE = re.compile(r"(?is)<USER_REQUEST\b[^<>]*>.*?</USER_REQUEST\s*>")
_USER_SETTINGS_BLOCK_RE = re.compile(r"(?is)<USER_SETTINGS_CHANGE\b[^<>]*>(.*?)</USER_SETTINGS_CHANGE\s*>")

_CUST_CMD_TARGET_PAT = (
    r"(?:\.agents?\b|_agents?\b|\.claude\b|\.cursor\b|\.harness\b|"
    r"(?:^|[\s'\"=/])(?:skills|agents|guard|porter|templates)(?:/|\b)|"
    r"GEMINI\.md\b|AGENTS\.md\b|CLAUDE\.md\b|DESIGN\.md\b|hooks\.json\b|"
    r"mcp_config\.json\b|skills\.json\b|plugins\.json\b|\.cursorrules\b|"
    r"SKILL\.md\b|[A-Za-z0-9_.-]+\.mdc\b|"
    r"guard\.py\b|porter\.py\b|install\.py\b|scripts/meta_audit\.py\b|scripts/verify_invariants\.py\b)"
)

_READONLY_SUBAGENT_TYPES = frozenset({
    "research",
    "meta-auditor",
    "consistency-auditor",
    "specification-gap-auditor",
    "security-boundary-verifier",
    "silent-failure-hunter",
    "contract-change-auditor",
    "test-adequacy-auditor",
    "build-error-resolver",
})


def _normalize_model_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9.]+", "-", (name or "").lower()).strip("-")


def _catalog_top_model_spec() -> Tuple[str, set[str]]:
    """
    Loads the authoritative top catalog model and high-effort slug from
    `skills/upstream-auditor/upstream_state.seed.json`, plus operator-approved peer
    flagship slugs listed in its `approved_customization_models` array and any
    operator-acknowledged high/max flagship slug in `upstream_state.json`.
    """
    top_name = "Gemini 4 Argon (High)"
    top_slug = "gemini-4-argon-high"
    peer_slugs: set[str] = set()
    seed_candidates = [
        REPO_ROOT / "skills" / "upstream-auditor" / "upstream_state.seed.json",
        configured_config_dir() / "skills" / "upstream-auditor" / "upstream_state.seed.json",
        config_dir() / "skills" / "upstream-auditor" / "upstream_state.seed.json",
        Path("/usr/share/antigravity-harness") / "skills" / "upstream-auditor" / "upstream_state.seed.json",
    ]
    for candidate in seed_candidates:
        if candidate.is_file():
            data = read_json(candidate, default={})
            if isinstance(data, dict) and data:
                raw_name = str(data.get("last_audited_model") or "").strip()
                raw_slug = _normalize_model_slug(str(data.get("last_model_slug") or raw_name))
                if not (raw_name or raw_slug):
                    continue
                if raw_name:
                    top_name = raw_name
                if raw_slug:
                    top_slug = raw_slug
                approved_peers = data.get("approved_customization_models")
                if isinstance(approved_peers, list):
                    for peer in approved_peers:
                        if not isinstance(peer, str):
                            continue
                        peer_slug = _normalize_model_slug(peer)
                        # Only highest-effort flagship slugs may widen the gate (GEMINI.md Rule 17).
                        if peer_slug.endswith(("-high", "-max", "-maximum")):
                            peer_slugs.add(peer_slug)
                break

    allowed = {top_slug} | peer_slugs
    state_candidates = [
        state_dir() / "upstream_state.json",
        Path.home() / ".local" / "state" / "antigravity-harness" / "upstream_state.json",
    ]
    for st_path in state_candidates:
        if st_path.is_file():
            st_data = read_json(st_path, default={})
            if isinstance(st_data, dict):
                acked_slug = _normalize_model_slug(
                    str(st_data.get("last_model_slug") or st_data.get("last_audited_model") or "")
                )
                if acked_slug and acked_slug.endswith(("-high", "-max", "-maximum")):
                    allowed.add(acked_slug)
    return top_name, allowed


def _infer_effort_from_model_label(model_label: str) -> str:
    if not model_label:
        return ""
    m = _MODEL_EMBEDDED_EFFORT_RE.search(model_label.strip())
    if m:
        return (m.group(1) or m.group(2) or "").strip().lower()
    slug = _normalize_model_slug(model_label)
    for suffix in ("high", "max", "maximum", "medium", "low", "minimal"):
        if slug.endswith(f"-{suffix}"):
            return suffix
    return ""


def _extract_transcript_model_and_effort(payload: Dict[str, Any]) -> Tuple[str, str]:
    transcript = payload.get("transcriptPath") or payload.get("transcript_path")
    if not isinstance(transcript, str) or not transcript.strip():
        return "", ""
    path = Path(transcript).expanduser()
    found_model = ""
    found_effort = ""
    try:
        if path.is_symlink() or not path.is_file():
            return "", ""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(path), flags)
        with os.fdopen(fd, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            chunk_size = 131072
            min_offset = max(0, size - 16 * 1024 * 1024)
            pos = size
            carry = b""
            while pos > min_offset:
                read_start = max(min_offset, pos - chunk_size)
                to_read = pos - read_start
                f.seek(read_start, os.SEEK_SET)
                buf = f.read(to_read) + carry
                pos = read_start
                if pos > min_offset:
                    nl_idx = buf.find(b"\n")
                    if nl_idx == -1:
                        carry = buf if len(buf) <= 2 * 1024 * 1024 else b""
                        continue
                    carry = buf[:nl_idx]
                    complete_bytes = buf[nl_idx + 1 :]
                else:
                    complete_bytes = buf
                    carry = b""

                lines = complete_bytes.decode("utf-8", errors="replace").splitlines()
                for raw in reversed(lines):
                    raw = raw.strip()
                    if not raw.startswith("{"):
                        continue
                    try:
                        entry = json.loads(raw)
                    except ValueError:
                        continue
                    if not isinstance(entry, dict):
                        continue
                    step_type = str(entry.get("type", "")).upper()
                    source = str(entry.get("source", "")).upper()
                    is_user_entry = (
                        step_type == "USER_INPUT" and source in ("", "USER_EXPLICIT")
                    ) or (not step_type and source == "USER_EXPLICIT")
                    if not is_user_entry:
                        continue
                    content = str(entry.get("content") or "")
                    if "USER_SETTINGS_CHANGE" not in content.upper():
                        continue
                    cleaned_content = _USER_REQUEST_BLOCK_RE.sub(
                        " ",
                        _INLINE_TAG_CODE_RE.sub(
                            " ",
                            _FENCE_RE.sub(" ", _PASTED_RE.sub(" ", content)),
                        ),
                    )
                    blocks = _USER_SETTINGS_BLOCK_RE.findall(cleaned_content)
                    for block in reversed(blocks):
                        if not found_effort:
                            eff_matches = _SETTINGS_EFFORT_RE.findall(block) or _SETTINGS_KV_EFFORT_RE.findall(block)
                            if eff_matches:
                                found_effort = eff_matches[-1].strip()
                        if not found_model:
                            mod_matches = _SETTINGS_MODEL_RE.findall(block) or _SETTINGS_KV_MODEL_RE.findall(block)
                            if mod_matches:
                                found_model = mod_matches[-1].strip()
                                if not found_effort:
                                    found_effort = _infer_effort_from_model_label(found_model)
                        if found_model and found_effort:
                            return found_model, found_effort
    except OSError:
        pass
    return found_model, found_effort


def _extract_transcript_model_setting(payload: Dict[str, Any]) -> str:
    return _extract_transcript_model_and_effort(payload)[0]


def _is_harness_repo_root(root: Path) -> bool:
    return (root / ".harness" / "manifest.json").is_file() or (root / "guard" / "agy_hooks.py").is_file()


def _targets_customization_structure(target_path_str: str, workspace: Optional[Path] = None) -> bool:
    """
    Returns True when `target_path_str` points to a customization or harness governance
    artifact (`.agents/`, `.claude/`, `.cursor/`, `.harness/`, `GEMINI.md`, `AGENTS.md`,
    `DESIGN.md`, `hooks.json`, `SKILL.md`, `.mdc`, or harness source `skills/`, `agents/`,
    `guard/`, `porter/`, `porter.py`, `install.py`, `scripts/meta_audit.py`).
    """
    if not target_path_str or not target_path_str.strip():
        return False
    raw = os.path.expanduser(target_path_str.strip()).replace("\\", "/")
    collapsed = _normalize_shell_paths(raw if raw.startswith("/") else f"/{raw}")
    norm = re.sub(r"^/+", "", collapsed) if not raw.startswith("/") else collapsed
    norm = re.sub(r"^\./+", "", norm)
    parts = [p for p in norm.split("/") if p and p != "."]
    if not parts:
        return False

    basename_lower = parts[-1].lower()
    if basename_lower in _CUSTOMIZATION_BASENAMES or basename_lower.endswith(".mdc"):
        return True
    if any(p.lower() in _CUSTOMIZATION_DIR_SEGMENTS for p in parts):
        return True

    # Relative path inside the active workspace (or REPO_ROOT when workspace is unspecified)
    effective_ws = workspace if workspace is not None else REPO_ROOT
    is_harness_ws = _is_harness_repo_root(effective_ws)
    if not raw.startswith("/"):
        if is_harness_ws and (parts[0].lower() in _HARNESS_SOURCE_TOP_DIRS or norm.lower() in _HARNESS_SOURCE_FILES):
            return True
        if parts[0].lower() in ("skills", "agents"):
            return True

    expanded = Path(os.path.expanduser(target_path_str.strip()))
    roots: List[Path] = [effective_ws]
    if REPO_ROOT not in roots:
        roots.append(REPO_ROOT)
    for root in roots:
        if root is None:
            continue
        candidate = (effective_ws / expanded) if not expanded.is_absolute() else expanded
        try:
            rel = candidate.resolve().relative_to(root.resolve())
        except (OSError, RuntimeError, ValueError):
            continue
        rel_norm = str(rel).replace("\\", "/").lower()
        rel_parts = [p.lower() for p in rel.parts if p]
        if not rel_parts:
            continue
        if rel_parts[-1] in _CUSTOMIZATION_BASENAMES or rel_parts[-1].endswith(".mdc"):
            return True
        if any(p in _CUSTOMIZATION_DIR_SEGMENTS for p in rel_parts):
            return True
        if _is_harness_repo_root(root) and (
            rel_norm in _HARNESS_SOURCE_FILES or rel_parts[0] in _HARNESS_SOURCE_TOP_DIRS
        ):
            return True
    return False


def _command_mutates_customization_structure(cmd: str) -> bool:
    """Detects shell commands that write, overwrite, move, delete, or regenerate customization/governance files."""
    norm_cmd = _normalize_shell_paths(_unquote_single_tokens(_expand_simple_shell_vars(cmd)))
    masked_cmd = _mask_quoted_operators(norm_cmd)
    has_subshell_c = bool(re.search(r"\b(?:ba|z|da|k)?sh\s+-(?:[A-Za-z]*c)\b", norm_cmd))
    verb_haystack = norm_cmd if has_subshell_c else masked_cmd
    cmd_start = (
        r"(?:^|[;&|()\n])\s*"
        rf"{_CMD_WRAPPER_PREFIX}"
        r"(?:(?:ba|z|da|k)?sh\s+-(?:[A-Za-z]*c)\s+['\"]?\s*)*"
    )

    if re.search(rf">{{1,2}}\|?\s*['\"]?[^\s;|&'\"]*{_CUST_CMD_TARGET_PAT}", norm_cmd):
        return True
    if re.search(
        rf"\b(?:cd|pushd)\s+(?:['\"]?(?:skills|agents|guard|porter|templates)(?:/|\b)|['\"]?[^\s;|&'\"]*{_CUST_CMD_TARGET_PAT})",
        norm_cmd,
    ) and _SHELL_MUTATION_INDICATOR_RE.search(norm_cmd):
        return True
    if re.search(
        rf"{cmd_start}(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip)\b[^\n;|&]*{_CUST_CMD_TARGET_PAT}",
        verb_haystack,
    ):
        return True
    if re.search(
        rf"{_CUST_CMD_TARGET_PAT}[^\n;&]*\|\s*(?:{_CMD_WRAPPER_PREFIX})*xargs\b[^\n;&]*\b(?:rm|mv|cp|chmod|chattr|chown|tee|touch|mkdir|rmdir|ln|install|rsync|tar|dd|truncate|shred|patch|unzip|sed)\b",
        norm_cmd,
    ):
        return True
    if re.search(rf"{cmd_start}find\b[^\n;|&]*{_CUST_CMD_TARGET_PAT}[^\n;|&]*\s-(?:delete|exec|execdir|ok)\b", norm_cmd):
        return True
    if re.search(
        rf"{cmd_start}sed\b[^\n;|&]*(?:\s-(?:[A-Za-z]*i\S*|-in-place(?:=\S*)?)\b[^\n;|&]*{_CUST_CMD_TARGET_PAT}|{_CUST_CMD_TARGET_PAT}[^\n;|&]*\s-(?:[A-Za-z]*i\S*|-in-place(?:=\S*)?)\b)",
        norm_cmd,
    ):
        return True
    if re.search(rf"{cmd_start}(?:curl|wget)\b[^\n;|&]*\s-(?:o|O)\b[^\n;|&]*{_CUST_CMD_TARGET_PAT}", norm_cmd):
        return True
    if re.search(
        rf"(?:\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*)\b[^\n;|&]*{_CUST_CMD_TARGET_PAT}|{_CUST_CMD_TARGET_PAT}[^\n;|&]*\b(?:python3?(?:\.\d+)?|node|ruby|perl)\b[^\n;|&]*\s-(?:[A-Za-z0-9]*c|e|i\S*|p[ie]\S*)\b)",
        norm_cmd,
    ):
        return True
    if re.search(r"\bporter\.py\s+manifest\b(?![^\n;|&]*--check)", norm_cmd):
        return True
    return False


def _evaluate_customization_model_and_effort(payload: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """
    Evaluates Rule 17 top-catalog model and highest-effort requirements for customization writes.
    Returns `("deny", reason)` on downgraded/malformed model or effort, `("force_ask", reason)`
    when model/effort metadata is absent from both payload and transcript, or `None` when compliant.
    """
    model_keys = ("modelName", "model_name", "model", "selectedModel", "selected_model", "activeModel", "active_model")
    effort_keys = (
        "effort",
        "effortLevel",
        "effort_level",
        "thinkingLevel",
        "thinking_level",
        "reasoningEffort",
        "reasoning_effort",
    )
    containers: List[Dict[str, Any]] = [payload]
    for sub_k in ("settings", "modelConfig", "model_config"):
        sub_v = payload.get(sub_k)
        if isinstance(sub_v, dict):
            containers.append(sub_v)

    top_name, allowed_slugs = _catalog_top_model_spec()
    has_model_key = False
    raw_model = ""
    for container in containers:
        for k in model_keys:
            if k in container:
                has_model_key = True
                val = container.get(k)
                if val is not None and not isinstance(val, str):
                    return (
                        "deny",
                        "[Harness Customization Model Gate] Malformed non-string model identifier in hook payload (GEMINI.md Rule 17).",
                    )
                if isinstance(val, str) and val.strip() and not raw_model:
                    raw_model = val.strip()

    has_effort_key = False
    raw_effort = ""
    for container in containers:
        for k in effort_keys:
            if k in container:
                has_effort_key = True
                val = container.get(k)
                if isinstance(val, bool) or (val is not None and not isinstance(val, (str, int, float))):
                    return (
                        "deny",
                        "[Harness Customization Model Gate] Malformed effort value in hook payload (GEMINI.md Rule 17).",
                    )
                if val is not None and str(val).strip() and not raw_effort:
                    raw_effort = str(val).strip()

    transcript_model, transcript_effort = _extract_transcript_model_and_effort(payload)

    if not has_model_key and not has_effort_key and not transcript_model and not transcript_effort:
        return (
            "force_ask",
            (
                "[Harness Customization Model Gate] Active model and effort metadata are unavailable in the hook "
                f"payload; human confirmation is required to verify `{top_name}` (`High`/`Max` effort) before "
                "modifying customization or governance files (GEMINI.md Rule 17)."
            ),
        )

    # Latest <USER_SETTINGS_CHANGE> in transcript is authoritative over "auto" or stale session-start payload fields.
    effective_model = transcript_model if transcript_model else raw_model
    effective_effort = transcript_effort if transcript_effort else raw_effort

    if has_model_key or transcript_model:
        eff_slug = _normalize_model_slug(effective_model)
        if eff_slug.endswith("-maximum"):
            eff_slug_alt = eff_slug[: -len("-maximum")] + "-max"
        elif eff_slug.endswith("-max"):
            eff_slug_alt = eff_slug[: -len("-max")] + "-maximum"
        else:
            eff_slug_alt = ""
        combined_top_slug = (
            any(f"{eff_slug}-{sfx}" in allowed_slugs for sfx in ("high", "max", "maximum"))
            and effective_effort.lower() in _ALLOWED_TOP_EFFORT_VALUES
        )
        if (
            not eff_slug
            or eff_slug == "auto"
            or (
                eff_slug not in allowed_slugs
                and (not eff_slug_alt or eff_slug_alt not in allowed_slugs)
                and not combined_top_slug
            )
        ):
            return (
                "deny",
                (
                    "[Harness Customization Model Gate] Modifying customization or governance architecture "
                    f"requires the catalog's top model and highest effort (`{top_name}` / approved: `{', '.join(sorted(allowed_slugs))}`); "
                    f"active model is `{effective_model or 'auto'}` (GEMINI.md Rule 17)."
                ),
            )

    if has_effort_key or transcript_effort:
        if effective_effort.lower() not in _ALLOWED_TOP_EFFORT_VALUES:
            return (
                "deny",
                (
                    "[Harness Customization Model Gate] Modifying customization or governance architecture "
                    f"requires the highest effort level (`High` / `Max`) on `{top_name}`; "
                    f"active effort is `{effective_effort}` (GEMINI.md Rule 17)."
                ),
            )

    if not (has_model_key or transcript_model):
        return (
            "force_ask",
            (
                "[Harness Customization Model Gate] Active model metadata is unavailable in the hook payload; "
                f"human confirmation is required to verify `{top_name}` before modifying customization or "
                "governance files (GEMINI.md Rule 17)."
            ),
        )

    return None


def _check_customization_model_and_effort(payload: Dict[str, Any]) -> Optional[str]:
    """
    Verifies that the active runtime model and effort match the catalog's top model and
    highest effort (`Gemini 4 Argon (High)` / `gemini-4-argon-high` in `upstream_state.seed.json`).
    Returns an error reason string on violation, or None if compliant (or missing payload metadata).
    """
    res = _evaluate_customization_model_and_effort(payload)
    if res is not None and res[0] == "deny":
        return res[1]
    return None


_WRITE_TARGET_ARG_KEYS = (
    "TargetFile",
    "targetFile",
    "target_file",
    "Path",
    "file_path",
    "filePath",
    "path",
    "AbsolutePath",
    "absolute_path",
    "absolutePath",
    "notebook_path",
    "notebookPath",
)


def _extract_write_targets(args: Dict[str, Any]) -> List[str]:
    targets: List[str] = []
    for key in _WRITE_TARGET_ARG_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip() and val not in targets:
            targets.append(val)
    edits = args.get("edits")
    if isinstance(edits, list):
        for item in edits:
            if isinstance(item, dict):
                for key in _WRITE_TARGET_ARG_KEYS:
                    val = item.get(key)
                    if isinstance(val, str) and val.strip() and val not in targets:
                        targets.append(val)
    return targets


_WORKFLOW_MAX_BYTES = 1024 * 1024
_WORKFLOW_MAX_ARG_DEPTH = 32
_WORKFLOW_MAX_FOLDED_LEN = 16384
_WORKFLOW_READONLY_MODE_RE = re.compile(r"^[rtbU]+$")
_WORKFLOW_ARCHIVE_READONLY_MODE_RE = re.compile(r"^(?:r(?::[a-z0-9*]*)?|[rtb]+)$")
_PEP263_ENCODING_RE = re.compile(r"coding[:=]\s*([-\w.]+)")

_FORBIDDEN_WORKFLOW_MODULES = frozenset({
    "subprocess",
    "pty",
    "popen2",
    "commands",
    "multiprocessing",
    "_posixsubprocess",
    "_winapi",
    "msvcrt",
    "posix",
    "nt",
    "os2",
    "ce",
    "_io",
    "_pyio",
    "fileinput",
    "ctypes",
    "cffi",
    "importlib",
    "runpy",
    "code",
    "codeop",
    "builtins",
    "operator",
    "gc",
    "inspect",
    "pdb",
    "bdb",
    "py_compile",
    "compileall",
    "zipapp",
    "signal",
    "fcntl",
    "resource",
    "tempfile",
    "sqlite3",
    "dbm",
    "shelve",
    "marshal",
    "pickle",
    "urllib",
    "http",
    "socket",
    "ssl",
    "ftplib",
    "poplib",
    "imaplib",
    "smtplib",
    "telnetlib",
    "xmlrpc",
    "logging",
    "xml",
    "webbrowser",
})

_FORBIDDEN_CHILD_PROC_MODULES = frozenset({
    "subprocess",
    "pty",
    "popen2",
    "commands",
    "multiprocessing",
    "_posixsubprocess",
    "_winapi",
})

_FORBIDDEN_OS_EXEC_NAMES = frozenset({
    "system",
    "startfile",
    "popen",
    "fdopen",
    "openpty",
    "login_tty",
    "pidfd_open",
    "putenv",
    "unsetenv",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "fork",
    "forkpty",
    "posix_spawn",
    "posix_spawnp",
    "kill",
    "killpg",
})

_FORBIDDEN_OS_FS_NAMES = frozenset({
    "open",
    "write",
    "pwrite",
    "writev",
    "pwritev",
    "remove",
    "unlink",
    "rmdir",
    "removedirs",
    "rename",
    "renames",
    "replace",
    "chdir",
    "fchdir",
    "chroot",
    "chmod",
    "fchmod",
    "lchmod",
    "chown",
    "fchown",
    "lchown",
    "symlink",
    "link",
    "truncate",
    "ftruncate",
    "posix_fallocate",
    "sendfile",
    "copy_file_range",
    "splice",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "memfd_create",
    "mkdir",
    "makedirs",
    "mknod",
    "mkfifo",
    "utime",
})

_FORBIDDEN_ASYNCIO_EXEC_NAMES = frozenset({
    "create_subprocess_exec",
    "create_subprocess_shell",
    "open_connection",
    "open_unix_connection",
    "start_server",
    "start_unix_server",
    "create_connection",
    "create_unix_connection",
    "create_server",
    "create_unix_server",
    "create_datagram_endpoint",
    "connect_write_pipe",
    "connect_read_pipe",
    "sock_connect",
    "sock_sendall",
    "sock_sendfile",
    "run_in_executor",
    "to_thread",
})

_FORBIDDEN_EXEC_ATTRS = (
    _FORBIDDEN_OS_EXEC_NAMES
    | _FORBIDDEN_ASYNCIO_EXEC_NAMES
    | frozenset({"subprocess_exec", "subprocess_shell", "Popen", "check_call", "check_output"})
)

_FORBIDDEN_DIRECT_FS_ATTRS = frozenset({
    "write",
    "writelines",
    "pwrite",
    "writev",
    "pwritev",
    "write_text",
    "write_bytes",
    "touch",
    "mkdir",
    "makedirs",
    "unlink",
    "rmdir",
    "removedirs",
    "rename",
    "renames",
    "chdir",
    "fchdir",
    "chroot",
    "chmod",
    "fchmod",
    "lchmod",
    "chown",
    "fchown",
    "lchown",
    "symlink",
    "symlink_to",
    "hardlink_to",
    "truncate",
    "ftruncate",
    "posix_fallocate",
    "sendfile",
    "copy_file_range",
    "splice",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "memfd_create",
    "utime",
    "mknod",
    "mkfifo",
    "move",
    "move_into",
    "copy_into",
    "copy2",
    "copyfile",
    "copyfileobj",
    "copymode",
    "copystat",
    "copytree",
    "unpack_archive",
    "make_archive",
    "extract",
    "extractall",
    "writestr",
    "FileType",
    "open_code",
    "bltn_open",
    "BufferedWriter",
    "BufferedRandom",
})

_NON_ALIASABLE_FS_ATTRS = (
    _FORBIDDEN_DIRECT_FS_ATTRS
    | _FORBIDDEN_OS_FS_NAMES
    | frozenset({
        "rmtree",
        "open",
        "FileIO",
        "ZipFile",
        "PyZipFile",
        "TarFile",
        "GzipFile",
        "BZ2File",
        "LZMAFile",
        "copy",
        "write",
        "writelines",
    })
)

_STDLIB_MODULES: frozenset[str] = frozenset(getattr(sys, "stdlib_module_names", ()))

_ALLOWED_STDLIB_WORKFLOW_MODULES = frozenset({
    "__future__",
    "abc",
    "argparse",
    "ast",
    "asyncio",
    "base64",
    "bisect",
    "bz2",
    "calendar",
    "codecs",
    "collections",
    "contextlib",
    "copy",
    "csv",
    "dataclasses",
    "datetime",
    "decimal",
    "difflib",
    "enum",
    "errno",
    "fnmatch",
    "fractions",
    "functools",
    "glob",
    "gzip",
    "hashlib",
    "heapq",
    "hmac",
    "html",
    "io",
    "ipaddress",
    "itertools",
    "json",
    "keyword",
    "lzma",
    "math",
    "numbers",
    "os",
    "pathlib",
    "posixpath",
    "pprint",
    "queue",
    "random",
    "re",
    "secrets",
    "shlex",
    "shutil",
    "stat",
    "statistics",
    "struct",
    "sys",
    "tarfile",
    "textwrap",
    "time",
    "tomllib",
    "typing",
    "unicodedata",
    "uuid",
    "zipfile",
    "zlib",
})

_FORBIDDEN_DUNDER_NAMES = frozenset({
    "__builtins__",
    "__import__",
    "__subclasses__",
    "__globals__",
    "__code__",
    "__loader__",
    "__spec__",
    "__dict__",
    "__class__",
    "__bases__",
    "__mro__",
    "__closure__",
    "__func__",
    "__self__",
    "__wrapped__",
    "__traceback__",
    "__cause__",
    "__context__",
    "__suppress_context__",
    "__objclass__",
    "__getattribute__",
    "__getattr__",
    "__setattr__",
    "__delattr__",
    "__match_args__",
    "__instancecheck__",
    "__subclasscheck__",
    "__init_subclass__",
    "__class_getitem__",
    "__prepare__",
    "__set_name__",
    "__reduce__",
    "__reduce_ex__",
    "__getstate__",
    "__setstate__",
})

_FORBIDDEN_FRAME_ATTRS = frozenset({
    "gi_frame",
    "gi_code",
    "gi_yieldfrom",
    "gi_running",
    "gi_suspended",
    "cr_frame",
    "cr_code",
    "cr_origin",
    "cr_await",
    "cr_running",
    "cr_suspended",
    "ag_frame",
    "ag_code",
    "ag_await",
    "ag_running",
    "ag_suspended",
    "tb_frame",
    "tb_next",
    "tb_lasti",
    "tb_lineno",
    "f_builtins",
    "f_globals",
    "f_locals",
    "f_back",
    "f_code",
    "f_trace",
    "f_trace_lines",
    "f_trace_opcodes",
    "f_lasti",
    "f_lineno",
})

_FORBIDDEN_CALLABLE_BUILTINS = frozenset({
    "eval",
    "exec",
    "compile",
    "__import__",
    "breakpoint",
    "help",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
    "input",
    "type",
})

_FORBIDDEN_REFLECTIVE_ATTRS = frozenset({
    "exec",
    "eval",
    "__import__",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
    "breakpoint",
    "help",
    "import_module",
    "exec_module",
    "load_module",
    "run_path",
    "run_module",
    "attrgetter",
    "methodcaller",
    "MethodType",
    "capture_call_graph",
    "format",
    "format_map",
    "vformat",
    "get_field",
    "get_value",
    "Formatter",
    "Template",
})

_SAFE_WORKFLOW_HOST_CALLABLES = frozenset({
    "parallel",
    "pipeline",
    "phase",
    "trajectory",
    "log",
    "print",
})

_SAFE_WORKFLOW_BUILTINS = frozenset({
    "abs",
    "aiter",
    "all",
    "anext",
    "any",
    "ascii",
    "bin",
    "bool",
    "bytearray",
    "bytes",
    "callable",
    "chr",
    "classmethod",
    "complex",
    "dict",
    "divmod",
    "enumerate",
    "filter",
    "float",
    "frozenset",
    "hash",
    "hex",
    "id",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "list",
    "map",
    "max",
    "memoryview",
    "min",
    "next",
    "object",
    "oct",
    "ord",
    "pow",
    "property",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "slice",
    "sorted",
    "staticmethod",
    "str",
    "sum",
    "super",
    "tuple",
    "zip",
    "BaseException",
    "Exception",
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "BlockingIOError",
    "BrokenPipeError",
    "BufferError",
    "ChildProcessError",
    "ConnectionError",
    "EOFError",
    "FileExistsError",
    "FileNotFoundError",
    "FloatingPointError",
    "GeneratorExit",
    "ImportError",
    "IndexError",
    "InterruptedError",
    "IsADirectoryError",
    "KeyError",
    "KeyboardInterrupt",
    "LookupError",
    "MemoryError",
    "ModuleNotFoundError",
    "NameError",
    "NotADirectoryError",
    "NotImplementedError",
    "OSError",
    "OverflowError",
    "PermissionError",
    "ProcessLookupError",
    "RecursionError",
    "ReferenceError",
    "RuntimeError",
    "StopAsyncIteration",
    "StopIteration",
    "SyntaxError",
    "SystemError",
    "SystemExit",
    "TimeoutError",
    "TypeError",
    "UnboundLocalError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "UnicodeError",
    "UnicodeTranslateError",
    "ValueError",
    "ZeroDivisionError",
})

_SAFE_ENVIRON_READ_METHODS = frozenset({"get", "keys", "values", "items", "copy"})

_PROTECTED_HOST_PRIMITIVES = frozenset({
    "open",
    "call_tool",
    "agent",
    "parallel",
    "pipeline",
    "trajectory",
    "log",
    "phase",
    "args",
})

_NON_ALIASABLE_WORKFLOW_NAMES = _FORBIDDEN_CALLABLE_BUILTINS | frozenset({
    "open",
    "call_tool",
    "agent",
    "parallel",
    "pipeline",
    "trajectory",
})

_UNCONDITIONAL_FORBIDDEN_SYS_ATTRS = frozenset({
    "meta_path",
    "path_hooks",
    "path_importer_cache",
    "addaudithook",
    "settrace",
    "gettrace",
    "setprofile",
    "getprofile",
    "monitoring",
    "exc_info",
    "last_traceback",
    "last_exc",
    "last_value",
    "last_type",
    "_getframe",
    "_getframemodulename",
    "_current_frames",
    "_current_exceptions",
    "breakpointhook",
    "excepthook",
    "unraisablehook",
    "displayhook",
    "remote_exec",
    "call_tracing",
})

_FORBIDDEN_SYS_ATTRS = _UNCONDITIONAL_FORBIDDEN_SYS_ATTRS | frozenset({
    "modules",
    "path",
    "audit",
    "exception",
    "setdlopenflags",
})

_FORBIDDEN_REEXPORT_ATTRS = (
    (_FORBIDDEN_WORKFLOW_MODULES - frozenset({"code"}))
    | _FORBIDDEN_CHILD_PROC_MODULES
    | frozenset({
        "builtins",
        "bltns",
        "os",
        "posix",
        "nt",
        "sys",
        "shutil",
        "io",
        "codecs",
        "tarfile",
        "zipfile",
        "gzip",
        "bz2",
        "lzma",
        "types",
        "concurrent",
        "threading",
        "importlib",
        "annotationlib",
        "copyreg",
        "weakref",
        "pwd",
        "grp",
        "pathlib",
        "posixpath",
        "ntpath",
        "genericpath",
        "linecache",
        "tokenize",
        "subprocess",
        "base_subprocess",
        "unix_events",
        "selector_events",
        "proactor_events",
        "windows_events",
        "windows_utils",
        "base_events",
        "base_futures",
        "base_tasks",
        "events",
        "tasks",
        "coroutines",
        "futures",
        "locks",
        "queues",
        "protocols",
        "threads",
        "timeouts",
        "staggered",
        "constants",
        "exceptions",
        "format_helpers",
        "mixins",
        "taskgroups",
        "tools",
        "graph",
        "runners",
        "streams",
        "sslproto",
        "trsock",
        "transports",
    })
)


def _check_pep263_cookie(source_text: str) -> Optional[str]:
    for header_line in source_text.splitlines()[:2]:
        if header_line.lstrip(" \t\ufeff").startswith("#"):
            m_enc = _PEP263_ENCODING_RE.search(header_line)
            if m_enc and m_enc.group(1).lower() not in (
                "utf-8",
                "utf8",
                "utf_8",
                "utf-8-sig",
                "ascii",
                "us-ascii",
            ):
                return (
                    f"[Harness Workflow Shield] Non-UTF-8 PEP 263 encoding cookie "
                    f"(`{m_enc.group(1)}`) inside `run_workflow` script is prohibited."
                )
    return None


def _collect_workflow_arg_strings(value: Any, out: List[str], depth: int = 0) -> Optional[str]:
    if depth > _WORKFLOW_MAX_ARG_DEPTH:
        return "[Harness Workflow Shield] `run_workflow` `Args` exceeds maximum nesting depth (32)."
    if isinstance(value, str):
        if "\x00" in value:
            return "[Harness Workflow Shield] Null bytes are prohibited inside `run_workflow` `Args`."
        if value:
            out.append(value)
        return None
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                if "\x00" in k:
                    return "[Harness Workflow Shield] Null bytes are prohibited inside `run_workflow` `Args`."
                if k:
                    out.append(k)
            err = _collect_workflow_arg_strings(v, out, depth + 1)
            if err:
                return err
        return None
    if isinstance(value, (list, tuple)):
        for elt in value:
            if isinstance(elt, str) and "\x00" in elt:
                return "[Harness Workflow Shield] Null bytes are prohibited inside `run_workflow` `Args`."
        str_parts = [elt for elt in value if isinstance(elt, str) and elt]
        if len(str_parts) >= 2:
            out.append(" ".join(str_parts))
        for elt in value:
            err = _collect_workflow_arg_strings(elt, out, depth + 1)
            if err:
                return err
        return None
    return None


def _extract_workflow_sources_ex(
    args: Dict[str, Any], workspace: Optional[Path]
) -> Tuple[List[str], List[str], Optional[Path], List[Tuple[Path, int]], Optional[str]]:
    """
    Extracts `(script_sources, arg_strings, workflow_cwd, script_paths_meta, error_reason)` from `run_workflow`.
    `script_paths_meta` records `(resolved_path, st_mode)` for every `ScriptPath` file read so TOCTOU
    risk on external/world-writable `ScriptPath` targets can require confirmation (`I-01`).
    """
    try:
        base_dir: Optional[Path] = workspace if workspace is not None else Path.cwd()
    except OSError:
        base_dir = workspace

    cwd_values: List[str] = []
    for ck in ("Cwd", "cwd"):
        if ck not in args:
            continue
        cwd_raw = args.get(ck)
        if cwd_raw is None:
            continue
        if not isinstance(cwd_raw, str):
            return [], [], base_dir, [], f"[Harness Workflow Shield] `run_workflow` `{ck}` argument must be a string."
        if "\x00" in cwd_raw:
            return [], [], base_dir, [], f"[Harness Workflow Shield] Null bytes are prohibited inside `run_workflow` `{ck}`."
        if cwd_raw != cwd_raw.strip():
            return (
                [],
                [],
                base_dir,
                [],
                f"[Harness Workflow Shield] `run_workflow` `{ck}` must not contain leading or trailing whitespace.",
            )
        if cwd_raw:
            cwd_values.append(cwd_raw)
    if len(set(cwd_values)) > 1:
        return [], [], base_dir, [], "[Harness Workflow Shield] Conflicting `Cwd`/`cwd` arguments in `run_workflow`."
    if cwd_values:
        cwd_path = Path(os.path.expanduser(cwd_values[0]))
        if not cwd_path.is_absolute():
            if base_dir is None:
                return [], [], None, [], "[Harness Workflow Shield] Cannot resolve relative `Cwd` without a working directory."
            base_dir = base_dir / cwd_path
        else:
            base_dir = cwd_path

    script_sources: List[str] = []
    script_paths_meta: List[Tuple[Path, int]] = []
    for sk in ("Script", "script"):
        if sk not in args:
            continue
        inline = args.get(sk)
        if inline is None:
            continue
        if not isinstance(inline, str):
            return [], [], base_dir, [], f"[Harness Workflow Shield] `run_workflow` `{sk}` argument must be a string."
        if "\x00" in inline:
            return [], [], base_dir, [], f"[Harness Workflow Shield] Null bytes are prohibited inside `run_workflow` `{sk}`."
        if inline.strip():
            if len(inline.encode("utf-8", errors="replace")) > _WORKFLOW_MAX_BYTES:
                return [], [], base_dir, [], "[Harness Workflow Shield] `run_workflow` inline `Script` exceeds 1 MB inspection limit."
            cookie_err = _check_pep263_cookie(inline)
            if cookie_err:
                return [], [], base_dir, [], cookie_err
            script_sources.append(inline)

    for sp_key in ("ScriptPath", "scriptPath", "script_path"):
        if sp_key not in args:
            continue
        sp_raw = args.get(sp_key)
        if sp_raw is None:
            continue
        if not isinstance(sp_raw, str):
            return [], [], base_dir, [], f"[Harness Workflow Shield] `run_workflow` `{sp_key}` argument must be a string."
        if "\x00" in sp_raw:
            return [], [], base_dir, [], f"[Harness Workflow Shield] Null bytes are prohibited inside `run_workflow` `{sp_key}`."
        if sp_raw != sp_raw.strip():
            return (
                [],
                [],
                base_dir,
                [],
                f"[Harness Workflow Shield] `run_workflow` `{sp_key}` must not contain leading or trailing whitespace.",
            )
        if not sp_raw:
            continue
        sp = Path(os.path.expanduser(sp_raw))
        if not sp.is_absolute():
            if base_dir is None:
                return [], [], None, [], f"[Harness Workflow Shield] Cannot resolve relative `{sp_key}` without a working directory."
            sp = base_dir / sp
        try:
            if sp.is_symlink():
                return [], [], base_dir, [], "[Harness Workflow Shield] `run_workflow` `ScriptPath` must not be a symbolic link."
            open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            fd = os.open(str(sp), open_flags)
        except (OSError, ValueError) as exc:
            return [], [], base_dir, [], f"[Harness Workflow Shield] Cannot inspect `run_workflow` `ScriptPath` (`{sp}`): {exc}"
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return [], [], base_dir, [], f"[Harness Workflow Shield] `run_workflow` `ScriptPath` (`{sp}`) must be a regular file."
            if st.st_size > _WORKFLOW_MAX_BYTES:
                return [], [], base_dir, [], "[Harness Workflow Shield] `run_workflow` `ScriptPath` exceeds 1 MB inspection limit."
            chunks_b: List[bytes] = []
            total_b = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total_b += len(chunk)
                if total_b > _WORKFLOW_MAX_BYTES:
                    return [], [], base_dir, [], "[Harness Workflow Shield] `run_workflow` `ScriptPath` exceeds 1 MB inspection limit."
                chunks_b.append(chunk)
            raw_bytes = b"".join(chunks_b)
            file_mode = int(st.st_mode)
        except OSError as exc:
            return [], [], base_dir, [], f"[Harness Workflow Shield] Failed reading `run_workflow` `ScriptPath` (`{sp}`): {exc}"
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        if b"\x00" in raw_bytes:
            return [], [], base_dir, [], f"[Harness Workflow Shield] Null bytes are prohibited inside `ScriptPath` (`{sp}`)."
        try:
            decoded_src = raw_bytes.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as exc:
            return [], [], base_dir, [], f"[Harness Workflow Shield] `run_workflow` `ScriptPath` (`{sp}`) must be valid UTF-8: {exc}"
        cookie_err = _check_pep263_cookie(decoded_src)
        if cookie_err:
            return [], [], base_dir, [], cookie_err
        if decoded_src.strip():
            script_sources.append(decoded_src)
            script_paths_meta.append((sp, file_mode))

    if not script_sources:
        return [], [], base_dir, [], "[Harness Workflow Shield] `run_workflow` requires a non-empty `Script` or `ScriptPath`."

    arg_strings: List[str] = []
    for ak in ("Args", "args"):
        if ak not in args:
            continue
        wf_args = args.get(ak)
        if wf_args is not None:
            err = _collect_workflow_arg_strings(wf_args, arg_strings)
            if err:
                return [], [], base_dir, [], err

    return script_sources, arg_strings, base_dir, script_paths_meta, None


def _extract_workflow_sources(
    args: Dict[str, Any], workspace: Optional[Path]
) -> Tuple[List[str], List[str], Optional[Path], Optional[str]]:
    sources, arg_strings, base_dir, _sp_meta, err = _extract_workflow_sources_ex(args, workspace)
    return sources, arg_strings, base_dir, err


def _eval_workflow_str_expr(node: Optional[ast.AST], const_vars: Dict[str, str], depth: int = 0) -> Optional[str]:
    if node is None or depth > 24:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value if len(node.value) <= _WORKFLOW_MAX_FOLDED_LEN else None
    if isinstance(node, ast.Name) and node.id in const_vars:
        val = const_vars[node.id]
        return val if len(val) <= _WORKFLOW_MAX_FOLDED_LEN else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_workflow_str_expr(node.left, const_vars, depth + 1)
        right = _eval_workflow_str_expr(node.right, const_vars, depth + 1)
        if left is not None and right is not None and len(left) + len(right) <= _WORKFLOW_MAX_FOLDED_LEN:
            return left + right
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], (ast.List, ast.Tuple))
    ):
        sep = _eval_workflow_str_expr(node.func.value, const_vars, depth + 1)
        if sep is not None and len(node.args[0].elts) <= 128:
            items = [_eval_workflow_str_expr(elt, const_vars, depth + 1) for elt in node.args[0].elts]
            if all(it is not None for it in items):
                joined = sep.join(it for it in items if it is not None)
                if len(joined) <= _WORKFLOW_MAX_FOLDED_LEN:
                    return joined
    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        total_len = 0
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                total_len += len(val.value)
                if total_len > _WORKFLOW_MAX_FOLDED_LEN:
                    return None
                parts.append(val.value)
            elif isinstance(val, ast.FormattedValue):
                inner = _eval_workflow_str_expr(val.value, const_vars, depth + 1)
                if inner is None:
                    return None
                total_len += len(inner)
                if total_len > _WORKFLOW_MAX_FOLDED_LEN:
                    return None
                parts.append(inner)
            else:
                return None
        return "".join(parts)
    return None


def _extract_partial_text_and_dynamic(
    node: Optional[ast.AST],
    const_vars: Dict[str, str],
    depth: int = 0,
    memo: Optional[Dict[int, Tuple[str, bool]]] = None,
) -> Tuple[str, bool]:
    """Extracts static text fragments from an AST string/f-string expression and flags dynamic holes."""
    if node is None or depth > 24:
        return "", False
    if memo is None:
        memo = {}
    nid = id(node)
    if nid in memo:
        return memo[nid]
    exact = _eval_workflow_str_expr(node, const_vars, depth)
    if exact is not None:
        res = (exact, False)
        memo[nid] = res
        return res
    if isinstance(node, ast.JoinedStr):
        frags: List[str] = []
        has_dyn = False
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                frags.append(val.value)
            elif isinstance(val, ast.FormattedValue):
                sub_txt, sub_dyn = _extract_partial_text_and_dynamic(val.value, const_vars, depth + 1, memo)
                if sub_txt:
                    frags.append(sub_txt)
                has_dyn = True or sub_dyn
            else:
                has_dyn = True
        res = (" ".join(frags)[:_WORKFLOW_MAX_FOLDED_LEN], has_dyn)
        memo[nid] = res
        return res
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        l_txt, l_dyn = _extract_partial_text_and_dynamic(node.left, const_vars, depth + 1, memo)
        r_txt, r_dyn = _extract_partial_text_and_dynamic(node.right, const_vars, depth + 1, memo)
        res = (f"{l_txt}{r_txt}"[:_WORKFLOW_MAX_FOLDED_LEN], (l_dyn or r_dyn))
        memo[nid] = res
        return res
    memo[nid] = ("", True)
    return "", True


def _eval_workflow_path_expr(node: Optional[ast.AST], const_vars: Dict[str, str], depth: int = 0) -> Optional[str]:
    if node is None or depth > 24:
        return None
    as_str = _eval_workflow_str_expr(node, const_vars, depth)
    if as_str is not None:
        return as_str
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _eval_workflow_path_expr(node.left, const_vars, depth + 1)
        right = _eval_workflow_path_expr(node.right, const_vars, depth + 1)
        if left is not None and right is not None:
            joined = os.path.join(left, right)
            return joined if len(joined) <= _WORKFLOW_MAX_FOLDED_LEN else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_workflow_path_expr(node.left, const_vars, depth + 1)
        right = _eval_workflow_path_expr(node.right, const_vars, depth + 1)
        if left is not None and right is not None:
            concat = f"{left}{right}"
            return concat if len(concat) <= _WORKFLOW_MAX_FOLDED_LEN else None
    if isinstance(node, ast.Call):
        if any(isinstance(a, ast.Starred) for a in node.args) or any(kw.arg is None for kw in node.keywords):
            return None
        if isinstance(node.func, ast.Name) and node.func.id in ("Path", "PurePath", "PosixPath"):
            if not node.args:
                return "."
            parts = [_eval_workflow_path_expr(a, const_vars, depth + 1) for a in node.args]
            if all(p is not None for p in parts):
                non_none = [p for p in parts if p is not None]
                joined = os.path.join(*non_none) if non_none else "."
                return (joined or ".") if len(joined) <= _WORKFLOW_MAX_FOLDED_LEN else None
        if isinstance(node.func, ast.Name) and node.func.id == "str" and len(node.args) == 1:
            return _eval_workflow_path_expr(node.args[0], const_vars, depth + 1)
        if isinstance(node.func, ast.Name) and node.func.id in ("expanduser", "abspath", "realpath", "normpath") and len(node.args) == 1:
            arg0 = _eval_workflow_path_expr(node.args[0], const_vars, depth + 1)
            if arg0 is not None:
                out = os.path.expanduser(arg0) if node.func.id == "expanduser" else arg0
                return out if len(out) <= _WORKFLOW_MAX_FOLDED_LEN else None
        if isinstance(node.func, ast.Name) and node.func.id == "join" and node.args:
            parts = [_eval_workflow_path_expr(a, const_vars, depth + 1) for a in node.args]
            if all(p is not None for p in parts):
                joined = os.path.join(*(p for p in parts if p is not None))
                return joined if len(joined) <= _WORKFLOW_MAX_FOLDED_LEN else None
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("expanduser", "resolve", "absolute") and not node.args:
                base = _eval_workflow_path_expr(node.func.value, const_vars, depth + 1)
                if base is not None:
                    out = os.path.expanduser(base) if node.func.attr == "expanduser" else base
                    return out if len(out) <= _WORKFLOW_MAX_FOLDED_LEN else None
            if node.func.attr in ("expanduser", "abspath", "realpath", "normpath") and len(node.args) == 1:
                arg0 = _eval_workflow_path_expr(node.args[0], const_vars, depth + 1)
                if arg0 is not None:
                    out = os.path.expanduser(arg0) if node.func.attr == "expanduser" else arg0
                    return out if len(out) <= _WORKFLOW_MAX_FOLDED_LEN else None
            if node.func.attr == "home" and not node.args:
                return str(Path.home())
            if node.func.attr == "join" and node.args:
                parts = [_eval_workflow_path_expr(a, const_vars, depth + 1) for a in node.args]
                if all(p is not None for p in parts):
                    joined = os.path.join(*(p for p in parts if p is not None))
                    return joined if len(joined) <= _WORKFLOW_MAX_FOLDED_LEN else None
            if node.func.attr == "joinpath" and node.args:
                base = _eval_workflow_path_expr(node.func.value, const_vars, depth + 1)
                parts = [_eval_workflow_path_expr(a, const_vars, depth + 1) for a in node.args]
                if base is not None and all(p is not None for p in parts):
                    joined = os.path.join(base, *(p for p in parts if p is not None))
                    return joined if len(joined) <= _WORKFLOW_MAX_FOLDED_LEN else None
    return None


def _eval_workflow_const_value(
    node: Optional[ast.AST], const_vars: Dict[str, str], depth: int = 0
) -> Tuple[Any, bool]:
    if node is None or depth > 24:
        return None, False
    folded_str = _eval_workflow_path_expr(node, const_vars, depth)
    if folded_str is not None:
        return folded_str, True
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float, bool, type(None))):
        if isinstance(node.value, str) and len(node.value) > _WORKFLOW_MAX_FOLDED_LEN:
            return None, False
        return node.value, True
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, (ast.USub, ast.UAdd))
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, (int, float))
        and not isinstance(node.operand.value, bool)
    ):
        return (-node.operand.value if isinstance(node.op, ast.USub) else +node.operand.value), True
    if isinstance(node, (ast.List, ast.Tuple)):
        if len(node.elts) > 256:
            return None, False
        items: List[Any] = []
        for elt in node.elts:
            if isinstance(elt, ast.Starred):
                return None, False
            val, ok = _eval_workflow_const_value(elt, const_vars, depth + 1)
            if not ok:
                return None, False
            items.append(val)
        return (items if isinstance(node, ast.List) else tuple(items)), True
    if isinstance(node, ast.Dict):
        if len(node.keys) > 256:
            return None, False
        out_dict: Dict[Any, Any] = {}
        for k_node, v_node in zip(node.keys, node.values):
            if k_node is None:
                return None, False
            k_val, k_ok = _eval_workflow_const_value(k_node, const_vars, depth + 1)
            if not k_ok or not isinstance(k_val, (str, int, float, bool, type(None))):
                return None, False
            v_val, v_ok = _eval_workflow_const_value(v_node, const_vars, depth + 1)
            if not v_ok:
                return None, False
            out_dict[k_val] = v_val
        return out_dict, True
    return None, False


def _is_readonly_open_call(node: ast.Call, mode_pos_index: int, const_vars: Dict[str, str], archive: bool = False) -> bool:
    if any(isinstance(a, ast.Starred) for a in node.args):
        return False
    if len(node.args) > mode_pos_index + 1:
        return False
    allowed_kw = (
        ("name", "file", "mode", "fileobj", "pwd", "compresslevel", "preset")
        if archive
        else (
            ("file", "mode", "buffering", "encoding", "errors", "newline", "closefd")
            if mode_pos_index == 1
            else ("mode", "buffering", "encoding", "errors", "newline")
        )
    )
    for kw in node.keywords:
        if kw.arg is None or kw.arg not in allowed_kw:
            return False
    mode_node: Optional[ast.AST] = None
    if len(node.args) > mode_pos_index:
        mode_node = node.args[mode_pos_index]
    else:
        for kw in node.keywords:
            if kw.arg == "mode":
                mode_node = kw.value
                break
    if mode_node is None:
        return True
    mode_val = _eval_workflow_str_expr(mode_node, const_vars)
    if mode_val is None or not mode_val:
        return False
    if archive:
        return bool(_WORKFLOW_ARCHIVE_READONLY_MODE_RE.match(mode_val))
    return bool(_WORKFLOW_READONLY_MODE_RE.match(mode_val)) and ("r" in mode_val or "U" in mode_val)


def _inspect_workflow_script(
    source: str,
    arg_strings: Sequence[str],
    payload: Dict[str, Any],
    workspace: Optional[Path],
    workflow_cwd: Optional[Path] = None,
) -> Tuple[Dict[str, Any], List[Tuple[str, str]]]:
    """
    Statically inspects a `run_workflow` Python script and its `Args` strings for:
      - Human-only `agy-guard` admin commands, `install.py`, and git hook bypasses (`Rule 12`)
      - Child-process / dynamic-eval / FFI / aliasing escapes (`subprocess`, `os.system`, `eval`, `ctypes` — `Rule 15e`)
      - Direct Python filesystem writes/mutations bypassing `call_tool` & Flight Recorder (`Rule 12`, `15a`, `15e`)
      - Static `call_tool(...)` invocations targeting governance, customization, or destructive commands
      - Delegated `agent(...)` model downgrades (`model='flash' | 'flash_lite'`) on customization files (`Rule 17`)
    """
    eff_cwd = workflow_cwd if workflow_cwd is not None else workspace

    def _path_hits_gov(cand: str, resolve_rel: bool = False) -> bool:
        return _targets_governance_dir(cand, base_dir=(eff_cwd if resolve_rel else None))

    def _path_hits_cust(cand: str, resolve_rel: bool = False) -> bool:
        if not cand or not cand.strip() or "\x00" in cand:
            return False
        if resolve_rel and eff_cwd is not None:
            exp = Path(os.path.expanduser(cand.strip()))
            if not exp.is_absolute():
                return _targets_customization_structure(str(eff_cwd / exp), workspace=workspace)
        return _targets_customization_structure(cand, workspace=workspace)

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as exc:
        return (
            {
                "decision": "deny",
                "reason": (
                    f"[Harness Workflow Shield] Failed to parse Python `run_workflow` script "
                    f"({type(exc).__name__}): {exc}"
                ),
            },
            [],
        )

    # Single-assignment constant propagation plus bounded multi-assignment candidate tracking (`P09`):
    # variables bound more than once are excluded from `const_vars`, while all candidate values are
    # tracked in `multi_var_values` so reassignment (`p = ''; p = 'GEM' + 'INI.md'`) cannot mask targets.
    bind_counts: Dict[str, int] = {}
    store_counts: Dict[str, int] = {}
    single_rhs: Dict[str, ast.AST] = {}
    multi_rhs: Dict[str, List[ast.AST]] = {}
    local_callable_defs: Dict[str, int] = {}
    rebound_host_primitive: Optional[str] = None
    forbidden_dunder_def: Optional[str] = None
    for stmt in ast.walk(tree):
        if isinstance(stmt, ast.Name) and isinstance(stmt.ctx, (ast.Store, ast.Del)):
            bind_counts[stmt.id] = bind_counts.get(stmt.id, 0) + 1
            if isinstance(stmt.ctx, ast.Store):
                store_counts[stmt.id] = store_counts.get(stmt.id, 0) + 1
            if stmt.id in _PROTECTED_HOST_PRIMITIVES:
                rebound_host_primitive = stmt.id
        elif isinstance(stmt, ast.arg):
            bind_counts[stmt.arg] = bind_counts.get(stmt.arg, 0) + 1
            store_counts[stmt.arg] = store_counts.get(stmt.arg, 0) + 1
            if stmt.arg in _PROTECTED_HOST_PRIMITIVES:
                rebound_host_primitive = stmt.arg
        elif isinstance(stmt, ast.ExceptHandler) and stmt.name:
            bind_counts[stmt.name] = bind_counts.get(stmt.name, 0) + 1
            store_counts[stmt.name] = store_counts.get(stmt.name, 0) + 1
            if stmt.name in _PROTECTED_HOST_PRIMITIVES:
                rebound_host_primitive = stmt.name
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bind_counts[stmt.name] = bind_counts.get(stmt.name, 0) + 1
            store_counts[stmt.name] = store_counts.get(stmt.name, 0) + 1
            local_callable_defs[stmt.name] = local_callable_defs.get(stmt.name, 0) + 1
            if stmt.name in _PROTECTED_HOST_PRIMITIVES:
                rebound_host_primitive = stmt.name
            if stmt.name in _FORBIDDEN_DUNDER_NAMES:
                forbidden_dunder_def = stmt.name
        elif isinstance(stmt, (ast.MatchAs, ast.MatchStar)) and stmt.name:
            bind_counts[stmt.name] = bind_counts.get(stmt.name, 0) + 1
            store_counts[stmt.name] = store_counts.get(stmt.name, 0) + 1
            if stmt.name in _PROTECTED_HOST_PRIMITIVES:
                rebound_host_primitive = stmt.name
        elif isinstance(stmt, ast.MatchMapping) and stmt.rest:
            bind_counts[stmt.rest] = bind_counts.get(stmt.rest, 0) + 1
            store_counts[stmt.rest] = store_counts.get(stmt.rest, 0) + 1
            if stmt.rest in _PROTECTED_HOST_PRIMITIVES:
                rebound_host_primitive = stmt.rest
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for al in stmt.names:
                bname = al.asname or al.name.split(".", 1)[0]
                bind_counts[bname] = bind_counts.get(bname, 0) + 1
                store_counts[bname] = store_counts.get(bname, 0) + 1
                if bname in _PROTECTED_HOST_PRIMITIVES:
                    rebound_host_primitive = bname
        if isinstance(stmt, ast.Assign):
            if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                single_rhs[stmt.targets[0].id] = stmt.value
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name):
                    multi_rhs.setdefault(tgt.id, []).append(stmt.value)
                elif isinstance(tgt, (ast.Tuple, ast.List)) and isinstance(stmt.value, (ast.Tuple, ast.List)):
                    if len(tgt.elts) == len(stmt.value.elts):
                        for sub_t, sub_v in zip(tgt.elts, stmt.value.elts):
                            if isinstance(sub_t, ast.Name):
                                multi_rhs.setdefault(sub_t.id, []).append(sub_v)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            single_rhs[stmt.target.id] = stmt.value
            multi_rhs.setdefault(stmt.target.id, []).append(stmt.value)
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            multi_rhs.setdefault(stmt.target.id, []).append(
                ast.BinOp(left=ast.Name(id=stmt.target.id, ctx=ast.Load()), op=stmt.op, right=stmt.value)
            )
        elif isinstance(stmt, ast.NamedExpr) and isinstance(stmt.target, ast.Name):
            single_rhs[stmt.target.id] = stmt.value
            multi_rhs.setdefault(stmt.target.id, []).append(stmt.value)

    const_vars: Dict[str, str] = {}
    for _ in range(8):
        progressed = False
        for vname, rhs in single_rhs.items():
            if bind_counts.get(vname, 0) != 1 or vname in const_vars:
                continue
            folded = _eval_workflow_path_expr(rhs, const_vars)
            if folded is not None:
                const_vars[vname] = folded
                progressed = True
        if not progressed:
            break

    def _eval_multi_candidates(
        expr: Optional[ast.AST], env_map: Dict[str, List[str]], depth: int = 0
    ) -> List[str]:
        if expr is None or depth > 16:
            return []
        direct = _eval_workflow_path_expr(expr, const_vars)
        if direct is not None:
            return [direct]
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return [expr.value] if len(expr.value) <= _WORKFLOW_MAX_FOLDED_LEN else []
        if isinstance(expr, ast.Name):
            return list(env_map.get(expr.id, ()))[:8]
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            lefts = _eval_multi_candidates(expr.left, env_map, depth + 1)
            rights = _eval_multi_candidates(expr.right, env_map, depth + 1)
            out_add: List[str] = []
            for l_s in lefts[:6]:
                for r_s in rights[:6]:
                    if len(l_s) + len(r_s) <= _WORKFLOW_MAX_FOLDED_LEN:
                        comb = l_s + r_s
                        if comb not in out_add:
                            out_add.append(comb)
                        if len(out_add) >= 12:
                            return out_add
            return out_add
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
            lefts = _eval_multi_candidates(expr.left, env_map, depth + 1)
            rights = _eval_multi_candidates(expr.right, env_map, depth + 1)
            out_div: List[str] = []
            for l_s in lefts[:6]:
                for r_s in rights[:6]:
                    comb = f"{l_s.rstrip('/')}/{r_s.lstrip('/')}"
                    if len(comb) <= _WORKFLOW_MAX_FOLDED_LEN and comb not in out_div:
                        out_div.append(comb)
                        if len(out_div) >= 12:
                            return out_div
            return out_div
        if isinstance(expr, ast.JoinedStr):
            acc = [""]
            for val in expr.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    step_vals = [val.value]
                elif isinstance(val, ast.FormattedValue):
                    step_vals = _eval_multi_candidates(val.value, env_map, depth + 1)
                    if not step_vals:
                        return []
                else:
                    return []
                next_acc: List[str] = []
                for prefix in acc[:8]:
                    for sv in step_vals[:6]:
                        if len(prefix) + len(sv) <= _WORKFLOW_MAX_FOLDED_LEN:
                            joined_s = prefix + sv
                            if joined_s not in next_acc:
                                next_acc.append(joined_s)
                            if len(next_acc) >= 12:
                                break
                    if len(next_acc) >= 12:
                        break
                acc = next_acc
                if not acc:
                    return []
            return acc
        return []

    multi_var_values: Dict[str, List[str]] = {k: [v] for k, v in const_vars.items()}
    for _ in range(4):
        progressed_m = False
        for vname, rhs_list in multi_rhs.items():
            existing = multi_var_values.setdefault(vname, [])
            for rhs_expr in rhs_list[:8]:
                for cand_s in _eval_multi_candidates(rhs_expr, multi_var_values):
                    if cand_s not in existing and len(existing) < 16:
                        existing.append(cand_s)
                        progressed_m = True
        if not progressed_m:
            break

    # Map persistent `var = agent(...)` bindings (across Assign, AnnAssign, NamedExpr, and reassignments)
    # and chained `agent(...)(prompt, ...)` calls BEFORE collecting benign prose node IDs.
    persistent_agents: Dict[str, List[ast.Call]] = {}
    persistent_agent_turn_nodes: Dict[str, List[ast.AST]] = {}
    chained_agent_turns: Dict[int, List[ast.AST]] = {}

    def _unwrap_agent_call(expr: Optional[ast.AST], allow_await: bool = True) -> Optional[ast.Call]:
        inner = expr.value if (allow_await and isinstance(expr, ast.Await)) else expr
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name) and inner.func.id == "agent":
            return inner
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            ag_val = _unwrap_agent_call(node.value, allow_await=False)
            if ag_val is not None:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        persistent_agents.setdefault(tgt.id, []).append(ag_val)
                        persistent_agent_turn_nodes.setdefault(tgt.id, [])
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            ag_val = _unwrap_agent_call(node.value, allow_await=False)
            if ag_val is not None:
                persistent_agents.setdefault(node.target.id, []).append(ag_val)
                persistent_agent_turn_nodes.setdefault(node.target.id, [])
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            ag_val = _unwrap_agent_call(node.value, allow_await=False)
            if ag_val is not None:
                persistent_agents.setdefault(node.target.id, []).append(ag_val)
                persistent_agent_turn_nodes.setdefault(node.target.id, [])

    # Track non-executing UI/prompt string node ids so prose in `log(...)`, `phase(...)`, `agent(...)`,
    # persistent `var(prompt, ...)`, or chained `agent(...)(prompt, ...)` does not trigger shell regex false positives.
    benign_prose_node_ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            if node.func.id in ("log", "phase"):
                for sub in ast.walk(node):
                    benign_prose_node_ids.add(id(sub))
            elif node.func.id == "agent":
                for arg_node in node.args[:3]:
                    for sub in ast.walk(arg_node):
                        benign_prose_node_ids.add(id(sub))
                for kw in node.keywords:
                    if kw.arg in ("prompt", "role", "schema"):
                        for sub in ast.walk(kw.value):
                            benign_prose_node_ids.add(id(sub))
            elif node.func.id in persistent_agents:
                for arg_node in node.args[:2]:
                    for sub in ast.walk(arg_node):
                        benign_prose_node_ids.add(id(sub))
                for kw in node.keywords:
                    if kw.arg in ("prompt", "schema"):
                        for sub in ast.walk(kw.value):
                            benign_prose_node_ids.add(id(sub))
        else:
            chained_ag = _unwrap_agent_call(node.func, allow_await=True)
            if chained_ag is not None:
                turns = chained_agent_turns.setdefault(id(chained_ag), [])
                if node.args:
                    turns.append(node.args[0])
                for arg_node in node.args[:2]:
                    for sub in ast.walk(arg_node):
                        benign_prose_node_ids.add(id(sub))
                for kw in node.keywords:
                    if kw.arg == "prompt":
                        turns.append(kw.value)
                    if kw.arg in ("prompt", "schema"):
                        for sub in ast.walk(kw.value):
                            benign_prose_node_ids.add(id(sub))

    all_literals: List[str] = []
    cmd_candidates: List[str] = list(arg_strings)
    for vals in multi_var_values.values():
        for mv in vals:
            if mv and mv not in all_literals:
                all_literals.append(mv)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value:
            all_literals.append(node.value)
            if id(node) not in benign_prose_node_ids:
                cmd_candidates.append(node.value)
        elif isinstance(node, (ast.BinOp, ast.JoinedStr)) or (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
        ):
            for folded_s in _eval_multi_candidates(node, multi_var_values):
                if folded_s:
                    all_literals.append(folded_s)
                    if id(node) not in benign_prose_node_ids:
                        cmd_candidates.append(folded_s)
        elif isinstance(node, (ast.List, ast.Tuple)):
            parts = [
                elt_str
                for elt in node.elts
                for elt_str in [_eval_workflow_str_expr(elt, const_vars)]
                if elt_str
            ]
            if len(parts) >= 2:
                joined = " ".join(parts)
                all_literals.append(joined)
                if id(node) not in benign_prose_node_ids:
                    cmd_candidates.append(joined)

    def _gov_deny_or(default_reason: str) -> Tuple[Dict[str, Any], List[Tuple[str, str]]]:
        for cand in [*const_vars.values(), *arg_strings, *all_literals]:
            if _path_hits_gov(cand, resolve_rel=False):
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            f"[Harness Governance Shield] Protected governance path (`{cand}`) targeted via "
                            f"prohibited `run_workflow` construct: {default_reason}"
                        ),
                    },
                    [],
                )
        return {"decision": "deny", "reason": default_reason}, []

    if rebound_host_primitive is not None:
        return _gov_deny_or(
            f"[Harness Workflow Shield] Rebinding or redefining host primitive `{rebound_host_primitive}` "
            "inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
        )
    if forbidden_dunder_def is not None:
        return _gov_deny_or(
            f"[Harness Workflow Shield] Defining reflective dunder hook `{forbidden_dunder_def}` inside "
            "`run_workflow` is prohibited (GEMINI.md Rule 15e)."
        )

    # 1. Human-only Guard admin, install.py, and git hook bypasses across workflow Args & non-prose candidates
    for text in cmd_candidates:
        masked_text = _mask_quoted_operators(text)
        if _GUARD_ADMIN_RE.search(masked_text) or _GUARD_INLINE_PY_RE.search(text):
            return (
                {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Human-only `agy-guard` administration commands are "
                        "prohibited inside `run_workflow` (GEMINI.md Rule 12)."
                    ),
                },
                [],
            )
        if _WORKFLOW_INSTALL_EXEC_RE.search(masked_text):
            return (
                {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Executing `install.py` inside `run_workflow` is "
                        "prohibited (GEMINI.md Rule 12)."
                    ),
                },
                [],
            )
        if _GIT_HOOK_BYPASS_RE.search(masked_text):
            return (
                {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Git hook bypass flags (`--no-verify`, `commit -n`, "
                        "`core.hooksPath`, `HUSKY=0`) are prohibited inside `run_workflow`."
                    ),
                },
                [],
            )

    # 2. Collect module aliases, imported callables, dunder/frame/MatchClass escapes, and anti-aliasing structural sets
    os_aliases: set[str] = set()
    environ_aliases: set[str] = set()
    shutil_aliases: set[str] = set()
    io_open_aliases: set[str] = set()
    archive_aliases: set[str] = set()
    sys_aliases: set[str] = set()
    copy_mod_aliases: set[str] = set()
    json_mod_aliases: set[str] = set()
    collections_mod_aliases: set[str] = set()
    namedtuple_factory_names: set[str] = set()
    imported_module_names: set[str] = set()
    safe_imported_callables: Dict[str, int] = {}
    pathlib_names: set[str] = {
        "Path",
        "PurePath",
        "PosixPath",
        "WindowsPath",
        "PurePosixPath",
        "PureWindowsPath",
    }
    imported_os_fs_funcs: set[str] = set()
    imported_shutil_fs_funcs: set[str] = set()
    imported_io_open_funcs: set[str] = set()
    imported_archive_open_funcs: set[str] = set()
    rmtree_funcs: set[str] = set()
    forbidden_child_exec_reason: Optional[str] = None
    forbidden_runtime_escape_reason: Optional[str] = None
    direct_fs_mutation_detected = False
    direct_fs_candidate_paths: List[str] = []

    call_func_node_ids: set[int] = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    attr_value_node_ids: set[int] = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Attribute)}

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in _FORBIDDEN_DUNDER_NAMES:
            forbidden_runtime_escape_reason = (
                f"[Harness Workflow Shield] Introspective/dunder escape (`{node.id}`) inside `run_workflow` "
                "is prohibited (GEMINI.md Rule 15e)."
            )
        elif isinstance(node, ast.Attribute) and (
            node.attr in _FORBIDDEN_DUNDER_NAMES or node.attr in _FORBIDDEN_FRAME_ATTRS
        ):
            forbidden_runtime_escape_reason = (
                f"[Harness Workflow Shield] Introspective/frame/dunder attribute (`{node.attr}`) inside `run_workflow` "
                "is prohibited (GEMINI.md Rule 15e)."
            )
        elif isinstance(node, ast.MatchClass):
            for kwd_attr in node.kwd_attrs:
                if (
                    kwd_attr.startswith("_")
                    or kwd_attr in _FORBIDDEN_DUNDER_NAMES
                    or kwd_attr in _FORBIDDEN_FRAME_ATTRS
                    or kwd_attr in _FORBIDDEN_EXEC_ATTRS
                    or kwd_attr in _FORBIDDEN_REFLECTIVE_ATTRS
                    or kwd_attr in _NON_ALIASABLE_WORKFLOW_NAMES
                    or kwd_attr in _NON_ALIASABLE_FS_ATTRS
                    or kwd_attr in _FORBIDDEN_REEXPORT_ATTRS
                    or kwd_attr in _FORBIDDEN_SYS_ATTRS
                ):
                    forbidden_runtime_escape_reason = (
                        f"[Harness Workflow Shield] `match` class attribute extraction (`{kwd_attr}=`) "
                        "inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                    )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                segments = alias.name.split(".")
                root_mod = segments[0]
                bound = alias.asname or root_mod
                imported_module_names.add(bound)
                if alias.asname is None:
                    imported_module_names.add(root_mod)
                if any(seg in _FORBIDDEN_CHILD_PROC_MODULES for seg in segments) or (
                    root_mod == "asyncio" and len(segments) > 1
                ):
                    forbidden_child_exec_reason = (
                        f"[Harness Workflow Shield] Direct child-process/event-loop submodule (`{alias.name}`) inside "
                        "`run_workflow` scripts bypasses tool-level safety gates; use `call_tool('run_command', ...)` "
                        "or delegated `agent(...)` turns (GEMINI.md Rule 15e)."
                    )
                elif (
                    (root_mod.startswith("_") and root_mod != "__future__")
                    or any(seg.startswith("_") for seg in segments[1:])
                    or any(seg in _FORBIDDEN_WORKFLOW_MODULES for seg in segments)
                    or (root_mod != "__future__" and root_mod not in _ALLOWED_STDLIB_WORKFLOW_MODULES)
                    or (len(segments) > 1 and alias.name != "os.path")
                ):
                    forbidden_runtime_escape_reason = (
                        f"[Harness Workflow Shield] Module `{alias.name}` is prohibited inside `run_workflow` "
                        "orchestration scripts; use `call_tool(...)` or `agent(...)` (GEMINI.md Rule 15e)."
                    )
                elif root_mod == "os":
                    if alias.name == "os":
                        os_aliases.add(bound)
                    elif alias.asname is None:
                        os_aliases.add("os")
                elif root_mod == "shutil":
                    shutil_aliases.add(bound if alias.name == "shutil" else "shutil")
                elif root_mod in ("io", "codecs"):
                    io_open_aliases.add(bound if alias.name == root_mod else root_mod)
                elif root_mod in ("tarfile", "zipfile", "gzip", "bz2", "lzma"):
                    archive_aliases.add(bound if alias.name == root_mod else root_mod)
                elif root_mod == "sys":
                    sys_aliases.add(bound if alias.name == "sys" else "sys")
                elif root_mod == "copy":
                    copy_mod_aliases.add(bound if alias.name == "copy" else "copy")
                elif root_mod == "json":
                    json_mod_aliases.add(bound if alias.name == "json" else "json")
                elif root_mod == "collections":
                    collections_mod_aliases.add(bound if alias.name == "collections" else "collections")
        elif isinstance(node, ast.ImportFrom):
            mod_str = node.module or ""
            segments = mod_str.split(".") if mod_str else []
            root_mod = segments[0] if segments else ""
            if (node.level or 0) > 0:
                forbidden_runtime_escape_reason = (
                    "[Harness Workflow Shield] Relative imports inside `run_workflow` scripts are prohibited (GEMINI.md Rule 15e)."
                )
            elif any(seg in _FORBIDDEN_CHILD_PROC_MODULES for seg in segments) or (
                root_mod == "asyncio" and len(segments) > 1
            ):
                forbidden_child_exec_reason = (
                    f"[Harness Workflow Shield] Direct child-process/event-loop import (`from {mod_str} import ...`) "
                    "inside `run_workflow` bypasses tool-level safety gates; use `call_tool('run_command', ...)` "
                    "or `agent(...)` (GEMINI.md Rule 15e)."
                )
            elif (
                (root_mod.startswith("_") and root_mod != "__future__")
                or any(seg.startswith("_") for seg in segments[1:])
                or any(seg in _FORBIDDEN_WORKFLOW_MODULES for seg in segments)
                or (root_mod != "__future__" and root_mod not in _ALLOWED_STDLIB_WORKFLOW_MODULES)
                or (len(segments) > 1 and mod_str != "os.path")
            ):
                forbidden_runtime_escape_reason = (
                    f"[Harness Workflow Shield] Importing from `{mod_str}` is prohibited inside "
                    "`run_workflow` orchestration scripts (GEMINI.md Rule 15e)."
                )
            else:
                for alias in node.names:
                    local = alias.asname or alias.name
                    if alias.name == "*":
                        forbidden_runtime_escape_reason = (
                            f"[Harness Workflow Shield] Wildcard `from {mod_str} import *` is prohibited inside `run_workflow`."
                        )
                    elif alias.name.startswith("_"):
                        forbidden_runtime_escape_reason = (
                            f"[Harness Workflow Shield] Importing private attribute `{mod_str}.{alias.name}` "
                            "inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                        )
                    elif alias.name in _FORBIDDEN_EXEC_ATTRS:
                        forbidden_child_exec_reason = (
                            f"[Harness Workflow Shield] Direct process/socket primitive (`{mod_str}.{alias.name}`) "
                            "inside `run_workflow` is prohibited; use `call_tool('run_command', ...)` (GEMINI.md Rule 15e)."
                        )
                    elif (
                        alias.name in _FORBIDDEN_DUNDER_NAMES
                        or alias.name in _FORBIDDEN_CALLABLE_BUILTINS
                        or alias.name in _FORBIDDEN_REFLECTIVE_ATTRS
                        or alias.name in _FORBIDDEN_REEXPORT_ATTRS
                        or (root_mod == "json" and alias.name == "tool")
                        or (root_mod == "asyncio" and alias.name == "log")
                        or (root_mod == "functools" and alias.name in ("partial", "partialmethod", "reduce"))
                    ):
                        forbidden_runtime_escape_reason = (
                            f"[Harness Workflow Shield] Importing re-exported/reflective symbol `{mod_str}.{alias.name}` "
                            "inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                        )
                    elif root_mod == "sys" and alias.name in _FORBIDDEN_SYS_ATTRS:
                        forbidden_runtime_escape_reason = (
                            f"[Harness Workflow Shield] Importing `sys.{alias.name}` inside `run_workflow` "
                            "is prohibited (GEMINI.md Rule 15e)."
                        )
                    elif root_mod == "os" and alias.name in ("environ", "environb"):
                        environ_aliases.add(local)
                    elif alias.name == "rmtree":
                        rmtree_funcs.add(local)
                    elif alias.name in ("ZipFile", "PyZipFile", "TarFile", "GzipFile", "BZ2File", "LZMAFile") or (
                        root_mod in ("tarfile", "zipfile", "gzip", "bz2", "lzma") and alias.name == "open"
                    ):
                        imported_archive_open_funcs.add(local)
                    elif alias.name in ("open", "FileIO"):
                        imported_io_open_funcs.add(local)
                    elif alias.name in _FORBIDDEN_DIRECT_FS_ATTRS or alias.name in _FORBIDDEN_OS_FS_NAMES:
                        imported_os_fs_funcs.add(local)
                    elif root_mod == "shutil":
                        imported_shutil_fs_funcs.add(local)
                    elif root_mod == "pathlib" or (root_mod == "zipfile" and alias.name == "Path"):
                        pathlib_names.add(local)
                        safe_imported_callables[local] = safe_imported_callables.get(local, 0) + 1
                    elif mod_str == "os" and alias.name == "path":
                        imported_module_names.add(local)
                    else:
                        safe_imported_callables[local] = safe_imported_callables.get(local, 0) + 1
                        if (root_mod == "collections" and alias.name == "namedtuple") or (
                            root_mod == "typing" and alias.name == "NamedTuple"
                        ):
                            namedtuple_factory_names.add(local)

    if forbidden_child_exec_reason:
        return _gov_deny_or(forbidden_child_exec_reason)
    if forbidden_runtime_escape_reason:
        return _gov_deny_or(forbidden_runtime_escape_reason)

    def _is_environ_expr(expr: ast.AST) -> bool:
        if isinstance(expr, ast.Attribute) and expr.attr in ("environ", "environb"):
            return True
        if isinstance(expr, ast.Name) and expr.id in environ_aliases:
            return True
        return False

    safe_environ_node_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load) and _is_environ_expr(node.value):
            safe_environ_node_ids.add(id(node.value))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _SAFE_ENVIRON_READ_METHODS
            and _is_environ_expr(node.func.value)
        ):
            safe_environ_node_ids.add(id(node.func.value))
        elif isinstance(node, ast.Compare) and all(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
            for comp in node.comparators:
                if _is_environ_expr(comp):
                    safe_environ_node_ids.add(id(comp))

    guarded_imported_funcs = (
        rmtree_funcs
        | imported_os_fs_funcs
        | imported_shutil_fs_funcs
        | imported_io_open_funcs
        | imported_archive_open_funcs
    )
    guarded_module_aliases = (
        imported_module_names
        | os_aliases
        | shutil_aliases
        | io_open_aliases
        | archive_aliases
        | sys_aliases
        | copy_mod_aliases
        | json_mod_aliases
    )

    for node in ast.walk(tree):
        if _is_environ_expr(node) and id(node) not in safe_environ_node_ids:
            return _gov_deny_or(
                "[Harness Workflow Shield] Mutating or aliasing `os.environ` inside `run_workflow` "
                "is prohibited (GEMINI.md Rule 15e)."
            )
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in _PROTECTED_HOST_PRIMITIVES:
                return _gov_deny_or(
                    f"[Harness Workflow Shield] Rebinding host primitive `{node.id}` inside "
                    "`run_workflow` is prohibited (GEMINI.md Rule 15e)."
                )
            if isinstance(node.ctx, ast.Load):
                if (
                    node.id in _NON_ALIASABLE_WORKFLOW_NAMES
                    or node.id in guarded_imported_funcs
                    or node.id in persistent_agents
                ) and (id(node) not in call_func_node_ids):
                    return _gov_deny_or(
                        f"[Harness Workflow Shield] Aliasing or passing primitive `{node.id}` as a "
                        "first-class value inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                    )
                if node.id in guarded_module_aliases and id(node) not in attr_value_node_ids:
                    return _gov_deny_or(
                        f"[Harness Workflow Shield] Aliasing or passing module `{node.id}` as a "
                        "first-class value inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                    )
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if isinstance(node.value, ast.Attribute) and node.value.attr in ("environ", "environb"):
                return _gov_deny_or(
                    "[Harness Workflow Shield] Mutating `os.environ` inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                )
        elif isinstance(node, ast.Attribute):
            if node.attr in _FORBIDDEN_EXEC_ATTRS:
                return _gov_deny_or(
                    f"[Harness Workflow Shield] Direct child-process primitive (`.{node.attr}`) inside "
                    "`run_workflow` bypasses tool-level safety gates; use `call_tool('run_command', ...)` "
                    "or delegated `agent(...)` turns (GEMINI.md Rule 15e)."
                )
            if node.attr in _FORBIDDEN_REFLECTIVE_ATTRS:
                return _gov_deny_or(
                    f"[Harness Workflow Shield] Reflective/dynamic execution attribute (`.{node.attr}`) "
                    "inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                )
            if (
                node.attr in _FORBIDDEN_REEXPORT_ATTRS
                or (
                    node.attr.startswith("_")
                    and node.attr not in ("_asdict", "_replace", "_fields", "_field_defaults")
                )
                or (
                    node.attr == "tool"
                    and isinstance(node.value, ast.Name)
                    and node.value.id in json_mod_aliases
                )
            ):
                return _gov_deny_or(
                    f"[Harness Workflow Shield] Re-exported or private module attribute traversal (`.{node.attr}`) "
                    "inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                )
            if node.attr in _UNCONDITIONAL_FORBIDDEN_SYS_ATTRS or (
                isinstance(node.value, ast.Name)
                and node.value.id in sys_aliases
                and node.attr in _FORBIDDEN_SYS_ATTRS
            ):
                return _gov_deny_or(
                    f"[Harness Workflow Shield] Accessing `sys.{node.attr}` inside `run_workflow` "
                    "is prohibited (GEMINI.md Rule 15e)."
                )
            if (
                isinstance(node.ctx, ast.Load)
                and id(node) not in call_func_node_ids
                and node.attr in _NON_ALIASABLE_FS_ATTRS
            ):
                return _gov_deny_or(
                    f"[Harness Workflow Shield] Aliasing or referencing filesystem/I/O method (`.{node.attr}`) "
                    "without a direct call inside `run_workflow` is prohibited (GEMINI.md Rule 15e)."
                )

    flight_writes: List[Tuple[str, str]] = []
    force_ask_reasons: List[str] = []
    rmtree_calls: List[ast.Call] = []
    indirect_call_reason: Optional[str] = None

    # 3. Inspect all AST calls for child-process escapes, direct Python writes, `rmtree`, `call_tool`, and `agent`
    raw_agent_call_nodes: List[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not isinstance(node.func, (ast.Name, ast.Attribute)) and _unwrap_agent_call(node.func, allow_await=True) is None:
            for arg_node in node.args[:2]:
                p = _eval_workflow_path_expr(arg_node, const_vars)
                if p:
                    direct_fs_candidate_paths.append(p)
            indirect_call_reason = (
                "[Harness Workflow Shield] Indirect/computed call targets (such as container indexing or "
                "factory chaining) inside `run_workflow` are prohibited so safety gates can inspect every call "
                "(GEMINI.md Rule 15e)."
            )
            continue

        if isinstance(node.func, ast.Name):
            fn = node.func.id
            if fn in _FORBIDDEN_CALLABLE_BUILTINS:
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            f"[Harness Workflow Shield] Dynamic/reflective builtin `{fn}()` is prohibited "
                            "inside `run_workflow` (GEMINI.md Rule 15e)."
                        ),
                    },
                    [],
                )
            if fn in rmtree_funcs:
                rmtree_calls.append(node)
                continue
            if fn in imported_os_fs_funcs or fn in imported_shutil_fs_funcs:
                direct_fs_mutation_detected = True
                for arg_node in node.args[:2]:
                    p = _eval_workflow_path_expr(arg_node, const_vars)
                    if p:
                        direct_fs_candidate_paths.append(p)
                continue
            if fn in imported_io_open_funcs or fn == "open":
                if not _is_readonly_open_call(node, 1, const_vars):
                    direct_fs_mutation_detected = True
                    if node.args:
                        p = _eval_workflow_path_expr(node.args[0], const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                    for kw in node.keywords:
                        if kw.arg == "file":
                            p = _eval_workflow_path_expr(kw.value, const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                continue
            if fn in imported_archive_open_funcs:
                if not _is_readonly_open_call(node, 1, const_vars, archive=True):
                    direct_fs_mutation_detected = True
                    if node.args:
                        p = _eval_workflow_path_expr(node.args[0], const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                continue
            if fn == "call_tool":
                if len(node.args) != 1 or isinstance(node.args[0], ast.Starred):
                    return (
                        {
                            "decision": "deny",
                            "reason": (
                                "[Harness Workflow Shield] `call_tool()` inside `run_workflow` requires "
                                "exactly one positional tool-name string and static keyword arguments."
                            ),
                        },
                        [],
                    )
                inner_name = _eval_workflow_str_expr(node.args[0], const_vars)
                if not inner_name or not inner_name.strip():
                    return (
                        {
                            "decision": "deny",
                            "reason": (
                                "[Harness Workflow Shield] `call_tool()` inside `run_workflow` must specify a "
                                "static string tool name so safety gates can inspect it."
                            ),
                        },
                        [],
                    )
                inner_tool = inner_name.strip().lower().rsplit(":", 1)[-1]
                if inner_tool == "run_workflow":
                    return (
                        {
                            "decision": "deny",
                            "reason": (
                                "[Harness Workflow Shield] Nested `call_tool('run_workflow', ...)` inside "
                                "`run_workflow` is prohibited."
                            ),
                        },
                        [],
                    )
                static_kwargs: Dict[str, Any] = {}
                has_dynamic_kw = False
                for kw in node.keywords:
                    if kw.arg is None:
                        has_dynamic_kw = True
                        continue
                    const_val, const_ok = _eval_workflow_const_value(kw.value, const_vars)
                    if const_ok:
                        static_kwargs[kw.arg] = const_val
                    else:
                        has_dynamic_kw = True

                if inner_tool in WRITE_TOOL_NAMES:
                    targets = _extract_write_targets(static_kwargs)
                    if not targets or has_dynamic_kw:
                        for cand in [*targets, *arg_strings, *all_literals]:
                            if _path_hits_gov(cand, resolve_rel=(cand in targets)):
                                return (
                                    {
                                        "decision": "deny",
                                        "reason": (
                                            "[Harness Governance Shield] Direct write to the protected governance tree "
                                            f"(`{cand}`) inside `run_workflow` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                                        ),
                                    },
                                    [],
                                )
                        return (
                            {
                                "decision": "deny",
                                "reason": (
                                    f"[Harness Workflow Shield] `call_tool('{inner_name}', ...)` inside `run_workflow` "
                                    "must pass static arguments (including `Path`) so Governance Shield and Flight Recorder can verify the write."
                                ),
                            },
                            [],
                        )
                    for target in targets:
                        if "\x00" in target:
                            return (
                                {
                                    "decision": "deny",
                                    "reason": "[Harness Workflow Shield] Null bytes in `call_tool` target paths are prohibited.",
                                },
                                [],
                            )
                        if _path_hits_gov(target, resolve_rel=True):
                            return (
                                {
                                    "decision": "deny",
                                    "reason": (
                                        "[Harness Governance Shield] Direct write to the protected governance tree "
                                        f"(`{target}`) inside `run_workflow` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                                    ),
                                },
                                [],
                            )
                    if any(_path_hits_cust(target, resolve_rel=True) for target in targets):
                        mod_eval = _evaluate_customization_model_and_effort(payload)
                        if mod_eval is not None:
                            if mod_eval[0] == "deny":
                                return {"decision": "deny", "reason": mod_eval[1]}, []
                            force_ask_reasons.append(mod_eval[1])
                    for target in targets:
                        if _write_mutates_authorized_test_section(target, static_kwargs, eff_cwd):
                            force_ask_reasons.append(
                                "[Harness Test Boundary] Modifying `## Authorized Test Modifications` in `tasks.md` "
                                "requires explicit human confirmation (GEMINI.md Rule 9)."
                            )
                        exp_t = Path(os.path.expanduser(target.strip()))
                        rec_t = str(eff_cwd / exp_t) if (not exp_t.is_absolute() and eff_cwd is not None) else target
                        flight_writes.append((inner_tool, rec_t))
                elif inner_tool in COMMAND_TOOL_NAMES:
                    if has_dynamic_kw:
                        return (
                            {
                                "decision": "deny",
                                "reason": (
                                    f"[Harness Workflow Shield] `call_tool('{inner_name}', ...)` inside `run_workflow` "
                                    "must pass static command arguments or delegate to `agent(...)`."
                                ),
                            },
                            [],
                        )
                    if inner_tool == "manage_task":
                        mt_act = str(static_kwargs.get("Action") or static_kwargs.get("action") or "").strip().lower()
                        mt_inp = str(static_kwargs.get("Input") or static_kwargs.get("input") or "").strip()
                        if mt_act not in ("list", "status", "kill") and not mt_inp:
                            return (
                                {
                                    "decision": "deny",
                                    "reason": (
                                        "[Harness Workflow Shield] `call_tool('manage_task', ...)` inside `run_workflow` "
                                        "requires an explicit `Action` (`list`/`status`/`kill` or non-empty `send_input`)."
                                    ),
                                },
                                [],
                            )
                    elif inner_tool == "send_command_input":
                        sci_inp = str(
                            static_kwargs.get("Input")
                            or static_kwargs.get("input")
                            or static_kwargs.get("CommandLine")
                            or static_kwargs.get("command")
                            or ""
                        ).strip()
                        if not sci_inp:
                            return (
                                {
                                    "decision": "deny",
                                    "reason": (
                                        "[Harness Workflow Shield] `call_tool('send_command_input', ...)` inside "
                                        "`run_workflow` requires a non-empty static `Input` string."
                                    ),
                                },
                                [],
                            )
                    else:
                        rc_cmd = str(static_kwargs.get("CommandLine") or static_kwargs.get("command") or "").strip()
                        if not rc_cmd:
                            return (
                                {
                                    "decision": "deny",
                                    "reason": (
                                        f"[Harness Workflow Shield] `call_tool('{inner_name}', ...)` inside "
                                        "`run_workflow` requires a non-empty static `CommandLine` string."
                                    ),
                                },
                                [],
                            )
                    inner_payload = {
                        **payload,
                        "_workflowDryCheck": True,
                        **({"cwd": str(eff_cwd)} if eff_cwd is not None else {}),
                        "toolCall": {"name": inner_tool, "args": static_kwargs},
                    }
                    inner_res = handle_pre_tool_use(inner_payload)
                    if inner_res.get("decision") == "deny":
                        return inner_res, []
                    if inner_res.get("decision") == "force_ask":
                        force_ask_reasons.append(str(inner_res.get("reason") or "Confirmation required."))
                elif inner_tool == "invoke_subagent":
                    if has_dynamic_kw:
                        return (
                            {
                                "decision": "deny",
                                "reason": (
                                    "[Harness Workflow Shield] `call_tool('invoke_subagent', ...)` inside "
                                    "`run_workflow` must pass static arguments."
                                ),
                            },
                            [],
                        )
                    inner_res = handle_pre_tool_use(
                        {
                            **payload,
                            "_workflowDryCheck": True,
                            **({"cwd": str(eff_cwd)} if eff_cwd is not None else {}),
                            "toolCall": {"name": "invoke_subagent", "args": static_kwargs},
                        }
                    )
                    if inner_res.get("decision") == "deny":
                        return inner_res, []
                    if inner_res.get("decision") == "force_ask":
                        force_ask_reasons.append(str(inner_res.get("reason") or "Confirmation required."))
                elif inner_tool == "call_mcp_tool" or inner_tool.startswith("mcp_"):
                    if has_dynamic_kw:
                        return (
                            {
                                "decision": "deny",
                                "reason": (
                                    f"[Harness Workflow Shield] `call_tool('{inner_name}', ...)` inside "
                                    "`run_workflow` must pass static arguments so MCP safety gates can inspect it."
                                ),
                            },
                            [],
                        )
                    inner_res = handle_pre_tool_use(
                        {
                            **payload,
                            "_workflowDryCheck": True,
                            **({"cwd": str(eff_cwd)} if eff_cwd is not None else {}),
                            "toolCall": {"name": inner_tool, "args": static_kwargs},
                        }
                    )
                    if inner_res.get("decision") == "deny":
                        return inner_res, []
                    if inner_res.get("decision") == "force_ask":
                        force_ask_reasons.append(str(inner_res.get("reason") or "Confirmation required."))
                    mcp_nested = (
                        static_kwargs.get("Arguments")
                        if isinstance(static_kwargs.get("Arguments"), dict)
                        else (
                            static_kwargs.get("arguments")
                            if isinstance(static_kwargs.get("arguments"), dict)
                            else static_kwargs
                        )
                    )
                    for mcp_t in _extract_mcp_target_paths(mcp_nested):
                        exp_mt = Path(os.path.expanduser(mcp_t.strip()))
                        rec_mt = str(eff_cwd / exp_mt) if (not exp_mt.is_absolute() and eff_cwd is not None) else mcp_t
                        flight_writes.append((inner_tool, rec_mt))
                continue
            if fn == "agent":
                raw_agent_call_nodes.append(node)
                continue
            if fn in persistent_agents and len(persistent_agents[fn]) == store_counts.get(fn, 0):
                if node.args:
                    persistent_agent_turn_nodes[fn].append(node.args[0])
                for kw in node.keywords:
                    if kw.arg == "prompt":
                        persistent_agent_turn_nodes[fn].append(kw.value)
                continue

            is_namedtuple_ctor = False
            if store_counts.get(fn, 0) == 1 and isinstance(single_rhs.get(fn), ast.Call):
                rhs_call = single_rhs[fn]
                assert isinstance(rhs_call, ast.Call)
                if (
                    isinstance(rhs_call.func, ast.Name)
                    and rhs_call.func.id in namedtuple_factory_names
                    and store_counts.get(rhs_call.func.id, 0) == 1
                ) or (
                    isinstance(rhs_call.func, ast.Attribute)
                    and rhs_call.func.attr == "namedtuple"
                    and isinstance(rhs_call.func.value, ast.Name)
                    and rhs_call.func.value.id in collections_mod_aliases
                    and store_counts.get(rhs_call.func.value.id, 0) == 1
                ):
                    is_namedtuple_ctor = True

            is_verified_name_call = (
                (fn in _SAFE_WORKFLOW_HOST_CALLABLES and bind_counts.get(fn, 0) == 0)
                or (fn in _SAFE_WORKFLOW_BUILTINS and bind_counts.get(fn, 0) == 0)
                or (fn in local_callable_defs and local_callable_defs[fn] == store_counts.get(fn, 0))
                or (fn in safe_imported_callables and safe_imported_callables[fn] == store_counts.get(fn, 0))
                or is_namedtuple_ctor
            )
            if not is_verified_name_call:
                return _gov_deny_or(
                    f"[Harness Workflow Shield] Calling dynamically bound or unverified symbol `{fn}()` "
                    "inside `run_workflow` is prohibited so safety gates can inspect every call (GEMINI.md Rule 15e)."
                )
            continue

        elif isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            recv = node.func.value
            recv_name = recv.id if isinstance(recv, ast.Name) else ""

            if attr in _FORBIDDEN_EXEC_ATTRS:
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            f"[Harness Workflow Shield] Direct child-process execution (`.{attr}()`) inside "
                            "`run_workflow` bypasses tool-level safety gates; use `call_tool('run_command', ...)` "
                            "or delegated `agent(...)` turns (GEMINI.md Rule 15e)."
                        ),
                    },
                    [],
                )
            if attr == "rmtree":
                rmtree_calls.append(node)
                continue
            if attr in _FORBIDDEN_DIRECT_FS_ATTRS:
                direct_fs_mutation_detected = True
                recv_path = _eval_workflow_path_expr(recv, const_vars)
                if recv_path:
                    direct_fs_candidate_paths.append(recv_path)
                for arg_node in node.args[:2]:
                    p = _eval_workflow_path_expr(arg_node, const_vars)
                    if p:
                        direct_fs_candidate_paths.append(p)
                for kw in node.keywords:
                    if kw.arg in ("src", "dst", "target", "target_dir", "path"):
                        p = _eval_workflow_path_expr(kw.value, const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                continue
            if attr == "replace":
                has_star = any(isinstance(a, ast.Starred) for a in node.args) or any(
                    kw.arg is None for kw in node.keywords
                )
                is_path_replace = (
                    recv_name in pathlib_names
                    or (isinstance(recv, ast.Attribute) and recv.attr in pathlib_names)
                    or (len(node.args) == 1 and not node.keywords)
                    or (len(node.args) == 0 and any(kw.arg == "target" for kw in node.keywords))
                    or has_star
                )
                if recv_name in os_aliases or is_path_replace:
                    direct_fs_mutation_detected = True
                    recv_path = _eval_workflow_path_expr(recv, const_vars)
                    if recv_path:
                        direct_fs_candidate_paths.append(recv_path)
                    for arg_node in node.args[:2]:
                        p = _eval_workflow_path_expr(arg_node, const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                    for kw in node.keywords:
                        if kw.arg in ("target", "dst"):
                            p = _eval_workflow_path_expr(kw.value, const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                continue
            if attr in ("remove", "truncate", "ftruncate", "link", "utime") and recv_name in os_aliases:
                direct_fs_mutation_detected = True
                for arg_node in node.args[:2]:
                    p = _eval_workflow_path_expr(arg_node, const_vars)
                    if p:
                        direct_fs_candidate_paths.append(p)
                continue
            if attr == "copy" and (
                recv_name in shutil_aliases
                or len(node.args) >= 2
                or ((bool(node.args) or bool(node.keywords)) and recv_name not in copy_mod_aliases)
            ):
                direct_fs_mutation_detected = True
                recv_path = _eval_workflow_path_expr(recv, const_vars)
                if recv_path:
                    direct_fs_candidate_paths.append(recv_path)
                for arg_node in node.args[:2]:
                    p = _eval_workflow_path_expr(arg_node, const_vars)
                    if p:
                        direct_fs_candidate_paths.append(p)
                for kw in node.keywords:
                    if kw.arg in ("src", "dst", "target"):
                        p = _eval_workflow_path_expr(kw.value, const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                continue
            if attr == "FileIO":
                if not _is_readonly_open_call(node, 1, const_vars):
                    direct_fs_mutation_detected = True
                    if node.args:
                        p = _eval_workflow_path_expr(node.args[0], const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                    for kw in node.keywords:
                        if kw.arg == "file":
                            p = _eval_workflow_path_expr(kw.value, const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                continue
            if attr in ("ZipFile", "PyZipFile", "TarFile", "GzipFile", "BZ2File", "LZMAFile"):
                if not _is_readonly_open_call(node, 1, const_vars, archive=True):
                    direct_fs_mutation_detected = True
                    if node.args:
                        p = _eval_workflow_path_expr(node.args[0], const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                    for kw in node.keywords:
                        if kw.arg in ("file", "name"):
                            p = _eval_workflow_path_expr(kw.value, const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                continue
            if attr == "open":
                is_unbound_path_open = recv_name in pathlib_names or (
                    isinstance(recv, ast.Attribute) and recv.attr in pathlib_names
                )
                if recv_name in os_aliases:
                    direct_fs_mutation_detected = True
                    if node.args:
                        p = _eval_workflow_path_expr(node.args[0], const_vars)
                        if p:
                            direct_fs_candidate_paths.append(p)
                    for kw in node.keywords:
                        if kw.arg in ("path", "file"):
                            p = _eval_workflow_path_expr(kw.value, const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                elif recv_name in io_open_aliases:
                    if not _is_readonly_open_call(node, 1, const_vars):
                        direct_fs_mutation_detected = True
                        if node.args:
                            p = _eval_workflow_path_expr(node.args[0], const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                elif recv_name in archive_aliases:
                    if not _is_readonly_open_call(node, 1, const_vars, archive=True):
                        direct_fs_mutation_detected = True
                        if node.args:
                            p = _eval_workflow_path_expr(node.args[0], const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                elif is_unbound_path_open:
                    if not _is_readonly_open_call(node, 1, const_vars):
                        direct_fs_mutation_detected = True
                        if node.args:
                            p = _eval_workflow_path_expr(node.args[0], const_vars)
                            if p:
                                direct_fs_candidate_paths.append(p)
                else:
                    # Bound `Path(...).open(mode='r', ...)` has `mode` at positional index 0
                    if not _is_readonly_open_call(node, 0, const_vars):
                        direct_fs_mutation_detected = True
                        recv_path = _eval_workflow_path_expr(recv, const_vars)
                        if recv_path:
                            direct_fs_candidate_paths.append(recv_path)
                continue

    if direct_fs_mutation_detected:
        for cand in [*direct_fs_candidate_paths, *const_vars.values()]:
            if _path_hits_gov(cand, resolve_rel=True):
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            "[Harness Governance Shield] Direct Python mutation of protected governance path "
                            f"(`{cand}`) inside `run_workflow` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                        ),
                    },
                    [],
                )
        for cand in [*arg_strings, *all_literals]:
            if _path_hits_gov(cand, resolve_rel=False):
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            "[Harness Governance Shield] Direct Python mutation of protected governance path "
                            f"(`{cand}`) inside `run_workflow` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                        ),
                    },
                    [],
                )
        return (
            {
                "decision": "deny",
                "reason": (
                    "[Harness Workflow Shield] Direct Python filesystem writes/mutations inside `run_workflow` "
                    "bypass tool-level safety and Flight Recorder gates; use `call_tool('write_file', ...)` "
                    "or `agent(...)` instead (GEMINI.md Rule 15e)."
                ),
            },
            [],
        )

    if indirect_call_reason:
        return _gov_deny_or(indirect_call_reason)

    for rmtree_node in rmtree_calls:
        if any(isinstance(a, ast.Starred) for a in rmtree_node.args) or any(
            kw.arg is None for kw in rmtree_node.keywords
        ):
            resolved_rm = None
        else:
            target_arg = rmtree_node.args[0] if rmtree_node.args else None
            if target_arg is None:
                for kw in rmtree_node.keywords:
                    if kw.arg == "path":
                        target_arg = kw.value
                        break
            resolved_rm = _eval_workflow_path_expr(target_arg, const_vars)
        if resolved_rm is None:
            if eff_cwd is not None and _targets_governance_dir(str(eff_cwd)):
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            "[Harness Governance Shield] Recursive deletion inside protected governance Cwd "
                            f"(`{eff_cwd}`) inside `run_workflow` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                        ),
                    },
                    [],
                )
            for cand in [*const_vars.values(), *arg_strings, *all_literals]:
                if _path_hits_gov(cand, resolve_rel=False):
                    return (
                        {
                            "decision": "deny",
                            "reason": (
                                "[Harness Governance Shield] Recursive deletion targeting protected governance path "
                                f"(`{cand}`) inside `run_workflow` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                            ),
                        },
                        [],
                    )
            return (
                {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] `shutil.rmtree()` inside `run_workflow` requires a static "
                        "path literal so Governance Shield can verify the target (GEMINI.md Rule 12 & Rule 15e)."
                    ),
                },
                [],
            )
        if _path_hits_gov(resolved_rm, resolve_rel=True):
            return (
                {
                    "decision": "deny",
                    "reason": (
                        "[Harness Governance Shield] Recursive deletion of protected governance path "
                        f"(`{resolved_rm}`) inside `run_workflow` is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                    ),
                },
                [],
            )
        if _path_hits_cust(resolved_rm, resolve_rel=True):
            mod_eval = _evaluate_customization_model_and_effort(payload)
            if mod_eval is not None:
                if mod_eval[0] == "deny":
                    return {"decision": "deny", "reason": mod_eval[1]}, []
                force_ask_reasons.append(mod_eval[1])
        force_ask_reasons.append(
            "[Harness Workflow Shield] Recursive directory deletion (`shutil.rmtree`) inside `run_workflow` "
            "requires explicit human confirmation (GEMINI.md Rule 12)."
        )

    # 4. Enforce Customization Model Gate on one-shot, persistent (`var = agent(...)`), and chained `agent(...)(...)` calls
    def _agent_has_oneshot_prompt(ag_call: ast.Call) -> bool:
        if any(isinstance(a, ast.Starred) for a in ag_call.args) or any(k.arg is None for k in ag_call.keywords):
            return False
        prompt_arg: Optional[ast.AST] = ag_call.args[0] if ag_call.args else None
        if prompt_arg is None:
            for k in ag_call.keywords:
                if k.arg == "prompt":
                    prompt_arg = k.value
                    break
        if prompt_arg is None:
            return False
        folded_prompt = _eval_workflow_str_expr(prompt_arg, const_vars)
        if folded_prompt is not None:
            return bool(folded_prompt.strip())
        if isinstance(prompt_arg, ast.JoinedStr):
            return True
        if isinstance(prompt_arg, ast.BinOp) and isinstance(prompt_arg.op, ast.Add):
            frag, _ = _extract_partial_text_and_dynamic(prompt_arg, const_vars)
            return bool(frag.strip())
        return False

    def _direct_parallel_agent_calls(par_call: ast.Call) -> List[ast.Call]:
        found: List[ast.Call] = []
        for par_arg in par_call.args:
            cand = _unwrap_agent_call(par_arg, allow_await=True)
            if cand is not None:
                found.append(cand)
            elif isinstance(par_arg, ast.Lambda):
                lam_cand = _unwrap_agent_call(par_arg.body, allow_await=True)
                if lam_cand is not None:
                    found.append(lam_cand)
            elif isinstance(par_arg, (ast.List, ast.Tuple)):
                for elt in par_arg.elts:
                    elt_cand = _unwrap_agent_call(elt, allow_await=True)
                    if elt_cand is not None:
                        found.append(elt_cand)
                    elif isinstance(elt, ast.Lambda):
                        lam_cand = _unwrap_agent_call(elt.body, allow_await=True)
                        if lam_cand is not None:
                            found.append(lam_cand)
            elif isinstance(par_arg, (ast.ListComp, ast.GeneratorExp)):
                comp_cand = _unwrap_agent_call(par_arg.elt, allow_await=True)
                if comp_cand is not None:
                    found.append(comp_cand)
                elif isinstance(par_arg.elt, ast.Lambda):
                    lam_cand = _unwrap_agent_call(par_arg.elt.body, allow_await=True)
                    if lam_cand is not None:
                        found.append(lam_cand)
        return found

    call_to_vars: Dict[int, List[str]] = {}
    allowed_agent_call_ids: set[int] = set(chained_agent_turns.keys())
    for var_name, ag_list in persistent_agents.items():
        for ag_c in ag_list:
            call_to_vars.setdefault(id(ag_c), []).append(var_name)
            allowed_agent_call_ids.add(id(ag_c))
    for n in ast.walk(tree):
        if isinstance(n, ast.Await):
            aw_ag = _unwrap_agent_call(n.value, allow_await=False)
            if aw_ag is not None and _agent_has_oneshot_prompt(aw_ag):
                allowed_agent_call_ids.add(id(aw_ag))
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("parallel", "pipeline"):
            for sub in _direct_parallel_agent_calls(n):
                if _agent_has_oneshot_prompt(sub):
                    allowed_agent_call_ids.add(id(sub))

    for ag_node in raw_agent_call_nodes:
        if id(ag_node) not in allowed_agent_call_ids:
            return (
                {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Persistent `agent()` handles inside `run_workflow` must be "
                        "bound directly to a variable name (`var = agent(...)`) or awaited directly so safety "
                        "gates can inspect every turn (GEMINI.md Rule 15e & Rule 17)."
                    ),
                },
                [],
            )
        extra_prompt_nodes: List[ast.AST] = list(chained_agent_turns.get(id(ag_node), []))
        for var_name in call_to_vars.get(id(ag_node), ()):
            extra_prompt_nodes.extend(persistent_agent_turn_nodes.get(var_name, []))

        # Signature: agent(prompt=None, schema=None, role=None, type_name="self", workspace="inherit", model=None)
        model_node: Optional[ast.AST] = ag_node.args[5] if len(ag_node.args) >= 6 else None
        type_node: Optional[ast.AST] = ag_node.args[3] if len(ag_node.args) >= 4 else None
        prompt_nodes: List[ast.AST] = list(extra_prompt_nodes)
        if ag_node.args:
            prompt_nodes.append(ag_node.args[0])
        if len(ag_node.args) >= 3:
            prompt_nodes.append(ag_node.args[2])
        has_star_kw = any(isinstance(a, ast.Starred) for a in ag_node.args)
        for kw in ag_node.keywords:
            if kw.arg is None:
                has_star_kw = True
            elif kw.arg == "model":
                model_node = kw.value
            elif kw.arg == "type_name":
                type_node = kw.value
            elif kw.arg in ("prompt", "role"):
                prompt_nodes.append(kw.value)

        model_dynamic = has_star_kw
        if model_node is None or (isinstance(model_node, ast.Constant) and model_node.value is None):
            model_tier = "inherit"
        else:
            eval_m = _eval_workflow_str_expr(model_node, const_vars)
            if eval_m is None:
                model_tier = ""
                model_dynamic = True
            else:
                model_tier = eval_m.strip().lower()

        if type_node is None or (isinstance(type_node, ast.Constant) and type_node.value is None):
            agent_type = "self"
        else:
            type_val = _eval_workflow_str_expr(type_node, const_vars)
            agent_type = type_val.strip().lower() if type_val is not None else "__dynamic__"
        if has_star_kw and type_node is None:
            agent_type = "__dynamic__"

        prompt_fragments: List[str] = []
        prompt_has_dynamic = False
        for p_node in prompt_nodes:
            frag, is_dyn = _extract_partial_text_and_dynamic(p_node, const_vars)
            if frag:
                prompt_fragments.append(frag)
            for multi_frag in _eval_multi_candidates(p_node, multi_var_values):
                if multi_frag and multi_frag not in prompt_fragments:
                    prompt_fragments.append(multi_frag)
            for sub_p in ast.walk(p_node):
                if isinstance(sub_p, ast.Name) and sub_p.id in multi_var_values:
                    for mv_cand in multi_var_values[sub_p.id]:
                        if mv_cand and mv_cand not in prompt_fragments:
                            prompt_fragments.append(mv_cand)
            if is_dyn:
                prompt_has_dynamic = True

        parent_cust_eval = _evaluate_customization_model_and_effort(payload) if agent_type != "research" else None
        parent_model_fails_cust = parent_cust_eval is not None
        agent_fails_cust_gate = (
            model_dynamic
            or model_tier in ("flash", "flash_lite")
            or (agent_type != "research" and model_tier not in ("", "none", "inherit"))
            or parent_model_fails_cust
        )

        haystacks = list(prompt_fragments)
        if prompt_has_dynamic or model_dynamic:
            haystacks.extend(arg_strings)
            if agent_fails_cust_gate:
                haystacks.extend(all_literals)

        combined_prompt = " ".join(haystacks)
        targets_cust = (
            bool(re.search(_CUST_CMD_TARGET_PAT, combined_prompt))
            or any(
                _targets_customization_structure(tok, workspace=workspace) or _targets_governance_dir(tok)
                for tok in haystacks
            )
            or (
                eff_cwd is not None
                and (
                    _targets_governance_dir(str(eff_cwd))
                    or _targets_customization_structure(str(eff_cwd), workspace=workspace)
                )
            )
        )
        if targets_cust and agent_type != "research":
            if model_dynamic:
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            "[Harness Customization Model Gate] `run_workflow` `agent()` targeting "
                            "customization or governance files must specify literal `model='inherit'` "
                            "(GEMINI.md Rule 15e & Rule 17)."
                        ),
                    },
                    [],
                )
            if model_tier in ("flash", "flash_lite") or model_tier not in ("", "none", "inherit"):
                return (
                    {
                        "decision": "deny",
                        "reason": (
                            "[Harness Customization Model Gate] `run_workflow` cannot delegate "
                            f"customization or governance modifications to downgraded model tier `{model_tier}` "
                            "(GEMINI.md Rule 15e & Rule 17)."
                        ),
                    },
                    [],
                )
            if parent_cust_eval is not None:
                if parent_cust_eval[0] == "deny":
                    return {"decision": "deny", "reason": parent_cust_eval[1]}, []
                force_ask_reasons.append(parent_cust_eval[1])

    # 5. Prompt (`force_ask`) on destructive shell patterns, unpinned remote packages, or `shutil.rmtree`
    for text in cmd_candidates:
        unquoted_t = _unquote_single_tokens(text)
        for pattern, reason in _DESTRUCTIVE_CMD_PATTERNS:
            if pattern.search(unquoted_t):
                force_ask_reasons.append(f"[Harness Workflow Shield] {reason}")
                break
        unpinned_reason = _detect_unpinned_package_exec(unquoted_t)
        if unpinned_reason:
            force_ask_reasons.append(f"[Harness Workflow Shield] {unpinned_reason}")

    if force_ask_reasons:
        return {"decision": "force_ask", "reason": force_ask_reasons[0]}, []

    return {"decision": "allow"}, flight_writes


def _payload_cwd(payload: Dict[str, Any], args: Dict[str, Any]) -> Optional[Path]:
    for container in (args, payload):
        if not isinstance(container, dict):
            continue
        for key in ("cwd", "Cwd", "workingDirectory", "working_directory"):
            val = container.get(key)
            if isinstance(val, str) and val.strip():
                return Path(os.path.expanduser(val.strip()))
    return None


def _cmd_input_buffer_key(payload: Dict[str, Any], args: Dict[str, Any]) -> str:
    conv_id = _conversation_id(payload)
    task_id = (
        str(
            args.get("TaskId")
            or args.get("taskId")
            or args.get("task_id")
            or args.get("CommandId")
            or "default"
        ).strip()
        or "default"
    )
    return f"{conv_id}::{task_id}"


def _has_unclosed_shell_quote(text: str) -> bool:
    in_sq = False
    in_dq = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_sq:
            if ch == "'":
                in_sq = False
            i += 1
            continue
        if in_dq:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_dq = False
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch == "'":
            in_sq = True
        elif ch == '"':
            in_dq = True
        i += 1
    return in_sq or in_dq


def _compute_trailing_cmd_buffer(combined_input: str) -> str:
    folded = _join_shell_line_continuations(combined_input)
    if _has_unclosed_shell_quote(folded):
        return folded[-4096:]
    return folded.rsplit("\n", 1)[-1].rsplit("\r", 1)[-1][-4096:]


def _load_cmd_input_prefix(payload: Dict[str, Any], args: Dict[str, Any]) -> Tuple[str, str]:
    buf_key = _cmd_input_buffer_key(payload, args)
    buf_file = state_dir() / "cmd_input_buffers.json"
    data = read_json(buf_file, default={})
    if not isinstance(data, dict):
        return buf_key, ""
    val = data.get(buf_key)
    return buf_key, (val if isinstance(val, str) else "")


def _save_cmd_input_prefix(buf_key: str, combined_input: str) -> None:
    trailing = _compute_trailing_cmd_buffer(combined_input)
    buf_file = state_dir() / "cmd_input_buffers.json"
    try:
        with file_lock(buf_file, timeout=HOOK_LOCK_TIMEOUT):
            data = read_json(buf_file, default={})
            if not isinstance(data, dict):
                data = {}
            if trailing:
                data[buf_key] = trailing
                if len(data) > 64:
                    oldest_key = next(iter(data))
                    if oldest_key != buf_key:
                        data.pop(oldest_key, None)
            else:
                data.pop(buf_key, None)
            atomic_write_json(buf_file, data)
    except (OSError, TimeoutError):
        pass


_SHELL_VERB_SKIP_NAMES = frozenset({
    "rm",
    "mv",
    "cp",
    "chmod",
    "chattr",
    "chown",
    "tee",
    "touch",
    "mkdir",
    "rmdir",
    "ln",
    "install",
    "rsync",
    "tar",
    "dd",
    "truncate",
    "shred",
    "patch",
    "unzip",
    "sed",
    "find",
    "xargs",
    "curl",
    "wget",
    "git",
    "sudo",
    "env",
    "timeout",
    "nice",
    "nohup",
    "command",
    "exec",
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "python",
    "python3",
    "py",
    "node",
    "ruby",
    "perl",
    "echo",
    "printf",
    "cat",
})


def _extract_shell_path_tokens(sub_cmd: str) -> List[str]:
    expanded = _unquote_single_tokens(_strip_unquoted_shell_comments(_expand_simple_shell_vars(sub_cmd)))
    no_multi_quotes = _QUOTED_SPAN_RE.sub(" ", expanded)
    out: List[str] = []
    for raw_tok in re.findall(r"[^\s;|&()<>\"'`]+", no_multi_quotes):
        tok = raw_tok.strip()
        if not tok or tok.startswith("-"):
            if "=" in tok:
                tok = tok.split("=", 1)[1].strip()
            else:
                continue
        elif "=" in tok and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok):
            tok = tok.split("=", 1)[1].strip()
        if not tok or tok.lower() in _SHELL_VERB_SKIP_NAMES:
            continue
        if re.match(r"^s/[^/]*/[^/]*/[gip0-9]*$", tok) or tok.isdigit():
            continue
        out.append(tok)
    for m_q in _QUOTED_SPAN_RE.finditer(expanded):
        inner = m_q.group(0)[1:-1].strip()
        if inner and "\n" not in inner and ("/" in inner or inner.endswith(".md") or inner.endswith(".py") or inner.endswith(".json")):
            out.append(inner)
    return out


def _shell_has_unquoted_mutation(sub_cmd: str) -> bool:
    expanded = _unquote_single_tokens(_strip_unquoted_shell_comments(sub_cmd))
    scrubbed = _QUOTED_SPAN_RE.sub('"__QUOTED__"', expanded)
    return bool(_SHELL_MUTATION_INDICATOR_RE.search(scrubbed))


_CD_SEG_RE = re.compile(
    r"^\s*\(*\s*(?:builtin\s+|command\s+)?(?P<verb>cd|pushd|popd)(?:\s+(?P<rest>.*))?$"
)
_INLINE_DIR_FLAG_RE = re.compile(
    r"(?:^|\s)(?:-C\s+(?P<c_arg>'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+)|--(?:directory|chdir)(?:=(?P<eq_arg>'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+)|\s+(?P<sp_arg>'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+)))"
)


def _resolve_shell_dir_token(raw_tok: str, cur_cwd: Optional[Path]) -> Optional[Path]:
    unq = raw_tok.strip().strip("'\"")
    if not unq or unq == "-":
        return cur_cwd
    home_str = str(Path.home())
    unq = unq.replace("${HOME}", home_str)
    unq = re.sub(r"\$HOME(?![A-Za-z0-9_])", lambda _m: home_str, unq)
    exp = Path(os.path.expanduser(unq))
    if exp.is_absolute():
        return Path(os.path.abspath(exp))
    if cur_cwd is not None:
        return Path(os.path.abspath(cur_cwd / exp))
    return None


def _iter_shell_segments_with_cwd(
    sub_cmd: str, initial_cwd: Optional[Path]
) -> List[Tuple[str, Optional[Path]]]:
    cleaned = _strip_unquoted_shell_comments(_join_shell_line_continuations(_expand_simple_shell_vars(sub_cmd)))
    segments = re.split(r"(?:&&|\|\||;|\n|(?<![>&])&(?!>))", cleaned)
    cur_cwd: Optional[Path] = initial_cwd
    dir_stack: List[Optional[Path]] = []
    out: List[Tuple[str, Optional[Path]]] = []
    for seg in segments:
        if not seg.strip():
            continue
        m_cd = _CD_SEG_RE.match(seg)
        if m_cd:
            verb = m_cd.group("verb")
            rest = m_cd.group("rest") or ""
            if verb == "popd":
                if dir_stack:
                    cur_cwd = dir_stack.pop()
                out.append((seg, cur_cwd))
                continue
            toks = re.findall(r"'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+", rest)
            cd_target: Optional[str] = None
            idx = 0
            while idx < len(toks):
                t = toks[idx]
                if t in (">", ">>", "<", "2>", "2>&1", "&>"):
                    idx += 2
                    continue
                if t.startswith((">", "<", "2>")):
                    idx += 1
                    continue
                if t == "--":
                    if idx + 1 < len(toks):
                        cd_target = toks[idx + 1]
                    break
                if t.startswith("-") and t != "-":
                    idx += 1
                    continue
                cd_target = t
                break
            new_cwd = Path.home() if cd_target is None else _resolve_shell_dir_token(cd_target, cur_cwd)
            if verb == "pushd":
                dir_stack.append(cur_cwd)
            cur_cwd = new_cwd
            out.append((seg, cur_cwd))
            continue

        out.append((seg, cur_cwd))
        for m_flag in _INLINE_DIR_FLAG_RE.finditer(seg):
            raw_dir = m_flag.group("c_arg") or m_flag.group("eq_arg") or m_flag.group("sp_arg") or ""
            flag_cwd = _resolve_shell_dir_token(raw_dir, cur_cwd)
            if flag_cwd is not None and flag_cwd != cur_cwd:
                out.append((seg, flag_cwd))
    return out


def _command_mutates_governance_in_cwd(sub_cmd: str, effective_cwd: Optional[Path]) -> bool:
    for seg, seg_cwd in _iter_shell_segments_with_cwd(sub_cmd, effective_cwd):
        if seg_cwd is None or not _shell_has_unquoted_mutation(seg):
            continue
        tokens = _extract_shell_path_tokens(seg)
        for tok in tokens:
            if _targets_governance_dir(tok, base_dir=seg_cwd):
                return True
        if _targets_governance_dir(str(seg_cwd)):
            rel_tokens = [t for t in tokens if not Path(os.path.expanduser(t)).is_absolute()]
            if not tokens or any(_targets_governance_dir(t, base_dir=seg_cwd) for t in rel_tokens):
                return True
    return False


def _command_mutates_customization_in_cwd(
    sub_cmd: str, effective_cwd: Optional[Path], workspaces: Sequence[Path], fallback_ws: Optional[Path]
) -> bool:
    for seg, seg_cwd in _iter_shell_segments_with_cwd(sub_cmd, effective_cwd):
        if seg_cwd is None or not _shell_has_unquoted_mutation(seg):
            continue
        ws_root = _workspace_for_target(str(seg_cwd), workspaces, fallback=fallback_ws)
        tokens = _extract_shell_path_tokens(seg)
        for tok in tokens:
            exp = Path(os.path.expanduser(tok))
            resolved_str = str(seg_cwd / exp) if not exp.is_absolute() else str(exp)
            tok_ws = _workspace_for_target(resolved_str, workspaces, fallback=ws_root)
            if _targets_customization_structure(resolved_str, workspace=tok_ws):
                return True
        if _targets_customization_structure(str(seg_cwd), workspace=ws_root):
            if not tokens or any(not Path(os.path.expanduser(t)).is_absolute() for t in tokens):
                return True
    return False


def _shell_targets_tasks_md(sub_cmd: str) -> bool:
    import fnmatch

    unquoted = _unquote_single_tokens(_strip_unquoted_shell_comments(sub_cmd))
    if re.search(r"(?:^|[\s/'\"=>])tasks\.md\b", unquoted, re.IGNORECASE):
        return True
    for tok in _extract_shell_path_tokens(sub_cmd):
        base = tok.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if any(ch in base for ch in ("*", "?", "[")) and len(base) >= 3 and ("t" in base or "md" in base):
            if fnmatch.fnmatchcase("tasks.md", base):
                return True
    return False


_INTERP_SCRIPT_SEG_RE = re.compile(
    rf"^\s*{_CMD_WRAPPER_PREFIX}"
    r"(?P<interp>(?:[^\s;|&`'\"()]*/)?(?:python3?(?:\.\d+)?|py|(?:ba|z|da|k)?sh|node|nodejs|ruby|perl)|source|\.)\s+"
    r"(?P<rest>.+)$",
    re.IGNORECASE,
)


_PY_MODULE_SCRIPT_RUNNERS = frozenset({
    "pdb",
    "bdb",
    "runpy",
    "trace",
    "cprofile",
    "profile",
    "timeit",
    "doctest",
})
_STR_LIST_SEQ_RE = re.compile(
    r"[\[(]\s*(?:['\"][^'\"\n]+['\"]\s*,\s*)+['\"][^'\"\n]*['\"]\s*,?\s*[\])]"
)
_QUOTED_ITEM_RE = re.compile(r"'([^'\\\n]*)'|\"([^\"\\\n]*)\"")
# Root-level gate entry points of a harness checkout whose edits are held by the Customization Model Gate.
_HARNESS_CHECKOUT_GATE_ENTRIES = (
    "install.py",
    "porter.py",
    "guard.py",
    "scripts/meta_audit.py",
    "scripts/verify_invariants.py",
)


def _extract_code_map_trace_target(rem_tokens: Sequence[str]) -> Optional[str]:
    if not rem_tokens:
        return None
    sub_idx = 0
    while sub_idx < len(rem_tokens) and rem_tokens[sub_idx].startswith("-"):
        sub_idx += 1
    if sub_idx >= len(rem_tokens) or rem_tokens[sub_idx] != "trace":
        return None
    j = sub_idx + 1
    while j < len(rem_tokens):
        t = rem_tokens[j]
        if t == "--":
            return rem_tokens[j + 1] if j + 1 < len(rem_tokens) else None
        if t in ("--timeout", "--max-events", "--limit", "--format", "-o", "--output") and j + 1 < len(rem_tokens):
            j += 2
            continue
        if t.startswith("-"):
            j += 1
            continue
        return t
    return None


def _inspect_external_script_command(
    sub_cmd: str,
    workspaces: Sequence[Path],
    effective_cwd: Optional[Path],
) -> Optional[Dict[str, Any]]:
    uncommented = _unquote_single_tokens(_strip_unquoted_shell_comments(_join_shell_line_continuations(sub_cmd)))
    segments = re.split(r"(?:&&|\|\||[;&|\n])", uncommented)
    trusted_roots: List[Path] = [
        *workspaces,
        REPO_ROOT,
        config_dir() / "skills",
        configured_config_dir() / "skills",
        Path("/usr/share/antigravity-harness/skills"),
        Path.home() / ".gemini" / "antigravity" / "builtin" / "skills",
    ]
    resolved_trusted_roots: List[Path] = []
    for tr in trusted_roots:
        if tr is None:
            continue
        resolved_trusted_roots.append(tr)
        try:
            r_tr = tr.resolve()
            if r_tr not in resolved_trusted_roots:
                resolved_trusted_roots.append(r_tr)
        except (OSError, RuntimeError):
            pass

    harness_checkout_roots: List[Path] = []
    for h_cand in workspaces:
        try:
            h_resolved = Path(h_cand).resolve()
        except (OSError, RuntimeError):
            continue
        # Only a workspace root carrying `.harness/manifest.json` (itself Customization-Model-Gated) qualifies;
        # an agent-chosen `Cwd` or a nested decoy `guard/agy_hooks.py` never does.
        if h_resolved not in harness_checkout_roots and (h_resolved / ".harness" / "manifest.json").is_file():
            harness_checkout_roots.append(h_resolved)

    for seg in segments:
        m = _INTERP_SCRIPT_SEG_RE.match(seg)
        if not m:
            continue
        interp_base = Path(m.group("interp")).name.lower()
        is_py_interp = interp_base == "py" or interp_base.startswith("python")
        tokens = [t.strip("'\"") for t in re.findall(r"'[^']*'|\"(?:\\.|[^\"\\])*\"|\S+", m.group("rest"))]
        candidate_script_args: List[str] = []
        idx = 0
        skip_seg = False
        while idx < len(tokens):
            tok = tokens[idx]
            if tok in (">", ">>", "<", "2>", "2>&1", "&>"):
                idx += 2
                continue
            if tok.startswith((">", "<", "2>")):
                idx += 1
                continue
            if tok == "--":
                if idx + 1 < len(tokens):
                    candidate_script_args.append(tokens[idx + 1])
                break
            if tok in ("-h", "--help", "-V", "--version", "-v") and interp_base not in ("sh", "bash", "zsh", "dash", "ksh"):
                skip_seg = True
                break
            if tok.startswith("-"):
                if is_py_interp and (tok == "-m" or re.match(r"^-[A-Za-z0-9]*m$", tok)):
                    if idx + 1 < len(tokens):
                        mod_name = tokens[idx + 1]
                        mod_lower = mod_name.lower()
                        if mod_lower in ("scripts.code_map", "code_map"):
                            cm_target = _extract_code_map_trace_target(tokens[idx + 2 :])
                            if cm_target:
                                candidate_script_args.append(cm_target)
                        elif mod_lower in _PY_MODULE_SCRIPT_RUNNERS:
                            j = idx + 2
                            while j < len(tokens):
                                mt = tokens[j]
                                if mt == "--":
                                    if j + 1 < len(tokens):
                                        candidate_script_args.append(tokens[j + 1])
                                    break
                                if mt in ("-c", "-o", "-s", "-m", "--command", "--outfile", "--sort") and j + 1 < len(tokens):
                                    j += 2
                                    continue
                                if mt.startswith("-"):
                                    j += 1
                                    continue
                                candidate_script_args.append(mt)
                                break
                    skip_seg = not bool(candidate_script_args)
                    break
                if tok in ("-c", "-m", "-e", "--eval", "--print", "-p"):
                    skip_seg = True
                    break
                if re.match(r"^-[A-Za-z0-9]*[cme]$", tok):
                    skip_seg = True
                    break
                if tok in ("-W", "-X", "-r", "--require", "-I") and idx + 1 < len(tokens):
                    idx += 2
                    continue
                idx += 1
                continue
            candidate_script_args.append(tok)
            if Path(tok).name == "code_map.py":
                cm_target = _extract_code_map_trace_target(tokens[idx + 1 :])
                if cm_target:
                    candidate_script_args.append(cm_target)
            break

        if skip_seg or not candidate_script_args:
            continue
        base_cwd = effective_cwd if effective_cwd is not None else (workspaces[0] if workspaces else REPO_ROOT)
        for script_arg in candidate_script_args:
            if not script_arg or script_arg in ("-", "/dev/stdin", "/dev/null") or script_arg.startswith("<("):
                continue
            exp = Path(os.path.expanduser(script_arg))
            script_path = (base_cwd / exp) if not exp.is_absolute() else exp
            try:
                resolved_script: Optional[Path] = script_path.resolve()
            except (OSError, RuntimeError):
                resolved_script = None

            lex_trusted = any(is_within(script_path, root) for root in trusted_roots if root is not None)
            res_trusted = (
                resolved_script is not None
                and any(is_within(resolved_script, root) for root in resolved_trusted_roots)
            )
            in_trusted = bool(lex_trusted and res_trusted)
            check_target = resolved_script if resolved_script is not None else script_path
            is_harness_internal = (
                not script_path.is_symlink()
                and is_within(check_target, REPO_ROOT)
                and (
                    any(is_within(check_target, REPO_ROOT / sub) for sub in ("guard", "scripts", "porter", "skills", "tests"))
                    or any(
                        os.path.abspath(check_target) == os.path.abspath(REPO_ROOT / entry)
                        for entry in ("install.py", "porter.py", "guard.py")
                    )
                )
            )
            if not is_harness_internal and not script_path.is_symlink():
                # A harness source checkout opened as a workspace runs its own gate entry points
                # (`scripts/meta_audit.py`, `install.py --dry-run`, ...). Only paths whose edits are
                # themselves held by the Customization Model Gate are exempt from content scanning.
                for h_root in harness_checkout_roots:
                    in_gate_set = any(is_within(check_target, h_root / sub) for sub in ("guard", "porter", "skills")) or any(
                        os.path.abspath(check_target) == os.path.abspath(h_root / entry)
                        for entry in _HARNESS_CHECKOUT_GATE_ENTRIES
                    )
                    if in_gate_set and _targets_customization_structure(str(check_target), workspace=h_root):
                        is_harness_internal = True
                        break
            if not is_harness_internal:
                try:
                    if check_target.is_file():
                        f_size = check_target.stat().st_size
                        if f_size > _WORKFLOW_MAX_BYTES:
                            in_trusted = False
                        else:
                            src_text = check_target.read_text(encoding="utf-8", errors="replace")
                            non_comment = "\n".join(
                                ln for ln in src_text.splitlines() if not ln.lstrip().startswith("#")
                            )
                            masked_src = _mask_quoted_operators(non_comment)
                            synth_list_cmds: List[str] = []
                            for m_seq in _STR_LIST_SEQ_RE.finditer(non_comment):
                                items = [
                                    (im.group(1) if im.group(1) is not None else (im.group(2) or ""))
                                    for im in _QUOTED_ITEM_RE.finditer(m_seq.group(0))
                                ]
                                if len(items) >= 2:
                                    synth_list_cmds.append(" ".join(items))
                            if (
                                re.search(_GUARD_API_TOKEN_PAT, non_comment)
                                or _GUARD_ADMIN_RE.search(masked_src)
                                or _INSTALL_PY_RE.search(masked_src)
                                or _GIT_HOOK_BYPASS_RE.search(masked_src)
                                or _command_mutates_governance(non_comment)
                                or any(
                                    _GUARD_ADMIN_RE.search(_mask_quoted_operators(sc))
                                    or _INSTALL_PY_RE.search(_mask_quoted_operators(sc))
                                    or _GIT_HOOK_BYPASS_RE.search(_mask_quoted_operators(sc))
                                    or _command_mutates_governance(sc)
                                    for sc in synth_list_cmds
                                )
                            ):
                                return {
                                    "decision": "deny",
                                    "reason": (
                                        f"[Harness Governance Shield] Script `{script_arg}` invokes human-only Guard "
                                        "administration or mutates protected governance state (GEMINI.md Rule 12)."
                                    ),
                                }
                except OSError:
                    in_trusted = False
            if not in_trusted:
                return {
                    "decision": "force_ask",
                    "reason": (
                        f"[Harness Bash Guard] Executing external script outside the active workspace (`{script_arg}`) "
                        "bypasses inline command inspection and requires explicit human confirmation (GEMINI.md Rule 12)."
                    ),
                }
    return None


_MCP_DEBUGGER_ESCAPE_RE = re.compile(r"^\s*(?:!+|\.!|#!(?:pipe|python3?|ba?sh)\s+|(?:shell|system)\s+)", re.IGNORECASE)
_MCP_MUTATING_TOOL_HINT_RE = re.compile(
    r"(?:write|edit|create|delete|remove|unlink|mv|move|rename|copy|chmod|chown|push|install|uninstall|"
    r"extract|save|exec|command|console|frida|script|gdb|rizin|cutter|adb|patch|modify|update|set_|put)",
    re.IGNORECASE,
)


def _collect_mcp_strings(value: Any, out: List[str], depth: int = 0) -> Optional[str]:
    if depth > _WORKFLOW_MAX_ARG_DEPTH:
        return "[Harness MCP Shield] MCP `Arguments` exceed maximum nesting depth (failing closed)."
    if isinstance(value, str):
        if "\x00" in value:
            return "[Harness MCP Shield] Null bytes in MCP arguments are prohibited."
        if value:
            out.append(value)
        return None
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                if "\x00" in k:
                    return "[Harness MCP Shield] Null bytes in MCP argument keys are prohibited."
                if k:
                    out.append(k)
            err = _collect_mcp_strings(v, out, depth + 1)
            if err:
                return err
        return None
    if isinstance(value, (list, tuple)):
        str_elts = [x for x in value if isinstance(x, str) and x]
        if len(str_elts) >= 2:
            out.append(" ".join(str_elts))
        for elt in value:
            err = _collect_mcp_strings(elt, out, depth + 1)
            if err:
                return err
        return None
    return None


_READONLY_MCP_ALLOWLIST = frozenset({"check_contrast"})
_MCP_PATH_ARG_KEYS_LOWER = frozenset({
    *(k.lower() for k in _WRITE_TARGET_ARG_KEYS),
    "filepath",
    "filename",
    "file",
    "files",
    "paths",
    "target",
    "targetpath",
    "target_path",
    "dest",
    "destination",
    "uri",
    "url",
    "source",
    "src",
    "dst",
    "directory",
    "dir",
})


def _normalize_mcp_path_value(val: str) -> str:
    s = val.strip()
    if s.lower().startswith("file://"):
        parsed = urllib.parse.urlparse(s)
        return urllib.parse.unquote(parsed.path or "")
    return s


def _extract_mcp_target_paths(mcp_args: Dict[str, Any], depth: int = 0) -> List[str]:
    if depth > _WORKFLOW_MAX_ARG_DEPTH or not isinstance(mcp_args, dict):
        return []
    targets: List[str] = []
    for t in _extract_write_targets(mcp_args):
        nt = _normalize_mcp_path_value(t)
        if nt and nt not in targets:
            targets.append(nt)
    for k, v in mcp_args.items():
        k_low = str(k).strip().lower()
        if k_low in _MCP_PATH_ARG_KEYS_LOWER:
            if isinstance(v, str) and v.strip():
                nt = _normalize_mcp_path_value(v)
                if nt and nt not in targets:
                    targets.append(nt)
            elif isinstance(v, (list, tuple)):
                for item in v:
                    if isinstance(item, str) and item.strip():
                        nt = _normalize_mcp_path_value(item)
                        if nt and nt not in targets:
                            targets.append(nt)
                    elif isinstance(item, dict):
                        for sub_t in _extract_mcp_target_paths(item, depth + 1):
                            if sub_t not in targets:
                                targets.append(sub_t)
        elif isinstance(v, dict):
            for sub_t in _extract_mcp_target_paths(v, depth + 1):
                if sub_t not in targets:
                    targets.append(sub_t)
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, dict):
                    for sub_t in _extract_mcp_target_paths(item, depth + 1):
                        if sub_t not in targets:
                            targets.append(sub_t)
    return targets


def _inspect_mcp_tool_call(
    tool_name: str,
    args: Dict[str, Any],
    effective_cwd: Optional[Path],
    payload: Optional[Dict[str, Any]] = None,
    workspaces: Sequence[Path] = (),
    workspace: Optional[Path] = None,
) -> Dict[str, Any]:
    if tool_name == "call_mcp_tool":
        raw_inner = (
            args.get("ToolName")
            if "ToolName" in args
            else (args.get("toolName") if "toolName" in args else args.get("tool_name"))
        )
        if not isinstance(raw_inner, str) or not raw_inner.strip():
            return {
                "decision": "deny",
                "reason": "[Harness MCP Shield] `call_mcp_tool` requires a non-empty string `ToolName` (failing closed).",
            }
        raw_mcp_args = args.get("Arguments") if "Arguments" in args else args.get("arguments")
        if raw_mcp_args is None:
            mcp_args: Dict[str, Any] = {}
        elif isinstance(raw_mcp_args, dict):
            mcp_args = raw_mcp_args
        else:
            return {
                "decision": "deny",
                "reason": "[Harness MCP Shield] `call_mcp_tool` `Arguments` must be a JSON object/dict (failing closed).",
            }
        effective_mcp_tool = raw_inner.strip().lower()
        srv = str(args.get("ServerName") or args.get("serverName") or args.get("server_name") or "").strip()
        effective_label = f"{srv}:{effective_mcp_tool}" if srv else effective_mcp_tool
        is_high_risk = effective_mcp_tool in HIGH_RISK_MCP_TOOL_NAMES
        is_readonly_allowlisted = effective_mcp_tool in _READONLY_MCP_ALLOWLIST
    else:
        mcp_args = args
        rest_name = tool_name[4:] if tool_name.startswith("mcp_") else tool_name
        effective_mcp_tool = rest_name
        effective_label = tool_name
        is_high_risk = any(
            rest_name == hr or rest_name.endswith(f"_{hr}") for hr in HIGH_RISK_MCP_TOOL_NAMES
        )
        is_readonly_allowlisted = any(
            rest_name == ro or rest_name.endswith(f"_{ro}") for ro in _READONLY_MCP_ALLOWLIST
        )

    strings: List[str] = []
    err = _collect_mcp_strings(mcp_args, strings)
    if err:
        return {"decision": "deny", "reason": err}

    checks_gov_path = not is_readonly_allowlisted
    mcp_targets = _extract_mcp_target_paths(mcp_args) if checks_gov_path else []
    for s in strings:
        stripped_esc = _MCP_DEBUGGER_ESCAPE_RE.sub("", s).strip()
        cand_cmds = [s]
        if stripped_esc and stripped_esc not in cand_cmds:
            cand_cmds.append(stripped_esc)
        for base_c in list(cand_cmds):
            for ext_c in _extract_shell_c_payloads(base_c):
                if ext_c not in cand_cmds:
                    cand_cmds.append(ext_c)

        for c_str in cand_cmds:
            masked_c = _mask_quoted_operators(c_str)
            if _GUARD_ADMIN_RE.search(masked_c) or _GUARD_INLINE_PY_RE.search(c_str) or re.search(_GUARD_API_TOKEN_PAT, c_str):
                return {
                    "decision": "deny",
                    "reason": (
                        f"[Harness MCP Shield] Human-only `agy-guard` administration via MCP tool "
                        f"(`{effective_label}`) is prohibited (GEMINI.md Rule 12)."
                    ),
                }
            if _INSTALL_PY_RE.search(masked_c):
                return {
                    "decision": "deny",
                    "reason": (
                        f"[Harness MCP Shield] Executing `install.py` via MCP tool (`{effective_label}`) "
                        "is prohibited (GEMINI.md Rule 12)."
                    ),
                }
            if _GIT_HOOK_BYPASS_RE.search(masked_c):
                return {
                    "decision": "deny",
                    "reason": (
                        f"[Harness MCP Shield] Git hook bypass flags via MCP tool (`{effective_label}`) "
                        "are prohibited."
                    ),
                }
            if _command_mutates_governance(c_str):
                return {
                    "decision": "deny",
                    "reason": (
                        f"[Harness MCP Shield] Mutating protected governance or Guard state via MCP tool "
                        f"(`{effective_label}`) is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                    ),
                }

        norm_s = _normalize_mcp_path_value(s)
        if checks_gov_path and any(
            _targets_governance_dir(cand_p)
            or (effective_cwd is not None and _targets_governance_dir(cand_p, base_dir=effective_cwd))
            or (workspace is not None and _targets_governance_dir(cand_p, base_dir=workspace))
            or any(_targets_governance_dir(cand_p, base_dir=ws) for ws in workspaces)
            for cand_p in ((s, norm_s) if norm_s != s else (s,))
        ):
            return {
                "decision": "deny",
                "reason": (
                    f"[Harness MCP Shield] Targeting protected governance or Guard path (`{s}`) via "
                    f"MCP tool (`{effective_label}`) is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                ),
            }

    if checks_gov_path and mcp_targets:
        def _resolve_mcp_target_and_ws(t_str: str) -> Tuple[str, Optional[Path]]:
            exp_t = Path(os.path.expanduser(t_str.strip()))
            res_str = str(effective_cwd / exp_t) if (effective_cwd is not None and not exp_t.is_absolute()) else t_str
            t_ws = _workspace_for_target(res_str, workspaces, fallback=workspace)
            return res_str, t_ws

        if payload is not None and any(
            _targets_customization_structure(res_t, workspace=t_ws)
            or _targets_customization_structure(t_raw, workspace=t_ws)
            for t_raw in mcp_targets
            for res_t, t_ws in [_resolve_mcp_target_and_ws(t_raw)]
        ):
            mod_eval = _evaluate_customization_model_and_effort(payload)
            if mod_eval is not None:
                return {"decision": mod_eval[0], "reason": mod_eval[1]}

        for t_raw in mcp_targets:
            res_t, t_ws = _resolve_mcp_target_and_ws(t_raw)
            if _write_mutates_authorized_test_section(t_raw, mcp_args, effective_cwd or t_ws):
                return {
                    "decision": "force_ask",
                    "reason": (
                        "[Harness Test Boundary] Modifying `## Authorized Test Modifications` in `tasks.md` "
                        "requires explicit human confirmation (GEMINI.md Rule 9)."
                    ),
                }
            if Path(t_raw.replace("\\", "/")).name.lower() == "tasks.md" and not any(
                ck in mcp_args for ck in ("Content", "FileContent", "CodeContent", "content", "file_text")
            ):
                tasks_disk = Path(os.path.expanduser(res_t))
                has_auth_heading = any("authorized test modifications" in x.lower() for x in strings)
                if not has_auth_heading:
                    try:
                        if tasks_disk.is_file():
                            has_auth_heading = (
                                "authorized test modifications"
                                in tasks_disk.read_text(encoding="utf-8", errors="ignore").lower()
                            )
                    except OSError:
                        pass
                if has_auth_heading:
                    return {
                        "decision": "force_ask",
                        "reason": (
                            "[Harness Test Boundary] Modifying `tasks.md` containing `## Authorized Test Modifications` "
                            f"via MCP tool (`{effective_label}`) requires explicit human confirmation (GEMINI.md Rule 9)."
                        ),
                    }

    if is_high_risk:
        return {
            "decision": "force_ask",
            "reason": (
                f"[Harness MCP Shield] High-risk MCP tool (`{effective_label}`) can execute commands, "
                "instrument processes, or mutate host/device state and requires explicit human confirmation "
                "(GEMINI.md Rule 12)."
            ),
        }

    if checks_gov_path and mcp_targets and payload is not None and not payload.get("_workflowDryCheck"):
        for t_raw in mcp_targets:
            exp_t = Path(os.path.expanduser(t_raw.strip()))
            res_t = str(effective_cwd / exp_t) if (effective_cwd is not None and not exp_t.is_absolute()) else t_raw
            t_ws = _workspace_for_target(res_t, workspaces, fallback=workspace)
            _record_flight_pre_write(payload, t_ws, tool_name, res_t)

    return {"decision": "allow"}


def handle_pre_tool_use(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {
            "decision": "deny",
            "reason": "[Harness PreToolUse Gate] Malformed non-dict hook payload (failing closed).",
        }
    if "toolCall" in payload:
        raw_tc = payload.get("toolCall")
        if not isinstance(raw_tc, dict):
            return {
                "decision": "deny",
                "reason": "[Harness PreToolUse Gate] Malformed non-dict `toolCall` envelope (failing closed).",
            }
        tool_call = raw_tc
    else:
        raw_input_obj = payload.get("tool_input") if "tool_input" in payload else payload.get("toolInput")
        if raw_input_obj is not None and not isinstance(raw_input_obj, dict):
            return {
                "decision": "deny",
                "reason": "[Harness PreToolUse Gate] Malformed non-dict `tool_input` arguments (failing closed).",
            }
        tool_call = {
            "name": payload.get("tool_name") or payload.get("toolName") or "",
            "args": raw_input_obj if raw_input_obj is not None else {},
        }
    tool_name = str(tool_call.get("name") or "").strip().lower().rsplit(":", 1)[-1]
    raw_args = tool_call.get("args")
    if raw_args is None:
        args: Dict[str, Any] = {}
    elif isinstance(raw_args, dict):
        args = raw_args
    else:
        return {
            "decision": "deny",
            "reason": "[Harness PreToolUse Gate] Malformed non-dict `toolCall.args` (failing closed).",
        }
    workspaces = _workspaces_from_payload(payload)
    workspace = workspaces[0] if workspaces else None
    payload_cwd = _payload_cwd(payload, args)
    effective_cwd: Optional[Path] = (
        ((workspace / payload_cwd) if (not payload_cwd.is_absolute() and workspace is not None) else payload_cwd)
        if payload_cwd is not None
        else workspace
    )

    # 0. MCP tools (`call_mcp_tool` lazy wrapper & `mcp_*` eager native tools — ADR-0004 Decision 1 / H-03)
    if tool_name == "call_mcp_tool" or tool_name.startswith("mcp_"):
        return _inspect_mcp_tool_call(
            tool_name,
            args,
            effective_cwd,
            payload=payload,
            workspaces=workspaces,
            workspace=workspace,
        )

    # 1. File-writing tools: enforce Governance Shield (~/.gemini/config governance seams + Guard state/runtime)
    #    and Top-Catalog Model & Effort Gate on customization/governance files (GEMINI.md Rule 17).
    if tool_name in WRITE_TOOL_NAMES:
        targets = _extract_write_targets(args)
        for target in targets:
            if "\x00" in target:
                return {
                    "decision": "deny",
                    "reason": "[Harness Governance Shield] Null bytes in target paths are prohibited.",
                }
            if (
                _targets_governance_dir(target)
                or (workspace is not None and _targets_governance_dir(target, base_dir=workspace))
                or (effective_cwd is not None and _targets_governance_dir(target, base_dir=effective_cwd))
                or any(_targets_governance_dir(target, base_dir=ws) for ws in workspaces)
            ):
                return {
                    "decision": "deny",
                    "reason": (
                        "[Harness Governance Shield] Direct write to the protected governance tree "
                        f"(`{target}`) is prohibited (GEMINI.md Rule 12 & Rule 15a). Author changes in "
                        "the source repository and ask the human operator to run `install.py`."
                    ),
                }

        def _resolve_target_and_ws(t_str: str) -> Tuple[str, Optional[Path]]:
            exp_t = Path(os.path.expanduser(t_str.strip()))
            res_str = str(effective_cwd / exp_t) if (effective_cwd is not None and not exp_t.is_absolute()) else t_str
            t_ws = _workspace_for_target(res_str, workspaces, fallback=workspace)
            return res_str, t_ws

        if any(
            _targets_customization_structure(res_t, workspace=t_ws) or _targets_customization_structure(t_raw, workspace=t_ws)
            for t_raw in targets
            for res_t, t_ws in [_resolve_target_and_ws(t_raw)]
        ):
            mod_eval = _evaluate_customization_model_and_effort(payload)
            if mod_eval is not None:
                return {"decision": mod_eval[0], "reason": mod_eval[1]}
        for target in targets:
            res_t, t_ws = _resolve_target_and_ws(target)
            if _write_mutates_authorized_test_section(target, args, effective_cwd or t_ws):
                return {
                    "decision": "force_ask",
                    "reason": (
                        "[Harness Test Boundary] Modifying `## Authorized Test Modifications` in `tasks.md` "
                        "requires explicit human confirmation (GEMINI.md Rule 9)."
                    ),
                }
        for target in targets:
            res_t, t_ws = _resolve_target_and_ws(target)
            _record_flight_pre_write(payload, t_ws, tool_name, res_t)
        return {"decision": "allow"}

    # 2. Command execution tools: enforce Guard Admin Shield, Governance Shield, Customization Model Gate, and Bash Guard
    if tool_name in COMMAND_TOOL_NAMES:
        def _eval_shell_command_string(raw_cmd_str: str) -> Optional[Dict[str, Any]]:
            joined_top = _join_shell_line_continuations(raw_cmd_str).strip()
            if not joined_top:
                return {"decision": "allow"}
            candidate_cmds = [joined_top]
            if raw_cmd_str.strip() != joined_top:
                candidate_cmds.append(raw_cmd_str.strip())
            for ext_sub in _extract_shell_c_payloads(raw_cmd_str):
                if ext_sub not in candidate_cmds:
                    candidate_cmds.append(ext_sub)

            pending_cmd_force_ask: Optional[Dict[str, Any]] = None
            for sub_cmd in candidate_cmds:
                masked_cmd = _mask_quoted_operators(sub_cmd)

                if _GUARD_ADMIN_RE.search(masked_cmd) or _GUARD_INLINE_PY_RE.search(sub_cmd):
                    return {
                        "decision": "deny",
                        "reason": (
                            "[Harness Governance Shield] Guard administration commands (`agy-guard unlock`, "
                            "`rebaseline`, `test-boundary snapshot`, `--authorize`, `snapshot restore/prune`, `porter stage`, `porter import --force`, "
                            "`env policy/add/remove`, `startup enable/disable`, `notify disable`, `doctor --fix/--recover`, `init`) are reserved exclusively "
                            "for the human operator (GEMINI.md Rule 12). You may only run `agy-guard request-unlock` "
                            "or read-only status/verify/`--dry-run` commands."
                        ),
                    }

                if _INSTALL_PY_RE.search(masked_cmd):
                    return {
                        "decision": "deny",
                        "reason": (
                            "[Harness Governance Shield] Running `install.py` (without `--dry-run`) is reserved "
                            "for the human operator (GEMINI.md Rule 12)."
                        ),
                    }

                if _command_mutates_governance(sub_cmd) or _command_mutates_governance_in_cwd(sub_cmd, effective_cwd):
                    return {
                        "decision": "deny",
                        "reason": (
                            "[Harness Governance Shield] Mutating or changing permissions on the governance tree "
                            "(`~/.gemini/config`) or Guard state via shell commands is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                        ),
                    }

                if _GIT_HOOK_BYPASS_RE.search(masked_cmd):
                    return {
                        "decision": "deny",
                        "reason": (
                            "[Harness Bash Guard] Bypassing repository verification hooks (`--no-verify`, "
                            "`commit -n`, `core.hooksPath`, `HUSKY=0`) is prohibited."
                        ),
                    }

                if _command_mutates_customization_structure(sub_cmd) or _command_mutates_customization_in_cwd(
                    sub_cmd, effective_cwd, workspaces, workspace
                ):
                    mod_eval = _evaluate_customization_model_and_effort(payload)
                    if mod_eval is not None:
                        if mod_eval[0] == "deny":
                            return {"decision": "deny", "reason": mod_eval[1]}
                        if pending_cmd_force_ask is None:
                            pending_cmd_force_ask = {"decision": "force_ask", "reason": mod_eval[1]}

                if _shell_targets_tasks_md(sub_cmd) and _shell_has_unquoted_mutation(sub_cmd):
                    if pending_cmd_force_ask is None:
                        pending_cmd_force_ask = {
                            "decision": "force_ask",
                            "reason": (
                                "[Harness Test Boundary] Mutating `tasks.md` via shell command could alter "
                                "`## Authorized Test Modifications` and requires explicit human confirmation (GEMINI.md Rule 9)."
                            ),
                        }

                unquoted_sub = _unquote_single_tokens(sub_cmd)
                for pattern, reason in _DESTRUCTIVE_CMD_PATTERNS:
                    if pattern.search(unquoted_sub):
                        if pending_cmd_force_ask is None:
                            pending_cmd_force_ask = {
                                "decision": "force_ask",
                                "reason": f"[Harness Bash Guard] {reason}",
                            }
                        break

                unpinned_msg = _detect_unpinned_package_exec(unquoted_sub)
                if unpinned_msg and pending_cmd_force_ask is None:
                    pending_cmd_force_ask = {
                        "decision": "force_ask",
                        "reason": f"[Harness Bash Guard] {unpinned_msg}",
                    }

                if _TERMINAL_INJECTION_RE.search(_blank_quoted_spans(sub_cmd)) and pending_cmd_force_ask is None:
                    pending_cmd_force_ask = {
                        "decision": "force_ask",
                        "reason": (
                            "[Harness Bash Guard] Injecting keystrokes or buffers into a terminal multiplexer "
                            "(`tmux send-keys`/`paste-buffer`, `screen -X stuff`, `zellij write-chars`) runs commands "
                            "outside `PreToolUse` inspection and requires explicit human confirmation (GEMINI.md Rule 12)."
                        ),
                    }

                ext_res = _inspect_external_script_command(sub_cmd, workspaces, effective_cwd)
                if ext_res is not None:
                    if ext_res.get("decision") == "deny":
                        return ext_res
                    if pending_cmd_force_ask is None:
                        pending_cmd_force_ask = ext_res

            return pending_cmd_force_ask

        is_interactive_input = False
        raw_chunk = ""
        if tool_name == "manage_task":
            action = str(args.get("Action") or args.get("action") or "").strip().lower()
            if action == "send_input":
                is_interactive_input = True
                raw_chunk = str(args.get("Input") if args.get("Input") is not None else (args.get("input") or ""))
            else:
                return {"decision": "allow"}
        elif tool_name == "send_command_input":
            is_interactive_input = True
            raw_chunk = str(
                args.get("Input")
                if args.get("Input") is not None
                else (
                    args.get("input")
                    if args.get("input") is not None
                    else (args.get("CommandLine") if args.get("CommandLine") is not None else (args.get("command") or ""))
                )
            )
        else:
            cmd = str(args.get("CommandLine") or args.get("command") or "").strip()
            if not cmd:
                return {"decision": "allow"}
            cmd_res = _eval_shell_command_string(cmd)
            return cmd_res if cmd_res is not None else {"decision": "allow"}

        buf_key = _cmd_input_buffer_key(payload, args)
        buf_file = state_dir() / "cmd_input_buffers.json"
        try:
            with file_lock(buf_file, timeout=HOOK_LOCK_TIMEOUT):
                data = read_json(buf_file, default={})
                if not isinstance(data, dict):
                    data = {}
                prev_prefix = data.get(buf_key) if isinstance(data.get(buf_key), str) else ""
                combined_interactive = prev_prefix + raw_chunk
                if not combined_interactive.strip():
                    return {"decision": "allow"}
                cmd_res = _eval_shell_command_string(combined_interactive)
                if cmd_res is not None:
                    return cmd_res
                trailing = _compute_trailing_cmd_buffer(combined_interactive)
                if trailing:
                    data[buf_key] = trailing
                    if len(data) > 64:
                        oldest_key = next(iter(data))
                        if oldest_key != buf_key:
                            data.pop(oldest_key, None)
                else:
                    data.pop(buf_key, None)
                atomic_write_json(buf_file, data)
        except (OSError, TimeoutError):
            cmd_res = _eval_shell_command_string(raw_chunk)
            if cmd_res is not None:
                return cmd_res
            return {
                "decision": "force_ask",
                "reason": "[Harness Bash Guard] Interactive input buffer lock unavailable; human confirmation required.",
            }
        return {"decision": "allow"}

    # 3. Subagent delegation (`invoke_subagent`): enforce Model & Effort Gate on customization/governance delegation (GEMINI.md Rule 17)
    if tool_name == "invoke_subagent":
        type_name = str(
            args.get("TypeName")
            or args.get("type_name")
            or args.get("typeName")
            or args.get("subagent_type")
            or ""
        ).strip().lower()
        sub_model_raw = (
            args.get("Model")
            if args.get("Model") is not None
            else (args.get("model") if args.get("model") is not None else "inherit")
        )
        sub_model = str(sub_model_raw).strip().lower() or "inherit"
        role_str = str(args.get("Role") or args.get("role") or "")
        prompt_str = str(args.get("Prompt") or args.get("prompt") or "")
        combined_brief = f"{role_str}\n{prompt_str}"
        if type_name not in _READONLY_SUBAGENT_TYPES and re.search(_CUST_CMD_TARGET_PAT, combined_brief, re.IGNORECASE):
            top_name, allowed_top_slugs = _catalog_top_model_spec()
            if sub_model != "inherit" and _normalize_model_slug(sub_model) not in allowed_top_slugs:
                return {
                    "decision": "deny",
                    "reason": (
                        f"[Harness Model & Effort Gate] Delegating customization or governance work via "
                        f"`invoke_subagent` with downgraded `Model='{sub_model}'` is prohibited; use "
                        f"`Model='inherit'` on `{top_name}` (GEMINI.md Rule 17)."
                    ),
                }
            mod_eval = _evaluate_customization_model_and_effort(payload)
            if mod_eval is not None:
                return {"decision": mod_eval[0], "reason": mod_eval[1]}
        return {"decision": "allow"}

    # 4. Dynamic Python orchestration workflows (`run_workflow`): enforce Workflow Shield (GEMINI.md Rule 15e & Rule 17)
    if tool_name == "run_workflow":
        script_sources, arg_strings, workflow_cwd, script_paths_meta, err_reason = _extract_workflow_sources_ex(
            args, workspace
        )
        if err_reason:
            return {"decision": "deny", "reason": err_reason}
        if workflow_cwd is not None and _targets_governance_dir(str(workflow_cwd)):
            return {
                "decision": "deny",
                "reason": (
                    f"[Harness Governance Shield] Executing `run_workflow` with `Cwd` inside a protected "
                    f"governance tree (`{workflow_cwd}`) is prohibited (GEMINI.md Rule 12 & Rule 15a)."
                ),
            }
        for arg_text in arg_strings:
            masked_arg = _mask_quoted_operators(arg_text)
            if _GUARD_ADMIN_RE.search(masked_arg) or _GUARD_INLINE_PY_RE.search(arg_text):
                return {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Human-only `agy-guard` administration commands are "
                        "prohibited inside `run_workflow` `Args` (GEMINI.md Rule 12)."
                    ),
                }
            if _WORKFLOW_INSTALL_EXEC_RE.search(masked_arg):
                return {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Executing `install.py` inside `run_workflow` `Args` is "
                        "prohibited (GEMINI.md Rule 12)."
                    ),
                }
            if _GIT_HOOK_BYPASS_RE.search(masked_arg):
                return {
                    "decision": "deny",
                    "reason": (
                        "[Harness Workflow Shield] Git hook bypass flags (`--no-verify`, `commit -n`, "
                        "`core.hooksPath`, `HUSKY=0`) are prohibited inside `run_workflow` `Args`."
                    ),
                }
        pending_flight_writes: List[Tuple[str, str]] = []
        pending_force_ask: Optional[Dict[str, Any]] = None
        for sp_path, sp_mode in script_paths_meta:
            in_ws = any(is_within(sp_path, ws) for ws in workspaces)
            if (sp_mode & stat.S_IWOTH) or (workspaces and not in_ws) or (not workspaces and (sp_mode & 0o222)):
                pending_force_ask = {
                    "decision": "force_ask",
                    "reason": (
                        f"[Harness Workflow Shield] `run_workflow` `ScriptPath` (`{sp_path}`) resides outside "
                        "the active workspace or is world-writable (TOCTOU risk); explicit human confirmation "
                        "is required (GEMINI.md Rule 12 & Rule 15e)."
                    ),
                }
                break
        wf_owner_ws = (
            _workspace_for_target(str(workflow_cwd), workspaces, fallback=workspace)
            if workflow_cwd is not None
            else workspace
        )
        for src in script_sources:
            res, fw = _inspect_workflow_script(src, arg_strings, payload, wf_owner_ws, workflow_cwd=workflow_cwd)
            if res.get("decision") == "deny":
                return res
            if res.get("decision") == "force_ask" and pending_force_ask is None:
                pending_force_ask = res
            pending_flight_writes.extend(fw)
        if pending_force_ask is not None:
            return pending_force_ask
        for inner_tool, target in pending_flight_writes:
            fw_ws = _workspace_for_target(target, workspaces, fallback=wf_owner_ws)
            _record_flight_pre_write(payload, fw_ws, inner_tool, target)
        return {"decision": "allow"}

    # Normal pass-through in Antigravity 2.0 PreToolUse requires explicit {"decision": "allow"}
    return {"decision": "allow"}


# ----------------------------------------------------------------------
# 3. Stop: Completion & Diff Integrity Gate (with 3-Strike Circuit Breaker)
# ----------------------------------------------------------------------
def _is_test_path(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/").lstrip("./")
    parts = norm.split("/")
    name = parts[-1] if parts else norm
    if any(p in ("tests", "test", "__tests__") for p in parts[:-1]):
        return True
    return (
        name.startswith("test_")
        or name.endswith(("_test.py", "_test.go", ".test.ts", ".test.tsx", ".test.js", ".spec.ts", ".spec.tsx", ".spec.js"))
    )


def _is_deferrable_question(assistant_text: str) -> bool:
    """
    True when the assistant is asking the user a clarifying question rather than claiming
    task completion (commands_at_questions: defer).
    """
    if not assistant_text:
        return False
    if "### Delivery Block" in assistant_text or "[COMPLETE]" in assistant_text:
        return False
    stripped = re.sub(r"[*_`>\s]+$", "", assistant_text.strip())
    return stripped.endswith("?")


_AUTH_HEADING_RE = re.compile(
    r"(?ims)^[^\S\r\n]*#{1,6}[^\S\r\n]+Authorized\s+Test\s+Modifications(?:\s*:\s*([^\r\n]*))?[^\S\r\n]*\r?$(.*?)(?=^[^\S\r\n]*#{1,6}[^\S\r\n]+|\Z)"
)
_EMPTY_AUTH_TOKENS = frozenset({"", "none", "yok", "n/a", "na", "null", "nil", "false", "hayir", "hayır"})


def _extract_normalized_auth_section(text: str) -> str:
    sections: List[str] = []
    for match in _AUTH_HEADING_RE.finditer(text or ""):
        combined = f"{match.group(1) or ''}\n{match.group(2) or ''}".strip()
        cleaned = re.sub(r"[-*•\[\]\s.`_:;()]+", "", combined.lower())
        if cleaned not in _EMPTY_AUTH_TOKENS:
            sections.append(combined)
    return "\n".join(sections)


def _auth_sections_differ(old_text: str, new_text: str) -> bool:
    if _extract_normalized_auth_section(new_text) != _extract_normalized_auth_section(old_text):
        return True
    try:
        from guard.test_boundary import TestBoundaryGuard

        if TestBoundaryGuard.parse_authorized_tasks_text(new_text) != TestBoundaryGuard.parse_authorized_tasks_text(old_text):
            return True
    except Exception:
        pass
    return False


def _write_mutates_authorized_test_section(target: str, args: Dict[str, Any], base_dir: Optional[Path]) -> bool:
    norm_target = target.replace("\\", "/").strip()
    if Path(norm_target).name.lower() != "tasks.md":
        return False
    disk_path = Path(os.path.expanduser(norm_target))
    if not disk_path.is_absolute():
        disk_path = (base_dir or REPO_ROOT) / disk_path
    try:
        disk_path = disk_path.resolve()
    except (OSError, RuntimeError):
        pass
    old_text = ""
    try:
        if disk_path.is_file():
            old_text = disk_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        old_text = ""
    norm_old = old_text.replace("\r\n", "\n").replace("\r", "\n")

    # Full-file or append write (`write_file`, `write_to_file`, `create_file`, `write`)
    for content_key in ("Content", "FileContent", "CodeContent", "content", "file_text"):
        if content_key in args and isinstance(args.get(content_key), str):
            body = args[content_key].replace("\r\n", "\n").replace("\r", "\n")
            is_append = bool(args.get("Append") or args.get("append"))
            sim_text = (norm_old + body) if is_append else body
            return _auth_sections_differ(norm_old, sim_text)

    # Targeted replacement (`edit_file`, `replace_file_content`, `multi_replace_file_content`, `edit`, `multiedit`)
    pairs: List[Tuple[str, str]] = []
    chunks = args.get("ReplacementChunks") or args.get("edits") or args.get("chunks")
    if isinstance(chunks, list):
        for ch in chunks:
            if isinstance(ch, dict):
                t_s = (
                    ch.get("TargetContent")
                    or ch.get("Target")
                    or ch.get("old_string")
                    or ch.get("old_str")
                    or ch.get("oldText")
                )
                r_s = (
                    ch.get("ReplacementContent")
                    if "ReplacementContent" in ch
                    else (
                        ch.get("Replacement")
                        if "Replacement" in ch
                        else (
                            ch.get("new_string")
                            if "new_string" in ch
                            else (ch.get("new_str") if "new_str" in ch else ch.get("newText"))
                        )
                    )
                )
                if isinstance(t_s, str) and isinstance(r_s, str):
                    pairs.append(
                        (
                            t_s.replace("\r\n", "\n").replace("\r", "\n"),
                            r_s.replace("\r\n", "\n").replace("\r", "\n"),
                        )
                    )
    else:
        t_s = (
            args.get("Target")
            or args.get("TargetContent")
            or args.get("old_string")
            or args.get("old_str")
            or args.get("oldText")
        )
        r_s = (
            args.get("Replacement")
            if "Replacement" in args
            else (
                args.get("ReplacementContent")
                if "ReplacementContent" in args
                else (
                    args.get("new_string")
                    if "new_string" in args
                    else (args.get("new_str") if "new_str" in args else args.get("newText"))
                )
            )
        )
        if isinstance(t_s, str) and isinstance(r_s, str):
            pairs.append(
                (
                    t_s.replace("\r\n", "\n").replace("\r", "\n"),
                    r_s.replace("\r\n", "\n").replace("\r", "\n"),
                )
            )

    if pairs:
        if norm_old and all(t_s in norm_old for t_s, _ in pairs):
            sim_text = norm_old
            for t_s, r_s in pairs:
                sim_text = sim_text.replace(t_s, r_s)
            return _auth_sections_differ(norm_old, sim_text)
        has_existing_heading = bool(_AUTH_HEADING_RE.search(norm_old))
        for t_s, r_s in pairs:
            if re.search(r"Authorized\s+Test\s+Modifications", f"{t_s}\n{r_s}", re.IGNORECASE):
                return True
            if has_existing_heading:
                return True
    return False


def _authorized_test_modification_text(workspace: Optional[Path]) -> str:
    """
    Extracts the normalized authorization text under `## Authorized Test Modifications`
    (supporting both the inline `## Authorized Test Modifications: [file: reason]` format from
    skills/harness/SKILL.md and multi-line section bodies). Returns "" if absent or placeholder.
    """
    if workspace is None:
        return ""
    tasks_file = workspace / "tasks.md"
    if not tasks_file.is_file():
        return ""
    try:
        text = tasks_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return _extract_normalized_auth_section(text)


def _has_authorized_test_modifications(workspace: Path, rel_path: str = "") -> bool:
    from guard.test_boundary import TestBoundaryGuard

    auth_paths = {
        p.replace("\\", "/").lstrip("./")
        for p in TestBoundaryGuard.load_authorized_from_tasks_md(workspace)
        if p.lower() not in _EMPTY_AUTH_TOKENS
    }
    if not auth_paths:
        return False
    if not rel_path:
        return True
    norm = str(rel_path).replace("\\", "/").lstrip("./")
    return norm in auth_paths


_MD_LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
_PLACEHOLDER_LINK_RE = re.compile(r"(?:[<>{}]|(?:/|^)path/to/|/absolute/path|/your[-_])", re.IGNORECASE)


def validate_structured_content(norm_path: str, content: str) -> List[str]:
    """
    Deterministically validates structured file formats (.json, .toml, .svg) using only
    the Python standard library.
    """
    lower = norm_path.lower()
    if lower.endswith(".json"):
        try:
            json.loads(content)
        except json.JSONDecodeError as exc:
            return [
                f"Malformed JSON syntax in `{norm_path}` (`line {exc.lineno}, column {exc.colno}: {exc.msg}`) "
                "— fix JSON syntax before completing (skills/harness/SKILL.md §3B Step 1)."
            ]
        except RecursionError:
            return [
                f"Malformed JSON syntax in `{norm_path}` (`maximum nesting depth exceeded`) "
                "— fix JSON syntax before completing (skills/harness/SKILL.md §3B Step 1)."
            ]
        return []

    if lower.endswith(".toml") and tomllib is not None:
        try:
            tomllib.loads(content)
        except Exception as exc:
            msg = str(exc).splitlines()[0][:80] if str(exc) else "invalid TOML"
            return [
                f"Malformed TOML syntax in `{norm_path}` (`{msg}`) "
                "— fix TOML syntax before completing (skills/harness/SKILL.md §3B Step 1)."
            ]
        return []

    if lower.endswith(".svg"):
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", content, re.IGNORECASE):
            return [
                f"Unsafe XML DOCTYPE/ENTITY declaration in `{norm_path}` (`DOCTYPE/ENTITY`) "
                "— DTD/entity declarations are forbidden in SVG files."
            ]
        try:
            root = ET.fromstring(content)
        except (ET.ParseError, RecursionError) as exc:
            msg = str(exc).splitlines()[0][:80] if str(exc) else "invalid XML"
            return [
                f"Malformed SVG/XML syntax in `{norm_path}` (`{msg}`) "
                "— fix XML structure before completing (skills/harness/SKILL.md §3B Step 1)."
            ]
        tag = root.tag.split("}", 1)[-1] if "}" in root.tag else root.tag
        if tag.lower() != "svg":
            return [
                f"Invalid SVG root element in `{norm_path}` (`<{tag}>`) "
                "— SVG files must have `<svg>` as their root element."
            ]
        return []

    return []


_UI_SLOP_EXTENSIONS = (".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".css")
_UI_SLOP_SCANNER_MOD: Any = None
_UI_SLOP_SCANNER_LOADED = False


def _load_ui_slop_scanner() -> Any:
    """Loads skills/antislop/scripts/check_ui_slop.py from REPO_ROOT or config_dir()."""
    global _UI_SLOP_SCANNER_MOD, _UI_SLOP_SCANNER_LOADED
    if _UI_SLOP_SCANNER_LOADED and _UI_SLOP_SCANNER_MOD is not None:
        return _UI_SLOP_SCANNER_MOD
    candidates = [
        REPO_ROOT / "skills" / "antislop" / "scripts" / "check_ui_slop.py",
        config_dir() / "skills" / "antislop" / "scripts" / "check_ui_slop.py",
        configured_config_dir() / "skills" / "antislop" / "scripts" / "check_ui_slop.py",
        Path("/usr/share/antigravity-harness") / "skills" / "antislop" / "scripts" / "check_ui_slop.py",
    ]
    for script_path in candidates:
        if script_path.is_file():
            try:
                spec = importlib.util.spec_from_file_location("_agy_check_ui_slop", script_path)
                if spec is not None and spec.loader is not None:
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules[spec.name] = mod
                    spec.loader.exec_module(mod)
                    _UI_SLOP_SCANNER_MOD = mod
                    _UI_SLOP_SCANNER_LOADED = True
                    return mod
            except Exception:
                continue
    return None


def validate_ui_slop_content(norm_path: str, content: str) -> List[str]:
    """
    Runs check_ui_slop.py (`UI-1`–`UI-5`, mode='auto' detecting game/editorial/utility)
    on modified non-test UI/HTML/game prototype files.
    """
    if not norm_path.lower().endswith(_UI_SLOP_EXTENSIONS) or norm_path.startswith("skills/silk-design/assets/"):
        return []
    mod = _load_ui_slop_scanner()
    if mod is None or not hasattr(mod, "scan_text"):
        return []
    try:
        report = mod.scan_text(content, path=norm_path, mode="auto")
    except Exception as exc:
        return [
            f"UI slop scanner failed on `{norm_path}` ({type(exc).__name__}: {exc}) "
            "— verify `skills/antislop/scripts/check_ui_slop.py` health."
        ]
    out: List[str] = []
    for f in getattr(report, "findings", [])[:3]:
        out.append(
            f"UI slop violation [{f.rule_id}] in `{norm_path}` (`L{f.line_number}: {f.matched_span}`) "
            f"— {f.fix_hint} (skills/harness/SKILL.md §3B Step 4b)."
        )
    return out


def _inspect_markdown_added_links(
    norm_path: str,
    raw_added: str,
    workspace: Optional[Path],
    md_doc_cache: Optional[Dict[str, Optional[Tuple[str, str]]]] = None,
) -> List[str]:
    """Checks added Markdown prose lines for broken workspace-local file:// or relative links."""
    if workspace is None or "](" not in raw_added:
        return []
    no_code = _INLINE_CODE_RE.sub(" ", raw_added)
    raw_links = [lnk for lnk in _MD_LINK_RE.findall(no_code) if not _PLACEHOLDER_LINK_RE.search(lnk)]
    if not raw_links:
        return []

    md_disk = workspace / norm_path
    try:
        if md_doc_cache is not None and norm_path in md_doc_cache:
            cached_pair = md_doc_cache[norm_path]
        else:
            cached_pair = None
            if (
                md_disk.is_file()
                and not md_disk.is_symlink()
                and is_within(md_disk, workspace)
                and md_disk.stat().st_size <= 262144
            ):
                full_doc = md_disk.read_text(encoding="utf-8", errors="replace")
                cached_pair = (full_doc, _FENCE_RE.sub(" ", full_doc))
            if md_doc_cache is not None:
                md_doc_cache[norm_path] = cached_pair
        if cached_pair is not None:
            full_doc, unfenced_doc = cached_pair
            if raw_added in full_doc and raw_added not in unfenced_doc:
                return []
    except OSError:
        pass

    issues: List[str] = []
    for raw_link in raw_links:
        if raw_link.startswith("file://"):
            parsed = urllib.parse.urlparse(raw_link)
            unquoted = urllib.parse.unquote(parsed.path or "")
            if not unquoted:
                continue
            target = Path(unquoted)
            if is_within(target, workspace) and not target.exists():
                issues.append(
                    f"Broken workspace link in `{norm_path}` (`{raw_link}`) "
                    "— referenced file does not exist in workspace (skills/harness/SKILL.md §3B Step 3)."
                )
        elif not re.match(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|#|/)", raw_link):
            rel_part = urllib.parse.unquote(raw_link.split("#", 1)[0].split("?", 1)[0])
            if rel_part and is_within(md_disk, workspace):
                resolved = md_disk.parent / rel_part
                if is_within(resolved, workspace) and not resolved.exists():
                    issues.append(
                        f"Broken workspace link in `{norm_path}` (`{raw_link}`) "
                        "— referenced file does not exist in workspace (skills/harness/SKILL.md §3B Step 3)."
                    )
    return issues


_ISO_TIMEBOMB_RE = re.compile(r"['\"]20(?:2[4-9]|[3-9]\d)-\d{2}-\d{2}T\d{2}:\d{2}")
_LIVE_CLOCK_CALL_RE = re.compile(r"\b(?:datetime\.(?:now|utcnow)|time\.time|Date\.now)\s*\(")
_CLOCK_INJECTION_RE = re.compile(
    r"(?:\b(?:now|clock|current_time)\s*=|mock\.patch|monkeypatch|freeze_time|timedelta\s*\()"
)
_STRING_LIT_RE = re.compile(r"'([^'\\\n]{8,120})'|\"([^\"\\\n]{8,120})\"")
_CODE_EXTS_FOR_STALE_NEG = (".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs")


def _scan_stale_negative_assertions(
    removed_by_prod_file: Dict[str, List[str]],
    all_added_lines: List[str],
    modified_test_files: set[str],
    workspace: Optional[Path],
) -> List[str]:
    if workspace is None or not removed_by_prod_file:
        return []
    added_blob = "\n".join(all_added_lines)
    candidate_lits: List[Tuple[str, str]] = []
    seen_lits: set[str] = set()
    for prod_path, rem_lines in removed_by_prod_file.items():
        if not prod_path.lower().endswith(_CODE_EXTS_FOR_STALE_NEG):
            continue
        if any(prod_path.endswith(sfx) for sfx in _SCANNER_EXEMPT_SUFFIXES):
            continue
        prod_disk = workspace / prod_path
        prod_current = ""
        try:
            if prod_disk.is_file() and prod_disk.stat().st_size <= 262144:
                prod_current = prod_disk.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
        for rem in rem_lines:
            for m in _STRING_LIT_RE.finditer(rem):
                lit = m.group(1) if m.group(1) is not None else (m.group(2) or "")
                if (
                    lit in seen_lits
                    or not re.search(r"[A-Za-z]", lit)
                    or lit.startswith(("http://", "https://", "/", "./", "../"))
                    or lit in added_blob
                    or (prod_current and lit in prod_current)
                ):
                    continue
                seen_lits.add(lit)
                candidate_lits.append((prod_path, lit))
                if len(candidate_lits) >= 25:
                    break
            if len(candidate_lits) >= 25:
                break
        if len(candidate_lits) >= 25:
            break

    if not candidate_lits:
        return []

    test_files: List[Tuple[str, str]] = []
    tests_root = workspace / "tests"
    scan_roots = [tests_root] if tests_root.is_dir() else [workspace]
    for s_root in scan_roots:
        for root, dirs, files in os.walk(s_root):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules", ".venv", "venv")]
            for fname in sorted(files):
                fpath = Path(root) / fname
                try:
                    rel = fpath.relative_to(workspace).as_posix()
                except ValueError:
                    continue
                if not _is_test_path(rel):
                    continue
                try:
                    if not fpath.is_file() or fpath.is_symlink() or fpath.stat().st_size > 262144:
                        continue
                    test_files.append((rel, fpath.read_text(encoding="utf-8", errors="replace")))
                except OSError:
                    continue
                if len(test_files) >= 60:
                    break
            if len(test_files) >= 60:
                break

    issues: List[str] = []
    fn_split_re = re.compile(r"^\s*(?:async\s+)?def\s+test_|^\s*(?:it|test)\s*\(")
    for prod_path, lit in candidate_lits:
        esc = re.escape(lit)
        neg_re = re.compile(
            rf"(?:assertNotIn\s*\(\s*['\"]{esc}['\"]\s*,|assert\s+['\"]{esc}['\"]\s+not\s+in\b|\.not\.toContain\s*\(\s*['\"]{esc}['\"]\s*\))"
        )
        for test_rel, t_content in test_files:
            fn_blocks: List[List[str]] = [[]]
            for ln in t_content.splitlines():
                if fn_split_re.match(ln) and fn_blocks[-1]:
                    fn_blocks.append([ln])
                else:
                    fn_blocks[-1].append(ln)
            for block_lines in fn_blocks:
                code_only = "\n".join(
                    ln for ln in block_lines if not ln.lstrip().startswith(("#", "//"))
                )
                if neg_re.search(code_only) and lit not in neg_re.sub("", code_only):
                    issues.append(
                        f"Stale negative assertion in `{test_rel}` (`{lit[:60]}`) referencing literal removed from `{prod_path}` "
                        "— update or replace vacuous negative assertions (GEMINI.md Rule 9)."
                    )
                    break
    return issues


_ACTIVE_TEST_ASSERT_RE = re.compile(
    r"^\s*(?!#|//|/\*|\*)(?:"
    r"assert\b|"
    r"(?:await\s+)?(?:self|t|assert|require)\.(?:assert\w*|fail\w*|Equal|NoError|True|False)\s*\(|"
    r"(?:await\s+)?expect\s*\(|"
    r"pytest\.raises\s*\(|"
    r"assert(?:_eq|_ne|!)!\s*\("
    r")"
)


_NEW_FILE_CAPABILITY_SKIP_RE = re.compile(
    r"^\s*@(?:unittest\.skip(?:If|Unless)|pytest\.mark\.skipif)\s*\("
    r"(?!\s*(?:True|False|1|0)\s*(?:,|\)))"
    r"[^#\n]*(?:os\.name|sys\.platform|platform\.system|shutil\.which|os\.geteuid|IS_ROOT|IS_WINDOWS|POSIX)\b"
)
_PY_TEST_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+(test_[A-Za-z0-9_]+)\s*\(")
_UNTRACKED_MAX_FILES = 200
_UNTRACKED_MAX_BYTES = 1024 * 1024
_INSCOPE_UNTRACKED_CODE_EXTS = (
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rs",
    *_UI_SLOP_EXTENSIONS,
)


def _unquote_git_diff_path(header_line: str, prefix: str = "b/") -> str:
    """
    Parses a unified diff `+++ ...` or `--- ...` header line into a normalized workspace-relative POSIX path,
    decoding C-quoted UTF-8 octal escapes (`+++ "b/tests/\\303\\247..."`) when `core.quotePath` is active.
    """
    raw_spec = header_line[3:].strip()
    if not raw_spec or raw_spec == "/dev/null" or raw_spec.startswith("/dev/null\t"):
        return ""
    if raw_spec.startswith('"'):
        buf = bytearray()
        i = 1
        n = len(raw_spec)
        closed = False
        esc_map = {
            "a": 0x07,
            "b": 0x08,
            "t": 0x09,
            "n": 0x0A,
            "v": 0x0B,
            "f": 0x0C,
            "r": 0x0D,
            "\\": 0x5C,
            '"': 0x22,
        }
        while i < n:
            ch = raw_spec[i]
            if ch == '"':
                closed = True
                break
            if ch == "\\" and i + 1 < n:
                nxt = raw_spec[i + 1]
                if nxt in "01234567":
                    oct_str = nxt
                    j = i + 2
                    while j < n and j < i + 4 and raw_spec[j] in "01234567":
                        oct_str += raw_spec[j]
                        j += 1
                    buf.append(int(oct_str, 8) & 0xFF)
                    i = j
                    continue
                if nxt in esc_map:
                    buf.append(esc_map[nxt])
                    i += 2
                    continue
                buf.extend(nxt.encode("utf-8"))
                i += 2
                continue
            buf.extend(ch.encode("utf-8"))
            i += 1
        decoded = buf.decode("utf-8", errors="replace") if closed else raw_spec.strip('"')
    else:
        decoded = raw_spec.split("\t", 1)[0].strip()

    if not decoded.startswith(prefix):
        return ""
    return decoded[len(prefix) :].replace("\\", "/")


def inspect_git_diff(diff_text: str, workspace: Optional[Path] = None) -> List[str]:
    """
    Scans a unified git diff (`git diff -U0`) for:
      1. Tautological assertions & calendar time-bombs in test files
      2. Test-runner environment sniffing in non-test production files (GEMINI.md Rule 9 C9)
      3. Unapproved test skip/weakening markers, net assertion removals/comment-outs/whole-file deletions, & stale negative assertions
      4. Malformed structured files (.json, .toml, .svg), UI/game slop (.html, .jsx, .tsx, .css), and broken workspace-local Markdown links
    """
    from guard.test_boundary import TestBoundaryGuard

    findings: List[str] = []
    current_file = ""
    pending_old_file = ""
    md_fence: Optional[Tuple[str, int]] = None
    file_added_lines: Dict[str, List[str]] = {}
    removed_by_prod_file: Dict[str, List[str]] = {}
    removed_assertions_by_test: Dict[str, int] = {}
    added_assertions_by_test: Dict[str, int] = {}
    removed_test_defs_by_file: Dict[str, set[str]] = {}
    added_test_defs_by_file: Dict[str, set[str]] = {}
    first_removed_assert: Dict[str, str] = {}
    all_added_lines: List[str] = []
    modified_test_files: set[str] = set()
    deleted_test_files: set[str] = set()
    file_is_new: set[str] = set()
    file_is_partial: set[str] = set()
    md_doc_cache: Dict[str, Optional[Tuple[str, str]]] = {}
    auth_cache: Dict[str, bool] = {}

    def _is_test_authorized(rel_p: str) -> bool:
        if rel_p not in auth_cache:
            auth_cache[rel_p] = _has_authorized_test_modifications(workspace, rel_p) if workspace else False
        return auth_cache[rel_p]

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            pending_old_file = ""
            current_file = ""
            md_fence = None
            continue
        if line.startswith("--- "):
            raw_old = line[3:].strip()
            if raw_old == "/dev/null" or raw_old.startswith("/dev/null\t"):
                pending_old_file = "__DEV_NULL__"
            else:
                pending_old_file = _unquote_git_diff_path(line, prefix="a/")
            continue
        if line.startswith("+++ "):
            new_file = _unquote_git_diff_path(line, prefix="b/")
            if new_file:
                current_file = new_file
                if pending_old_file == "__DEV_NULL__":
                    file_is_new.add(current_file)
            else:
                current_file = pending_old_file if pending_old_file and pending_old_file != "__DEV_NULL__" else ""
                if current_file and _is_test_path(current_file):
                    deleted_test_files.add(current_file)
            pending_old_file = ""
            md_fence = None
            if current_file:
                file_added_lines.setdefault(current_file, [])
                if _is_test_path(current_file):
                    modified_test_files.add(current_file)
            continue
        if not current_file:
            continue

        if line.startswith("@@ "):
            if re.match(r"^@@\s+-0,0\s+\+", line):
                if current_file not in file_is_partial:
                    file_is_new.add(current_file)
            else:
                file_is_partial.add(current_file)
                file_is_new.discard(current_file)
            continue
        if line.startswith("-") and not line.startswith("--- "):
            file_is_partial.add(current_file)
            file_is_new.discard(current_file)
            rem_body = line[1:]
            if _is_test_path(current_file):
                modified_test_files.add(current_file)
                m_tdef = _PY_TEST_DEF_RE.match(rem_body)
                if m_tdef:
                    removed_test_defs_by_file.setdefault(current_file, set()).add(m_tdef.group(1))
                if _ACTIVE_TEST_ASSERT_RE.search(rem_body):
                    removed_assertions_by_test[current_file] = removed_assertions_by_test.get(current_file, 0) + 1
                    first_removed_assert.setdefault(current_file, rem_body.strip()[:80])
            else:
                removed_by_prod_file.setdefault(current_file, []).append(rem_body)
            continue
        if not line.startswith("+"):
            continue

        norm_path = current_file
        added_body = line[1:]
        if added_body.startswith("# __AGY_UNINSPECTED_UNTRACKED__:"):
            findings.append(
                f"Uninspected untracked file in `{norm_path}` exceeds Stop-gate scan cap (`1 MiB` / `200` files) "
                "— split or stage/inspect manually before completion (GEMINI.md Rule 8)."
            )
            continue

        file_added_lines.setdefault(norm_path, []).append(added_body)
        all_added_lines.append(added_body)
        is_test = _is_test_path(norm_path)

        if norm_path.lower().endswith((".md", ".mdc")):
            m_fence = re.match(r"^\s*(`{3,}|~{3,})", added_body)
            if m_fence:
                marker = m_fence.group(1)
                if md_fence is None:
                    md_fence = (marker[0], len(marker))
                elif md_fence[0] == marker[0] and len(marker) >= md_fence[1]:
                    md_fence = None
            elif md_fence is None:
                findings.extend(_inspect_markdown_added_links(norm_path, added_body, workspace, md_doc_cache))

        if is_test:
            m_adef = _PY_TEST_DEF_RE.match(added_body)
            if m_adef:
                added_test_defs_by_file.setdefault(norm_path, set()).add(m_adef.group(1))
            is_tautology = bool(_TAUTOLOGY_PY_RE.search(line) or _TAUTOLOGY_JS_RE.search(line))
            if is_tautology:
                findings.append(
                    f"Tautological test assertion in `{norm_path}` (`{added_body.strip()[:80]}`) "
                    "— assertions must verify real behaviour (GEMINI.md Rule 9)."
                )
            elif _ACTIVE_TEST_ASSERT_RE.search(added_body):
                added_assertions_by_test[norm_path] = added_assertions_by_test.get(norm_path, 0) + 1

            is_new_test_file = norm_path in file_is_new and norm_path not in file_is_partial
            is_allowed_cap_skip = is_new_test_file and bool(_NEW_FILE_CAPABILITY_SKIP_RE.search(added_body))
            if not is_allowed_cap_skip and (
                _TEST_SKIP_RE.search(line) or bool(TestBoundaryGuard.weakening_lines([added_body]))
            ):
                if not _is_test_authorized(norm_path):
                    findings.append(
                        f"Unapproved test skip or weakening marker in `{norm_path}` (`{added_body.strip()[:80]}`) "
                        "— skipping or commenting out tests without logging the file under "
                        "`## Authorized Test Modifications` in `tasks.md` is forbidden (GEMINI.md Rule 9)."
                    )
        else:
            if not norm_path.lower().endswith((".md", ".mdc")) and not any(norm_path.endswith(sfx) for sfx in _SCANNER_EXEMPT_SUFFIXES):
                if not _COMMENT_ADDED_LINE_RE.match(line) and _TEST_RUNNER_SNIFF_RE.search(line):
                    findings.append(
                        f"Test-runner detection in production file `{norm_path}` (`{added_body.strip()[:80]}`) "
                        "— branching on test-runner state in production code is forbidden (GEMINI.md Rule 9 C9)."
                    )

    matched_rename_targets: set[str] = set()

    def _deleted_test_is_authorized_rename(del_path: str, rem_cnt: int) -> bool:
        if del_path not in deleted_test_files:
            return False
        rem_defs = removed_test_defs_by_file.get(del_path, set())
        for cand_new in sorted(file_is_new):
            if cand_new in matched_rename_targets or not _is_test_path(cand_new):
                continue
            if not (_is_test_authorized(del_path) or _is_test_authorized(cand_new)):
                continue
            if added_assertions_by_test.get(cand_new, 0) < rem_cnt:
                continue
            if rem_defs and not (rem_defs <= added_test_defs_by_file.get(cand_new, set())):
                continue
            matched_rename_targets.add(cand_new)
            return True
        return False

    for norm_path, rem_cnt in removed_assertions_by_test.items():
        add_cnt = added_assertions_by_test.get(norm_path, 0)
        if rem_cnt > add_cnt and not _is_test_authorized(norm_path):
            if _deleted_test_is_authorized_rename(norm_path, rem_cnt):
                continue
            findings.append(
                f"Unapproved test assertion removal in `{norm_path}` (`{first_removed_assert.get(norm_path, '')}`) "
                f"— net active assertions decreased ({rem_cnt} removed vs {add_cnt} added) without logging `{norm_path}` "
                "under `## Authorized Test Modifications` in `tasks.md` (GEMINI.md Rule 9)."
            )

    for del_test in sorted(deleted_test_files):
        if (
            removed_assertions_by_test.get(del_test, 0) == 0
            and removed_test_defs_by_file.get(del_test)
            and not _is_test_authorized(del_test)
            and not _deleted_test_is_authorized_rename(del_test, 0)
        ):
            findings.append(
                f"Unapproved test assertion removal in `{del_test}` (`deleted test file`) "
                f"— test file `{del_test}` was deleted without logging it under "
                "`## Authorized Test Modifications` in `tasks.md` (GEMINI.md Rule 9)."
            )

    if workspace is not None and _is_git_repo_workspace(workspace):
        for norm_path in sorted(modified_test_files):
            if not norm_path.lower().endswith(".py") or norm_path not in file_is_partial or _is_test_authorized(norm_path):
                continue
            disk_test = workspace / norm_path
            try:
                if not disk_test.is_file() or disk_test.is_symlink() or disk_test.stat().st_size > 262144:
                    continue
                new_test_src = disk_test.read_text(encoding="utf-8", errors="replace")
                head_blob = subprocess.run(
                    ["git", "-c", "core.quotePath=false", "-C", str(workspace), "show", f"HEAD:{norm_path}"],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    stdin=subprocess.DEVNULL,
                )
                if head_blob.returncode == 0 and head_blob.stdout:
                    ast_weak = TestBoundaryGuard.python_weakening(
                        head_blob.stdout, new_test_src, file_added_lines.get(norm_path, ())
                    )
                    for note in ast_weak[:3]:
                        findings.append(
                            f"Test boundary weakening in `{norm_path}` (`{note}`) "
                            "— weakening existing tests without authorization is forbidden (GEMINI.md Rule 9)."
                        )
            except (OSError, subprocess.SubprocessError):
                continue

    # Validate up to 20 modified structured files (.json, .toml, .svg) and non-test UI/game files
    checked_structured = 0
    for norm_path, added_lines in file_added_lines.items():
        lower_path = norm_path.lower()
        is_struct = lower_path.endswith((".json", ".toml", ".svg"))
        is_ui = (not _is_test_path(norm_path)) and lower_path.endswith(_UI_SLOP_EXTENSIONS)
        if not is_struct and not is_ui:
            continue
        if checked_structured >= 20:
            break
        checked_structured += 1
        content_to_check: Optional[str] = None
        skipped_oversized = False
        if workspace is not None:
            disk_path = workspace / norm_path
            try:
                if (
                    disk_path.is_file()
                    and not disk_path.is_symlink()
                    and is_within(disk_path, workspace)
                ):
                    if disk_path.stat().st_size <= 262144:
                        content_to_check = disk_path.read_text(encoding="utf-8", errors="replace")
                    else:
                        skipped_oversized = True
            except OSError:
                content_to_check = None
        if (
            content_to_check is None
            and not skipped_oversized
            and norm_path not in file_is_partial
            and added_lines
            and sum(len(x) for x in added_lines) <= 262144
        ):
            content_to_check = "\n".join(added_lines)
        if content_to_check is not None:
            if is_struct:
                findings.extend(validate_structured_content(norm_path, content_to_check))
            if is_ui:
                findings.extend(validate_ui_slop_content(norm_path, content_to_check))

    # Check added test blocks per test function for calendar time-bombs & tests for stale negative assertions
    _test_fn_boundary_re = re.compile(r"^\s*(?:async\s+)?def\s+test_|^\s*(?:it|test)\s*\(")
    for norm_path, added_lines in file_added_lines.items():
        if not _is_test_path(norm_path) or not added_lines:
            continue
        fn_chunks: List[List[str]] = [[]]
        for ln in added_lines:
            if _test_fn_boundary_re.match(ln) and fn_chunks[-1]:
                fn_chunks.append([ln])
            else:
                fn_chunks[-1].append(ln)
        for chunk_lines in fn_chunks:
            joined_test = "\n".join(chunk_lines)
            m_iso = _ISO_TIMEBOMB_RE.search(joined_test)
            if m_iso and _LIVE_CLOCK_CALL_RE.search(joined_test) and not _CLOCK_INJECTION_RE.search(joined_test):
                findings.append(
                    f"Calendar time-bomb in `{norm_path}` (`{m_iso.group(0)[1:]}`) "
                    "— inject or mock `now` instead of comparing live clocks against hardcoded dates (skills/test-design/SKILL.md)."
                )
                break

    findings.extend(
        _scan_stale_negative_assertions(removed_by_prod_file, all_added_lines, modified_test_files, workspace)
    )

    # Deduplicate while preserving order
    seen = set()
    unique: List[str] = []
    for item in findings:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def _is_git_repo_workspace(workspace: Path) -> bool:
    cur = workspace
    try:
        cur = workspace.resolve()
    except (OSError, RuntimeError):
        pass
    for candidate in (cur, *cur.parents):
        try:
            if (candidate / ".git").exists():
                return True
        except OSError:
            continue
    return False


def _collect_workspace_diff_status_ex(workspace: Path) -> Tuple[str, bool, bool]:
    chunks: List[str] = []
    diff_ok = False
    untracked_ok = False
    git_base = ["git", "-c", "core.quotePath=false", "-C", str(workspace)]
    try:
        res = subprocess.run(
            [*git_base, "diff", "-U0", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            stdin=subprocess.DEVNULL,
        )
        if res.returncode == 0:
            diff_ok = True
            if res.stdout:
                chunks.append(res.stdout)
        else:
            # Unborn HEAD fallback — only valid when `HEAD` is genuinely an unborn branch (not corrupt `.git/HEAD`)
            rev_head = subprocess.run(
                [*git_base, "symbolic-ref", "-q", "HEAD"],
                capture_output=True,
                text=True,
                timeout=3,
                stdin=subprocess.DEVNULL,
            )
            ref_name = (rev_head.stdout or "").strip()
            ref_Verify = (
                subprocess.run(
                    [*git_base, "show-ref", "--verify", "--quiet", ref_name],
                    capture_output=True,
                    timeout=3,
                    stdin=subprocess.DEVNULL,
                ).returncode
                if (rev_head.returncode == 0 and ref_name.startswith("refs/heads/") and ".." not in ref_name)
                else 0
            )
            if rev_head.returncode == 0 and ref_name.startswith("refs/heads/") and ".." not in ref_name and ref_Verify != 0:
                staged = subprocess.run(
                    [*git_base, "diff", "-U0", "--cached"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    stdin=subprocess.DEVNULL,
                )
                unstaged = subprocess.run(
                    [*git_base, "diff", "-U0"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    stdin=subprocess.DEVNULL,
                )
                if staged.returncode == 0 and unstaged.returncode == 0:
                    diff_ok = True
                    if staged.stdout:
                        chunks.append(staged.stdout)
                    if unstaged.stdout:
                        chunks.append(unstaged.stdout)
    except (OSError, subprocess.SubprocessError):
        pass

    # Also synthesize added-line diffs for newly created untracked files so brand-new test/source files are checked
    has_any_untracked = False
    try:
        untracked = subprocess.run(
            [*git_base, "ls-files", "--others", "--exclude-standard", "-z"],
            capture_output=True,
            timeout=3,
            stdin=subprocess.DEVNULL,
        )
        if untracked.returncode == 0:
            untracked_ok = True
            if untracked.stdout:
                rel_paths = [p.decode("utf-8", errors="replace") for p in untracked.stdout.split(b"\0") if p]
                has_any_untracked = bool(rel_paths)
                for idx_u, rel in enumerate(rel_paths):
                    norm_rel = rel.replace("\\", "/")
                    is_inscope = _is_test_path(norm_rel) or norm_rel.lower().endswith(_INSCOPE_UNTRACKED_CODE_EXTS)
                    if idx_u >= _UNTRACKED_MAX_FILES:
                        if is_inscope:
                            chunks.append(
                                f"--- /dev/null\n+++ b/{norm_rel}\n@@ -0,0 +1,1 @@\n+# __AGY_UNINSPECTED_UNTRACKED__:count_cap\n"
                            )
                        continue
                    fpath = workspace / rel
                    try:
                        if fpath.is_symlink() or not fpath.is_file():
                            continue
                        st_size = fpath.stat().st_size
                        if st_size > _UNTRACKED_MAX_BYTES:
                            if is_inscope:
                                chunks.append(
                                    f"--- /dev/null\n+++ b/{norm_rel}\n@@ -0,0 +1,1 @@\n+# __AGY_UNINSPECTED_UNTRACKED__:{st_size}\n"
                                )
                            continue
                        content = fpath.read_text(encoding="utf-8")
                    except (OSError, UnicodeDecodeError):
                        continue
                    line_list = content.splitlines()
                    added_lines = "\n".join(f"+{ln}" for ln in line_list)
                    chunks.append(
                        f"--- /dev/null\n+++ b/{norm_rel}\n@@ -0,0 +1,{max(1, len(line_list))} @@\n{added_lines}\n"
                    )
    except (OSError, subprocess.SubprocessError):
        pass

    joined = "\n".join(chunks)
    git_error = _is_git_repo_workspace(workspace) and not (diff_ok and untracked_ok)
    is_clean = (not git_error) and diff_ok and untracked_ok and not joined.strip() and not has_any_untracked
    return joined, is_clean, git_error


def _collect_workspace_diff_status(workspace: Path) -> Tuple[str, bool]:
    joined, is_clean, _git_err = _collect_workspace_diff_status_ex(workspace)
    return joined, is_clean


def _collect_workspace_diff(workspace: Path) -> str:
    return _collect_workspace_diff_status(workspace)[0]


def _finding_structural_key(finding: str) -> str:
    """Strips the volatile (`line snippet`) portion so A/B edit flipping on a line shares one strike key."""
    return re.sub(r"\s*\(`[^`]*`\)", "", finding)


def _conversation_has_recorded_writes(workspaces: Sequence[Path], conv_id: str) -> bool:
    flight_file = _flight_recorder_file()
    if not flight_file.is_file():
        return False
    try:
        with file_lock(flight_file, timeout=HOOK_LOCK_TIMEOUT):
            ledger = _read_ledger_safe(flight_file)
    except (OSError, TimeoutError):
        return True
    for ws in workspaces:
        try:
            ws_key = str(ws.resolve())
        except (OSError, RuntimeError):
            continue
        entry = ledger.get(ws_key)
        if isinstance(entry, dict):
            if str(entry.get("status") or "") == "in_flight":
                return True
            if conv_id and str(entry.get("conversation_id") or "") == conv_id and entry.get("touched_files"):
                return True
    return False


def _verify_workspace_test_boundary(workspace: Path) -> List[str]:
    out: List[str] = []
    try:
        from guard.test_boundary import TestBoundaryGuard

        tbg = TestBoundaryGuard(workspace_dir=workspace)
        if tbg.state_file.is_file() or tbg.legacy_state_file.is_file():
            tb_report = tbg.verify(
                mode="tdd",
                authorized_modifications=TestBoundaryGuard.load_authorized_from_tasks_md(workspace),
            )
            if not tb_report.is_intact:
                for viol in tb_report.violations:
                    out.append(f"Test boundary violation in `{workspace.name}`: {viol} (GEMINI.md Rule 9).")
    except Exception:
        out.append(
            f"TestBoundaryGuard verification failed in `{workspace}` — test snapshot integrity could not be verified."
        )
    return out


def handle_stop(payload: Dict[str, Any]) -> Dict[str, Any]:
    reason = str(payload.get("terminationReason") or "NO_TOOL_CALL").strip()
    if reason != "NO_TOOL_CALL":
        return {}

    workspaces = _workspaces_from_payload(payload)
    workspace = workspaces[0] if workspaces else None
    conv_id = _conversation_id(payload)
    has_session_writes = _conversation_has_recorded_writes(workspaces, conv_id)

    if bool(payload.get("readOnly") or payload.get("read_only")) and not has_session_writes:
        return {}
    raw_prompt, _ = _extract_latest_user_prompt(payload)
    cleaned_prompt = _extract_user_request_prose(raw_prompt) if raw_prompt else ""
    if (
        cleaned_prompt
        and re.match(r"^\s*/(?:audit|retro)\b", cleaned_prompt, re.IGNORECASE)
        and not workspaces
        and not has_session_writes
    ):
        return {}

    assistant_msg = _extract_latest_assistant_message(payload)
    is_question = _is_deferrable_question(assistant_msg)

    findings: List[str] = []
    explicit_diff = payload.get("diffText")
    if isinstance(explicit_diff, str):
        if not explicit_diff.strip():
            tb_extra = _verify_workspace_test_boundary(workspace) if workspace is not None else []
            if not tb_extra:
                if is_question:
                    _record_flight_stop(workspace, conv_id, 0, deferred_question=True)
                    return {}
                git_clean = _collect_workspace_diff_status(workspace)[1] if workspace is not None else True
                _record_flight_stop(workspace, conv_id, 0, workspace_clean=bool(git_clean))
                return {}
            findings.extend(tb_extra)
            _record_flight_stop(workspace, conv_id, len(findings), workspace_clean=False)
        else:
            findings.extend(inspect_git_diff(explicit_diff, workspace=workspace))
            if workspace is not None:
                findings.extend(_verify_workspace_test_boundary(workspace))
            if not findings and is_question:
                _record_flight_stop(workspace, conv_id, 0, deferred_question=True)
                return {}
            _record_flight_stop(workspace, conv_id, len(findings), workspace_clean=False)
    else:
        if not workspaces:
            if is_question:
                _record_flight_stop(None, conv_id, 0, deferred_question=True)
            return {}
        for ws in workspaces:
            ws_diff, ws_clean, ws_git_error = _collect_workspace_diff_status_ex(ws)
            ws_findings: List[str] = []
            if ws_git_error:
                ws_findings.append(
                    f"Git diff inspection failed in `{ws}` (corrupt `.git/HEAD`, locked/corrupt git index, "
                    "or git subprocess error) — workspace diff integrity could not be verified "
                    "(failing closed; GEMINI.md Rule 8 & Rule 9)."
                )
            if ws_diff.strip():
                ws_findings.extend(inspect_git_diff(ws_diff, workspace=ws))
            ws_findings.extend(_verify_workspace_test_boundary(ws))

            if not ws_findings:
                if is_question:
                    _record_flight_stop(ws, conv_id, 0, deferred_question=True)
                else:
                    _record_flight_stop(ws, conv_id, 0, workspace_clean=bool(ws_clean))
            else:
                _record_flight_stop(
                    ws,
                    conv_id,
                    len(ws_findings),
                    workspace_clean=False,
                    create_if_missing=ws_git_error,
                )
                for item in ws_findings:
                    if item not in findings:
                        findings.append(item)

        if not findings and is_question:
            return {}

    strikes_file = state_dir() / "hook_strikes.json"
    count = 1
    try:
        with file_lock(strikes_file, timeout=HOOK_LOCK_TIMEOUT):
            ledger = _read_ledger_safe(strikes_file)

            if not findings:
                if conv_id in ledger:
                    del ledger[conv_id]
                    try:
                        atomic_write_json(strikes_file, ledger)
                    except OSError:
                        pass
                return {}

            stable_keys = sorted({_finding_structural_key(f) for f in findings})
            fingerprint = hashlib.sha256("\n".join(stable_keys).encode("utf-8")).hexdigest()[:16]
            record = ledger.get(conv_id) if isinstance(ledger.get(conv_id), dict) else {}
            prev_fp = record.get("fingerprint", "")
            count = (_safe_int(record.get("count"), default=0) + 1) if prev_fp == fingerprint else 1

            if conv_id in ledger:
                del ledger[conv_id]
            ledger[conv_id] = {"fingerprint": fingerprint, "count": count}
            while len(ledger) > 50:
                oldest = next(iter(ledger))
                del ledger[oldest]
            try:
                atomic_write_json(strikes_file, ledger)
            except OSError:
                pass
    except (OSError, TimeoutError):
        if not findings:
            return {}
        count = 1

    if count >= MAX_STRIKES:
        # Rule 13 3-strike circuit breaker: allow stop rather than trapping the agent in an infinite loop
        return {}

    bullets = "\n".join(f"- {f}" for f in findings[:5])
    return {
        "decision": "continue",
        "reason": (
            f"[Harness Stop Gate — Strike {count}/{MAX_STRIKES - 1}] Verification check failed on workspace diff:\n"
            f"{bullets}\n"
            "Fix the violation before completing the turn (after 2 failed retries the circuit breaker will yield)."
        ),
    }


def _is_pre_tool_use_event(event: str) -> bool:
    return event.strip().lower().replace("_", "-") in ("pre-tool-use", "pretooluse")


def _is_stop_event(event: str) -> bool:
    return event.strip().lower().replace("_", "-") == "stop"


def dispatch_hook(event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    norm = event.strip().lower().replace("_", "-")
    if norm in ("pre-invocation", "preinvocation"):
        return handle_pre_invocation(payload)
    if norm in ("pre-tool-use", "pretooluse"):
        return handle_pre_tool_use(payload)
    if norm in ("stop",):
        return handle_stop(payload)
    return {}


_RAW_HOOK_EVENT_RE = re.compile(r'"hookEventName"\s*:\s*"([^"]+)"')


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agy_hooks.py",
        description="Native Antigravity 2.0 lifecycle hooks for Antigravity Harness.",
    )
    parser.add_argument(
        "event",
        nargs="?",
        default="",
        help="Hook event: pre-invocation, pre-tool-use, or stop.",
    )
    args = parser.parse_args(argv)

    stdin_invalid = False
    raw = ""
    try:
        raw = sys.stdin.read().strip()
        if not raw:
            stdin_invalid = True
            payload: Dict[str, Any] = {}
        else:
            parsed_stdin = json.loads(raw)
            if not isinstance(parsed_stdin, dict):
                stdin_invalid = True
                payload = {}
            else:
                payload = parsed_stdin
    except Exception:
        stdin_invalid = True
        payload = {}

    event = args.event or str(payload.get("hookEventName") or "")
    if stdin_invalid and not event and raw:
        m_ev = _RAW_HOOK_EVENT_RE.search(raw)
        if m_ev:
            event = m_ev.group(1).strip()

    if stdin_invalid and (_is_pre_tool_use_event(event) or not event):
        response: Dict[str, Any] = {
            "decision": "deny",
            "reason": "[Harness PreToolUse Gate] Empty, malformed, or non-object JSON payload on stdin (failing closed).",
        }
    elif stdin_invalid and _is_stop_event(event):
        sys.stderr.write("[Harness Stop Gate] Malformed, empty, or non-object JSON payload on stdin.\n")
        response = {
            "decision": "continue",
            "reason": "[Harness Stop Gate] Empty, malformed, or non-object JSON payload on stdin (failing closed).",
        }
    else:
        try:
            response = dispatch_hook(event, payload)
        except Exception as exc:
            if _is_pre_tool_use_event(event) or not event:
                response = {
                    "decision": "deny",
                    "reason": "[Harness PreToolUse Gate] Internal hook error (failing closed).",
                }
            elif _is_stop_event(event):
                sys.stderr.write(f"[Harness Stop Gate] Unhandled internal error ({type(exc).__name__}): {exc}\n")
                response = {}
            else:
                response = {}

    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        fallback_event = sys.argv[1] if len(sys.argv) > 1 else ""
        if _is_pre_tool_use_event(fallback_event) or not fallback_event:
            sys.stdout.write(
                json.dumps(
                    {
                        "decision": "deny",
                        "reason": "[Harness PreToolUse Gate] Internal hook error (failing closed).",
                    }
                )
                + "\n"
            )
        elif _is_stop_event(fallback_event):
            sys.stderr.write(f"[Harness Stop Gate] Fatal fallback error ({type(exc).__name__}): {exc}\n")
            sys.stdout.write(
                json.dumps(
                    {
                        "decision": "continue",
                        "reason": "[Harness Stop Gate] Internal hook error during Stop verification (failing closed).",
                    }
                )
                + "\n"
            )
        else:
            sys.stdout.write("{}\n")
        sys.stdout.flush()
        sys.exit(0)
