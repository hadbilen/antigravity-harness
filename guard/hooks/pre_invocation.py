"""
guard/hooks/pre_invocation.py — PreInvocation skill-suggest, context routing & recovery gate (ADR-0008).
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import hashlib
import itertools
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from guard.paths import HOOK_LOCK_TIMEOUT

from .common import (
    CONTINUATION_WORDS,
    MAX_CONTEXT_SIGNALS,
    MAX_EXPLICIT_HINTS,
    MAX_HINTS,
    MIN_PROMPT_CHARS,
    REHINT_TURN_GAP,
    _EXPLICIT_CMD_TOKEN_RE,
    _FENCE_RE,
    _INLINE_CODE_RE,
    _PATH_WORD_POST,
    _PATH_WORD_PRE,
    _SLASH_POST,
    _SLASH_PRE,
    _USER_REQUEST_TAG_RE,
    _VIABLE_HINT_TOKEN_RE,
    _conversation_id,
    _extract_latest_user_prompt,
    _extract_user_request_prose,
    _facade,
    _facade_attr,
    _flight_recorder_file,
    _is_git_repo_workspace,
    _is_harness_repo_root,
    _iter_jsonl_tail_entries,
    _prune_missing_flight_workspaces,
    _read_bounded_markdown_checked,
    _read_ledger_checked,
    _read_ledger_safe,
    _repo_root,
    _safe_int,
    _strip_non_user_prose,
    _workspaces_from_payload,
    atomic_write_json,
    config_dir,
    configured_config_dir,
    file_lock,
    json,
    state_dir,
    subprocess,
)


# Bilingual (EN + TR) skill suggestion table: (skill_name, skill_rel_path, compiled_regex, summary)
SKILL_HINTS: Tuple[Tuple[str, str, re.Pattern[str], str], ...] = (
    (
        "diagnosing-bugs",
        "skills/diagnosing-bugs/SKILL.md",
        re.compile(
            rf"(?:{_SLASH_PRE}/diagnosing-bugs{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"bug|regression|regresyon\w*|crash(?:es|ed|ing)?|traceback|stack\s*trace|segfault|"
            r"failing\s+(?:tests?|assertions?)|flaky\s+(?:tests?|assertions?|failures?|builds?|checks?)|intermittent\s+failure|bisect|"
            r"(?:debug|investigat(?:e|ing)|diagnos(?:e|ing))\s+(?:this\s+|the\s+|an?\s+)?(?:[\w-]+\s+){0,2}(?:failure|error|bug|crash|regression|flaky)|"
            r"root\s+cause(?:\s+(?:of|analysis))?|test\s+suite\s+(?:is\s+)?failing|"
            r"hata\s+var|çalışmıyor|calismiyor|patlıyor|patliyor|bozuldu|neden\s+hata|"
            r"hata(?:yı|sı|ları)?\s+(?:ayıkla\w*|bul\w*|teşhis\s+et\w*)|"
            r"kök\s+neden\w*|test(?:ler|i)?\s+(?:kırıl\w*|patl\w*|fail\s+ediyor|geçmiyor)"
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
            r"(?:write|add)\s+(?:unit|integration|regression)\s+tests?|"
            r"test\s+yaz|test\s+ekle|regresyon\s+testi|birim\s+test(?:i|leri)\s+(?:yaz|ekle)|"
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
            r"refactor(?:ing)?|extract\s+(?:\w+\s+)?(?:functions?|methods?|classes|modules?|helpers?)|"
            r"restructur(?:e|ing)\s+(?:this\s+|the\s+|these\s+)?(?:modules?|classes|functions?|codebase)|"
            r"split\s+(?:file|module|class)|decouple|code\s+smell|dead\s+code|"
            r"refactor\s+et|yeniden\s+düzenle|sadeleştir|parçala|kod\s+tekrarını\s+kaldır|"
            r"yeniden\s+yapılandır|kod\s+kokusu|modüllere\s+ayır|fonksiyon\w*\s+çıkar"
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
            r"sürümü\s+yükselt|bağımlılık(?:ları|\w*\s+sürüm\w*)(?:\s+[\wçğıöşüÇĞİÖŞÜ-]+){0,3}\s+(?:güncelle\w*|yükselt\w*)|"
            r"paket\w*\s+(?:güncelle|yeni\s+sürüme\s+(?:taşı|geçir|yükselt))|bağımlılık\s+güncelle|sürüm\s+yükselt"
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
            r"(?:use|apply|run|invoke|load)\s+(?:the\s+)?renew\s+(?:skill|workflow)?|"
            r"renew\s+(?:skill|beceri\w*)|"
            r"(?:moderniz(?:e|ing)|reviv(?:e|ing)|port(?:ing)?|remaster(?:ing)?|bring(?:ing)?)\s+(?:(?:this|the|an?|our|my)\s+)*(?:old|legacy|classic|obsolete|unbuildable|abandoned|win32|winforms|mfc|delphi|vb6|visual\s+basic(?:\s*6)?|flash|dos|j2me|sdl1?|pygame|python\s*2|actionscript)\b(?:\s+[\w.-]+){0,5}\s+(?:app(?:lication)?s?|programs?|software|codebases?|projects?|tools?|utilit(?:y|ies)|servic(?:e|es)|games?|up\s+to\s+date)|"
            r"remaster(?:ing)?\s+(?:(?:this|the|an?|our|my|old|classic|legacy|retro)\s+)*(?:games?|app(?:lication)?s?|programs?|titles?)|"
            r"legacy\s+(?:software|app(?:lication)?|codebase|program|game)\s+(?:modernization|revival|remaster(?:ing)?|port(?:ing)?)|"
            r"(?:windows-?1254|iso-?8859-9|cp437)\b[^\n.?!]{0,50}(?:\butf-?8\b|moderniz\w*|legacy|desktop|yenile\w*)|"
            r"(?:eski|klasik|atıl|çalışmayan|derlenmeyen|legacy)\s+(?:bir\s+)?(?:[\wçğıöşüÇĞİÖŞÜ.-]+\s+){0,3}(?:program\w*|yazılım\w*|uygulama\w*|oyun\w*|kod\s+taban\w*|codebase\w*|araç\w*|arac\w*|proje\w*)(?:\s+[\wçğıöşüÇĞİÖŞÜ-]+){0,3}\s+(?:yenile\w*|modernize\s+et\w*|dirilt\w*|ayağa\s+kaldır\w*|remaster\s+yap\w*|(?:güncel|modern)\s+(?:sistem\w*|ortam\w*|çalışma\s+zaman\w*)\s+(?:taşı\w*|geçir\w*|uyarla\w*))|"
            r"(?:win32|winforms|vb6|delphi|flash|sdl1|pygame|mfc)\s+(?:[\wçğıöşüÇĞİÖŞÜ.-]+\s+){0,3}(?:uygulama\w*|oyun\w*|proje\w*|program\w*)\s+(?:modern|güncel|html5|webgl|web|\w+\s+ortam\w*)\s+(?:taşı\w*|geçir\w*|ayağa\s+kaldır\w*|uyarla\w*)|"
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
            r"(?:(?:c(?:/c\+\+|\+\+)?|cpp|golang|python)\s+(?:[\w+/.-]+\s+){0,4}(?:to|into)\s+(?:(?:idiomatic|memory[- ]safe|compiler[- ]verified|zero[- ]panic|safe|pure),?\s+)*rust\b|"
            r"go\s+(?:(?:code(?:base)?|module|service|library|binary|daemon|cli|worker|server|backend|runtime|app|package|crate)\s+)?(?:to|into)\s+(?:(?:idiomatic|memory[- ]safe|compiler[- ]verified|zero[- ]panic|safe|pure),?\s+)*rust\b(?!\s*(?:edition\s*)?20\d{2}\b|\s+1\.\d+\b))|"
            r"(?:rust\s+(?:ffi(?:\s+(?:bindings?|wrappers?|bridges?))?|bindings?|wrappers?)\s+(?:for|to)\s+(?:c/c\+\+|c\+\+|(?:cpp|golang|python|go|c)\b)|(?:ffi|c\s+abi)\s+(?:bridge|wrapper|interop)\s+(?:for|to|with|in)\s+rust\b)|"
            r"(?:c(?:/c\+\+|\+\+)?|cpp|go|golang|python)'?(?:dan|den|tan|ten)\s+rust'?(?:a|ya)\b|"
            r"(?:c(?:/c\+\+|\+\+)?|cpp|go|golang|python)\s+(?:[\wçğıöşüÇĞİÖŞÜ.-]+\s+){0,3}rust\s+ile\s+(?:yeniden\s+yaz\w*|değiştir\w*)|"
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
            r"deep[- ]grill|"
            r"(?:tier[- ]?3|architecture|design|schema|protocol|requirements?|spec(?:ification)?)\s+grill\s+me|"
            r"grill\s+me\s+(?:on|about)\s+(?:this\s+|the\s+|our\s+)?(?:architecture|design|schema|protocol|api|system|spec\w*|code\w*|feature|requirements?)|"
            r"design\s+interview|stress[- ]test\s+requirements|edge[- ]case\s+interview|"
            r"(?:mimari\w*|tasarım\w*|sistem\w*|şema\w*|protokol\w*|gereksinim\w*|uç\s+durum\w*|kod\w*)\s+(?:\S+\s+){0,2}(?:mülakat\s+yap\w*|sorgula\w*)|"
            r"uç\s+durumlar\w*\s+sorgula\w*"
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
            r"game\s+loop|fixed[- ]timestep|game\s+dev(?:elopment)?|canvas\s+game|webgl\s+game|webgpu\s+game|"
            r"(?:2d|3d|phaser|godot|unity|unreal|pixi(?:\.js)?|three(?:\.js)?|browser|arcade|indie|platformer|roguelike)\s+games?|"
            r"build(?:ing)?\s+(?:a\s+|an\s+|this\s+)?game\b|frame\s+accumulator|seeded\s+(?:prng|rng)|deterministic\s+game|"
            r"collision\s+detection|game\s+physics|entity\s+state\s+machine|"
            r"oyun\s+(?:geliştir(?:me)?|yap\w*|tasarla\w*|kodla\w*|motoru|fiziğ\w*|fizik\w*|döngü\w*)|"
            r"sabit\s+(?:timestep|zaman\s+adımı)|fizik\s+döngüsü|çarpışma\s+(?:algılama|sistemi|testi)|"
            r"(?:canvas|webgl|tarayıcı|2d|3d|2b|3b|arcade|platform)\s+oyun\w*"
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
            r"sprite\s*sheets?|pixel\s+art|tile\s*sets?|texture\s+atlas\w*|alpha\s+(?:bleed|matting)|color[- ]?key(?:ed)?\s+(?:bitmap|sprite|transparency)|"
            r"(?:game\s+)?(?:sound\s+effects?|sfx\b|game\s+audio|loop(?:ing)?\s+(?:audio|sfx|sound|music))|"
            r"(?:audio|video|sound|voice|music|track|song|photo|image|media)\s+(?:mastering|remaster(?:ing)?|restoration|salvage|upscal(?:e|ing)|super[- ]resolution|denois(?:e|ing)|editing|transcod(?:e|ing)|synthesis)|"
            r"(?:salvage|restore|repair|upscale|uncorrupt|resize|crop|trim|compress|normalize)\s+(?:(?:this|the|an?|my|old|damaged|corrupted|broken|truncated|scanned|low[- ]res(?:olution)?|blurry|noisy|archival)\s+)*(?:sprite\s*sheet\w*|pixel\s+art|textures?|sound\s+effects?|sfx\b|audio|video|sound|voice|photo(?:graph)?|image|picture|footage|recording|mp4|mkv|webm|wav|ogg|opus|flac|mp3|jpe?g|png|webp|gif|tiff?)\b|"
            r"ebu\s*r128|loudness\s+normalization|lufs|deband(?:ing)?|jpeg\s+(?:blocking|artifacts?)|animated\s+(?:webp|gif|apng|visuals?)|"
            r"ffmpeg\s+filter(?:graph)?|(?:audio|video|image|photo)\s+quality\s+(?:fix|repair|gate|enhancement|upscal(?:e|ing))|"
            r"(?:piksel\s+sanat\w*|oyun\s+ses\w*|ses\s+efekt\w*)|"
            r"(?:bozuk|hasarlı|kırık|eski|düşük\s+kaliteli|bulanık|cızırtılı)\s+(?:bir\s+)?(?:(?!session\w*)ses\w*|video\w*|görüntü\w*|fotoğraf\w*|fotograf\w*|görsel\w*|(?:(?!session\w*)ses|video|görüntü|ekran|kamera|mikrofon)\s+(?:kayıt\w*|kayd\w*)|wav|ogg|mp4|mkv|mp3|jpe?g|png)(?:\s+[\wçğıöşüÇĞİÖŞÜ-]+){0,5}\s+(?:düzelt\w*|onar\w*|kurtar\w*|temizle\w*|iyileştir\w*|yükselt\w*|artır\w*)|"
            r"(?:(?!session\w*)ses\w*|video\w*|görüntü\w*|fotoğraf\w*|fotograf\w*)\s+(?:üret(?:im|me)?|düzenle(?:me)?|kurgu(?:la|su)?|kurtar\w*|onar(?:ım|ma)?|mastering|remaster(?:\s+yap\w*)?|kalite\w*(?:\s+[\wçğıöşüÇĞİÖŞÜ-]+){0,3}\s+(?:düzelt\w*|artır\w*|yükselt\w*|iyileştir\w*))|"
            r"(?:(?:(?!session\w*)ses|müzik|şarkı)(?:\s+kayıt\w*|\s+kayd\w*)?)\s+remaster(?:\s+yap\w*)?|"
            r"(?:görsel\w*|fotoğraf\w*|fotograf\w*|görüntü\w*|(?!session\w*)ses\w*|video\w*)\s+(?:[\wçğıöşüÇĞİÖŞÜ-]+\s+){0,2}(?:temizle\w*|boyutlandır\w*|ölçekle\w*|kırp\w*|normalize\s+et\w*)|"
            r"(?:png|jpe?g|webp|gif|apng|wav|ogg|opus|flac|mp3|mp4|webm|mkv)\s+(?:temizle\w*|boyutlandır\w*|dönüştür\w*|normalize\s+et\w*|sıkıştır\w*|kırp\w*|birleştir\w*)|"
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
            r"(?:benchmark|profile)\s+(?:(?:and\s+optimize|memory|ram|cpu|latency|network|waterfall|startup|frame|performance)(?:\s+footprint)?)|"
            r"optimize\s+(?:startup|latency|frame\s+rate|fps|performance|memory|ram|disk\s+space|binary\s+size|bundle\s+size|footprint|network|bandwidth|download|upload)|"
            r"optimize\s+(?:this\s+|the\s+)?(?:game|app|application|software|codebase|program|service|backend|script|tool|library|binary|package|(?:software|coding)\s+project|(?:operating|file|build|cache|distributed)\s+system)|"
            r"speed\s+up\s+(?:this\s+|the\s+)?(?:game|app|application|software|codebase|program|service|backend|script|query|loop|startup|build|pipeline|renderer|download|upload)|"
            r"(?:reduce|shrink|cut|lower|decreas(?:e|ing))\s+(?:(?:--net|memory|ram|disk|binary|bundle|network|bandwidth|download|upload|round[- ]trip|request|api|render)\s+)*(?:memory|ram|disk|binary|bundle|network|bandwidth|download|upload|round[- ]trip|allocations?|gc\s+pressure|startup\s+time|cold[- ]start|frame\s+time|rtt|waterfall\s+latency|latency|n\+1\s+(?:queries|requests?))(?:\s+(?:usage|footprint|size|traffic|latency|payload))?|"
            r"sweetspot\s+analizi|tatlı\s+nokta\s+optimizasyonu|performans\s+optimizasyonu|(?:bellek|ram|disk|ağ|bant\s+genişliği)\s+optimizasyonu|"
            r"(?:oyun\w*|servis\w*|uygulama\w*|yazılım\w*|beti[kğ]\w*|kod\w*|(?:işletim|dosya|derleme|önbellek)\s+sistem\w*|modül\w*|sorgu\w*|fonksiyon\w*|algoritma\w*|motor\w*|derleme\w*|[iİ]ndirme\w*|ağ\w*|bellek\w*|ram\w*|hız\w*|render\w*)\s+(?:\S+\s+){0,2}(?:optimize\s+et|hızlandır)|"
            r"(?:bellek|ram|cpu|ağ|disk|yükleme|başlatma|soğuk\s+başlangıç|sorgu|döngü|render|kare)\s+(?:tüketimi\w*|kullanımı\w*|maliyeti\w*|süresi\w*|gecikmesi\w*|boyutu\w*)\s+(?:düşür\w*|azalt\w*|küçült\w*|optimize\s+et\w*|hızlandır\w*)|"
            r"(?:uygulama\w*|servis\w*|oyun\w*|sorgu\w*|beti[kğ]\w*|motor\w*|derleme\w*|paket\w*|dosya\w*|pipeline\w*)\s+(?:performans\w*|hız\w*|fps|belle[kğ]\w*|boyut\w*)\s+(?:iyileştir\w*|artır\w*|düşür\w*|optimize\s+et\w*)|"
            r"(?:bellek|ram|bant\s+genişliği)\s+kullanımını\s+(?:düşür|azalt)|"
            r"(?:disk\s+alanını|dosya\s+boyutunu|paket\s+boyutunu|[iİ]ndirme\s+(?:ve\s+yükleme\s+)?boyutunu|yükleme\s+boyutunu|çıktının\s+boyutunu)\s+küçült|"
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
        "40-rule design/copy quality filter, Liveliness Toolkit & UI Delivery Gate",
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
            r"reverse[- ]engineer(?:ing)?|"
            r"decompile\s+(?:(?:this|the)\s+)?(?:(?:compiled\s+)?(?:binary|executable)|apk|elf|macho|jar|wasm|exe|dll|firmware)|"
            r"disassemble\s+(?:(?:this|the)\s+)?(?:(?:compiled\s+)?(?:binary|executable)|apk|elf|macho|jar|wasm|exe|dll|firmware)|"
            r"inspect\s+(?:this\s+|the\s+)?(?:(?:[A-Za-z0-9_.-]+\.(?:asar|pak|apk|ipa|exe|dll|so|dylib|wasm))|apk|ipa|elf|macho|firmware|pcap|asar|pak|exe|dll|so|dylib|compiled\s+binary|shipped\s+artifact|electron\s+app)|"
            r"(?:unpack|extract\s+(?:assets?|strings|symbols)\s+from)\s+(?:this\s+|the\s+)?(?:(?:[A-Za-z0-9_.-]+\.(?:asar|pak|apk|ipa|exe|dll|wasm))|asar|pak|apk|ipa|exe|dll|firmware|binary)|"
            r"clean[- ]room\s+(?:spec(?:ification)?|reverse[- ]engineering|extraction)|"
            r"frida\s+(?:hook|session|trace)|rizin\s+debug|jeb\s+project|"
            r"(?:exe|dll|apk|ipa|elf|macho|asar|pak|firmware|pcap|wasm)\s+(?:dosyasını|ikilisini|paketini|içeriğini)\s+(?:incele\w*|çözümle\w*|analiz\s+et\w*|aç\w*)|"
            r"ikili\s+dosyay(?:ı|i)\s+disassemble|disassemble(?:\s+ve\s+decompile)?\s+et|"
            r"tersine\s+mühendislik|binary\s+analiz(?:i)?|apk\s+incele|decompile\s+et|ikili\s+dosya\s+analiz|"
            r"derlenmiş\s+(?:ikili\s+dosya\w*|binary|uygulama\w*)\s+(?:analiz|incele|çözümle|disassemble|decompile)"
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
            r"reverse[- ]engineer(?:ing)?|"
            r"decompile\s+(?:(?:this|the)\s+)?(?:(?:compiled\s+)?(?:binary|executable)|apk|elf|macho|jar|wasm|exe|dll|firmware)|"
            r"disassemble\s+(?:(?:this|the)\s+)?(?:(?:compiled\s+)?(?:binary|executable)|apk|elf|macho|jar|wasm|exe|dll|firmware)|"
            r"inspect\s+(?:this\s+|the\s+)?(?:(?:[A-Za-z0-9_.-]+\.(?:asar|pak|apk|ipa|exe|dll|so|dylib|wasm))|apk|ipa|elf|macho|firmware|pcap|asar|pak|exe|dll|so|dylib|compiled\s+binary|shipped\s+artifact|electron\s+app)|"
            r"(?:unpack|extract\s+(?:assets?|strings|symbols)\s+from)\s+(?:this\s+|the\s+)?(?:(?:[A-Za-z0-9_.-]+\.(?:asar|pak|apk|ipa|exe|dll|wasm))|asar|pak|apk|ipa|exe|dll|firmware|binary)|"
            r"clean[- ]room\s+(?:spec(?:ification)?|reverse[- ]engineering|extraction)|"
            r"frida\s+(?:hook|session|trace)|rizin\s+debug|jeb\s+project|"
            r"(?:exe|dll|apk|ipa|elf|macho|asar|pak|firmware|pcap|wasm)\s+(?:dosyasını|ikilisini|paketini|içeriğini)\s+(?:incele\w*|çözümle\w*|analiz\s+et\w*|aç\w*)|"
            r"ikili\s+dosyay(?:ı|i)\s+disassemble|disassemble(?:\s+ve\s+decompile)?\s+et|"
            r"tersine\s+mühendislik|binary\s+analiz(?:i)?|apk\s+incele|decompile\s+et|ikili\s+dosya\s+analiz|"
            r"derlenmiş\s+(?:ikili\s+dosya\w*|binary|uygulama\w*)\s+(?:analiz|incele|çözümle|disassemble|decompile)"
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
            r"permission\s+boundary|auth(?:entication|orization)\s+bypass|toctou|race\s+condition|"
            r"kimlik\s+doğrulama|yetkilendirme\s+sınır(?:ı|i)|yetki\s+sınır(?:ı|i)|güvenlik\s+sınır(?:ı|i)|"
            r"kriptografi|ödeme\s+altyapısı|depolama\s+bütünlüğü"
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
            r"public\s+interface\s+migration|migration\s+rollback\s+safety|wire\s+format\s+change|schema\s+breaking\s+change|"
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
            r"multi[- ]file\s+invariant|axiomatic\s+consistency|"
            r"resmi\s+spesifikasyon|güvenlik\s+çekirdeği\s+spesifikasyonu|aksiyomatik\s+tutarlılık|durum\s+makinesi\s+değişmezi"
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
            r"(?:read|check)\s+(?:the\s+)?(?:(?:official|external|latest|versioned)\s+){1,2}(?:(?:sdk|library|framework)\s+)?(?:docs|documentation|reference|spec|api)|"
            r"explore\s+(?:the\s+|this\s+)?(?:codebase|repository)\s+broadly|research\s+subagent|"
            r"dış\s+dokümantasyon\s+araştır|resmi\s+kütüphane\s+dokümanı|"
            r"(?:resmi|dış|harici|güncel)\s+(?:dokümantasyon\w*|api\s+referans\w*)\s+(?:araştır\w*|oku\w*|incele\w*|kontrol\s+et\w*)|"
            r"kütüphane\s+(?:api|doküman)\w*\s+(?:doğrula\w*|araştır\w*)"
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
            r"(?:fix|resolve|debug)\s+(?:these\s+|the\s+|this\s+)?(?:(?:typescript|tsc|mypy|cargo|rustc|go)\s+)?(?:build|compiler|type)\s+errors?|"
            r"(?:fix|resolve|debug)\s+(?:these\s+|the\s+|this\s+)?(?:typescript|tsc|mypy|cargo|rustc)\s+errors?|"
            r"500\+?\s*lines?\s+of\s+(?:build|compiler|type|tsc|cargo|mypy)\s+errors?|"
            r"uzun\s+derleme\s+hatası|tip\s+hatası\s+izini\s+çöz|"
            r"(?:derleme|typecheck|tip\s+kontrol|tsc|mypy|cargo\s+build)\s+hatalar(?:ı|ını)\s+(?:çöz\w*|gider\w*|ayıkla\w*)"
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
    (
        "route:builtin:native_swarm",
        re.compile(
            rf"(?:{_SLASH_PRE}/(?:swarm|native_swarm){_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"native[- _]swarm|agent\s+swarm|swarm\s+(?:mode|board|workers?)|"
            r"ajan\s+sürüsü\w*|paylaşımlı\s+mesaj\s+panosu\w*"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "Built-in Skill `native_swarm` (`swarm` tool & `~/.gemini/antigravity/builtin/skills/native_swarm/SKILL.md`; obey GEMINI.md Rule 15f & Rule 17: never downgrade worker `model` when editing customization/governance files, and isolate parallel authors with `workspace='share'`/`'branch'`)",
    ),
    (
        "route:builtin:migrate-agent-settings",
        re.compile(
            rf"(?:{_SLASH_PRE}/migrate-agent-settings{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"migrate[- _]agent[- _]settings|"
            r"import\s+(?:claude\s+code|codex|cursor|gemini\s+cli)\s+(?:config|settings|rules|mcp)|"
            r"(?:claude\s+code|codex|cursor|gemini\s+cli)\s+ayarlarını\s+içe\s+aktar\w*"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "Built-in Skill `migrate-agent-settings` (read `~/.gemini/antigravity/builtin/skills/migrate-agent-settings/SKILL.md`; obey GEMINI.md Rules 12, 15g & 16: keep `npx` dependencies pinned, pass imported rules through `porter inspect`, and obtain human confirmation before plugin writes)",
    ),
    (
        "route:builtin:mcp-app-development",
        re.compile(
            rf"(?:{_SLASH_PRE}/mcp-app-development{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"mcp[- _]app[- _]development|mcp\s+app\s+(?:ui|resource|widget)|ui://\s*app|"
            r"mcp\s+uygulama\s+arayüzü\w*"
            rf"){_PATH_WORD_POST})",
            re.IGNORECASE,
        ),
        "Built-in Skill `mcp-app-development` (read `~/.gemini/antigravity/builtin/skills/mcp-app-development/SKILL.md`; obey GEMINI.md Rules 12 & 15h: never emit `ANTIGRAVITY_CSRF_TOKEN`, restrict endpoints to Content Security Policy allowlists, and pin `@modelcontextprotocol/ext-apps` packages)",
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
    "route:builtin:native_swarm": ("swarm", "native_swarm"),
    "route:builtin:migrate-agent-settings": ("migrate-agent-settings",),
    "route:builtin:mcp-app-development": ("mcp-app-development",),
}

_ROUTE_EXPLICIT_SLUGS: Dict[str, Tuple[str, ...]] = {
    "route:mcp:rea_rea": ("rea_rea", "reverse-engineer-anything"),
    "route:mcp:antislop-contrast": ("antislop-contrast", "check_contrast"),
    "route:subagent:security-silent": ("security-boundary-verifier", "silent-failure-hunter"),
    "route:subagent:contract-test": ("contract-change-auditor", "test-adequacy-auditor"),
    "route:subagent:spec-consistency": ("consistency-auditor", "specification-gap-auditor"),
    "route:subagent:research": ("research-subagent",),
    "route:subagent:build-error-resolver": ("build-error-resolver",),
    "route:builtin:generative_ui": ("generative_ui", "generative-ui"),
    "route:builtin:antigravity-guide": ("antigravity-guide", "antigravity_guide"),
    "route:builtin:agy-customizations": ("agy-customizations",),
    "route:subagent:meta-auditor": ("meta-auditor",),
    "route:subagent:image-generator": ("image-generator-subagent",),
    "route:builtin:native_swarm": ("native_swarm", "native-swarm"),
    "route:builtin:migrate-agent-settings": ("migrate-agent-settings",),
    "route:builtin:mcp-app-development": ("mcp-app-development",),
}

_SKILL_HINT_BY_NAME: Dict[str, Tuple[str, str, str]] = {
    skill_name: (skill_name, rel_path, summary)
    for skill_name, rel_path, _pattern, summary in SKILL_HINTS
}

_ROUTE_HINT_BY_KEY: Dict[str, Tuple[str, str]] = {
    route_key: (route_key, directive)
    for route_key, _pattern, directive in ECOSYSTEM_ROUTING_HINTS
}

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

_KNOWN_INLINE_SLASH_ALIASES = frozenset(
    alias.lower()
    for aliases in list(_SKILL_SLASH_ALIASES.values()) + list(_ROUTE_SLASH_ALIASES.values())
    for alias in aliases
) | frozenset(s.lower() for s in _SKILL_HINT_BY_NAME)

_KNOWN_INLINE_EXPLICIT_SLUGS = frozenset(
    s.lower()
    for s in _SKILL_HINT_BY_NAME
    if ("-" in s or "_" in s or s in _DISTINCTIVE_SKILL_SLUGS)
) | frozenset(
    slug.lower()
    for slugs in _ROUTE_EXPLICIT_SLUGS.values()
    for slug in slugs
    if ("-" in slug or "_" in slug or slug in _DISTINCTIVE_SKILL_SLUGS)
)

def _extract_explicit_inline_command_tokens(raw_prompt: str) -> str:
    """Extracts known bare command/slug tokens written inside single inline backticks (e.g. `` `/deep-grill` ``)."""
    un_fenced = _strip_non_user_prose(raw_prompt or "", strip_inline_code=False)
    blocks = _USER_REQUEST_TAG_RE.findall(un_fenced)
    scope = "\n".join(blocks) if blocks else un_fenced
    extracted: List[str] = []
    for m in _INLINE_CODE_RE.finditer(scope):
        inner = m.group(0)[1:-1].strip()
        if not re.fullmatch(r"[/\$]?[a-zA-Z][a-zA-Z0-9_-]{1,63}", inner):
            continue
        low = inner.lower()
        if low.startswith(("/", "$")):
            if low[1:] in _KNOWN_INLINE_SLASH_ALIASES:
                extracted.append(inner)
        elif low in _KNOWN_INLINE_EXPLICIT_SLUGS:
            extracted.append(inner)
    return " ".join(extracted)

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
    """Returns True when a distinctive, hyphenated, or underscore skill/agent slug is named directly in prose outside paths."""
    if "-" not in slug and "_" not in slug and slug not in _DISTINCTIVE_SKILL_SLUGS:
        return False
    pattern = re.compile(
        rf"(?:^|(?<=[\s(\[\"'«“])){re.escape(slug)}{_SLASH_POST}",
        re.IGNORECASE,
    )
    return bool(pattern.search(cleaned))

def _has_explicit_route_slug_mention(cleaned: str, route_key: str) -> bool:
    """Returns True when any explicit slug mapped to `route_key` appears in prose outside paths."""
    return any(_has_explicit_slug_mention(cleaned, slug) for slug in _ROUTE_EXPLICIT_SLUGS.get(route_key, ()))

_ANY_EXPLICIT_SLUG_RE = re.compile(
    rf"(?:^|(?<=[\s(\[\"'«“]))(?:{'|'.join(re.escape(s) for s in sorted(_KNOWN_INLINE_EXPLICIT_SLUGS, key=len, reverse=True))}){_SLASH_POST}",
    re.IGNORECASE,
)

def _has_any_explicit_slug_mention(explicit_surface: str) -> bool:
    """Returns True when any known explicit skill or ecosystem route slug appears directly in user prose."""
    return bool(_ANY_EXPLICIT_SLUG_RE.search(explicit_surface))

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

_HANDOFF_IN_PROGRESS_RE = re.compile(r"(?im)^\s*(?:\*\*Status:\*\*|Status:)\s*\[IN-PROGRESS\]\s*$")

_TASKS_PENDING_RE = re.compile(r"(?m)^\s*-\s*\[\s\]\s+\S")

_TASKS_PARTIAL_RE = re.compile(r"(?m)^\s*(?:-\s*\[~\]|\|[^\n]*\[~\])")

_TASKS_BLOCKED_RE = re.compile(r"(?m)^\s*(?:-\s*\[!\]|\|[^\n]*\[!\])")

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
    flight_file = _flight_recorder_file()
    if workspace is None or not workspace.is_dir():
        if workspace is not None and flight_file.is_file():
            try:
                with file_lock(flight_file, timeout=HOOK_LOCK_TIMEOUT):
                    ledger_ok, ledger = _read_ledger_checked(flight_file)
                    if ledger_ok and _prune_missing_flight_workspaces(ledger):
                        atomic_write_json(flight_file, ledger)
            except (OSError, TimeoutError):
                pass
        return True, None

    try:
        ws_key = str(workspace.resolve())
    except (OSError, RuntimeError):
        return False, None

    flight_entry: Dict[str, Any] = {}
    flight_alert_reason = ""
    ack_seq: Optional[int] = None
    inspect_ok = True
    if flight_file.is_file():
        try:
            with file_lock(flight_file, timeout=HOOK_LOCK_TIMEOUT):
                ledger_ok, ledger = _read_ledger_checked(flight_file)
                if not ledger_ok:
                    inspect_ok = False
                elif _prune_missing_flight_workspaces(ledger):
                    atomic_write_json(flight_file, ledger)
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
        hoff_ok, raw_handoff = _read_bounded_markdown_checked(workspace / "HANDOFF.md")
        if not hoff_ok:
            inspect_ok = False
        if raw_handoff:
            htext = _FENCE_RE.sub(" ", raw_handoff)
            if _HANDOFF_IN_PROGRESS_RE.search(htext):
                handoff_in_progress = True

        tasks_ok, raw_tasks = _read_bounded_markdown_checked(workspace / "tasks.md")
        if not tasks_ok:
            inspect_ok = False
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
    inspect_target = (
        "`git status`/`git diff`, `tasks.md`, and `HANDOFF.md` (if present)"
        if _is_git_repo_workspace(workspace)
        else "`tasks.md`, `HANDOFF.md` (if present), and recent workspace files (non-git workspace)"
    )
    msg = (
        f"[Harness Recovery & Continuity Gate] Unfinished or interrupted workspace state detected: "
        f"{'; '.join(details)}. Before making new edits, inspect {inspect_target} "
        "to reconcile any half-finished modifications and resume deterministically."
    )
    return inspect_ok, (dedup_key, msg, ack_seq)

def _optional_plugin_skill_available(rel_path: str, workspaces: Sequence[Path]) -> bool:
    """Checks disk existence for optional `plugins/...` skill files so uninstalled plugins are not hinted."""
    if not rel_path.startswith("plugins/"):
        return True
    cfg = configured_config_dir()
    roots: List[Path] = [
        cfg,
        config_dir(),
        _repo_root(),
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
_WS_SKIP_DIRS = frozenset({
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "target",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "tests",
    "test",
    "__tests__",
    "spec",
    "specs",
    "fixtures",
    "fixture",
    ".gemini",
    ".claude",
    ".cursor",
})

_GAME_PKG_RE = re.compile(
    r'"(?:phaser|pixi\.js|kaboom|kaplay|excalibur|littlejs|rot-js|three|babylonjs|@babylonjs/core)"',
    re.IGNORECASE,
)

_RUST_BRIDGE_RE = re.compile(r"\b(?:pyo3|cxx|cbindgen|bindgen|maturin)\b", re.IGNORECASE)

_CANVAS_RE = re.compile(r"(?:<canvas\b|getContext\s*\(\s*[\"'](?:2d|webgl2?)[\"'])", re.IGNORECASE)

_RAF_RE = re.compile(r"\brequestAnimationFrame\b")

_AUDIO_VIDEO_EXTS = frozenset({
    ".wav",
    ".flac",
    ".ogg",
    ".opus",
    ".m4a",
    ".mp3",
    ".mp4",
    ".mov",
    ".mkv",
    ".webm",
    ".avi",
    ".apng",
    ".ase",
    ".aseprite",
    ".psd",
    ".xcf",
})

_RASTER_MEDIA_EXTS = frozenset({".png", ".jpg", ".jpeg", ".webp", ".gif", ".tiff", ".tif", ".bmp"})

_MEDIA_ASSET_DIRS = frozenset({"assets", "sprites", "audio", "sfx", "media", "video"})

_SPRITE_NAME_RE = re.compile(r"(?:sprite|spritesheet|tileset|atlas|sfx|bgm|foley|frame_\d|anim_)", re.IGNORECASE)

_WEB_ICON_IGNORE_RE = re.compile(r"^(?:favicon|logo|icon|apple-touch-icon)(?:[-._].*)?$", re.IGNORECASE)

_BINARY_ARTIFACT_EXTS = frozenset({
    ".exe",
    ".dll",
    ".apk",
    ".ipa",
    ".asar",
    ".macho",
    ".elf",
    ".so",
    ".dylib",
    ".wasm",
    ".pak",
})

_TRACE_ERROR_MARKER_RE = re.compile(
    r"(?:"
    r"\berror\s+TS\d+\b|\berror\[E\d+\]|Traceback\s*\(most\s+recent\s+call\s+last\):|"
    r"\bFAILED\s*\(|\bCommand\s+exited\s+with\s+code\s+[1-9]\d*\b|"
    r"\b(?:AssertionError|SyntaxError|TypeError|ImportError|ModuleNotFoundError|ReferenceError):|"
    r"\bfatal\s+error:|\b(?:COMPILATION|BUILD|TYPECHECK)\s+FAILED\b"
    r")"
)

_CLEAN_BUILD_PASS_RE = re.compile(
    r"(?:Ran\s+\d+\s+tests?(?:\s+in\s+[^\n]+)?\s+\bOK\b|\b\d+\s+passed\b|\bFinished\s+`(?:dev|test|release)`|\b0\s+errors?\b|Found\s+0\s+errors?|\bok\s+\S+\s+[0-9.]+s\b|Success:\s+no\s+issues\s+found\b|All\s+checks?\s+passed\b)"
)

_NON_EXEC_READ_TOOLS = frozenset(
    {"read_file", "view_file", "list_dir", "grep_search", "find_by_name", "search_web", "read_url_content"}
)

def _is_rea_mcp_available(workspaces: Sequence[Path]) -> bool:
    """Returns True when the REA plugin skill or `rea_rea` MCP server directory is installed."""
    mcp_rea_dir = Path.home() / ".gemini" / "antigravity" / "mcp" / "rea_rea"
    try:
        mcp_ok = (not mcp_rea_dir.is_symlink()) and mcp_rea_dir.is_dir()
    except OSError:
        mcp_ok = False
    return mcp_ok or _optional_plugin_skill_available(
        "plugins/rea/skills/reverse-engineer-anything/SKILL.md", workspaces
    )

def _read_bounded_bytes_nofollow(path: Path, max_bytes: int = 32768, *, from_tail: bool = False) -> Optional[bytes]:
    """Reads up to `max_bytes` from a non-symlink regular file without following symlinks or blocking on FIFOs."""
    try:
        path_str = os.fspath(path)
        if "\x00" in path_str or path.is_symlink() or not path.is_file():
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path_str, flags)
    except (OSError, TypeError, ValueError):
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            return None
        fh = os.fdopen(fd, "rb")
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        return None
    try:
        with fh:
            if from_tail:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - max_bytes), os.SEEK_SET)
            return fh.read(max_bytes)
    except OSError:
        return None

def _select_tiered_hints(
    candidates: List[Tuple[Any, ...]],
    *,
    max_generic: int = MAX_HINTS,
    max_explicit: int = MAX_EXPLICIT_HINTS,
) -> List[Tuple[Any, ...]]:
    """Selects up to `max_explicit` explicit hints first, leaving remaining `max_generic` slots for keyword matches."""
    candidates.sort(key=lambda item: (item[0], item[1]))
    explicit = [item for item in candidates if item[0] < 0][:max_explicit]
    remaining_generic = max(0, max_generic - len(explicit))
    generic = [item for item in candidates if item[0] == 0][:remaining_generic]
    return explicit + generic

def _detect_workspace_domain_signals(workspaces: Sequence[Path]) -> Tuple[List[str], List[str]]:
    """Scans bounded workspace markers (`depth <= 2`, `<= 200` entries) for domain skill and MCP route signals."""
    skills: List[str] = []
    routes: List[str] = []
    for ws in workspaces:
        if not ws.is_dir() or _is_harness_repo_root(ws):
            continue
        has_cargo_toml = False
        has_c_cpp = False
        has_rust_bridge = False
        has_game_marker = False
        has_media_asset = False
        has_binary_artifact = False
        entries_seen = 0
        web_reads = 0
        stack: List[Tuple[Path, int, bool]] = [(ws, 0, False)]

        while stack and entries_seen < 200:
            cur_dir, depth, in_media_dir = stack.pop()
            try:
                with os.scandir(cur_dir) as it:
                    entries = sorted(itertools.islice(it, 1000), key=lambda e: e.name)
            except OSError:
                continue
            for entry in entries:
                entries_seen += 1
                if entries_seen > 200:
                    break
                try:
                    is_lnk = entry.is_symlink()
                except OSError:
                    continue
                if is_lnk:
                    continue
                name = entry.name
                low = name.lower()
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError:
                    continue
                if is_dir:
                    if low in _WS_SKIP_DIRS or low.startswith("."):
                        continue
                    if depth < 2:
                        next_media = in_media_dir or (low in _MEDIA_ASSET_DIRS)
                        stack.append((Path(entry.path), depth + 1, next_media))
                    continue

                fpath = Path(entry.path)
                suffix = fpath.suffix.lower()
                if low == "cargo.toml":
                    has_cargo_toml = True
                    raw = _read_bounded_bytes_nofollow(fpath, 32768)
                    if raw and _RUST_BRIDGE_RE.search(raw.decode("utf-8", errors="replace")):
                        has_rust_bridge = True
                elif suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
                    has_c_cpp = True
                elif low == "project.godot" or suffix in {".uproject", ".unity"} or (
                    low == "projectversion.txt" and cur_dir.name == "ProjectSettings"
                ):
                    has_game_marker = True
                elif low == "package.json":
                    raw = _read_bounded_bytes_nofollow(fpath, 32768)
                    if raw and _GAME_PKG_RE.search(raw.decode("utf-8", errors="replace")):
                        has_game_marker = True
                elif not has_game_marker and suffix in {".html", ".htm", ".js", ".ts", ".jsx", ".tsx"} and web_reads < 12:
                    web_reads += 1
                    raw = _read_bounded_bytes_nofollow(fpath, 32768)
                    if raw:
                        text = raw.decode("utf-8", errors="replace")
                        if _CANVAS_RE.search(text) and _RAF_RE.search(text):
                            has_game_marker = True

                if suffix in _AUDIO_VIDEO_EXTS:
                    has_media_asset = True
                elif suffix in _RASTER_MEDIA_EXTS:
                    if _SPRITE_NAME_RE.search(fpath.stem) or (in_media_dir and not _WEB_ICON_IGNORE_RE.match(name)):
                        has_media_asset = True

                if suffix in _BINARY_ARTIFACT_EXTS:
                    has_binary_artifact = True

        if has_cargo_toml and (has_c_cpp or has_rust_bridge) and "rustify" not in skills:
            skills.append("rustify")
        if has_game_marker and "game-engineering" not in skills:
            skills.append("game-engineering")
        if has_media_asset and "media-studio" not in skills:
            skills.append("media-studio")
        if has_binary_artifact and "route:mcp:rea_rea" not in routes and _is_rea_mcp_available(workspaces):
            routes.append("route:mcp:rea_rea")

    return skills, routes

def _detect_transcript_tool_signals(payload: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Detects post-user >500-line, truncated, or repeated compiler/test error traces in transcript tail."""
    transcript = payload.get("transcriptPath") or payload.get("transcript_path")
    if not isinstance(transcript, str) or not transcript.strip():
        return None
    tx_path = Path(transcript).expanduser()

    rev_tail: List[Dict[str, Any]] = []
    for entry in _iter_jsonl_tail_entries(tx_path, max_scan_bytes=2 * 1024 * 1024):
        if (
            str(entry.get("type", "")).upper() == "USER_INPUT"
            or str(entry.get("source", "")).upper() == "USER_EXPLICIT"
        ):
            break
        rev_tail.append(entry)
        if len(rev_tail) >= 200:
            break
    if not rev_tail:
        return None
    tail_entries = list(reversed(rev_tail))

    heavy_fail = False
    consec_build_fails = 0
    snippets: List[str] = []
    for entry in tail_entries:
        step_type = str(entry.get("type", "")).upper()
        if step_type in {"USER_INPUT", "PLANNER_RESPONSE"}:
            continue
        status = str(entry.get("status", "")).upper()
        err_field = entry.get("error")
        content = entry.get("content") if isinstance(entry.get("content"), str) else ""
        truncated = entry.get("truncated_fields")
        tool_name = str(entry.get("tool_name") or entry.get("tool") or entry.get("name") or "").strip().lower()
        if (
            tool_name in _NON_EXEC_READ_TOOLS
            and status != "ERROR"
            and not re.search(r"\bCommand\s+exited\s+with\s+code\s+[1-9]", content)
        ):
            continue
        is_error_status = status == "ERROR" or (
            isinstance(err_field, str) and bool(err_field.strip())
        ) or (isinstance(err_field, dict) and bool(err_field))
        is_clean_exit_zero = bool(re.search(r"\bCommand\s+exited\s+with\s+code\s+0\b", content)) and not is_error_status
        has_trace_marker = False if is_clean_exit_zero else bool(_TRACE_ERROR_MARKER_RE.search(content))

        if is_clean_exit_zero and _CLEAN_BUILD_PASS_RE.search(content):
            consec_build_fails = 0
            heavy_fail = False
            snippets.clear()
            continue

        is_truncated_content = isinstance(truncated, list) and "content" in truncated
        line_count = content.count("\n") + (1 if content else 0)
        is_failing = (is_error_status or has_trace_marker) and not is_clean_exit_zero
        if not is_failing:
            continue

        if (has_trace_marker and (line_count > 500 or is_truncated_content)) or (
            is_error_status and line_count > 500
        ):
            heavy_fail = True
            snippets.append(content[-400:] if content else str(err_field)[:400])

        if has_trace_marker or (is_error_status and bool(re.search(r"\bCommand\s+exited\s+with\s+code\s+[1-9]", content))):
            consec_build_fails += 1
            snippets.append(content[:300] if content else str(err_field)[:300])

    if heavy_fail or consec_build_fails >= 2:
        digest = hashlib.sha256("\n".join(snippets)[:4096].encode("utf-8")).hexdigest()[:12]
        return ("route:subagent:build-error-resolver", f"tx_err:{digest}")
    return None

def _collect_context_domain_and_transcript_hints(
    payload: Dict[str, Any],
    workspaces: Sequence[Path],
    seen_turns: Dict[str, int],
    matched: List[Tuple[str, str, str]],
    matched_routes: List[Tuple[str, str]],
    *,
    is_short_or_continuation: bool,
    is_new_user_turn: bool,
    active_turn: int,
) -> Tuple[List[Tuple[str, str, str]], List[Tuple[str, str]], set[str]]:
    """Appends bounded workspace marker and transcript error-trace hints with turn-gap deduplication."""
    if is_short_or_continuation:
        return matched, matched_routes, set()

    extra_keys: set[str] = set()
    emitted_skills = {m[0] for m in matched}
    emitted_routes = {r[0] for r in matched_routes}
    ws_skills, ws_routes = _detect_workspace_domain_signals(workspaces)

    def _within_cooldown(key: str) -> bool:
        return key in seen_turns and (not is_new_user_turn or (active_turn - seen_turns[key]) < REHINT_TURN_GAP)

    added_ctx_skills = 0
    for skill_name in ws_skills:
        if added_ctx_skills >= MAX_CONTEXT_SIGNALS:
            break
        ctx_key = f"ws_ctx:{skill_name}"
        if skill_name in emitted_skills or _within_cooldown(skill_name) or _within_cooldown(ctx_key):
            continue
        hint_tuple = _SKILL_HINT_BY_NAME.get(skill_name)
        if hint_tuple is None:
            continue
        matched.append(hint_tuple)
        emitted_skills.add(skill_name)
        extra_keys.add(skill_name)
        extra_keys.add(ctx_key)
        added_ctx_skills += 1

    added_ctx_routes = 0
    for route_key in ws_routes:
        if added_ctx_routes >= MAX_CONTEXT_SIGNALS:
            break
        ctx_key = f"ws_ctx:{route_key}"
        if route_key in emitted_routes or _within_cooldown(route_key) or _within_cooldown(ctx_key):
            continue
        route_tuple = _ROUTE_HINT_BY_KEY.get(route_key)
        if route_tuple is None:
            continue
        matched_routes.append(route_tuple)
        emitted_routes.add(route_key)
        extra_keys.add(route_key)
        extra_keys.add(ctx_key)
        added_ctx_routes += 1

    tx_sig = _detect_transcript_tool_signals(payload)
    if tx_sig is not None and added_ctx_routes < MAX_CONTEXT_SIGNALS:
        route_key, tx_digest_key = tx_sig
        if (
            route_key not in emitted_routes
            and tx_digest_key not in seen_turns
            and not _within_cooldown(route_key)
        ):
            route_tuple = _ROUTE_HINT_BY_KEY.get(route_key)
            if route_tuple is not None:
                matched_routes.append(route_tuple)
                emitted_routes.add(route_key)
                extra_keys.add(route_key)
                extra_keys.add(tx_digest_key)
                added_ctx_routes += 1

    return matched, matched_routes, extra_keys

def _collect_invocation_skill_hints(
    scan_text: str,
    workspaces: Sequence[Path],
    seen_turns: Dict[str, int],
    *,
    is_short_or_continuation: bool,
    is_new_user_turn: bool,
    has_explicit_cmd: bool,
    active_turn: int,
    explicit_text: Optional[str] = None,
) -> Tuple[List[Tuple[str, str, str]], List[Tuple[str, str]]]:
    """Selects bounded skill hints and ecosystem routing directives for `handle_pre_invocation`."""
    if is_short_or_continuation:
        return [], []
    explicit_surface = scan_text if explicit_text is None else explicit_text
    has_viable_token = has_explicit_cmd or bool(_VIABLE_HINT_TOKEN_RE.search(scan_text))
    skill_candidates: List[Tuple[int, int, str, str, str]] = []
    for table_idx, (skill_name, rel_path, pattern, summary) in enumerate(SKILL_HINTS):
        aliases = _SKILL_SLASH_ALIASES.get(skill_name, (skill_name,))
        explicit_slash = has_explicit_cmd and _has_explicit_slash_command(explicit_surface, aliases)
        explicit_slug = (
            False
            if (not has_explicit_cmd or explicit_slash)
            else _has_explicit_slug_mention(explicit_surface, skill_name)
        )
        is_explicit = explicit_slash or explicit_slug
        if not is_explicit:
            if not has_viable_token and "@\\[" not in pattern.pattern:
                continue
            if not pattern.search(scan_text):
                continue
        if not _optional_plugin_skill_available(rel_path, workspaces):
            continue
        if skill_name in seen_turns:
            if not is_new_user_turn:
                continue
            if not explicit_slash and (active_turn - seen_turns[skill_name]) < REHINT_TURN_GAP:
                continue
        priority = 2 if explicit_slash else (1 if explicit_slug else 0)
        skill_candidates.append((-priority, table_idx, skill_name, rel_path, summary))
    selected_skills = _select_tiered_hints(skill_candidates)
    matched = [(s, r, d) for _p, _i, s, r, d in selected_skills]

    route_candidates: List[Tuple[int, int, str, str]] = []
    for table_idx, (route_key, pattern, directive) in enumerate(ECOSYSTEM_ROUTING_HINTS):
        route_aliases = _ROUTE_SLASH_ALIASES.get(route_key, ())
        explicit_route_slash = has_explicit_cmd and _has_explicit_slash_command(explicit_surface, route_aliases)
        if (
            has_explicit_cmd
            and route_key == "route:subagent:meta-auditor"
            and re.search(
                rf"{_SLASH_PRE}/audit\s+--(?:meta|self){_SLASH_POST}",
                explicit_surface,
                re.IGNORECASE,
            )
        ):
            explicit_route_slash = True
        explicit_route_slug = (
            False
            if (not has_explicit_cmd or explicit_route_slash)
            else _has_explicit_route_slug_mention(explicit_surface, route_key)
        )
        is_explicit_route = explicit_route_slash or explicit_route_slug
        if not is_explicit_route:
            if not has_viable_token and "@\\[" not in pattern.pattern:
                continue
            if not pattern.search(scan_text):
                continue
        if route_key == "route:mcp:rea_rea" and not _is_rea_mcp_available(workspaces):
            continue
        if route_key in seen_turns:
            if not is_new_user_turn:
                continue
            if not explicit_route_slash and (active_turn - seen_turns[route_key]) < REHINT_TURN_GAP:
                continue
        priority = 2 if explicit_route_slash else (1 if explicit_route_slug else 0)
        route_candidates.append((-priority, table_idx, route_key, directive))
    selected_routes = _select_tiered_hints(route_candidates)
    matched_routes = [(rk, d) for _p, _i, rk, d in selected_routes]
    return matched, matched_routes

def handle_pre_invocation(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw_prompt, step_idx = _extract_latest_user_prompt(payload)
    if not raw_prompt:
        return {}

    cleaned = _extract_user_request_prose(raw_prompt).strip()
    scan_text = cleaned[:16384]
    inline_cmd_surface = _extract_explicit_inline_command_tokens(raw_prompt)
    explicit_text = f"{scan_text} {inline_cmd_surface}".strip() if inline_cmd_surface else scan_text
    normalized = re.sub(r"[.!?,;:]+$", "", scan_text.lower()).strip()
    has_explicit_cmd = bool(
        _EXPLICIT_CMD_TOKEN_RE.search(explicit_text) or _has_any_explicit_slug_mention(explicit_text)
    )
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

    try:
        with file_lock(hints_file, timeout=HOOK_LOCK_TIMEOUT):
            ledger_ok, ledger = _read_ledger_checked(hints_file)
            if not ledger_ok:
                sys.stderr.write(f"[Harness PreInvocation] Quarantine/read fallback on `{hints_file}`.\n")
            seen_turns, turn_num, last_sig = _load_conv_hint_state(ledger.get(conv_id))
            first_turn_in_conv = "__workspace_checked__" not in seen_turns
            is_new_user_turn = (not is_short_or_continuation) and (current_sig != last_sig)
            inv_raw = payload.get("invocationNum")
            if inv_raw is None:
                inv_raw = payload.get("invocation_num")
            inv_num = _safe_int(inv_raw, default=1)
            if inv_num > 1 and not is_new_user_turn and (not workspaces or not first_turn_in_conv):
                active_turn = max(turn_num, 1)
                tx_keys: set[str] = set()
                if payload.get("transcriptPath") or payload.get("transcript_path"):
                    tx_sig = _detect_transcript_tool_signals(payload)
                    if tx_sig is not None:
                        route_key, tx_digest_key = tx_sig
                        prev_turn = seen_turns.get(route_key)
                        if (
                            tx_digest_key not in seen_turns
                            and (prev_turn is None or (active_turn - prev_turn) >= REHINT_TURN_GAP)
                        ):
                            route_tuple = _ROUTE_HINT_BY_KEY.get(route_key)
                            if route_tuple is not None and len(matched_routes) < MAX_CONTEXT_SIGNALS:
                                matched_routes.append(route_tuple)
                                tx_keys.add(route_key)
                                tx_keys.add(tx_digest_key)
                if not tx_keys:
                    return {}
                for key in tx_keys:
                    seen_turns[key] = active_turn
                serialized_fast: Dict[str, Any] = {k: seen_turns[k] for k in sorted(seen_turns)}
                serialized_fast["__turn__"] = turn_num
                serialized_fast["__last_sig__"] = last_sig
                if conv_id in ledger:
                    del ledger[conv_id]
                ledger[conv_id] = serialized_fast
                while len(ledger) > 50:
                    oldest = next(iter(ledger))
                    del ledger[oldest]
                atomic_write_json(hints_file, ledger)
                routes_fast = "; ".join(directive for _key, directive in matched_routes)
                msg_fast = (
                    f"[Harness Ecosystem Routing] Relevant subagent(s) / MCP server(s): {routes_fast}. "
                    "Invoke or call them automatically when the task touches these boundaries."
                )
                return {"injectSteps": [{"systemMessage": {"systemMessage": msg_fast}}]}

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
                    inspect_ok, recovery = _facade_attr(
                        "_detect_workspace_recovery_hint", _detect_workspace_recovery_hint
                    )(
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

            matched, matched_routes = _collect_invocation_skill_hints(
                scan_text,
                workspaces,
                seen_turns,
                is_short_or_continuation=is_short_or_continuation,
                is_new_user_turn=is_new_user_turn,
                has_explicit_cmd=has_explicit_cmd,
                active_turn=active_turn,
                explicit_text=explicit_text,
            )
            matched, matched_routes, ctx_keys = _collect_context_domain_and_transcript_hints(
                payload,
                workspaces,
                seen_turns,
                matched,
                matched_routes,
                is_short_or_continuation=is_short_or_continuation,
                is_new_user_turn=is_new_user_turn,
                active_turn=active_turn,
            )

            new_keys |= {m[0] for m in matched} | {r[0] for r in matched_routes} | ctx_keys
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
                except OSError as exc:
                    hints_persisted = False
                    sys.stderr.write(f"[Harness PreInvocation] Failed to write `{hints_file}`: {exc}\n")

            if pending_acks and hints_persisted:
                for ack_ws, ack_seq_val in pending_acks:
                    _acknowledge_interrupted_flight(ack_ws, ack_seq_val)
    except (OSError, TimeoutError) as exc:
        sys.stderr.write(f"[Harness PreInvocation] Failed to lock `{hints_file}` ({type(exc).__name__}): {exc}\n")
        for ws in workspaces:
            _inspect_ok, recovery = _facade_attr(
                "_detect_workspace_recovery_hint", _detect_workspace_recovery_hint
            )(ws, conv_id, first_turn_in_conv=False)
            if recovery is not None:
                recovery_msgs.append(recovery[1])
        matched, matched_routes = _collect_invocation_skill_hints(
            scan_text,
            workspaces,
            {},
            is_short_or_continuation=is_short_or_continuation,
            is_new_user_turn=not is_short_or_continuation,
            has_explicit_cmd=has_explicit_cmd,
            active_turn=1,
            explicit_text=explicit_text,
        )
        matched, matched_routes, _ctx_keys = _collect_context_domain_and_transcript_hints(
            payload,
            workspaces,
            {},
            matched,
            matched_routes,
            is_short_or_continuation=is_short_or_continuation,
            is_new_user_turn=not is_short_or_continuation,
            active_turn=1,
        )

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
    return {"injectSteps": [{"systemMessage": {"systemMessage": " ".join(parts)}}]}
