"""
guard/hooks/pre_invocation.py — PreInvocation skill-suggest, context routing & recovery gate (ADR-0008).
Part of Plumbwork (https://github.com/tozhax/plumbwork)
Zero external dependencies: uses strictly the Python standard library.
"""

from __future__ import annotations

import hashlib
import itertools
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from guard.paths import CorruptStateError, HOOK_LOCK_TIMEOUT, read_json_strict

from .common import (
    CONTINUATION_WORDS,
    MAX_CONTEXT_SIGNALS,
    MAX_EXPLICIT_HINTS,
    MAX_HINTS,
    MIN_PROMPT_CHARS,
    REHINT_TURN_GAP,
    _EXPLICIT_CMD_TOKEN_RE,
    _FENCE_RE,
    _HARNESS_PLUGIN_NAMES,
    _INLINE_CODE_RE,
    _LazyRegex,
    _PATH_WORD_POST,
    _PATH_WORD_PRE,
    _PLUGIN_SKILL_TO_PACK,
    _SLASH_POST,
    _SLASH_PRE,
    _STALE_IN_FLIGHT_SECONDS,
    _USER_REQUEST_TAG_RE,
    _VIABLE_HINT_TOKEN_RE,
    _conversation_id,
    _extract_latest_user_prompt,
    _extract_user_request_prose,
    _extract_user_request_with_inline,
    _extract_ws_flight_conversations,
    _facade,
    _facade_attr,
    _flight_recorder_file,
    _inspect_transcript_turn_state,
    _inspect_transcript_turn_state_ex,
    _is_auxiliary_readonly_context,
    _is_git_repo_workspace,
    _is_harness_repo_root,
    _iter_jsonl_tail_entries,
    _normalize_markdown_newlines,
    _parse_iso_utc,
    _prune_missing_flight_workspaces,
    _read_bounded_markdown_checked,
    _read_ledger_checked,
    _read_ledger_safe,
    _rebuild_ws_flight_entry,
    _repo_root,
    _resolve_transcript_path,
    _safe_int,
    _strip_non_user_prose,
    _upstream_seed_candidates,
    _workspaces_from_payload,
    atomic_write_json,
    config_dir,
    configured_config_dir,
    file_lock,
    json,
    state_dir,
    subprocess,
)


# Bilingual (EN + TR) skill suggestion table: (skill_name, skill_rel_path, raw_pattern, summary)
# Compiled lazily via PEP 562 `__getattr__` (`SKILL_HINTS`) and sound necessary-literal prefiltering
# in `_match_hint_pattern` to avoid ~100 ms cold-start `re.compile` overhead on `inv=1`.
_SKILL_HINTS_RAW: Tuple[Tuple[str, str, str, str], ...] = (
    (
        "diagnosing-bugs",
        "skills/diagnosing-bugs/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/diagnosing-bugs{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"bug|regression|regresyon\w*|crash(?:es|ed|ing)?|traceback|stack\s*trace|segfault|"
            r"failing\s+(?:tests?|assertions?)|flaky\s+(?:tests?|assertions?|failures?|builds?|checks?)|intermittent\s+failure|bisect|"
            r"(?:debug|investigat(?:e|ing)|diagnos(?:e|ing))\s+(?:this\s+|the\s+|an?\s+)?(?:[\w-]+\s+){0,2}(?:failure|error|bug|crash|regression|flaky)|"
            r"root\s+cause(?:\s+(?:of|analysis))?|test\s+suite\s+(?:is\s+)?failing|"
            r"hata\s+var|çalışmıyor|calismiyor|patlıyor|patliyor|bozuldu|neden\s+hata|"
            r"neden\s+(?:çalışmıyor|calismiyor|patlıyor|patliyor|hata\s+veriyor|kırmızı|kirmizi|geçmiyor|gecmiyor)|"
            r"hata(?:yı|sı|ları)?\s+(?:ayıkla\w*|bul\w*|teşhis\s+et\w*)|"
            r"kök\s+neden\w*|test(?:ler|i)?\s+(?:neden\s+)?(?:kırmızı|kirmizi|kırıl\w*|patl\w*|fail(?:\s+ediyor)?|geçmiyor|gecmiyor|çalışmıyor|calismiyor|hata\s+veriyor)"
            rf"){_PATH_WORD_POST})"
        ),
        "7-phase root-cause analysis before editing code",
    ),
    (
        "test-design",
        "skills/harness/references/test-design.md",
        (
            rf"(?:{_SLASH_PRE}/test-design{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"test\s+design|design\s+tests?|coverage\s+gaps?|property[- ]based\s+test|"
            r"boundary[- ]value|equivalence\s+partition|parametrize[d]?\s+tests?|"
            r"(?:write|add)\s+(?:unit|integration|regression)\s+tests?|"
            r"test\s+yaz|test\s+ekle|regresyon\s+testi|birim\s+test(?:i|leri)\s+(?:yaz|ekle)|"
            r"test\s+tasar(?:ımı|imi|la)|test\s+senaryo(?:su|ları)|kapsama\s+boşlu(?:ğu|gu)|"
            r"sınır\s+değer\s+test"
            rf"){_PATH_WORD_POST})"
        ),
        "behaviour-first test design, boundary analysis & anti-tautology checks",
    ),
    (
        "mistake-proofing",
        "skills/harness/references/mistake-proofing.md",
        (
            rf"(?:{_SLASH_PRE}/mistake-proofing{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"poka[- ]?yoke|mistake[- ]proof(?:ing)?|parse[,\s]+don'?t\s+validate|"
            r"boolean\s+trap|primitive\s+obsession|illegal\s+state\s+unrepresentable|"
            r"yine\s+aynı\s+hata|bir\s+daha\s+olmasın|tekrar\s+etti|"
            r"hata\s+önleme|yanlış\s+kullanımı\s+engelle|tip\s+güvenli(?:ği|gi)\s+ile\s+koru"
            rf"){_PATH_WORD_POST})"
        ),
        "compile/parse-time structural mistake-proofing (poka-yoke) for APIs & schemas",
    ),
    (
        "refactoring",
        "skills/refactoring/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/refactoring{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"refactor(?:ing)?|extract\s+(?:\w+\s+)?(?:functions?|methods?|classes|modules?|helpers?)|"
            r"restructur(?:e|ing)\s+(?:this\s+|the\s+|these\s+)?(?:modules?|classes|functions?|codebase)|"
            r"split\s+(?:file|module|class)|decouple|code\s+smell|dead\s+code|"
            r"refactor\s+et|yeniden\s+düzenle|sadeleştir|parçala|kod\s+tekrarını\s+kaldır|"
            r"yeniden\s+yapılandır|kod\s+kokusu|modüllere\s+ayır|fonksiyon\w*\s+çıkar"
            rf"){_PATH_WORD_POST})"
        ),
        "behaviour-preserving step-by-step refactoring with red-green test seams",
    ),
    (
        "dependency-upgrade",
        "skills/harness/references/dependency-upgrade.md",
        (
            rf"(?:{_SLASH_PRE}/dependency-upgrade{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"upgrade\s+(?:dependenc(?:y|ies)|packages?)|bump\s+version|version\s+bump|major\s+upgrade|"
            r"lockfile\s+update|cve\s+fix|dependenc(?:y|ies)\s+migration|"
            r"sürümü\s+yükselt|bağımlılık(?:ları|\w*\s+sürüm\w*)(?:\s+[\wçğıöşüÇĞİÖŞÜ-]+){0,3}\s+(?:güncelle\w*|yükselt\w*)|"
            r"paket\w*\s+(?:güncelle|yeni\s+sürüme\s+(?:taşı|geçir|yükselt))|bağımlılık\s+güncelle|sürüm\s+yükselt"
            rf"){_PATH_WORD_POST})"
        ),
        "compatibility matrix, changelog review & lockfile-safe dependency upgrades",
    ),
    (
        "renew",
        "skills/renew/SKILL.md",
        (
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
            rf"){_PATH_WORD_POST})"
        ),
        "5-stage legacy app & classic game modernization (autopsy, contract, golden-master oracle, strangler cutover & security sanitization)",
    ),
    (
        "rustify",
        "skills/rustify/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/rustify{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"rustify\w*(?!\.(?:rs|py|c|cc|cpp|cxx|h|hh|hpp|hxx|go|js|ts|md|json|toml|yaml|yml)\b)|"
            r"(?<!bump\s)(?<!upgrade\s)(?<!update\s)(?:cbindgen|bindgen|cxx\s+bridge|#?\[?cxx::bridge\]?|pyo3|napi[-_]rs|wasm[-_]bindgen)(?!\s+(?:from|to|in)\s+[\dv]|[^\n]{0,30}\bcargo\.toml\b)|"
            r"(?:port(?:ing)?|migrat(?:e|ing)|rewrit(?:e|ing)|convert(?:ing)?|translat(?:e|ing)|bridg(?:e|ing))\s+(?!this\s+unsafe\b|unsafe\s+(?:rust|helper|fn|function|block|code|impl|trait)\b|(?!(?:c|cpp|golang|python|go|typescript|ts|javascript|js|ruby|java|kotlin)\b)(?:(?:this|the|our|my|existing|these)\s+){0,2}(?:(?!\b(?:to|into|c|cpp|golang|python|go|cgo|cython|typescript|ts|javascript|js|ruby|java|kotlin|napi|magnus|jni)\b)(?:[\w+/.-]+,*|,+)\s+){0,7}\brust\b)(?:(?:[\w+/.-]+,*|,+)\s+){0,8}(?:to|into)\s+(?:(?:a|an)\s+)?(?:(?:new|greenfield|standalone|idiomatic|memory[- ]safe|compiler[- ]verified|zero[- ]panic|safe|pure),?\s+)*rust\b(?!\s*(?:edition\s*)?20\d{2}\b|\s+1\.\d+\b)|"
            r"(?:(?:c(?:/c\+\+|\+\+)?|cpp|golang|python|typescript|javascript|ts/js|js/ts|ruby|java(?:/kotlin)?|kotlin)\s+(?:[\w+/.-]+\s+){0,4}(?:to|into)\s+(?:(?:a|an)\s+)?(?:(?:new|greenfield|standalone|idiomatic|memory[- ]safe|compiler[- ]verified|zero[- ]panic|safe|pure),?\s+)*rust\b|"
            r"go\s+(?:(?:code(?:base)?|module|service|library|binary|daemon|cli|worker|server|backend|runtime|app|package|crate)\s+)?(?:to|into)\s+(?:(?:a|an)\s+)?(?:(?:new|greenfield|standalone|idiomatic|memory[- ]safe|compiler[- ]verified|zero[- ]panic|safe|pure),?\s+)*rust\b(?!\s*(?:edition\s*)?20\d{2}\b|\s+1\.\d+\b))|"
            r"(?:rust\s+(?:ffi(?:\s+(?:bindings?|wrappers?|bridges?))?|bindings?|wrappers?)\s+(?:for|to)\s+(?:c/c\+\+|c\+\+|(?:cpp|golang|python|go|c|typescript|javascript|ts/js|js/ts|node(?:\.?js)?|ruby|java(?:/kotlin)?|kotlin)\b)|(?:ffi|c\s+abi)\s+(?:bridge|wrapper|interop)\s+(?:for|to|with|in)\s+rust\b)|"
            r"(?:c(?:/c\+\+|\+\+)?|cpp|go|golang|python|typescript|javascript|ts/js|js/ts|ruby|java(?:/kotlin)?|kotlin)'?(?:dan|den|tan|ten)\s+rust'?(?:a|ya)\b|"
            r"(?:c(?:/c\+\+|\+\+)?|cpp|go|golang|python|typescript|javascript|ruby|java|kotlin)\s+(?:[\wçğıöşüÇĞİÖŞÜ.-]+\s+){0,3}rust\s+ile\s+(?:yeniden\s+yaz\w*|değiştir\w*)|"
            r"rust'?(?:a|ya)\s*(?:çevir\w*|cevir\w*|taşı\w*|tasi\w*|dönüştür\w*|donustur\w*|geçir\w*|gecir\w*|aktar\w*|port\s+et\w*)"
            rf"){_PATH_WORD_POST})"
        ),
        "5-stage C/C++/Go/Python/TS/JS/Ruby/Java -> memory-safe Rust migration, ABI/FFI bridges (bindgen/cbindgen/cxx/PyO3/napi-rs/JNI) & Miri/sanitizer/Kani verification",
    ),
    (
        "rust-harden",
        "skills/rust-harden/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/rust-harden{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"rust[-_]harden(?![./\w-])|"
            r"harden(?:ing)?\s+(?:(?:this|the|our|my|existing)\s+)?(?:[\w-]+\s+){0,3}rust\b|"
            r"rust\s+(?:crate\s+|code(?:base)?\s+|module\s+|service\s+|kernel\s+)?harden(?:ing)?\b|"
            r"(?:convert(?:ing)?|rewrit(?:e|ing)|refactor(?:ing)?|clean(?:ing)?\s+up|turn(?:ing)?|mak(?:e|ing))\s+(?:(?:this|the|our|my|existing|these)\s+){0,2}(?:[\w<>:.,()/+-]+\s+){0,6}rust\s+(?:crate|module|service|code(?:base)?|daemon|driver|kernel)\s+(?:to|into|more)?\s*(?:idiomatic|zero[- ]panic|panic[- ]free|memory[- ]safe)(?:\s+rust)?\b|"
            r"idiomatic\s+rust\s+(?:cleanup|hardening|pass|refactor\w*)|"
            r"(?:remove|eliminate|clean\s+up|replace)\s+(?:(?:unnecessary|reflexive|production)\s+)*(?:rust\s+(?:\.?unwrap(?:\(\))?|\.?expect(?:\(\))?|\.?clone(?:\(\))?|arc<mutex\w*>?|rc<refcell\w*>?|ownership\s+debt|borrow[- ]checker\s+debt)\b|(?:\.?unwrap(?:\(\))?|\.?expect(?:\(\))?|\.?clone(?:\(\))?|arc<mutex\w*>?|rc<refcell\w*>?|ownership\s+debt|borrow[- ]checker\s+debt)\b[^\n.?!]{0,50}\brust\b)|"
            r"(?:narrow(?:ing)?|purif(?:y|ying)|shrink(?:ing)?|eliminat(?:e|ing))\s+unsafe\s+(?:blocks?|code|wrappers?|fns?|functions?)(?:\s+in\s+(?:this\s+|the\s+|our\s+)?(?:#!\[no_std\]\s+)?rust\b)?|"
            r"tokio::select!\s+cancellation(?:\s+safety)?|await[_ ]holding[_ ]lock|"
            r"greenfield\s+rust\b|"
            r"(?:scaffold(?:ing)?|design(?:ing)?|architect(?:ing)?)\s+(?:(?:a|an|this|the|our|my|new|greenfield)\s+){0,3}(?:[\w-]+\s+){0,2}rust\s+(?:workspace|crate|project|service|daemon|library|backend|architecture)\b|"
            r"rust\s+(?:workspace|crate|service|project)\s+(?:architecture|scaffolding|layout)\b|"
            r"(?:yeni|sıfırdan|sifirdan)\s+(?:bir\s+)?rust\s+(?:proje\w*|workspace\w*|crate\w*|servis\w*|kütüphane\w*|kutuphane\w*|mimari\w*)|"
            r"rust\s+(?:crate\w*|proje\w*|workspace\w*|servis\w*|kütüphane\w*|kutuphane\w*|mimari\w*)\s+(?:tasarla\w*|kur(?!tar|ulu)\w*|başlat(?!ılam|ilam)\w*|baslat(?!ılam|ilam)\w*|iskele\w*)|"
            r"rust\s+(?:servis\w*|crate\w*|kütüphane\w*|kutuphane\w*|workspace\w*)\s+yaz(?!ılım|ilim|dır|dir|ılmış|ilmis|ıl\b|il\b)\w*|"
            r"rust\s+kod\w*\s+sertleştir\w*|idiomatic\s+rust\s+yap\w*|"
            r"sahiplik\s+borc\w*\s+temizle\w*|unsafe\s+(?:blok\w*\s+|kod\w*\s+)?arındır\w*"
            rf"){_PATH_WORD_POST})"
        ),
        "intra-Rust hardening (`--internal` vs `--contract`), greenfield crate/workspace architecture (`--greenfield`), panic removal, async cancellation & `#![no_std]`/kernel `unsafe` narrowing",
    ),
    (
        "retro",
        "skills/retro/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/retro{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"retrospective|sprint\s+retro|post[- ]?mortem|"
            r"retrospektif\w*|tekrarlayan\s+hata\w*"
            rf"){_PATH_WORD_POST})"
        ),
        "read-only retrospective over MISTAKES.md, plan outcomes & 3-strike rule promotion",
    ),
    (
        "deep-grill",
        "skills/deep-grill/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/deep-grill{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"deep[- ]grill|"
            r"(?:tier[- ]?3|architecture|design|schema|protocol|requirements?|spec(?:ification)?)\s+grill\s+me|"
            r"grill\s+me\s+(?:on|about)\s+(?:this\s+|the\s+|our\s+)?(?:architecture|design|schema|protocol|api|system|spec\w*|code\w*|feature|requirements?)|"
            r"design\s+interview|stress[- ]test\s+requirements|edge[- ]case\s+interview|"
            r"(?:mimari\w*|tasarım\w*|sistem\w*|şema\w*|protokol\w*|gereksinim\w*|uç\s+durum\w*|kod\w*)\s+(?:\S+\s+){0,2}(?:mülakat\s+yap\w*|sorgula\w*)|"
            r"uç\s+durumlar\w*\s+sorgula\w*"
            rf"){_PATH_WORD_POST})"
        ),
        "adversarial requirement & architecture boundary interview before coding",
    ),
    (
        "audit",
        "skills/audit/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/audit{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"audit\s+this|full\s+audit|security\s+audit|consistency\s+audit|boundary\s+audit|spec\s+gap\s+audit|"
            r"perform\s+consistency\s+analysis|inspect\s+design\s+and\s+security\s+boundaries|"
            r"run\s+harness\s+meta[- ]audit|self[- ]audit\s+harness|"
            r"güvenlik\s+denetim\w*|tutarlılık\s+denetim\w*|mimari\s+denetim\w*|sınır\s+denetim\w*"
            rf"){_PATH_WORD_POST})"
        ),
        "read-only multi-pass consistency, specification-gap & security boundary audit",
    ),
    (
        "technical-writing",
        "skills/technical-writing/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/technical-writing{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"technical\s+writing|documentation\s+architecture|diataxis|diátaxis|"
            r"api\s+reference\s+docs?|write\s+(?:a\s+)?(?:tutorial|runbook|release\s+notes)|"
            r"teknik\s+dokümantasyon|teknik\s+yazarlık|kullanım\s+kılavuzu|sürüm\s+notları|doküman\s+yaz"
            rf"){_PATH_WORD_POST})"
        ),
        "Diataxis mode separation, executable snippet verification & changelog discipline",
    ),
    (
        "data-analysis",
        "skills/data-analysis/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/data-analysis{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"data\s+analysis|exploratory\s+data\s+analysis|jupyter\s+notebooks?|data\s+leakage|"
            r"train[/-]test\s+split|feature\s+engineering|statistical\s+analysis|"
            r"veri\s+analizi|veri\s+bilimi|istatistiksel\s+analiz|veri\s+sızıntısı"
            rf"){_PATH_WORD_POST})"
        ),
        "row-count/drop accounting, train/test split anti-leakage & honest chart scaling",
    ),
    (
        "game-engineering",
        "skills/game-engineering/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/game-engineering{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"game\s+loop|fixed[- ]timestep|game\s+dev(?:elopment)?|canvas\s+game|webgl\s+game|webgpu\s+game|"
            r"(?:2d|3d|phaser|godot|unity|unreal|pixi(?:\.js)?|three(?:\.js)?|browser|arcade|indie|platformer|roguelike)\s+games?|"
            r"build(?:ing)?\s+(?:a\s+|an\s+|this\s+)?game\b|frame\s+accumulator|seeded\s+(?:prng|rng)|deterministic\s+game|"
            r"collision\s+detection|game\s+physics|entity\s+state\s+machine|"
            r"oyun\s+(?:geliştir(?:me)?|yap\w*|tasarla\w*|kodla\w*|motoru|fiziğ\w*|fizik\w*|döngü\w*)|"
            r"sabit\s+(?:timestep|zaman\s+adımı)|fizik\s+döngüsü|çarpışma\s+(?:algılama|sistemi|testi)|"
            r"(?:canvas|webgl|tarayıcı|2d|3d|2b|3b|arcade|platform)\s+oyun\w*"
            rf"){_PATH_WORD_POST})"
        ),
        "fixed-timestep simulation loop, zero per-frame allocation, seeded PRNG & MODE: GAME vitality",
    ),
    (
        "media-studio",
        "skills/media-studio/SKILL.md",
        (
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
            rf"){_PATH_WORD_POST})"
        ),
        "4-stage Probe->Plan->Process->Verify media pipeline, container salvage, photo/AV restoration, fidelity upscaling & media_qc.py gate",
    ),
    (
        "marathon",
        "skills/harness/references/marathon.md",
        (
            rf"(?:{_SLASH_PRE}/marathon{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"marathon\s+plan|multi[- ]window\s+(?:plan|rework|build)|split\s+into\s+windows|"
            r"maraton\s+başlat|maraton\s+plan(?:ı|la)|pencerelere\s+böl"
            rf"){_PATH_WORD_POST})"
        ),
        "proactive multi-window goal planning, model/effort routing & HANDOFF.md orchestration",
    ),
    (
        "sweetspot",
        "skills/sweetspot/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/(?:sweetspot|optimize){_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"sweetspot|sweet[- ]spot\s+optimization|"
            r"(?:benchmark|profile)\s+(?:(?:and\s+optimize|memory|ram|cpu|latency|network|waterfall|startup|frame|performance)(?:\s+footprint)?)|"
            r"optimize\s+(?:startup|latency|frame\s+rate|fps|performance|memory|ram|disk\s+space|binary\s+size|bundle\s+size|footprint|network|bandwidth|download|upload)|"
            r"optimize\s+(?:this\s+|the\s+)?(?:game|app|application|software|codebase|program|service|backend|script|tool|library|binary|package|(?:software|coding)\s+project|(?:operating|file|build|cache|distributed)\s+system)|"
            r"speed\s+up\s+(?:this\s+|the\s+)?(?:game|app|application|software|codebase|program|service|backend|script|query|loop|startup|build|pipeline|renderer|download|upload)|"
            r"(?:reduce|shrink|cut|lower|decreas(?:e|ing))\s+(?:(?:--net|memory|ram|disk|binary|bundle|network|bandwidth|download|upload|round[- ]trip|request|api|render)\s+)*(?:memory|ram|disk|binary|bundle|network|bandwidth|download|upload|round[- ]trip|allocations?|gc\s+pressure|startup\s+time|cold[- ]start|frame\s+time|rtt|waterfall\s+latency|latency|n\+1\s+(?:queries|requests?))(?:\s+(?:usage|footprint|size|traffic|latency|payload))?|"
            r"sweetspot\s+analizi|tatlı\s+nokta\s+optimizasyonu|performans\s+optimizasyonu|(?:bellek|ram|disk|ağ|bant\s+genişliği)\s+optimizasyonu|"
            r"(?:oyun\w*|servis\w*|uygulama\w*|yazılım\w*|proje\w*|repo\w*|beti[kğ]\w*|kod\w*|(?:işletim|dosya|derleme|önbellek)\s+sistem\w*|modül\w*|sorgu\w*|fonksiyon\w*|algoritma\w*|motor\w*|derleme\w*|[iİ]ndirme\w*|ağ\w*|bellek\w*|ram\w*|hız\w*|render\w*)\s+(?:\S+\s+){0,2}(?:optimize\s+et|hızlandır\w*|hizlandir\w*)|"
            r"(?:bellek|ram|cpu|ağ|disk|yükleme|başlatma|soğuk\s+başlangıç|sorgu|döngü|render|kare)\s+(?:tüketimi\w*|kullanımı\w*|maliyeti\w*|süresi\w*|gecikmesi\w*|boyutu\w*)\s+(?:düşür\w*|azalt\w*|küçült\w*|optimize\s+et\w*|hızlandır\w*)|"
            r"(?:uygulama\w*|servis\w*|oyun\w*|sorgu\w*|beti[kğ]\w*|motor\w*|derleme\w*|paket\w*|dosya\w*|pipeline\w*)\s+(?:performans\w*|hız\w*|fps|belle[kğ]\w*|boyut\w*)\s+(?:iyileştir\w*|artır\w*|düşür\w*|optimize\s+et\w*)|"
            r"(?:bellek|ram|bant\s+genişliği)\s+kullanımını\s+(?:düşür|azalt)|"
            r"(?:disk\s+alanını|dosya\s+boyutunu|paket\s+boyutunu|[iİ]ndirme\s+(?:ve\s+yükleme\s+)?boyutunu|yükleme\s+boyutunu|çıktının\s+boyutunu)\s+küçült|"
            r"(?:ağ\s+)?gecikme(?:yi|sini)\s+(?:düşür|azalt)|(?:fps|kare\s+hızını)\s+artır"
            rf"){_PATH_WORD_POST})"
        ),
        "controlled behavior-preserving speed, memory (RAM), disk & network optimization (3-Zone Sweet-Spot Gate)",
    ),
    (
        "vibecoder",
        "skills/vibecoder/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/vibecoder?{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"vibecoder|vibe\s*coding|rapid\s+prototyp(?:e|ing)|single[- ]file\s+(?:html\s+)?prototyp(?:e|ing)|"
            r"game\s+prototype|interactive\s+(?:prototype|sandbox)|(?:audio|sound|visual)\s+synthesizer|creative\s+studio\s+prototype|"
            r"fikrim\s+var|hızlı\s+prototip|oyun\s+prototipi|etkileşimli\s+kum\s+havuzu|ses\s+sentezleyici|"
            r"yaratıcı\s+stüdyo\s+prototip(?:i)?|tek\s+dosya(?:lık)?\s+(?:html|prototip|oyun|stüdyo)|prototip\s+üret"
            rf"){_PATH_WORD_POST})"
        ),
        "3-question Vibe-Grill & zero-friction single-file rich HTML app, game & creative sandbox prototyping",
    ),
    (
        "ui-refinery",
        "skills/ui-refinery/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/ui-refinery{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"ui[- ]refinery|ui\s+delivery\s+gate|ai\s+slop|design\s+quality\s+gate|"
            r"arayüz\s+kalite(?:si)?|tasarım\s+denetimi|yapay\s+zeka\s+klişe(?:si|leri)"
            rf"){_PATH_WORD_POST})"
        ),
        "40-rule design/copy quality filter, Liveliness Toolkit & UI Delivery Gate",
    ),
    (
        "ui-audit",
        "skills/ui-refinery/references/ui.md",
        (
            rf"(?:{_SLASH_PRE}/ui-audit{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"ui[- ]audit|visual\s+slop\s+audit|audit\s+ui\s+components?|anti[- ]boxification|sibling\s+symmetry|"
            r"görsel\s+slop|bileşen\s+denetimi|kart\s+simetrisi"
            rf"){_PATH_WORD_POST})"
        ),
        "Anti-Boxification, Sibling Symmetry Cap, Typographic Scale Lock & HUD vitality",
    ),
    (
        "copy-polish",
        "skills/ui-refinery/references/copywriting.md",
        (
            rf"(?:{_SLASH_PRE}/copy-polish{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"copy[- ]polish|write\s+copy|de[- ]ai\s+(?:prose|text|copy)|synthetic\s+markers?|anti[- ]ai\s+tone|"
            r"metin\s+yazımı|pazarlama\s+metni|yapay\s+zeka\s+dili(?:ni)?\s+temizle"
            rf"){_PATH_WORD_POST})"
        ),
        "de-AI prose rewrites, tone calibration & EN/TR synthetic-marker scanning",
    ),
    (
        "a11y-check",
        "skills/ui-refinery/references/human-a11y.md",
        (
            rf"(?:{_SLASH_PRE}/a11y-check{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"a11y[- ]check|check\s+contrast|wcag\s+contrast|accessibility\s+audit|a11y\s+audit|color\s+contrast\s+ratio|"
            r"renk\s+kontrast(?:ı|i)|erişilebilirlik\s+denetimi|wcag\s+uyumu"
            rf"){_PATH_WORD_POST})"
        ),
        "WCAG AA contrast verification, keyboard navigation & 5 component states",
    ),
    (
        "mobile-layout",
        "skills/ui-refinery/references/layoutmobile.md",
        (
            rf"(?:{_SLASH_PRE}/mobile-layout{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"mobile[- ]layout|fix\s+overflow|horizontal\s+overflow|tap[- ]target\s+siz(?:e|ing)|responsive\s+check|"
            r"mobil\s+yerleşim|yatay\s+taşma|mobil\s+uyumluluk|dokunma\s+hedefi"
            rf"){_PATH_WORD_POST})"
        ),
        "mobile horizontal-overflow elimination, 44px tap targets & responsive reflow",
    ),
    (
        "code-comments",
        "skills/ui-refinery/references/code-comments.md",
        (
            rf"(?:{_SLASH_PRE}/code-comments{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"code-comments|clean\s+comments|comment\s+hygiene|remove\s+slop\s+comments|"
            r"yorum\s+temizli(?:ği|gi)|gereksiz\s+yorumlar(?:ı|i)\s+(?:sil|temizle|kaldır)"
            rf"){_PATH_WORD_POST})"
        ),
        "code-comment hygiene: strips AI-slop comments while preserving why/contract notes",
    ),
    (
        "motion-physics",
        "skills/ui-refinery/references/motion-physics.md",
        (
            rf"(?:{_SLASH_PRE}/motion-physics{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"motion[- ]physics|kinetic\s+(?:motion|typography)|smooth[- ]scroll(?:ing)?|motion\s+3|lenis\s+scroll|"
            r"kinetik\s+tasarım|akıcı\s+kaydırma|vitrin\s+sayfası\s+tasarla"
            rf"){_PATH_WORD_POST})"
        ),
        "physics-based kinetic motion (MOTION 3), fluid typography & showcase landing pages",
    ),
    (
        "visualizer",
        "skills/technical-writing/references/visualizer.md",
        (
            rf"(?:{_SLASH_PRE}/visualizer{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"visualize\s+(?:architecture|workflow|state|codebase|journey)|architecture\s+diagram|mermaid\s+diagram|sequence\s+diagram|"
            r"mimari(?:yi)?\s+görselleştir|diyagram\s+çiz|akış\s+şeması\s+oluştur|şematize\s+et"
            rf"){_PATH_WORD_POST})"
        ),
        "4-lens visual structure routing (Mermaid for static, generative_ui for interactive)",
    ),
    (
        "porter",
        "skills/porter/SKILL.md",
        (
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
            rf"){_PATH_WORD_POST})"
        ),
        "bidirectional rule/skill suitability analyzer, sanitizer & ecosystem transpiler",
    ),
    (
        "database-migrations",
        "skills/database-migrations/SKILL.md",
        (
            rf"{_PATH_WORD_PRE}(?:"
            r"schema\s+migration|database\s+migration|zero[- ]downtime\s+migration|database\s+rollback|alter\s+table|"
            r"veritabanı\s+göç\w*|şema\s+göç\w*|migrasyon\s+yaz\w*|"
            r"(?:veritabanı|veritabani|şema|sema|tablo|sql|prisma|drizzle|alembic|django|knex|typeorm)\s+migration\w*|"
            r"migration\s+(?:yaz\w*|oluştur\w*|olustur\w*|ekle\w*|hazırla\w*|hazirla\w*|geri\s+al\w*)"
            rf"){_PATH_WORD_POST}"
        ),
        "expand-migrate-contract schema changes, lock timeouts & rollback safety",
    ),
    (
        "architecture-decision-records",
        "skills/harness/references/adr.md",
        (
            rf"(?:{_SLASH_PRE}/adr{_SLASH_POST}|(?<![/\w\\-])docs/adr(?![\w-])|{_PATH_WORD_PRE}(?:"
            r"record\s+adr|architecture\s+decision\s+records?|write\s+an\s+adr|"
            r"mimari\s+karar\s+kayd\w*|adr\s+(?:yaz\w*|oluştur\w*|kaydet\w*)"
            rf"){_PATH_WORD_POST})"
        ),
        "weighted trade-off matrix & structured Architecture Decision Records in docs/adr/",
    ),
    (
        "security-review",
        "skills/audit/references/security-review.md",
        (
            rf"(?:{_SLASH_PRE}/security-review{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"security\s+review\s+checklist|pre[- ]deployment\s+security|transport\s+security\s+headers|"
            r"dağıtım\s+öncesi\s+güvenlik\w*|güvenlik\s+kontrol\s+liste\w*"
            rf"){_PATH_WORD_POST})"
        ),
        "pre-deployment security checklist for secrets, transport headers & cloud boundaries",
    ),
    (
        "chisle",
        "skills/chisle/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/chisle{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"chisle\s+mode|activate\s+chisle|chislify"
            rf"){_PATH_WORD_POST})"
        ),
        "terse zero-fluff prose & YAGNI/ladder-first engineering mode",
    ),
    (
        "harness",
        "skills/harness/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/(?:harness|verify|gate|run-gate){_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"harness\s+verification\s+gate|run\s+verification\s+gate|doğrulama\s+kapıs\w*"
            rf"){_PATH_WORD_POST})"
        ),
        "strict computational verification gates, artifact-driven task lifecycle & auditor handoffs",
    ),
    (
        "unlazy",
        "skills/harness/references/unlazy.md",
        (
            rf"(?:{_SLASH_PRE}[/\$]unlazy{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"tree\s+\d+|do\s+not\s+stop\s+until\s+it\s+is\s+done|bitene\s+kadar\s+durma"
            rf"){_PATH_WORD_POST})"
        ),
        "Tier-3 deep completion engine with Depth Tree & reverification gates",
    ),
    (
        "upstream-auditor",
        "skills/upstream-auditor/SKILL.md",
        (
            rf"(?:{_SLASH_PRE}/audit-upstream{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"upstream[- ]auditor|model\s+drift\s+audit|upstream\s+skill\s+sync"
            rf"){_PATH_WORD_POST})"
        ),
        "upstream model catalog, runtime & tracked repository synchronization auditor",
    ),
    (
        "reverse-engineer-anything",
        "plugins/rea/skills/reverse-engineer-anything/SKILL.md",
        (
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
            rf"){_PATH_WORD_POST})"
        ),
        "evidence-backed binary, APK/IPA/ELF, firmware, PCAP & Electron/JS reverse engineering",
    ),
)

# Bilingual (EN + TR) Subagent, MCP Server & Plugin routing hints: (route_key, raw_pattern, directive)
_ECOSYSTEM_ROUTING_HINTS_RAW: Tuple[Tuple[str, str, str], ...] = (
    (
        "route:mcp:rea_rea",
        (
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
            rf"){_PATH_WORD_POST})"
        ),
        "MCP Server `rea_rea` & Plugin `rea` (`call_mcp_tool` with `ServerName=\"rea_rea\"` + read `~/.gemini/config/plugins/rea/skills/reverse-engineer-anything/SKILL.md`)",
    ),
    (
        "route:mcp:ui-refinery-contrast",
        (
            rf"{_PATH_WORD_PRE}(?:"
            r"check\s+contrast|wcag\s+contrast|color\s+contrast(?:\s+ratio)?|contrast\s+ratio|"
            r"renk\s+kontrast(?:ı|i)|kontrast\s+oran(?:ı|i)"
            rf"){_PATH_WORD_POST}"
        ),
        "MCP Server `ui-refinery-contrast` (`call_mcp_tool` with `ServerName=\"ui-refinery-contrast\"`, `ToolName=\"check_contrast\"`)",
    ),
    (
        "route:subagent:security-silent",
        (
            rf"{_PATH_WORD_PRE}(?:"
            r"authentication\s+boundary|authorization\s+boundary|jwt\s+(?:token|auth)|oauth2?\s+flow|"
            r"cryptograph(?:y|ic)|payment\s+processing|storage\s+integrity|secret\s+boundary|"
            r"permission\s+boundary|auth(?:entication|orization)\s+bypass|toctou|race\s+condition|"
            r"kimlik\s+doğrulama|yetkilendirme\s+sınır(?:ı|i)|yetki\s+sınır(?:ı|i)|güvenlik\s+sınır(?:ı|i)|"
            r"kriptografi|ödeme\s+altyapısı|depolama\s+bütünlüğü"
            rf"){_PATH_WORD_POST}"
        ),
        "Subagents `security-boundary-verifier` & `silent-failure-hunter` (`invoke_subagent` before delivery per GEMINI.md §3 Critical Exceptions)",
    ),
    (
        "route:subagent:contract-test",
        (
            rf"{_PATH_WORD_PRE}(?:"
            r"public\s+api\s+contract|breaking\s+contract\s+change|wire\s+protocol\s+change|openapi\s+schema\s+change|"
            r"public\s+interface\s+migration|migration\s+rollback\s+safety|wire\s+format\s+change|schema\s+breaking\s+change|"
            r"sözleşme\s+değişikliği|api\s+kontrat(?:ı|i)|public\s+arayüz\s+değişikliği|kırıcı\s+şema\s+değişikliği"
            rf"){_PATH_WORD_POST}"
        ),
        "Subagents `contract-change-auditor` & `test-adequacy-auditor` (`invoke_subagent` before delivering public contract/schema changes)",
    ),
    (
        "route:subagent:spec-consistency",
        (
            rf"{_PATH_WORD_PRE}(?:"
            r"formal\s+specification|multi[- ]volume\s+spec|state\s+machine\s+invariant|safety\s+core\s+spec|"
            r"multi[- ]file\s+invariant|axiomatic\s+consistency|"
            r"resmi\s+spesifikasyon|güvenlik\s+çekirdeği\s+spesifikasyonu|spesifikasyon\s+tutarsızl\w*|durum\s+makinesi\s+değişmezi"
            rf"){_PATH_WORD_POST}"
        ),
        "Subagents `consistency-auditor` & `specification-gap-auditor` (`invoke_subagent` per GEMINI.md §3 Critical Exceptions)",
    ),
    (
        "route:subagent:simplicity-auditor",
        (
            rf"{_PATH_WORD_PRE}(?:"
            r"simplicity[- ]auditor(?![./\w-])|"
            r"yagni\s+(?:audit|review|check)|over[- ]engineering\s+(?:audit|review|check)|"
            r"efficiency\s+ladder\s+(?:audit|review|check)|premature\s+abstraction\s+(?:audit|review|check)|"
            r"yagni\s+denetim\w*|aşırı\s+mühendislik\s+denetim\w*|gereksiz\s+soyutlama\s+denetim\w*"
            rf"){_PATH_WORD_POST}"
        ),
        "Subagent `simplicity-auditor` (`invoke_subagent` with `TypeName=\"simplicity-auditor\"` to audit Tier 2/3 diffs for GEMINI.md Rule 4 YAGNI, Rule 18 surgical reuse & 7-Rung Efficiency Ladder compliance)",
    ),
    (
        "route:subagent:research",
        (
            rf"{_PATH_WORD_PRE}(?:"
            r"external\s+documentation|official\s+sdk\s+docs|research\s+library\s+api|"
            r"(?:read|check)\s+(?:the\s+)?(?:(?:official|external|latest|versioned)\s+){1,2}(?:(?:sdk|library|framework)\s+)?(?:docs|documentation|reference|spec|api)|"
            r"explore\s+(?:the\s+|this\s+)?(?:codebase|repository)\s+broadly|research\s+subagent|"
            r"dış\s+dokümantasyon\s+araştır|resmi\s+kütüphane\s+dokümanı|"
            r"(?:resmi|dış|harici|güncel)\s+(?:dokümantasyon\w*|api\s+referans\w*)\s+(?:araştır\w*|oku\w*|incele\w*|kontrol\s+et\w*)|"
            r"kütüphane\s+(?:api|doküman)\w*\s+(?:doğrula\w*|araştır\w*)"
            rf"){_PATH_WORD_POST}"
        ),
        "Subagent `research` (`invoke_subagent` to isolate >50 KB documentation or broad codebase exploration per GEMINI.md Rule 11)",
    ),
    (
        "route:subagent:build-error-resolver",
        (
            rf"{_PATH_WORD_PRE}(?:"
            r"compiler\s+error\s+trace|typescript\s+build\s+error|typecheck\s+failure\s+log|"
            r"(?:fix|resolve|debug)\s+(?:these\s+|the\s+|this\s+)?(?:(?:typescript|tsc|mypy|cargo|rustc|go)\s+)?(?:build|compiler|type)\s+errors?|"
            r"(?:fix|resolve|debug)\s+(?:these\s+|the\s+|this\s+)?(?:typescript|tsc|mypy|cargo|rustc)\s+errors?|"
            r"500\+?\s*lines?\s+of\s+(?:build|compiler|type|tsc|cargo|mypy)\s+errors?|"
            r"uzun\s+derleme\s+hatası|tip\s+hatası\s+izini\s+çöz|"
            r"(?:derleme|typecheck|tip\s+kontrol|tsc|mypy|cargo\s+build)\s+hatalar(?:ı|ını)\s+(?:çöz\w*|gider\w*|ayıkla\w*)"
            rf"){_PATH_WORD_POST}"
        ),
        "Subagent `build-error-resolver` (`invoke_subagent` on >500-line traces or after 2 consecutive failed compiler/type fix attempts)",
    ),
    (
        "route:builtin:generative_ui",
        (
            rf"{_PATH_WORD_PRE}(?:"
            r"generative[_ ]ui|agent-embed|inline\s+(?:interactive\s+)?widget|interactive\s+chat\s+widget|"
            r"sohbet\s+içinde\s+(?:interaktif|etkileşimli)\s+widget|interaktif\s+widget|canlı\s+kontrol\s+paneli\s+göm\w*"
            rf"){_PATH_WORD_POST}"
        ),
        "Built-in Skill `generative_ui` (read `~/.gemini/antigravity/builtin/skills/generative_ui/SKILL.md`; use host theme variables and allowlisted `gstatic` Tailwind solely inside isolated widgets per GEMINI.md Rule 15c)",
    ),
    (
        "route:builtin:automation",
        (
            rf"(?:{_SLASH_PRE}/automation{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"scheduled\s+background\s+automation|recurring\s+scheduled\s+task|background\s+cron\s+automation|"
            r"zamanlanmış\s+görev|arka\s+plan\s+otomasyonu|tekrarlayan\s+otomasyon"
            rf"){_PATH_WORD_POST})"
        ),
        "Built-in Skill `automation` (read `~/.gemini/antigravity/builtin/skills/automation/SKILL.md`; obey GEMINI.md Rule 15a/15b: never write to governance seams in `~/.gemini/config/`, route runtime sidecars only to `~/.gemini/config/sidecars/` or `~/.gemini/antigravity/sidecars/`, default to the native `schedule` tool, and report progress via `toolAction`/`toolSummary`)",
    ),
    (
        "route:builtin:antigravity-guide",
        (
            rf"{_PATH_WORD_PRE}(?:"
            r"antigravity\s+(?:ide|cli|sdk|keybindings?|slash\s+commands?|2\.0)|agy\s+cli|"
            r"antigravity\s+(?:kısayol\w*|ayar\w*|nasıl\s+kullanıl\w*)|agy\s+komut\s+satır\w*"
            rf"){_PATH_WORD_POST}"
        ),
        "Built-in Skill `antigravity-guide` (read `~/.gemini/antigravity/builtin/skills/antigravity_guide/SKILL.md` for Antigravity 2.0, `agy` CLI, IDE keybindings, slash commands & Python SDK reference)",
    ),
    (
        "route:builtin:agy-customizations",
        (
            rf"{_PATH_WORD_PRE}(?:"
            r"agy[- ]customizations|"
            r"antigravity\s+customization\w*|"
            r"customization\s+(?:system|loading\s+priority|discovery|precedence)|"
            r"antigravity\s+özelleştir\w*|"
            r"yerleşik\s+(?:antigravity\s+)?özelleştir\w*|"
            r"keşif\s+önceliğ\w*\s+ve\s+kanca\s+yapı\w*|"
            r"(?:hint|ipucu)\s+mekanizma\w*"
            rf"){_PATH_WORD_POST}"
        ),
        "Built-in Skill `agy-customizations` (read `~/.gemini/antigravity/builtin/skills/agy-customizations/SKILL.md`; obey GEMINI.md Rule 15a: `~/.gemini/config/` is read-only, author repo-managed changes in the source checkout)",
    ),
    (
        "route:builtin:plugin",
        (
            rf"(?:{_SLASH_PRE}/plugin{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"antigravity\s+plugin|package\s+into\s+a\s+plugin|install\s+or\s+uninstall\s+a\s+plugin|"
            r"eklenti\s+paketi\s+olarak\s+paketle\w*|antigravity\s+eklentisi\s+(?:oluştur|kur|kaldır)\w*"
            rf"){_PATH_WORD_POST})"
        ),
        "Built-in Skill `plugin` (read `~/.gemini/antigravity/builtin/skills/plugin/SKILL.md`; obey GEMINI.md Rule 15a: harness plugin packs under `~/.gemini/config/plugins/` are OS-locked/denied and mutating `agy plugin` commands targeting them require human confirmation)",
    ),
    (
        "route:subagent:meta-auditor",
        (
            rf"(?:{_SLASH_PRE}/audit\s+--(?:meta|self){_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"meta[- ]auditor|"
            r"harness\s+(?:self[- ]audit|meta[- ]consistency|meta[- ]audit)|"
            r"porter\s+parity\s+audit|"
            r"harness\s+(?:öz[- ]?denetim\w*|meta[- ]?tutarlılık\w*|iç\s+tutarlılık\w*)|"
            r"(?:beceri|kanca|anayasa)\s+tutarlılık\s+denetim\w*"
            rf"){_PATH_WORD_POST})"
        ),
        "Subagent `meta-auditor` (`invoke_subagent` with `TypeName=\"meta-auditor\"` + `plumb-guard self-audit --strict` (or `python3 scripts/meta_audit.py --strict` in repo checkouts) for harness, skill, hook & Porter meta-consistency verification per GEMINI.md Rule 17)",
    ),
    (
        "route:subagent:image-generator",
        (
            rf"{_PATH_WORD_PRE}(?:"
            r"generate\s+(?:an\s+)?(?:illustration|raster\s+image|hero\s+image)|image[- ]generator\s+subagent|"
            r"özel\s+bir\s+illüstrasyon\s+ve\s+görsel\s+üret\w*|illüstrasyon\s+üret\w*|görsel\s+varlık\s+üret\w*"
            rf"){_PATH_WORD_POST}"
        ),
        "Built-in Subagent `image-generator` (`invoke_subagent` with `TypeName=\"image-generator\"` after obtaining explicit user approval for asset creation per `ui-refinery` R-23; never use for logical diagrams per `visualizer`)",
    ),
    (
        "route:builtin:native_swarm",
        (
            rf"(?:{_SLASH_PRE}/(?:swarm|native_swarm){_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"native[- _]swarm|agent\s+swarm|swarm\s+(?:mode|board|workers?)|"
            r"ajan\s+sürüsü\w*|paylaşımlı\s+mesaj\s+panosu\w*"
            rf"){_PATH_WORD_POST})"
        ),
        "Built-in Skill `native_swarm` (`swarm` tool & `~/.gemini/antigravity/builtin/skills/native_swarm/SKILL.md`; obey GEMINI.md Rule 15f & Rule 17: never downgrade worker `model` when editing customization/governance files, and isolate parallel authors with `workspace='share'`/`'branch'`)",
    ),
    (
        "route:builtin:migrate-agent-settings",
        (
            rf"(?:{_SLASH_PRE}/migrate-agent-settings{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"migrate[- _]agent[- _]settings|"
            r"import\s+(?:claude\s+code|codex|cursor|gemini\s+cli)\s+(?:config|settings|rules|mcp)|"
            r"(?:claude\s+code|codex|cursor|gemini\s+cli)\s+ayarlarını\s+içe\s+aktar\w*"
            rf"){_PATH_WORD_POST})"
        ),
        "Built-in Skill `migrate-agent-settings` (read `~/.gemini/antigravity/builtin/skills/migrate-agent-settings/SKILL.md`; obey GEMINI.md Rule 12 & maintainer Rule 15g/16: keep `npx` dependencies pinned, pass imported rules through `plumb-porter inspect`, and obtain human confirmation before plugin writes)",
    ),
    (
        "route:builtin:mcp-app-development",
        (
            rf"(?:{_SLASH_PRE}/mcp-app-development{_SLASH_POST}|{_PATH_WORD_PRE}(?:"
            r"mcp[- _]app[- _]development|mcp\s+app\s+(?:ui|resource|widget)|ui://\s*app|"
            r"mcp\s+uygulama\s+arayüzü\w*"
            rf"){_PATH_WORD_POST})"
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
    "route:mcp:ui-refinery-contrast": ("ui-refinery-contrast", "ui-refinery_contrast", "check_contrast"),
    "route:subagent:security-silent": ("security-boundary-verifier", "silent-failure-hunter"),
    "route:subagent:contract-test": ("contract-change-auditor", "test-adequacy-auditor"),
    "route:subagent:spec-consistency": ("consistency-auditor", "specification-gap-auditor"),
    "route:subagent:simplicity-auditor": ("simplicity-auditor",),
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
    for skill_name, rel_path, _pattern, summary in _SKILL_HINTS_RAW
}

_ROUTE_HINT_BY_KEY: Dict[str, Tuple[str, str]] = {
    route_key: (route_key, directive)
    for route_key, _pattern, directive in _ECOSYSTEM_ROUTING_HINTS_RAW
}

_DISTINCTIVE_SKILL_SLUGS = frozenset({
    "porter",
    "sweetspot",
    "vibecoder",
    "chisle",
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

_ANY_EXPLICIT_SLUG_RE = _LazyRegex(
    rf"(?:^|(?<=[\s(\[\"'«“]))(?:{'|'.join(re.escape(s) for s in sorted(_KNOWN_INLINE_EXPLICIT_SLUGS, key=len, reverse=True))}){_SLASH_POST}",
    re.IGNORECASE,
)

def _extract_necessary_literals(pat: str) -> Optional[Tuple[str, ...]]:
    """
    Sound conservative necessary-literal extractor for `re.IGNORECASE` regex patterns.

    Returns a non-empty tuple of normalized lowercase substrings (`>= 2` chars) such that ANY
    text matched by `re.compile(pat, re.IGNORECASE)` MUST contain at least one returned literal
    after `İ`/`ı` -> `i` + `.casefold()`. Returns `None` whenever a branch may match without a
    guaranteed safe literal (caller must then compile and run the full regex — zero false negatives).
    """
    if not pat or "(?#" in pat or "(?(" in pat:
        return None
    norm_trans = getattr(_extract_necessary_literals, "_norm_trans", None)
    if norm_trans is None:
        norm_trans = str.maketrans({"İ": "i", "ı": "i"})
        unescaped_safe = frozenset(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_:#çğıöşüÇĞİÖŞÜ-"
        )
        escaped_safe = unescaped_safe | frozenset(".+$")
        tok_re = re.compile(
            r"\\."
            r"|\[(?:\^?\]?(?:\\.|[^\]])*)\]"
            r"|\(\?(?:<=|<!|[:=!]|P<[^>]*>|[aiLmsux-]+:?)"
            r"|[()|]"
            r"|[?*+][?+]?"
            r"|\{\d+(?:,\d*)?\}[?+]?"
            r"|[.^$]"
            r"|[A-Za-z0-9/_:#çğıöşüÇĞİÖŞÜ-]+"
            r"|[^\\\[\]()|?*+.^${}]"
        )
        setattr(_extract_necessary_literals, "_norm_trans", norm_trans)
        setattr(_extract_necessary_literals, "_unescaped_safe", unescaped_safe)
        setattr(_extract_necessary_literals, "_escaped_safe", escaped_safe)
        setattr(_extract_necessary_literals, "_tok_re", tok_re)
    else:
        unescaped_safe = getattr(_extract_necessary_literals, "_unescaped_safe")
        escaped_safe = getattr(_extract_necessary_literals, "_escaped_safe")
        tok_re = getattr(_extract_necessary_literals, "_tok_re")

    clean_pat = pat
    for _zwa in (_PATH_WORD_PRE, _PATH_WORD_POST, _SLASH_PRE, _SLASH_POST):
        if _zwa in clean_pat:
            clean_pat = clean_pat.replace(_zwa, "")
    tokens = tok_re.findall(clean_pat)
    if "".join(tokens) != clean_pat:
        return None
    n = len(tokens)
    pos = 0
    abort = False

    def parse_alt() -> Optional[Tuple[str, ...]]:
        nonlocal pos, abort
        b0 = parse_seq()
        if abort:
            return None
        if pos >= n or tokens[pos] != "|":
            return b0
        out: Optional[List[str]] = None if b0 is None else list(b0)
        while pos < n and tokens[pos] == "|":
            pos += 1
            bi = parse_seq()
            if abort:
                return None
            if out is None or bi is None:
                out = None
            else:
                out.extend(bi)
        return tuple(out) if out else None

    def parse_seq() -> Optional[Tuple[str, ...]]:
        nonlocal pos, abort
        best: Optional[Tuple[str, ...]] = None
        best_n = 999999
        best_m = 0
        lit = ""
        while pos < n:
            tok = tokens[pos]
            c0 = tok[0]
            if c0 == "|" or c0 == ")":
                break
            pos += 1
            if c0 in unescaped_safe:
                if pos < n and tokens[pos][0] in "?*+{":
                    nt = tokens[pos]
                    pos += 1
                    nc = nt[0]
                    if nc in "?*" or (nc == "{" and (nt[1] == "0" or nt[1] == ",")):
                        s = lit + tok[:-1]
                    else:
                        s = lit + tok
                    lit = ""
                    if len(s) >= 2 and (1 < best_n or (best_n == 1 and len(s) > best_m)):
                        best = (s,)
                        best_n = 1
                        best_m = len(s)
                else:
                    lit += tok
                continue
            if c0 == "\\":
                ec = tok[1:]
                has_q = False
                opt = False
                if pos < n and tokens[pos][0] in "?*+{":
                    nt = tokens[pos]
                    pos += 1
                    has_q = True
                    nc = nt[0]
                    opt = nc in "?*" or (nc == "{" and (nt[1] == "0" or nt[1] == ","))
                if not opt and len(ec) == 1 and not ec.isalnum() and ec in escaped_safe:
                    if has_q:
                        s = lit + ec
                        lit = ""
                        if len(s) >= 2 and (1 < best_n or (best_n == 1 and len(s) > best_m)):
                            best = (s,)
                            best_n = 1
                            best_m = len(s)
                    else:
                        lit += ec
                    continue
            if lit:
                if len(lit) >= 2 and (1 < best_n or (best_n == 1 and len(lit) > best_m)):
                    best = (lit,)
                    best_n = 1
                    best_m = len(lit)
                lit = ""
            if c0 == "(":
                if len(tok) > 2 and tok[1] == "?" and not tok.startswith("(?P<") and "x" in tok:
                    abort = True
                    return None
                is_assert = len(tok) > 1 and (
                    tok[1:3] in ("?=", "?!", "?<")
                    or (tok[1] == "?" and not tok.startswith(("(?:", "(?P<")) and not tok.endswith(":"))
                )
                sub = parse_alt()
                if abort or pos >= n or tokens[pos] != ")":
                    abort = True
                    return None
                pos += 1
                opt = False
                if pos < n and tokens[pos][0] in "?*+{":
                    nt = tokens[pos]
                    pos += 1
                    nc = nt[0]
                    opt = nc in "?*" or (nc == "{" and (nt[1] == "0" or nt[1] == ","))
                if not is_assert and not opt and sub is not None:
                    sn = len(sub)
                    if sn < best_n:
                        best = sub
                        best_n = sn
                        best_m = min(len(x) for x in sub)
                    elif sn == best_n:
                        sm = min(len(x) for x in sub)
                        if sm > best_m:
                            best = sub
                            best_m = sm
            elif c0 in "[.^$":
                if pos < n and tokens[pos][0] in "?*+{":
                    pos += 1
        if lit and len(lit) >= 2 and (1 < best_n or (best_n == 1 and len(lit) > best_m)):
            best = (lit,)
        return best

    res = parse_alt()
    if abort or pos != n or not res:
        return None
    return tuple(dict.fromkeys(x.translate(norm_trans).casefold() for x in res))


def _match_hint_pattern(pat_str: str, scan_text: str, norm_scan: str) -> bool:
    """Matches a raw `re.IGNORECASE` hint regex using sound necessary-literal prefiltering + lazy compilation."""
    rx_cache: Dict[str, re.Pattern[str]] = getattr(_match_hint_pattern, "_rx_cache", None)  # type: ignore[assignment]
    if rx_cache is None:
        rx_cache = {}
        lit_cache: Dict[str, Optional[Tuple[str, ...]]] = {}
        setattr(_match_hint_pattern, "_rx_cache", rx_cache)
        setattr(_match_hint_pattern, "_lit_cache", lit_cache)
    else:
        lit_cache = getattr(_match_hint_pattern, "_lit_cache")
    compiled = rx_cache.get(pat_str)
    if compiled is not None:
        return bool(compiled.search(scan_text))
    if pat_str not in lit_cache:
        lit_cache[pat_str] = _extract_necessary_literals(pat_str)
    lits = lit_cache[pat_str]
    if lits is not None and not any(tok in norm_scan for tok in lits):
        return False
    compiled = re.compile(pat_str, re.IGNORECASE)
    rx_cache[pat_str] = compiled
    return bool(compiled.search(scan_text))


def _has_any_explicit_slug_mention(explicit_surface: str) -> bool:
    """Returns True when any known explicit skill or ecosystem route slug appears directly in user prose."""
    if not explicit_surface:
        return False
    norm = explicit_surface.replace("İ", "i").replace("ı", "i").casefold()
    if not any(slug in norm for slug in _KNOWN_INLINE_EXPLICIT_SLUGS):
        return False
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

_HANDOFF_IN_PROGRESS_RE = _LazyRegex(
    r"(?im)^[^\S\r\n]*(?:[-*•][^\S\r\n]+)?(?:\*\*Status:\*\*|\*\*Status\*\*:|Status:)[^\S\r\n]*`?\[IN-PROGRESS\]`?[^\S\r\n]*$"
)

_HANDOFF_COMPLETE_RE = _LazyRegex(
    r"(?im)^[^\S\r\n]*(?:[-*•][^\S\r\n]+)?(?:\*\*Status:\*\*|\*\*Status\*\*:|Status:)[^\S\r\n]*`?\[COMPLETE\]`?[^\S\r\n]*$"
)

_CAMPAIGN_ID_RE = _LazyRegex(
    r"(?im)^[^\S\r\n]*(?:[-*•][^\S\r\n]+)?(?:\*\*Campaign[^\S\r\n]+ID:\*\*|\*\*Campaign[^\S\r\n]+ID\*\*:|Campaign[^\S\r\n]+ID:)[^\S\r\n]*`?([A-Za-z0-9][A-Za-z0-9._/-]{1,120})`?[^\S\r\n]*$"
)

_HANDOFF_COMMIT_RE = _LazyRegex(
    r"(?im)^[^\S\r\n]*(?:[-*•][^\S\r\n]+)?(?:\*\*Git[^\S\r\n]+Branch[^\S\r\n]*/[^\S\r\n]*Commit:\*\*|\*\*Git[^\S\r\n]+Branch[^\S\r\n]*/[^\S\r\n]*Commit\*\*:|Git[^\S\r\n]+Branch[^\S\r\n]*/[^\S\r\n]*Commit:)[^\S\r\n]*[^\s@\r\n][^\r\n@]*@[^\S\r\n]*`?([0-9a-fA-F]{7,64})`?(?:\b|`)"
)

_TASKS_PENDING_RE = _LazyRegex(r"(?m)^[^\S\r\n]*-[^\S\r\n]*\[\s\][^\S\r\n]+\S")

_TASKS_NEXT_ROW_RE = _LazyRegex(r"(?im)^[^\S\r\n]*\|[^\r\n]*\[\s\][^\S\r\n]*NEXT\b")

_TASKS_PARTIAL_RE = _LazyRegex(r"(?m)^\s*(?:-\s*\[~\]|\|[^\n]*\[~\])")

_TASKS_BLOCKED_RE = _LazyRegex(r"(?m)^\s*(?:-\s*\[!\]|\|[^\n]*\[!\])")

_TASKS_UNCHECKED_LINE_RE = _LazyRegex(
    r"(?m)^[^\S\r\n]*(?:[-*][^\S\r\n]*\[(?: |~|!)\][^\S\r\n]+([^\r\n]+)|\|[^\r\n]*\[(?: |~|!)\][^\r\n]*)"
)

_PROMPT_LIST_ITEM_RE = _LazyRegex(r"(?m)^[^\S\r\n]*(?:[-*•]|\d+[.)])[^\S\r\n]+\S")

_CTX_HANDOFF_TIER1_KEY = "__ctx_handoff_tier1__"
_CTX_HANDOFF_TIER2_KEY = "__ctx_handoff_tier2__"
_CTX_FRESH_WINDOW_BASELINE = 45_000
_CTX_DEFAULT_STEP_BURN = 12_000
_CTX_MIN_STEP_BURN = 6_000
_CTX_MAX_STEP_BURN = 40_000

_HEAVY_WORKFLOW_SLASH_RE = _LazyRegex(
    rf"{_SLASH_PRE}[/\$](?:"
    r"audit|audit-upstream|rustify|rust-harden|renew|marathon|unlazy|deep-grill|"
    r"refactoring|sweetspot|optimize|game-engineering|media-studio|database-migrations|"
    r"rea|harness|verify|gate|run-gate"
    rf"){_SLASH_POST}",
    re.IGNORECASE,
)

_HEAVY_WORKFLOW_PROSE_RE = _LazyRegex(
    rf"{_PATH_WORD_PRE}(?:"
    r"tier[- ]?3|multi[- ]?file|architectur(?:e|al)|migrat(?:e|ion|ing)|redesign|overhaul|"
    r"refactor(?:ing)?|security\s+audit|full\s+audit|codebase\s+audit|subagent|swarm|fan[- ]?out|"
    r"end[- ]to[- ]end|full\s+suite|all\s+tests|whole\s+(?:repo|codebase|project)|"
    r"across\s+(?:all|multiple|\d+)\s+(?:files?|modules?|services?|packages?)|"
    r"window\s+\d+/\d+|campaign|rewrite\s+(?:the\s+|this\s+|all\s+)?(?:module|service|system|engine|layer)|"
    r"mimari\w*|denetim\w*|yeniden\s+yapılandır\w*|refactor\s+et\w*|migrasyon\w*|göç\w*|"
    r"çoklu\s+dosya\w*|tüm\s+(?:test\w*|dosya\w*|proje\w*|modül\w*)|sıfırdan|maraton|pencere\s+\d+|"
    r"alt\s+ajan\w*|tam\s+doğrulama"
    rf"){_PATH_WORD_POST}",
    re.IGNORECASE,
)

_TRIVIAL_MICRO_EDIT_RE = _LazyRegex(
    rf"{_PATH_WORD_PRE}(?:"
    r"typo|spelling|whitespace|one[- ]line|single[- ]line|"
    r"fix\s+(?:a\s+|this\s+|the\s+)?(?:typo|spelling|comment|whitespace|formatting|indent\w*|label)|"
    r"rename\s+(?:this\s+|the\s+)?(?:variable|symbol|param\w*|field|label)|"
    r"update\s+(?:this\s+|the\s+)?(?:comment|docstring|copy|label|version\s+number)|"
    r"git\s+(?:status|log|diff)|"
    r"yazım\s+hatas\w*|imla|tek\s+satır\w*|küçük\s+düzeltme\w*|ufak\s+düzeltme\w*|"
    r"sadece\s+(?:şu|bu)\s+(?:satır\w*|yorum\w*|yazım\w*)"
    rf"){_PATH_WORD_POST}",
    re.IGNORECASE,
)


def _load_model_compaction_ceilings() -> Tuple[Dict[str, int], Dict[str, str]]:
    """Loads `model_compaction_ceilings` and `known_placeholder_models` from shipped seed, state, and fallback."""
    try:
        from guard.upstream import (
            DEFAULT_KNOWN_PLACEHOLDER_MODELS,
            DEFAULT_MODEL_COMPACTION_CEILINGS,
            _clean_compaction_ceilings,
            _clean_known_placeholder_map,
            reconcile_state_with_seed,
        )
    except ImportError as exc:  # pragma: no cover - defensive fallback
        sys.stderr.write(f"[Harness PreInvocation] Failed to import guard.upstream defaults: {exc}\n")
        return {"default": 200_000}, {}

    ceilings: Dict[str, int] = dict(DEFAULT_MODEL_COMPACTION_CEILINGS)
    placeholders: Dict[str, str] = dict(DEFAULT_KNOWN_PLACEHOLDER_MODELS)

    def _merge_ceiling_record(src_label: str, src_path: Path, rec: Dict[str, Any]) -> None:
        raw_mcc = rec.get("model_compaction_ceilings")
        if raw_mcc is not None and not isinstance(raw_mcc, dict):
            sys.stderr.write(f"[Harness PreInvocation] {src_label} `{src_path}` has non-object model_compaction_ceilings.\n")
        else:
            cleaned_mcc = _clean_compaction_ceilings(raw_mcc)
            if isinstance(raw_mcc, dict) and len(cleaned_mcc) < len(raw_mcc):
                sys.stderr.write(f"[Harness PreInvocation] {src_label} `{src_path}` dropped invalid model_compaction_ceilings entries.\n")
            ceilings.update(cleaned_mcc)
        placeholders.update(_clean_known_placeholder_map(rec.get("known_placeholder_models")))

    loaded_seed: Optional[Dict[str, Any]] = None
    for cand in _upstream_seed_candidates():
        try:
            if not cand.is_file():
                continue
            data = read_json_strict(cand)
        except (CorruptStateError, OSError) as exc:
            sys.stderr.write(f"[Harness PreInvocation] Skipping unreadable/corrupt seed `{cand}`: {exc}\n")
            continue
        if isinstance(data, dict) and data:
            loaded_seed = data
            _merge_ceiling_record("Seed", cand, data)
            break

    st_path = state_dir() / "upstream_state.json"
    try:
        st_exists = st_path.is_file()
    except OSError as exc:
        sys.stderr.write(f"[Harness PreInvocation] Cannot stat `{st_path}`: {exc}\n")
        st_exists = False
    if st_exists:
        try:
            st_data = read_json_strict(st_path)
        except (CorruptStateError, OSError) as exc:
            sys.stderr.write(f"[Harness PreInvocation] Ignoring unreadable/corrupt `{st_path}`: {exc}\n")
            st_data = None
        if isinstance(st_data, dict):
            merge_state = True
            if loaded_seed is not None:
                try:
                    st_data, _ = reconcile_state_with_seed(dict(st_data), loaded_seed)
                except Exception as exc:
                    sys.stderr.write(f"[Harness PreInvocation] Failed to reconcile `{st_path}` with seed: {exc}\n")
                    merge_state = False
            if merge_state:
                _merge_ceiling_record("State", st_path, st_data)
    return ceilings, placeholders


def _effective_compaction_ceiling(
    model_name: str,
    ceilings: Dict[str, int],
    placeholders: Dict[str, str],
) -> Tuple[int, str]:
    """Resolves a model label/slug/placeholder to its empirical compaction ceiling in tokens."""
    raw = str(model_name or "").strip()
    raw = re.sub(r"^(?:[a-z0-9._-]+/)+", "", raw, flags=re.IGNORECASE)
    ph_match = re.match(r"^(MODEL_PLACEHOLDER_[A-Z0-9_]+)\b", raw, re.IGNORECASE)
    if ph_match:
        ph_key = ph_match.group(1).upper()
        for pk, mapped in placeholders.items():
            if pk.upper() == ph_key:
                raw = mapped
                break
    slug = re.sub(r"[^a-z0-9.]+", "-", raw.lower()).strip("-")
    if slug and slug in ceilings:
        return max(32_000, int(ceilings[slug])), slug
    best_prefix = ""
    best_val: Optional[int] = None
    if slug:
        for k, v in ceilings.items():
            if k == "default":
                continue
            if slug.startswith((f"{k}-", f"{k}.")):
                if len(k) > len(best_prefix):
                    best_prefix = k
                    best_val = v
        if best_val is None:
            norm_family = re.sub(r"^(claude)-[0-9]+(?:\.[0-9]+)?-(opus|sonnet|haiku)\b", r"\1-\2", slug)
            if norm_family != slug:
                if norm_family in ceilings:
                    best_val = ceilings[norm_family]
                else:
                    for k, v in ceilings.items():
                        if k != "default" and norm_family.startswith((f"{k}-", f"{k}.")):
                            if len(k) > len(best_prefix):
                                best_prefix = k
                                best_val = v
    if best_val is not None:
        return max(32_000, int(best_val)), slug
    return max(32_000, int(ceilings.get("default", 200_000))), (slug or "default")


def _extract_planner_token_total(entry: Dict[str, Any]) -> int:
    """Extracts active prompt tokens (`input_tokens + cache_read_tokens + cache_creation_input_tokens`) from a `PLANNER_RESPONSE`."""
    max_sane = 100_000_000
    usage = entry.get("usage") if isinstance(entry.get("usage"), dict) else {}

    raw_in = entry.get("input_tokens")
    is_inclusive_prompt = False
    if raw_in is None:
        raw_in = entry.get("inputTokens")
    if raw_in is None and usage:
        for k in ("input_tokens", "inputTokens"):
            if usage.get(k) is not None:
                raw_in = usage.get(k)
                break
        if raw_in is None:
            for k in ("prompt_tokens", "promptTokens"):
                if usage.get(k) is not None:
                    raw_in = usage.get(k)
                    is_inclusive_prompt = True
                    break

    raw_cache = entry.get("cache_read_tokens")
    if raw_cache is None:
        raw_cache = entry.get("cacheReadTokens")
    if raw_cache is None and usage:
        for k in ("cache_read_tokens", "cache_read_input_tokens", "cacheReadTokens"):
            if usage.get(k) is not None:
                raw_cache = usage.get(k)
                break

    raw_cache_create = entry.get("cache_creation_input_tokens")
    if raw_cache_create is None:
        raw_cache_create = entry.get("cacheCreationTokens")
    if raw_cache_create is None and usage:
        for k in ("cache_creation_input_tokens", "cacheCreationTokens"):
            if usage.get(k) is not None:
                raw_cache_create = usage.get(k)
                break

    if raw_in is None and raw_cache is None and raw_cache_create is None:
        return 0

    in_tok = _safe_int(raw_in, default=-1) if raw_in is not None else 0
    if in_tok < 0:
        in_tok = 0
    cache_tok = _safe_int(raw_cache, default=0) if raw_cache is not None else 0
    if cache_tok < 0:
        cache_tok = 0
    cache_create_tok = _safe_int(raw_cache_create, default=0) if raw_cache_create is not None else 0
    if cache_create_tok < 0:
        cache_create_tok = 0

    if in_tok > max_sane or cache_tok > max_sane or cache_create_tok > max_sane:
        return 0
    if is_inclusive_prompt:
        total = max(in_tok, cache_tok) + cache_create_tok
    else:
        total = in_tok + cache_tok + cache_create_tok
    return total if 0 < total <= max_sane else 0


def _inspect_transcript_context_metrics(payload: Dict[str, Any]) -> Optional[Tuple[int, int, str]]:
    """
    Tail-reads `transcriptPath` up to the latest `CHECKPOINT` compaction boundary and returns
    `(active_tokens, clamped_burn_rate_per_step, active_model)` from post-checkpoint `PLANNER_RESPONSE` steps.
    """
    tx_path = _resolve_transcript_path(payload)
    if tx_path is None:
        return None

    def _scan(scan_bytes: int) -> Tuple[List[Tuple[int, str]], bool]:
        found: List[Tuple[int, str]] = []
        hit_checkpoint = False
        scanned = 0
        for entry in _iter_jsonl_tail_entries(tx_path, max_scan_bytes=scan_bytes, raise_on_error=True):
            scanned += 1
            step_type = str(entry.get("type", "")).upper()
            if step_type == "CHECKPOINT":
                hit_checkpoint = True
                break
            if step_type == "PLANNER_RESPONSE":
                status = str(entry.get("status", "")).upper()
                if status in ("ERROR", "FAILED", "CANCELLED"):
                    continue
                total = _extract_planner_token_total(entry)
                if total > 0:
                    raw_m = entry.get("model") or entry.get("modelName") or entry.get("model_name") or ""
                    model_val = raw_m.strip() if isinstance(raw_m, str) else ""
                    found.append((total, model_val))
                    if len(found) >= 8:
                        break
            if scanned >= 400:
                break
        return found, hit_checkpoint

    try:
        samples, saw_checkpoint = _scan(512 * 1024)
        if not samples and not saw_checkpoint:
            samples, _ = _scan(2 * 1024 * 1024)
    except OSError as exc:
        sys.stderr.write(f"[Harness PreInvocation] Failed to tail-read `{tx_path}` for context metrics: {exc}\n")
        return None

    if not samples:
        return None
    samples.reverse()
    active_tokens = samples[-1][0]

    active_model = ""
    for pk in ("modelName", "model_name", "model"):
        pv = payload.get(pk)
        if isinstance(pv, str) and pv.strip() and pv.strip().lower() != "auto":
            active_model = pv.strip()
            break
    if not active_model:
        for _tok, m_val in reversed(samples):
            if m_val and m_val.lower() != "auto":
                active_model = m_val
                break

    if len(samples) >= 2:
        pos_deltas = sorted(
            delta
            for i in range(1, len(samples))
            for delta in (samples[i][0] - samples[i - 1][0],)
            if 0 < delta <= 100_000
        )
        if pos_deltas:
            mid = len(pos_deltas) // 2
            burn_rate = (
                pos_deltas[mid]
                if (len(pos_deltas) % 2 == 1)
                else (pos_deltas[mid - 1] + pos_deltas[mid]) // 2
            )
        else:
            burn_rate = _CTX_MIN_STEP_BURN
    else:
        burn_rate = _CTX_DEFAULT_STEP_BURN
    clamped_burn = max(_CTX_MIN_STEP_BURN, min(burn_rate, _CTX_MAX_STEP_BURN))
    return active_tokens, clamped_burn, active_model


def _inspect_workspace_remaining_tasks(workspaces: Sequence[Path]) -> Tuple[int, bool]:
    """Counts unchecked checklist/table items in the primary workspace's `tasks.md` and detects 1 small remaining item."""
    for ws in workspaces:
        try:
            if not ws.is_dir():
                continue
        except OSError as exc:
            sys.stderr.write(f"[Harness PreInvocation] Cannot inspect workspace `{ws}`: {exc}\n")
            continue
        ok, raw_tasks = _read_bounded_markdown_checked(ws / "tasks.md")
        if not ok:
            sys.stderr.write(f"[Harness PreInvocation] Failed to read `{ws / 'tasks.md'}` for context sizing.\n")
            continue
        if not raw_tasks:
            continue
        ttext = _FENCE_RE.sub(" ", _normalize_markdown_newlines(raw_tasks))
        u_items = [(m.group(1) or m.group(0)).strip() for m in _TASKS_UNCHECKED_LINE_RE.finditer(ttext)]
        rem = len(u_items)
        if rem == 1:
            sole = u_items[0]
            is_small = (
                len(sole) < 220
                and not _HEAVY_WORKFLOW_SLASH_RE.search(sole)
                and not _HEAVY_WORKFLOW_PROSE_RE.search(sole)
            )
            return 1, is_small
        return rem, False
    return 0, False


def _estimate_next_job_cost(
    scan_text: str,
    explicit_text: str,
    raw_prompt: str,
    burn_rate: int,
    remaining_tasks: int,
    is_single_small_item: bool,
) -> Tuple[int, bool]:
    """
    Dynamically estimates incoming job token demand from prompt weight, `tasks.md`, and clamped `burn_rate`.
    Returns `(estimated_tokens, is_heavy_job)` where `estimated_tokens == 0` suppresses the advisory.
    """
    has_heavy_slash = bool(_HEAVY_WORKFLOW_SLASH_RE.search(explicit_text))
    prose_hits = min(
        3,
        len({m.group(0).lower() for m in _HEAVY_WORKFLOW_PROSE_RE.finditer(scan_text)}),
    )
    list_bonus = 1 if len(_PROMPT_LIST_ITEM_RE.findall(scan_text)) >= 3 else 0
    len_bonus = 1 if len(scan_text) >= 450 else 0
    heavy_signals = (2 if has_heavy_slash else 0) + prose_hits + list_bonus + len_bonus

    if heavy_signals == 0:
        if _TRIVIAL_MICRO_EDIT_RE.search(scan_text):
            return 0, False
        if is_single_small_item:
            return 0, False
        if len(scan_text) < 120 and remaining_tasks <= 1:
            return 0, False

    is_heavy_job = (heavy_signals >= 1) or (remaining_tasks >= 4)
    task_steps = min(remaining_tasks, 5) if remaining_tasks >= 2 else 0
    if is_heavy_job:
        estimated_steps = min(20, 10 + min(heavy_signals, 4) * 2 + task_steps)
    else:
        estimated_steps = 5 + task_steps
    prompt_tokens = len(raw_prompt) // 4
    return (estimated_steps * burn_rate) + prompt_tokens, is_heavy_job


def _evaluate_predictive_handoff_advisory(
    payload: Dict[str, Any],
    workspaces: Sequence[Path],
    scan_text: str,
    explicit_text: str,
    raw_prompt: str,
    seen_turns: Dict[str, int],
    active_turn: int,
) -> Optional[Tuple[int, str, str]]:
    """
    Evaluates dynamic post-`CHECKPOINT` headroom vs. estimated next-job token demand without any
    fixed `%` threshold. Returns `(tier, state_key, message)` where Tier 1 emits `0`-token
    `metadata.user_markdown` and Tier 2 emits a one-time latched terse `systemMessage`.
    """
    if _CTX_HANDOFF_TIER2_KEY in seen_turns:
        return None
    metrics = _inspect_transcript_context_metrics(payload)
    if metrics is None:
        return None
    active_tokens, effective_burn, active_model = metrics
    remaining_tasks, is_single_small_item = _inspect_workspace_remaining_tasks(workspaces)
    estimated_cost, is_heavy_job = _estimate_next_job_cost(
        scan_text,
        explicit_text,
        raw_prompt,
        effective_burn,
        remaining_tasks,
        is_single_small_item,
    )
    if estimated_cost <= 0:
        return None

    safety_buffer = max(12_000, min(36_000, 2 * effective_burn))
    if (active_tokens - _CTX_FRESH_WINDOW_BASELINE) <= safety_buffer:
        return None

    ceilings, placeholders = _load_model_compaction_ceilings()
    ceiling, model_slug = _effective_compaction_ceiling(active_model, ceilings, placeholders)
    remaining_headroom = max(0, ceiling - active_tokens)
    if remaining_headroom >= estimated_cost:
        return None

    active_k = (active_tokens + 500) // 1000
    ceil_k = (ceiling + 500) // 1000
    rem_k = (remaining_headroom + 500) // 1000
    est_k = (estimated_cost + 500) // 1000
    burn_k = max(1, (effective_burn + 500) // 1000)
    safe_model = model_slug[:32] or "model"

    critical_floor = (estimated_cost // 2) + safety_buffer
    if (is_heavy_job and remaining_headroom < critical_floor) or remaining_headroom < safety_buffer:
        tier2_msg = (
            f"[Harness Context Handoff] Active ~{active_k}K/{ceil_k}K (~{rem_k}K left vs ~{est_k}K est.). "
            "Before heavy edits, offer a 1-sentence choice: continue here or write a clean HANDOFF.md for a new window."
        )
        return (2, _CTX_HANDOFF_TIER2_KEY, tier2_msg)

    prev_t1 = seen_turns.get(_CTX_HANDOFF_TIER1_KEY)
    if prev_t1 is not None and (active_turn - prev_t1) < REHINT_TURN_GAP:
        return None
    tier1_md = (
        f"[Context Advisory] Active ~{active_k}K/{ceil_k}K ({safe_model}); est. next job ~{est_k}K "
        f"exceeds ~{rem_k}K headroom (burn ~{burn_k}K/step). Consider a clean HANDOFF.md window for heavy work."
    )
    return (1, _CTX_HANDOFF_TIER1_KEY, tier1_md)

def _acknowledge_interrupted_flight(workspace: Path, expected_seq: int, conv_id: str = "") -> None:
    """Marks the matching `"in_flight"` crash record as `"interrupted_notified"` without touching sibling records."""
    flight_file = _flight_recorder_file()
    if not flight_file.is_file():
        return
    try:
        ws_key = str(workspace.resolve())
        with file_lock(flight_file, timeout=HOOK_LOCK_TIMEOUT):
            ledger_ok, ledger = _read_ledger_checked(flight_file, quarantine=False)
            if not ledger_ok:
                return
            convs = _extract_ws_flight_conversations(ledger.get(ws_key))
            if not convs:
                return
            target_cid = ""
            if conv_id and isinstance(convs.get(conv_id), dict):
                cand = convs[conv_id]
                if cand.get("status") == "in_flight" and _safe_int(cand.get("seq"), default=0) == expected_seq:
                    target_cid = conv_id
            if not target_cid:
                for cid, rec in reversed(list(convs.items())):
                    if rec.get("status") == "in_flight" and _safe_int(rec.get("seq"), default=0) == expected_seq:
                        target_cid = cid
                        break
            if not target_cid:
                return
            updated_entry = dict(convs[target_cid])
            updated_entry["status"] = "interrupted_notified"
            convs[target_cid] = updated_entry
            ledger[ws_key] = _rebuild_ws_flight_entry(ws_key, convs, primary_conv=target_cid)
            atomic_write_json(flight_file, ledger)
    except (OSError, RuntimeError, TimeoutError) as exc:
        sys.stderr.write(
            f"[Harness Flight Recorder] Failed acknowledging interrupted flight ({type(exc).__name__}): {exc}\n"
        )

_QUESTION_ONLY_OPENER_RE = _LazyRegex(
    r"^\s*(?:"
    r"what|why|how|where|when|which|who|explain|describe|summarize|show\s+me|tell\s+me|"
    r"list|compare|can\s+you\s+explain|could\s+you\s+explain|is\s+there|are\s+there|does\s+\w+|do\s+we|"
    r"neden|nasıl|nasil|nerede|hangi|kim|ne\s+işe|ne\s+ise|nedir|açıkla|acikla|"
    r"özetle|ozetle|anlat|düz\s+anlat|duz\s+anlat|göster|goster|listele|karşılaştır|karsilastir"
    r")\b",
    re.IGNORECASE,
)

_QUESTION_ONLY_TR_CLITIC_RE = _LazyRegex(
    r"\b(?:mı|mi|mu|mü|mısın|misin|musun|müsün|mıdır|midir|mudur|müdür|"
    r"nedir|ne\s+işe\s+yarar|ne\s+ise\s+yarar|nasıl\s+çalışır|nasil\s+calisir|"
    r"düz\s+anlat|duz\s+anlat|anlat(?:ır\s+mısın|ir\s+misin)?|"
    r"açıkla(?:r\s+mısın)?|acikla(?:r\s+misin)?|özetle(?:r\s+misin)?|ozetle(?:r\s+misin)?)"
    r"\s*[.?]?\s*$",
    re.IGNORECASE,
)

_QUESTION_ONLY_ACTION_VERB_RE = _LazyRegex(
    r"(?:"
    r"\b(?:implement|build|create|write|edit|modify|update|fix|refactor|migrate|delete|remove|add|"
    r"rename|install|deploy|upgrade|reset|start|continue|proceed|resume|apply|run|execute|commit|"
    r"push|patch|harden|optimize|port|convert|scaffold|rewrite|replace|clean\s+up|wire)\b|"
    r"\b(?:uygula|ekle|sil|kur|devam|yeniden\s+düzenle|yeniden\s+duzenle|optimize\s+et)\b|"
    r"\b(?:yaz|düzelt|duzelt|güncelle|guncelle|değiştir|degistir|kaldır|kaldir|oluştur|olustur|"
    r"taşı|tasi|çevir|cevir|başla|basla|hızlandır|hizlandir|temizle|uyarlayalım|yapalım|yapalim)"
    r"(?:ır|ir|ur|ür|ar|er|alım|elim|sana|sene|in|ın|un|ün|iniz|ınız|mısın|misin|musun|müsün)?\b"
    r")",
    re.IGNORECASE,
)

_READONLY_SLASH_RE = _LazyRegex(r"^\s*/(?:audit|retro|grill-me)\b", re.IGNORECASE)

_PASTED_BLOCKQUOTE_LINE_RE = _LazyRegex(r"^\s*>")
_PASTED_DIFF_LINE_RE = _LazyRegex(r"^(?:diff --git |index [0-9a-f]{6,}\.\.|--- [ab]/|\+\+\+ [ab]/|@@ -\d+)")
_PASTED_TABLE_LINE_RE = _LazyRegex(r"^\s*\|.+\|\s*$")
_PASTED_AUDIT_FINDING_LINE_RE = _LazyRegex(
    r"^\s*(?:[-*•]\s+)?(?:\*\*)?\[?(?:CRITICAL|HIGH|MEDIUM|LOW|INFO|PASS|FAIL|WARN(?:ING)?|"
    r"CONFIRMED|REFUTED|FINDING\s*#?\d+|F-\d+|P\d+|H-\d+)\]?(?:\*\*)?[:\s|]",
    re.IGNORECASE,
)
_PASTED_REPORT_BOUNDARY_RE = _LazyRegex(
    r"^\s*(?:---+\s*$|#{1,4}\s+(?:Findings?|Audit(?:\s+Report)?|Review(?:\s+Summary)?|Defects?|"
    r"Issues?|Bulgular|Denetim(?:\s+Raporu)?|İnceleme(?:\s+Raporu)?|Rapor)\b)",
    re.IGNORECASE,
)
_PASTED_REPORT_SIGNAL_RE = _LazyRegex(
    r"(?:\b(?:CRITICAL|HIGH|MEDIUM|Severity|Verdict|CONFIRMED|REFUTED|Bulgu|Önem)\b|"
    r"\b[A-Za-z0-9_.-]+\.[A-Za-z]{1,5}:\d+\b|^\s*\|.+\|\s*$)",
    re.IGNORECASE | re.MULTILINE,
)

_READONLY_HINT_ALLOWLIST_SKILLS = frozenset({"diagnosing-bugs", "porter"})
_READONLY_HINT_ALLOWLIST_ROUTES = frozenset({
    "route:builtin:antigravity-guide",
    "route:builtin:agy-customizations",
    "route:subagent:research",
})
_SHORT_ACTION_INTENT_RE = _LazyRegex(
    rf"{_PATH_WORD_PRE}(?:"
    r"(?:migration|migrasyon|test|doküman|dokuman)\s+(?:yaz\w*|ekle\w*|oluştur\w*|olustur\w*)|"
    r"refactor\s+et\w*|alter\s+table"
    rf"){_PATH_WORD_POST}",
    re.IGNORECASE,
)


def _strip_pasted_review_and_quote_blocks(text: str) -> str:
    """Strips quoted lines, unified diffs, markdown tables, and pasted audit/review report blocks before hint matching."""
    if not text:
        return ""
    lines = text.splitlines()
    if len(lines) >= 4:
        for idx, line in enumerate(lines):
            if idx == 0:
                continue
            if _PASTED_REPORT_BOUNDARY_RE.match(line):
                tail = "\n".join(lines[idx + 1 :])
                if _PASTED_REPORT_SIGNAL_RE.search(tail):
                    lines = lines[:idx]
                    break
    kept: List[str] = []
    for line in lines:
        s = line.lstrip()
        if s:
            c0 = s[0]
            if c0 == ">" and _PASTED_BLOCKQUOTE_LINE_RE.match(line):
                continue
            if line[0] in "di-+@" and _PASTED_DIFF_LINE_RE.match(line):
                continue
            if c0 == "|" and _PASTED_TABLE_LINE_RE.match(line):
                continue
            if (c0 in "-*•[" or c0.lower() in "chmlipfwrı" or c0 == "İ") and _PASTED_AUDIT_FINDING_LINE_RE.match(line):
                continue
        kept.append(line)
    return "\n".join(kept).strip()


def _read_bounded_json_nofollow(
    path: Path,
    label: str,
    max_bytes: int = 2 * 1024 * 1024,
    *,
    warn: bool = True,
) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Reads a bounded regular JSON object file with O_NOFOLLOW/O_NONBLOCK, warning and failing safe on error."""
    def _warn(reason: str) -> None:
        if warn:
            sys.stderr.write(f"[Harness PreInvocation] Ignoring {reason} {label} `{path}`; failing safe enabled.\n")

    try:
        path_str = os.fspath(path)
        if "\x00" in path_str:
            _warn("invalid NUL path")
            return "invalid", None
        if path.is_symlink():
            _warn("symlink")
            return "invalid", None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path_str, flags)
    except (FileNotFoundError, NotADirectoryError):
        return "missing", None
    except OSError as exc:
        _warn(f"unreadable/symlink ({exc})")
        return "invalid", None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            _warn("non-regular")
            return "invalid", None
        if st.st_size > max_bytes:
            os.close(fd)
            _warn(f"oversized ({st.st_size} > {max_bytes} bytes)")
            return "invalid", None
        fh = os.fdopen(fd, "rb")
    except OSError as exc:
        try:
            os.close(fd)
        except OSError:
            pass
        _warn(f"unreadable ({exc})")
        return "invalid", None
    try:
        with fh:
            raw = fh.read(max_bytes + 1)
    except OSError as exc:
        _warn(f"unreadable ({exc})")
        return "invalid", None
    if len(raw) > max_bytes:
        _warn(f"oversized (>{max_bytes} bytes)")
        return "invalid", None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        _warn(f"corrupt/deep JSON ({exc})")
        return "invalid", None
    if not isinstance(parsed, dict):
        _warn("non-object JSON")
        return "invalid", None
    return "ok", parsed


def _is_harness_plugin_active(
    pack_name: str,
    cfg_dir: Optional[Path] = None,
    workspaces: Sequence[Path] = (),
    *,
    _turn_cache: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Determines whether a harness-owned plugin pack is active for PreInvocation skill/MCP routing.

    Live toggle precedence (ADR-0016 D9):
      1. `cfg_dir/plugins/<pack>` present: `config.json["plugins"][<pack>]["enabled"]` (bool) >
         `plugin.json["disabled"] is True` > enabled.
      2. `cfg_dir/plugins/<pack>` absent & flat `cfg_dir/skills/<slug>/SKILL.md` present:
         active (`True`, ignoring stale `config.json["plugins"]` toggles after `--flat-skills` revert
         and ignoring workspace `.agents/plugins/<pack>` disable flags).
      3. Workspace `<ws>/.agents/plugins/<pack>` present: `config.json["plugins"][<pack>]["enabled"]`
         > `plugin.json["disabled"] is True` > enabled.
      4. Absent everywhere: disabled if `cfg_enabled is False` or an explicit hybrid-install signal exists
         for `cfg_dir`; otherwise enabled (flat/repo/isolated test mode).
    """
    pack = (pack_name or "").strip().lower()
    if pack not in _HARNESS_PLUGIN_NAMES:
        return False
    cache = _turn_cache if _turn_cache is not None else {}
    cfg = Path(cfg_dir) if cfg_dir is not None else configured_config_dir()
    cfg_key = os.path.abspath(cfg)
    pack_cache = cache.setdefault("pack_active", {})
    cache_key = (cfg_key, pack)
    if cache_key in pack_cache:
        return bool(pack_cache[cache_key])

    cfg_json_cache = cache.setdefault("config_json", {})
    if cfg_key not in cfg_json_cache:
        cfg_json_cache[cfg_key] = _read_bounded_json_nofollow(cfg / "config.json", "config.json")
    cfg_status, cfg_data = cfg_json_cache[cfg_key]

    cfg_enabled: Optional[bool] = None
    if cfg_status == "ok" and isinstance(cfg_data, dict):
        plugins_map = cfg_data.get("plugins")
        if plugins_map is not None and not isinstance(plugins_map, dict):
            warned_cfg = cache.setdefault("warned_cfg_plugins", set())
            if cfg_key not in warned_cfg:
                warned_cfg.add(cfg_key)
                sys.stderr.write(
                    f"[Harness PreInvocation] Ignoring non-object `plugins` in `{cfg / 'config.json'}`; "
                    "failing safe enabled.\n"
                )
        elif isinstance(plugins_map, dict):
            pack_entry = plugins_map.get(pack)
            if isinstance(pack_entry, dict) and isinstance(pack_entry.get("enabled"), bool):
                cfg_enabled = pack_entry["enabled"]
            elif pack_entry is not None and not isinstance(pack_entry, dict):
                sys.stderr.write(
                    f"[Harness PreInvocation] Ignoring non-object `plugins.{pack}` in `{cfg / 'config.json'}`; "
                    "failing safe enabled.\n"
                )

    plugins_root = cfg / "plugins"
    pack_dir = plugins_root / pack
    try:
        if plugins_root.is_symlink() or pack_dir.is_symlink():
            sys.stderr.write(
                f"[Harness PreInvocation] Ignoring symlinked plugin path `{pack_dir}`; failing safe enabled.\n"
            )
            pack_cache[cache_key] = True
            return True
    except OSError as exc:
        sys.stderr.write(
            f"[Harness PreInvocation] Cannot inspect plugin path `{pack_dir}` ({exc}); failing safe enabled.\n"
        )
        pack_cache[cache_key] = True
        return True

    global_pack_dir: Optional[Path] = None
    try:
        if pack_dir.is_dir():
            global_pack_dir = pack_dir
    except OSError:
        global_pack_dir = None

    if global_pack_dir is not None:
        if cfg_enabled is False:
            pack_cache[cache_key] = False
            return False
        if cfg_enabled is True:
            pack_cache[cache_key] = True
            return True
        pj_status, pj_data = _read_bounded_json_nofollow(global_pack_dir / "plugin.json", f"plugins/{pack}/plugin.json")
        if pj_status == "ok" and isinstance(pj_data, dict) and pj_data.get("disabled") is True:
            pack_cache[cache_key] = False
            return False
        pack_cache[cache_key] = True
        return True

    # Global pack dir is absent: if flat skill copies exist under `cfg/skills/`, honor Flat Layout directly
    # (prevents stale `config.json["plugins"]` toggles or workspace plugin manifests from silencing flat skills).
    for slug, owner in _PLUGIN_SKILL_TO_PACK.items():
        if owner == pack:
            try:
                if (cfg / "skills" / slug / "SKILL.md").is_file():
                    pack_cache[cache_key] = True
                    return True
            except OSError:
                continue

    ws_pack_dir: Optional[Path] = None
    for ws in workspaces:
        try:
            ws_proot = ws / ".agents" / "plugins"
            ws_pdir = ws_proot / pack
            if not ws_proot.is_symlink() and not ws_pdir.is_symlink() and ws_pdir.is_dir():
                ws_pack_dir = ws_pdir
                break
        except (OSError, ValueError):
            continue

    if ws_pack_dir is not None:
        if cfg_enabled is False:
            pack_cache[cache_key] = False
            return False
        if cfg_enabled is True:
            pack_cache[cache_key] = True
            return True
        pj_status, pj_data = _read_bounded_json_nofollow(ws_pack_dir / "plugin.json", f"plugins/{pack}/plugin.json")
        if pj_status == "ok" and isinstance(pj_data, dict) and pj_data.get("disabled") is True:
            pack_cache[cache_key] = False
            return False
        pack_cache[cache_key] = True
        return True

    if cfg_enabled is False:
        pack_cache[cache_key] = False
        return False

    # Suppress removed pack only when an explicit hybrid-install signal exists for `cfg`.
    hyb_cache = cache.setdefault("hybrid_signal", {})
    if cfg_key not in hyb_cache:
        has_hybrid_signal = False
        receipt_targets_cfg_flat = False
        try:
            cfg_res = cfg.resolve()
        except (OSError, RuntimeError):
            cfg_res = cfg
        rec_status, rec_data = _read_bounded_json_nofollow(
            state_dir() / "install_receipt.json", "install_receipt.json", warn=False
        )
        if rec_status == "ok" and isinstance(rec_data, dict):
            raw_tgt = rec_data.get("target")
            if isinstance(raw_tgt, str) and raw_tgt.strip():
                try:
                    tgt_res = Path(os.path.expanduser(raw_tgt.strip())).resolve()
                except (OSError, RuntimeError):
                    tgt_res = None
                if tgt_res == cfg_res:
                    rec_layout = str(rec_data.get("layout") or "").strip().lower()
                    rec_plugs = rec_data.get("installed_plugins")
                    has_rec_plugs = isinstance(rec_plugs, list) and any(
                        isinstance(x, str) and x in _HARNESS_PLUGIN_NAMES for x in rec_plugs
                    )
                    if rec_layout == "hybrid" or has_rec_plugs:
                        has_hybrid_signal = True
                    elif rec_layout == "flat":
                        receipt_targets_cfg_flat = True
        if not has_hybrid_signal:
            try:
                if plugins_root.is_dir() and not plugins_root.is_symlink():
                    for other_pack in _HARNESS_PLUGIN_NAMES:
                        other_dir = plugins_root / other_pack
                        if not other_dir.is_symlink() and other_dir.is_dir():
                            has_hybrid_signal = True
                            break
            except OSError:
                pass
        if (
            not has_hybrid_signal
            and not receipt_targets_cfg_flat
            and cfg_status == "ok"
            and isinstance(cfg_data, dict)
            and isinstance(cfg_data.get("plugins"), dict)
            and any(k in _HARNESS_PLUGIN_NAMES for k in cfg_data["plugins"])
        ):
            try:
                if (cfg / "skills").is_dir():
                    has_hybrid_signal = True
            except OSError:
                pass
        hyb_cache[cfg_key] = has_hybrid_signal

    result = not bool(hyb_cache[cfg_key])
    pack_cache[cache_key] = result
    return result


def _resolve_hint_skill_path(
    rel_path: str,
    workspaces: Sequence[Path],
    *,
    _turn_cache: Optional[Dict[str, Any]] = None,
) -> str:
    """Resolves a canonical skill/plugin relpath to an installed-layout-safe path for external workspaces."""
    if not rel_path.startswith(("skills/", "plugins/")):
        return rel_path
    cfg = configured_config_dir()
    default_cfg = Path.home() / ".gemini" / "config"
    is_default_cfg = cfg.expanduser() == default_cfg
    if rel_path.startswith("skills/"):
        parts = rel_path.split("/")
        pack = _PLUGIN_SKILL_TO_PACK.get(parts[1]) if len(parts) >= 2 else None
        if pack is not None and _is_harness_plugin_active(pack, cfg, workspaces, _turn_cache=_turn_cache):
            plugin_rel = f"plugins/{pack}/{rel_path}"
            try:
                plugins_root = cfg / "plugins"
                pack_dir = plugins_root / pack
                plugin_file = cfg / plugin_rel
                if (
                    not plugins_root.is_symlink()
                    and not pack_dir.is_symlink()
                    and not plugin_file.is_symlink()
                    and plugin_file.is_file()
                ):
                    return f"~/.gemini/config/{plugin_rel}" if is_default_cfg else str(plugin_file)
            except (OSError, ValueError):
                pass
            for ws in workspaces:
                try:
                    ws_plugin_file = ws / ".agents" / plugin_rel
                    if not ws_plugin_file.is_symlink() and ws_plugin_file.is_file():
                        return f".agents/{plugin_rel}"
                except (OSError, ValueError):
                    continue
    try:
        if (cfg / rel_path).is_file():
            if is_default_cfg:
                return f"~/.gemini/config/{rel_path}"
            return str(cfg / rel_path)
    except (OSError, ValueError):
        pass
    for ws in workspaces:
        try:
            if (ws / rel_path).is_file():
                return rel_path
        except (OSError, ValueError):
            continue
    return f"~/.gemini/config/{rel_path}"


def _is_pure_readonly_or_question_prompt(scan_text: str, explicit_text: str = "") -> bool:
    """True when the user prompt is purely a question or read-only inquiry with no edit/action verb."""
    text = (scan_text or "").strip()
    if not text:
        return False
    exp = (explicit_text or text).strip()
    if _EXPLICIT_CMD_TOKEN_RE.search(exp) and not _READONLY_SLASH_RE.match(exp):
        return False
    tail_stripped = re.sub(r"[*_`\"'»”\s)]+$", "", text)
    is_question_shaped = (
        tail_stripped.endswith("?")
        or bool(_QUESTION_ONLY_OPENER_RE.match(text))
        or bool(_QUESTION_ONLY_TR_CLITIC_RE.search(tail_stripped))
    )
    if not is_question_shaped:
        return False
    if _QUESTION_ONLY_ACTION_VERB_RE.search(text):
        return False
    return True


def _detect_workspace_recovery_hint(
    workspace: Optional[Path],
    conv_id: str,
    first_turn_in_conv: bool,
    *,
    is_mid_turn: bool = False,
    now: Optional[datetime] = None,
    is_question_only: bool = False,
) -> Tuple[bool, Optional[Tuple[str, str, Optional[int]]]]:
    """
    Inspects `state_dir() / "flight_recorder.json"`, `HANDOFF.md`, and `tasks.md` to detect:
      1. Same-conversation mid-turn interruptions (`status == "in_flight"` for `conv_id`,
         suppressed during active mid-turn tool continuations), or stale cross-conversation
         `"in_flight"` crashes whose `updated_at` exceeds `_STALE_IN_FLIGHT_SECONDS` (fresh
         sibling `"in_flight"` workers are ignored so concurrent swarms never collide),
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

    ref_now = now if isinstance(now, datetime) else datetime.now(timezone.utc)
    if ref_now.tzinfo is None:
        ref_now = ref_now.replace(tzinfo=timezone.utc)
    else:
        ref_now = ref_now.astimezone(timezone.utc)

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
                convs = _extract_ws_flight_conversations(ledger.get(ws_key))
                if convs:
                    self_entry = convs.get(conv_id) if conv_id else None
                    if (
                        isinstance(self_entry, dict)
                        and str(self_entry.get("status") or "") == "in_flight"
                        and not is_mid_turn
                    ):
                        flight_entry = dict(self_entry)
                        flight_alert_reason = "in_flight"
                        ack_seq = _safe_int(self_entry.get("seq"), default=0)
                    elif first_turn_in_conv:
                        other_items = [
                            (cid, rec) for cid, rec in reversed(list(convs.items())) if cid != conv_id
                        ]
                        for _cid, rec in other_items:
                            st = str(rec.get("status") or "")
                            if st in ("in_progress_blocked", "interrupted_notified"):
                                flight_entry = dict(rec)
                                flight_alert_reason = st
                                break
                        if not flight_alert_reason:
                            for _cid, rec in other_items:
                                if str(rec.get("status") or "") != "in_flight":
                                    continue
                                ts = _parse_iso_utc(str(rec.get("updated_at") or ""))
                                if ts is None or (ref_now - ts).total_seconds() >= _STALE_IN_FLIGHT_SECONDS:
                                    flight_entry = dict(rec)
                                    flight_alert_reason = "in_flight"
                                    ack_seq = _safe_int(rec.get("seq"), default=0)
                                    break
                        if not flight_alert_reason:
                            if isinstance(self_entry, dict):
                                flight_entry = dict(self_entry)
                            else:
                                for _cid, rec in other_items:
                                    if str(rec.get("status") or "") != "in_flight":
                                        flight_entry = dict(rec)
                                        break
        except (OSError, TimeoutError):
            inspect_ok = False

    handoff_in_progress = False
    handoff_complete = False
    handoff_campaign_id = ""
    tasks_campaign_id = ""
    campaign_id = ""
    handoff_commit = ""
    pending_count = 0
    partial_count = 0
    blocked_count = 0
    next_row_count = 0

    if first_turn_in_conv or flight_alert_reason:
        hoff_ok, raw_handoff = _read_bounded_markdown_checked(workspace / "HANDOFF.md")
        if not hoff_ok:
            inspect_ok = False
        if raw_handoff:
            htext = _FENCE_RE.sub(" ", _normalize_markdown_newlines(raw_handoff))
            if _HANDOFF_IN_PROGRESS_RE.search(htext):
                handoff_in_progress = True
            elif _HANDOFF_COMPLETE_RE.search(htext):
                handoff_complete = True
            m_cid = _CAMPAIGN_ID_RE.search(htext)
            if m_cid:
                handoff_campaign_id = m_cid.group(1)
            m_sha = _HANDOFF_COMMIT_RE.search(htext)
            if m_sha:
                handoff_commit = m_sha.group(1).lower()

        tasks_ok, raw_tasks = _read_bounded_markdown_checked(workspace / "tasks.md")
        if not tasks_ok:
            inspect_ok = False
        has_harness_handoff = bool(handoff_in_progress or handoff_complete or handoff_campaign_id)
        if raw_tasks:
            ttext = _FENCE_RE.sub(" ", _normalize_markdown_newlines(raw_tasks))
            m_tcid = _CAMPAIGN_ID_RE.search(ttext)
            if m_tcid:
                tasks_campaign_id = m_tcid.group(1)
            # 5.7: Treat tasks.md as a harness ledger only when backed by Campaign ID or a harness HANDOFF.md
            if tasks_campaign_id or has_harness_handoff:
                pending_count = len(_TASKS_PENDING_RE.findall(ttext))
                partial_count = len(_TASKS_PARTIAL_RE.findall(ttext))
                blocked_count = len(_TASKS_BLOCKED_RE.findall(ttext))
                next_row_count = len(_TASKS_NEXT_ROW_RE.findall(ttext))

    tasks_supersedes_complete_handoff = bool(
        handoff_complete and tasks_campaign_id and tasks_campaign_id != handoff_campaign_id
    )
    campaign_id = tasks_campaign_id if tasks_supersedes_complete_handoff else (handoff_campaign_id or tasks_campaign_id)

    has_unfinished_tasks = (pending_count + partial_count + blocked_count + next_row_count) > 0
    if not flight_alert_reason and not (first_turn_in_conv and (handoff_in_progress or has_unfinished_tasks)):
        return inspect_ok, None

    is_git_ws = _is_git_repo_workspace(workspace)
    head_advanced = False
    current_head = ""
    if handoff_commit and is_git_ws and not tasks_supersedes_complete_handoff:
        try:
            head_proc = subprocess.run(
                ["git", "-C", str(workspace), "rev-parse", "HEAD"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if head_proc.returncode == 0:
                cand_head = head_proc.stdout.strip().lower()
                if len(cand_head) >= 7 and not (
                    cand_head.startswith(handoff_commit) or handoff_commit.startswith(cand_head)
                ):
                    head_advanced = True
                    current_head = cand_head
        except (OSError, subprocess.SubprocessError):
            pass

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

    campaign_suffix = f" (Campaign ID: `{campaign_id}`)" if campaign_id else ""
    if handoff_in_progress:
        details.append(f"`HANDOFF.md` has `Status: [IN-PROGRESS]`{campaign_suffix}")
    elif handoff_complete and not tasks_supersedes_complete_handoff:
        details.append(f"`HANDOFF.md` has `Status: [COMPLETE]`{campaign_suffix}")
    elif campaign_id:
        details.append(f"active Campaign ID: `{campaign_id}`")

    if head_advanced:
        details.append(
            f"repository `HEAD` (`{current_head[:8]}`) has advanced past `HANDOFF.md` commit `{handoff_commit[:8]}`"
        )

    if has_unfinished_tasks:
        counts = []
        if pending_count:
            counts.append(f"{pending_count} `[ ]` pending")
        elif next_row_count:
            counts.append(f"{next_row_count} `[ ] NEXT` window(s)")
        if partial_count:
            counts.append(f"{partial_count} `[~]` partial")
        if blocked_count:
            counts.append(f"{blocked_count} `[!]` blocked")
        details.append(f"`tasks.md` has unfinished items ({', '.join(counts)})")

    is_stale_ledger = (handoff_complete and not tasks_supersedes_complete_handoff) or head_advanced
    fingerprint_raw = (
        f"{ws_key}|{flight_alert_reason}|{seq_val}|{updated_at}|{last_target}|"
        f"{handoff_in_progress}|{handoff_complete}|{tasks_supersedes_complete_handoff}|{campaign_id}|"
        f"{handoff_commit[:12]}|{current_head[:12] if head_advanced else ''}|"
        f"{pending_count}|{next_row_count}|{partial_count}|{blocked_count}|{int(is_question_only)}"
    )
    fp_hash = hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()[:12]
    dedup_key = f"recovery:{fp_hash}"
    inspect_target = (
        "`git status`/`git diff`, `tasks.md`, and `HANDOFF.md` (if present)"
        if is_git_ws
        else "`tasks.md`, `HANDOFF.md` (if present), and recent workspace files (non-git workspace)"
    )
    reset_guidance = ""
    if not is_question_only and (handoff_in_progress or handoff_complete or has_unfinished_tasks or campaign_id):
        campaign_ref = f"Campaign `{campaign_id}`" if campaign_id else "the recorded ledger"
        stale_prefix = "Stale ledger boundary: if " if is_stale_ledger else "If "
        reset_guidance = (
            f" {stale_prefix}the user's request starts a new unrelated task rather than continuing "
            f"{campaign_ref}, reset `tasks.md` and `HANDOFF.md` from `W1` (`AC-1`) under a fresh "
            "`Campaign ID` (`YYYY-MM-DD-<topic-slug>`) instead of appending `Wn+1`."
        )
    msg = (
        f"[Harness Recovery & Continuity Gate] Unfinished or interrupted workspace state detected: "
        f"{'; '.join(details)}. Before making new edits, inspect {inspect_target} "
        f"to reconcile any half-finished modifications and resume deterministically.{reset_guidance}"
    )
    return inspect_ok, (dedup_key, msg, ack_seq)

def _optional_plugin_skill_available(rel_path: str, workspaces: Sequence[Path]) -> bool:
    """Checks disk existence for optional `plugins/...` skill files so uninstalled plugins are not hinted."""
    if not rel_path.startswith("plugins/"):
        return True
    from guard.paths import share_dir_candidates

    cfg = configured_config_dir()
    roots: List[Path] = [
        cfg,
        config_dir(),
        _repo_root(),
        *share_dir_candidates(),
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

_GAME_PKG_RE = _LazyRegex(
    r'"(?:phaser|pixi\.js|kaboom|kaplay|excalibur|littlejs|rot-js|three|babylonjs|@babylonjs/core)"',
    re.IGNORECASE,
)

_RUST_BRIDGE_RE = _LazyRegex(
    r"\b(?:pyo3|cxx|cbindgen|bindgen|maturin|napi|napi-derive|napi-build|wasm-bindgen|magnus|jni)\b",
    re.IGNORECASE,
)

_CANVAS_RE = _LazyRegex(r"(?:<canvas\b|getContext\s*\(\s*[\"'](?:2d|webgl2?)[\"'])", re.IGNORECASE)

_RAF_RE = _LazyRegex(r"\brequestAnimationFrame\b")

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

_SPRITE_NAME_RE = _LazyRegex(r"(?:sprite|spritesheet|tileset|atlas|sfx|bgm|foley|frame_\d|anim_)", re.IGNORECASE)

_WEB_ICON_IGNORE_RE = _LazyRegex(r"^(?:favicon|logo|icon|apple-touch-icon)(?:[-._].*)?$", re.IGNORECASE)

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

_COMPILER_TRACE_MARKER_RE = _LazyRegex(
    r"(?:"
    r"\berror\s+TS\d+\b|\berror\[E\d+\]|Traceback\s*\(most\s+recent\s+call\s+last\):|"
    r"\bFAILED\s*\(|"
    r"\b(?:AssertionError|SyntaxError|TypeError|ImportError|ModuleNotFoundError|ReferenceError):|"
    r"\bfatal\s+error:|\b(?:COMPILATION|BUILD|TYPECHECK)\s+FAILED\b"
    r")"
)

_NONZERO_EXIT_CODE_RE = _LazyRegex(r"\bCommand\s+exited\s+with\s+code\s+([1-9]\d*)\b")

_TRACE_ERROR_MARKER_RE = _LazyRegex(
    rf"(?:{_COMPILER_TRACE_MARKER_RE.pattern}|{_NONZERO_EXIT_CODE_RE.pattern})"
)

_SHELL_EXEC_TOOL_NAMES = frozenset({"run_command", "bash", "execute_command", "shell"})
_BENIGN_SEARCH_VERBS = frozenset({"grep", "egrep", "fgrep", "rg", "diff", "cmp", "test", "["})
_BENIGN_STDERR_REDIR_RE = _LazyRegex(r"(?<!\w)(?:\d*>\s*&\d+|&>\s*/dev/null|\d*>\s*/dev/null)(?!\S)")


def _extract_cmd_from_args_obj(args_obj: Any) -> str:
    if isinstance(args_obj, str):
        s = args_obj.strip()
        if s.startswith("{"):
            try:
                args_obj = json.loads(s)
            except ValueError:
                return ""
        else:
            return ""
    if isinstance(args_obj, dict):
        for k in ("CommandLine", "command", "cmd", "command_line"):
            v = args_obj.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def _extract_entry_command_line(entry: Dict[str, Any]) -> str:
    for k in ("CommandLine", "command", "cmd"):
        v = entry.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for ak in ("args", "tool_args", "arguments", "input"):
        c = _extract_cmd_from_args_obj(entry.get(ak))
        if c:
            return c
    return ""


def _scrub_shell_quotes_and_substitutions(cmd_line: str) -> Optional[str]:
    """Scrubs quoted literals and escaped chars; returns None on command substitution or unclosed quotes."""
    out: List[str] = []
    n = len(cmd_line)
    i = 0
    mode = ""
    while i < n:
        ch = cmd_line[i]
        if not mode:
            if ch == "\\":
                if i + 1 >= n:
                    return None
                out.append("_")
                i += 2
                continue
            if ch == "`" or (ch == "$" and i + 1 < n and cmd_line[i + 1] == "("):
                return None
            if ch in ("'", '"'):
                mode = ch
                out.append("__Q__")
                i += 1
                continue
            out.append(ch)
            i += 1
        elif mode == "'":
            if ch == "'":
                mode = ""
            i += 1
        else:
            if ch == "\\":
                if i + 1 >= n:
                    return None
                i += 2
                continue
            if ch == "`" or (ch == "$" and i + 1 < n and cmd_line[i + 1] == "("):
                return None
            if ch == '"':
                mode = ""
            i += 1
    if mode:
        return None
    return "".join(out)


def _is_pure_search_or_diff_command(cmd_line: str) -> bool:
    """Returns True only when every simple command in `cmd_line` invokes grep/rg/diff/cmp/test/[."""
    if not cmd_line or not cmd_line.strip():
        return False
    scrubbed = _scrub_shell_quotes_and_substitutions(cmd_line)
    if scrubbed is None:
        return False
    scrubbed = _BENIGN_STDERR_REDIR_RE.sub(" ", scrubbed)
    segments = [seg.strip() for seg in re.split(r"(?:&&|\|\||&|;|\||\n)", scrubbed) if seg.strip()]
    if not segments:
        return False
    for seg in segments:
        if ">" in seg or "<" in seg:
            return False
        tokens = [t.strip("()") for t in seg.split() if t.strip("()")]
        idx = 0
        while idx < len(tokens):
            tok = tokens[idx]
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok) or tok in ("command", "builtin", "!"):
                idx += 1
                continue
            break
        if idx >= len(tokens):
            return False
        verb = Path(tokens[idx]).name.lower()
        if verb not in _BENIGN_SEARCH_VERBS:
            return False
    return True

_CLEAN_BUILD_PASS_RE = _LazyRegex(
    r"(?:Ran\s+\d+\s+tests?(?:\s+in\s+[^\n]+)?\s+\bOK\b|\b\d+\s+passed\b|\bFinished\s+`(?:dev|test|release)`|\b0\s+errors?\b|Found\s+0\s+errors?|\bok\s+\S+\s+[0-9.]+s\b|Success:\s+no\s+issues\s+found\b|All\s+checks?\s+passed\b)"
)

_COMPILER_OR_TEST_CMD_VERBS = frozenset({
    "tsc", "tsgo", "mypy", "pyright", "basedpyright", "ruff", "flake8", "pylint", "pytest",
    "py.test", "nosetests", "vitest", "jest", "mocha", "ava", "eslint", "biome", "oxlint",
    "rustc", "gcc", "g++", "clang", "clang++", "cc", "c++", "cmake", "make", "gmake", "ninja",
    "meson", "javac", "kotlinc", "scalac", "mvn", "mvnw", "gradle", "gradlew", "msbuild",
    "csc", "fsc", "zig", "cabal", "stack", "ghc", "mix", "elixirc", "erlc", "phpunit",
    "phpstan", "psalm", "rspec", "rubocop", "luacheck", "shellcheck", "golangci-lint", "staticcheck",
})

_SUBCMD_BUILD_RUNNERS: Dict[str, frozenset[str]] = {
    "cargo": frozenset({"build", "b", "check", "c", "test", "t", "clippy", "bench", "doc"}),
    "go": frozenset({"build", "test", "vet", "install"}),
    "dotnet": frozenset({"build", "test", "publish", "pack"}),
    "swift": frozenset({"build", "test"}),
    "npm": frozenset({"test", "t", "tst", "build", "check", "typecheck", "lint", "compile"}),
    "pnpm": frozenset({"test", "t", "build", "check", "typecheck", "lint", "compile"}),
    "yarn": frozenset({"test", "build", "check", "typecheck", "lint", "compile"}),
    "bun": frozenset({"test", "build", "check", "typecheck", "lint"}),
    "deno": frozenset({"test", "check", "lint", "compile"}),
}

_PY_M_BUILD_MODULES = frozenset({
    "unittest", "pytest", "mypy", "pyright", "ruff", "flake8", "pylint", "doctest", "compileall", "py_compile",
})

_SHORT_UNATTRIBUTED_BUILD_RE = _LazyRegex(
    r"(?:^\s*FAIL(?:\s|$)|\bFAIL\t|:\d+(?::\d+)?:\s*error:|^\s*FAILED\b)",
    re.MULTILINE,
)


def _invokes_compiler_or_test_runner(cmd_line: str) -> bool:
    """Returns True when any shell segment in `cmd_line` invokes a compiler, typechecker, linter, or test runner."""
    if not cmd_line or not cmd_line.strip():
        return False
    scrubbed = _scrub_shell_quotes_and_substitutions(cmd_line)
    surface = _BENIGN_STDERR_REDIR_RE.sub(" ", scrubbed if scrubbed is not None else cmd_line)
    segments = [seg.strip() for seg in re.split(r"(?:&&|\|\||&|;|\||\n)", surface) if seg.strip()]
    for seg in segments:
        tokens = [t.strip("()'\"") for t in seg.split() if t.strip("()'\"")]
        idx = 0
        while idx < len(tokens):
            tok = tokens[idx]
            low_tok = Path(tok).name.lower()
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok) or low_tok in (
                "command", "builtin", "env", "nice", "nohup", "time", "sudo", "!", "npx", "bunx", "uvx",
            ):
                idx += 1
                continue
            if low_tok == "timeout" and idx + 1 < len(tokens):
                idx += 2
                continue
            if low_tok in ("poetry", "pipenv", "uv") and idx + 1 < len(tokens) and tokens[idx + 1].lower() == "run":
                idx += 2
                continue
            break
        if idx >= len(tokens):
            continue
        verb = Path(tokens[idx]).name.lower()
        if verb in _COMPILER_OR_TEST_CMD_VERBS:
            return True
        if verb in _SUBCMD_BUILD_RUNNERS:
            rest = [t.lower() for t in tokens[idx + 1 :] if not t.startswith("-")]
            if rest:
                sub = rest[1] if (rest[0] == "run" and len(rest) > 1 and verb in ("npm", "pnpm", "yarn", "bun")) else rest[0]
                if sub in _SUBCMD_BUILD_RUNNERS[verb] or sub.startswith(("test:", "build:", "lint:", "typecheck:", "check:")):
                    return True
        if re.fullmatch(r"python(?:3(?:\.\d+)?)?|py", verb):
            for j in range(idx + 1, len(tokens) - 1):
                if tokens[j] == "-m" and tokens[j + 1].lower() in _PY_M_BUILD_MODULES:
                    return True
    return False

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
    tx_path = _resolve_transcript_path(payload)
    if tx_path is None:
        return None

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
    heavy_snippets: List[str] = []
    consec_snippets: List[str] = []
    pending_tool_calls: List[Tuple[str, str]] = []
    for entry in tail_entries:
        step_type = str(entry.get("type", "")).upper()
        if step_type in ("USER_INPUT", "SYSTEM_MESSAGE"):
            continue
        if step_type == "PLANNER_RESPONSE":
            pending_tool_calls.clear()
            tcs = entry.get("tool_calls") or entry.get("toolCalls")
            if isinstance(tcs, list):
                for tc in tcs:
                    if not isinstance(tc, dict):
                        continue
                    tc_name = str(tc.get("name") or tc.get("tool_name") or tc.get("tool") or "").strip().lower()
                    tc_cmd = (
                        _extract_cmd_from_args_obj(tc.get("args") or tc.get("arguments") or tc.get("input"))
                        if tc_name in _SHELL_EXEC_TOOL_NAMES
                        else ""
                    )
                    pending_tool_calls.append((tc_name, tc_cmd))
            continue
        status = str(entry.get("status", "")).upper()
        err_field = entry.get("error")
        content = entry.get("content") if isinstance(entry.get("content"), str) else ""
        truncated = entry.get("truncated_fields")
        tool_name = str(entry.get("tool_name") or entry.get("tool") or entry.get("name") or "").strip().lower()
        queued_tool = ""
        queued_cmd = ""
        if pending_tool_calls and (
            not tool_name
            or tool_name == pending_tool_calls[0][0]
            or (tool_name in _SHELL_EXEC_TOOL_NAMES and pending_tool_calls[0][0] in _SHELL_EXEC_TOOL_NAMES)
        ):
            queued_tool, queued_cmd = pending_tool_calls.pop(0)
        resolved_tool = tool_name or queued_tool
        is_error_status = status == "ERROR" or (
            isinstance(err_field, str) and bool(err_field.strip())
        ) or (isinstance(err_field, dict) and bool(err_field))
        if resolved_tool in _NON_EXEC_READ_TOOLS and not is_error_status:
            continue
        if (
            not resolved_tool
            and not is_error_status
            and status == "DONE"
            and content.startswith("Created At:")
            and "Command exited with code" not in content[:320]
        ):
            continue
        cmd_line = _extract_entry_command_line(entry) or queued_cmd
        is_clean_exit_zero = bool(re.search(r"\bCommand\s+exited\s+with\s+code\s+0\b", content)) and not is_error_status
        has_compiler_marker = False if is_clean_exit_zero else bool(_COMPILER_TRACE_MARKER_RE.search(content))
        m_nonzero = None if is_clean_exit_zero else _NONZERO_EXIT_CODE_RE.search(content)
        exit_code = _safe_int(m_nonzero.group(1), default=0) if m_nonzero else 0
        has_trace_marker = has_compiler_marker or (exit_code > 0)

        if is_clean_exit_zero:
            consec_build_fails = 0
            consec_snippets.clear()
            if _CLEAN_BUILD_PASS_RE.search(content):
                heavy_fail = False
                heavy_snippets.clear()
            continue

        is_truncated_content = isinstance(truncated, list) and "content" in truncated
        line_count = content.count("\n") + (1 if content else 0)
        if (
            exit_code in (126, 127)
            and not has_compiler_marker
            and line_count <= 500
            and not is_truncated_content
        ):
            continue
        if (
            exit_code in (1, 2)
            and not has_compiler_marker
            and line_count <= 500
            and not is_truncated_content
            and _is_pure_search_or_diff_command(cmd_line)
        ):
            continue
        if (
            not has_compiler_marker
            and line_count <= 25
            and not is_truncated_content
            and (
                (bool(cmd_line.strip()) and not _invokes_compiler_or_test_runner(cmd_line))
                or (not cmd_line.strip() and exit_code > 0 and not _SHORT_UNATTRIBUTED_BUILD_RE.search(content))
            )
        ):
            continue

        is_failing = (is_error_status or has_trace_marker) and not is_clean_exit_zero
        if not is_failing:
            continue

        if (has_trace_marker and (line_count > 500 or is_truncated_content)) or (
            is_error_status and line_count > 500
        ):
            heavy_fail = True
            heavy_snippets.append(content[-400:] if content else str(err_field)[:400])

        if has_trace_marker or (is_error_status and exit_code > 0):
            consec_build_fails += 1
            consec_snippets.append(content[:300] if content else str(err_field)[:300])

    if heavy_fail or consec_build_fails >= 2:
        combined_snips = (heavy_snippets if heavy_fail else []) + (consec_snippets if consec_build_fails >= 2 else [])
        digest = hashlib.sha256("\n".join(combined_snips)[:4096].encode("utf-8")).hexdigest()[:12]
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
    suppress_workspace_domain_hints: bool = False,
    _turn_cache: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Tuple[str, str, str]], List[Tuple[str, str]], set[str]]:
    """Appends bounded workspace marker and transcript error-trace hints with turn-gap deduplication."""
    if is_short_or_continuation:
        return matched, matched_routes, set()

    turn_cache = _turn_cache if _turn_cache is not None else {}
    cfg = configured_config_dir()
    extra_keys: set[str] = set()
    emitted_skills = {m[0] for m in matched}
    emitted_routes = {r[0] for r in matched_routes}
    ws_skills, ws_routes = ([], []) if suppress_workspace_domain_hints else _detect_workspace_domain_signals(workspaces)

    def _within_cooldown(key: str) -> bool:
        return key in seen_turns and (not is_new_user_turn or (active_turn - seen_turns[key]) < REHINT_TURN_GAP)

    added_ctx_skills = 0
    for skill_name in ws_skills:
        if added_ctx_skills >= MAX_CONTEXT_SIGNALS:
            break
        hint_tuple = _SKILL_HINT_BY_NAME.get(skill_name)
        if hint_tuple is None:
            continue
        h_rel = hint_tuple[1]
        if h_rel.startswith("skills/"):
            h_parts = h_rel.split("/")
            h_pack = _PLUGIN_SKILL_TO_PACK.get(h_parts[1]) if len(h_parts) >= 2 else None
            if h_pack is not None and not _is_harness_plugin_active(h_pack, cfg, workspaces, _turn_cache=turn_cache):
                continue
        ctx_key = f"ws_ctx:{skill_name}"
        if skill_name in emitted_skills or _within_cooldown(skill_name) or _within_cooldown(ctx_key):
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
    is_readonly_meta_question: bool = False,
    _turn_cache: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Tuple[str, str, str]], List[Tuple[str, str]]]:
    """Selects bounded skill hints and ecosystem routing directives for `handle_pre_invocation`."""
    if is_short_or_continuation:
        return [], []
    turn_cache = _turn_cache if _turn_cache is not None else {}
    cfg = configured_config_dir()
    explicit_surface = scan_text if explicit_text is None else explicit_text
    has_viable_token = has_explicit_cmd or bool(_VIABLE_HINT_TOKEN_RE.search(scan_text))
    norm_scan = scan_text.replace("İ", "i").replace("ı", "i").casefold()
    fac = _facade()
    fac_globals = getattr(fac, "_globals", None) if fac is not None else None
    fac_dict = fac_globals if isinstance(fac_globals, dict) else (getattr(fac, "__dict__", {}) if fac is not None else {})
    mod_globals = globals()
    custom_skills = (
        fac_dict["SKILL_HINTS"]
        if "SKILL_HINTS" in fac_dict
        else (mod_globals["SKILL_HINTS"] if "SKILL_HINTS" in mod_globals else None)
    )
    skill_source = custom_skills if custom_skills is not None else _SKILL_HINTS_RAW
    skill_candidates: List[Tuple[int, int, str, str, str]] = []
    for table_idx, (skill_name, rel_path, pat_or_rx, summary) in enumerate(skill_source):
        aliases = _SKILL_SLASH_ALIASES.get(skill_name, (skill_name,))
        explicit_slash = has_explicit_cmd and _has_explicit_slash_command(explicit_surface, aliases)
        explicit_slug = (
            False
            if (not has_explicit_cmd or explicit_slash)
            else _has_explicit_slug_mention(explicit_surface, skill_name)
        )
        is_explicit = explicit_slash or explicit_slug
        if skill_name in seen_turns:
            if not is_new_user_turn:
                continue
            if not explicit_slash and (active_turn - seen_turns[skill_name]) < REHINT_TURN_GAP:
                continue
        if not is_explicit:
            if is_readonly_meta_question and skill_name not in _READONLY_HINT_ALLOWLIST_SKILLS:
                continue
            pat_text = pat_or_rx if isinstance(pat_or_rx, str) else pat_or_rx.pattern
            if not has_viable_token and "@\\[" not in pat_text:
                continue
        if not _optional_plugin_skill_available(rel_path, workspaces):
            continue
        if rel_path.startswith("skills/"):
            s_parts = rel_path.split("/")
            s_pack = _PLUGIN_SKILL_TO_PACK.get(s_parts[1]) if len(s_parts) >= 2 else None
            if s_pack is not None and not _is_harness_plugin_active(s_pack, cfg, workspaces, _turn_cache=turn_cache):
                continue
        if not is_explicit:
            if isinstance(pat_or_rx, str):
                if not _match_hint_pattern(pat_or_rx, scan_text, norm_scan):
                    continue
            elif not pat_or_rx.search(scan_text):
                continue
        priority = 2 if explicit_slash else (1 if explicit_slug else 0)
        skill_candidates.append((-priority, table_idx, skill_name, rel_path, summary))
    if any(c[2] == "rustify" for c in skill_candidates):
        skill_candidates = [c for c in skill_candidates if not (c[2] == "rust-harden" and c[0] == 0)]
    selected_skills = _select_tiered_hints(skill_candidates)
    matched = [(s, r, d) for _p, _i, s, r, d in selected_skills]

    custom_routes = (
        fac_dict["ECOSYSTEM_ROUTING_HINTS"]
        if "ECOSYSTEM_ROUTING_HINTS" in fac_dict
        else (mod_globals["ECOSYSTEM_ROUTING_HINTS"] if "ECOSYSTEM_ROUTING_HINTS" in mod_globals else None)
    )
    route_source = custom_routes if custom_routes is not None else _ECOSYSTEM_ROUTING_HINTS_RAW
    route_candidates: List[Tuple[int, int, str, str]] = []
    for table_idx, (route_key, pat_or_rx, directive) in enumerate(route_source):
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
        if route_key in seen_turns:
            if not is_new_user_turn:
                continue
            if not explicit_route_slash and (active_turn - seen_turns[route_key]) < REHINT_TURN_GAP:
                continue
        if not is_explicit_route:
            if is_readonly_meta_question and route_key not in _READONLY_HINT_ALLOWLIST_ROUTES:
                continue
            pat_text = pat_or_rx if isinstance(pat_or_rx, str) else pat_or_rx.pattern
            if not has_viable_token and "@\\[" not in pat_text:
                continue
        if route_key == "route:mcp:rea_rea" and not _is_rea_mcp_available(workspaces):
            continue
        if not is_explicit_route:
            if isinstance(pat_or_rx, str):
                if not _match_hint_pattern(pat_or_rx, scan_text, norm_scan):
                    continue
            elif not pat_or_rx.search(scan_text):
                continue
        effective_directive = directive
        if route_key == "route:mcp:ui-refinery-contrast":
            if not _is_harness_plugin_active("ui-refinery", cfg, workspaces, _turn_cache=turn_cache):
                continue
            try:
                p_root = cfg / "plugins"
                p_dir = p_root / "ui-refinery"
                p_mcp = p_dir / "mcp_config.json"
                has_plugin_mcp = (
                    not p_root.is_symlink()
                    and not p_dir.is_symlink()
                    and not p_mcp.is_symlink()
                    and p_mcp.is_file()
                )
            except (OSError, ValueError):
                has_plugin_mcp = False
            if not has_plugin_mcp:
                for ws in workspaces:
                    try:
                        ws_a = ws / ".agents"
                        ws_proot = ws_a / "plugins"
                        ws_pdir = ws_proot / "ui-refinery"
                        ws_mcp = ws_pdir / "mcp_config.json"
                        if (
                            not ws_a.is_symlink()
                            and not ws_proot.is_symlink()
                            and not ws_pdir.is_symlink()
                            and not ws_mcp.is_symlink()
                            and ws_mcp.is_file()
                        ):
                            has_plugin_mcp = True
                            break
                    except (OSError, ValueError):
                        continue
            if has_plugin_mcp:
                effective_directive = (
                    "MCP Server `ui-refinery_contrast` (`call_mcp_tool` with "
                    '`ServerName="ui-refinery_contrast"`, `ToolName="check_contrast"`)'
                )
            else:
                flat_cache_key = ("flat_contrast_key", str(cfg))
                if flat_cache_key in turn_cache:
                    flat_key = turn_cache[flat_cache_key]
                else:
                    flat_key = None
                    mcp_path = cfg / "mcp_config.json"
                    try:
                        if not os.path.islink(cfg) and not os.path.islink(mcp_path):
                            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                            fd = os.open(os.fspath(mcp_path), flags)
                            try:
                                import stat as _stat

                                st = os.fstat(fd)
                                if _stat.S_ISREG(st.st_mode) and st.st_size <= 512 * 1024:
                                    with os.fdopen(fd, "rb") as fh:
                                        fd = -1
                                        raw = fh.read(512 * 1024 + 1)
                                    if len(raw) <= 512 * 1024:
                                        data = json.loads(raw.decode("utf-8"))
                                        servers = data.get("mcpServers") if isinstance(data, dict) else None
                                        if isinstance(servers, dict):
                                            if "ui-refinery-contrast" in servers:
                                                flat_key = "ui-refinery-contrast"
                                            else:
                                                suffix = "skills/ui-refinery/scripts/contrast-mcp.py"
                                                for skey, scfg in servers.items():
                                                    if not isinstance(skey, str) or not skey.strip() or not isinstance(scfg, dict):
                                                        continue
                                                    sargs = scfg.get("args")
                                                    if not isinstance(sargs, list):
                                                        continue
                                                    for a in sargs:
                                                        if not isinstance(a, str):
                                                            continue
                                                        norm_a = a.strip().replace("\\", "/").lower()
                                                        if norm_a == suffix or norm_a.endswith("/" + suffix):
                                                            flat_key = skey.strip()
                                                            break
                                                    if flat_key:
                                                        break
                            finally:
                                if fd >= 0:
                                    try:
                                        os.close(fd)
                                    except OSError:
                                        pass
                    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
                        flat_key = None
                    turn_cache[flat_cache_key] = flat_key
                if flat_key and flat_key != "ui-refinery-contrast":
                    effective_directive = (
                        f"MCP Server `{flat_key}` (`call_mcp_tool` with "
                        f'`ServerName="{flat_key}"`, `ToolName="check_contrast"`)'
                    )
        priority = 2 if explicit_route_slash else (1 if explicit_route_slug else 0)
        route_candidates.append((-priority, table_idx, route_key, effective_directive))
    selected_routes = _select_tiered_hints(route_candidates)
    matched_routes = [(rk, d) for _p, _i, rk, d in selected_routes]
    return matched, matched_routes

def _call_recovery_hint(
    ws: Path,
    conv_id: str,
    *,
    first_turn_in_conv: bool,
    is_mid_turn: bool,
    is_question_only: bool,
) -> Tuple[bool, Optional[Tuple[str, str, Optional[int]]]]:
    fn = _facade_attr("_detect_workspace_recovery_hint", _detect_workspace_recovery_hint)
    try:
        return fn(
            ws,
            conv_id,
            first_turn_in_conv=first_turn_in_conv,
            is_mid_turn=is_mid_turn,
            is_question_only=is_question_only,
        )
    except TypeError:
        return fn(
            ws,
            conv_id,
            first_turn_in_conv=first_turn_in_conv,
            is_mid_turn=is_mid_turn,
        )


def handle_pre_invocation(payload: Dict[str, Any]) -> Dict[str, Any]:
    tx_state_ex = _inspect_transcript_turn_state_ex(payload)
    _tx_text, _tx_step, tx_mid_turn, has_tx, tx_ends_with_user = tx_state_ex
    tx_state = tx_state_ex[:4]
    inv_raw = payload.get("invocationNum")
    if inv_raw is None:
        inv_raw = payload.get("invocation_num")
    inv_num = _safe_int(inv_raw, default=1)
    if tx_ends_with_user:
        is_mid_turn = False
    elif inv_raw is not None and inv_num in (0, 1):
        is_mid_turn = bool(has_tx and tx_mid_turn)
    else:
        is_mid_turn = (inv_num > 1) or tx_mid_turn

    raw_prompt, step_idx = _extract_latest_user_prompt(payload, _tx_state=tx_state)
    if not raw_prompt and not is_mid_turn:
        return {}

    cleaned = _extract_user_request_prose(raw_prompt).strip() if raw_prompt else ""
    prompt_with_inline = _extract_user_request_with_inline(raw_prompt).strip() if raw_prompt else ""
    is_aux_readonly = _is_auxiliary_readonly_context(payload, prompt_with_inline)
    scan_text = cleaned[:16384]
    hint_scan_text = _strip_pasted_review_and_quote_blocks(scan_text)
    raw_for_inline = _strip_pasted_review_and_quote_blocks(prompt_with_inline) if prompt_with_inline else ""
    inline_cmd_surface = _extract_explicit_inline_command_tokens(raw_for_inline) if raw_for_inline else ""
    explicit_text = f"{hint_scan_text} {inline_cmd_surface}".strip() if inline_cmd_surface else hint_scan_text
    normalized = re.sub(r"[.!?,;:]+$", "", scan_text.lower()).strip()
    has_explicit_cmd = bool(
        explicit_text
        and (_EXPLICIT_CMD_TOKEN_RE.search(explicit_text) or _has_any_explicit_slug_mention(explicit_text))
    )
    has_short_action = bool(hint_scan_text and _SHORT_ACTION_INTENT_RE.search(hint_scan_text))
    is_short_or_continuation = (not has_explicit_cmd) and (not has_short_action) and (
        len(scan_text) < MIN_PROMPT_CHARS or normalized in CONTINUATION_WORDS
    )
    workspaces = _workspaces_from_payload(payload)

    if not is_mid_turn and is_short_or_continuation and not workspaces:
        return {}

    conv_id = _conversation_id(payload)
    hints_file = state_dir() / "hook_hints.json"
    recovery_msgs: List[str] = []
    pending_acks: List[Tuple[Path, int]] = []
    matched: List[Tuple[str, str, str]] = []
    matched_routes: List[Tuple[str, str]] = []
    ctx_advisory: Optional[Tuple[int, str, str]] = None
    turn_cache: Dict[str, Any] = {}
    prompt_hash = hashlib.sha256(explicit_text.encode("utf-8")).hexdigest()[:12]
    current_sig = f"{step_idx}:{prompt_hash}"

    try:
        with file_lock(hints_file, timeout=HOOK_LOCK_TIMEOUT):
            ledger_ok, ledger = _read_ledger_checked(hints_file)
            if not ledger_ok:
                sys.stderr.write(f"[Harness PreInvocation] Quarantine/read fallback on `{hints_file}`.\n")
            seen_turns, turn_num, last_sig = _load_conv_hint_state(ledger.get(conv_id))
            if (
                is_mid_turn
                and not _tx_text
                and raw_prompt
                and (
                    (
                        inv_raw is not None
                        and inv_num in (0, 1)
                        and last_sig
                        and not last_sig.endswith(f":{prompt_hash}")
                    )
                    or (not tx_mid_turn and (not last_sig or not last_sig.endswith(f":{prompt_hash}")))
                )
            ):
                is_mid_turn = False
            first_turn_in_conv = "__workspace_checked__" not in seen_turns
            is_distinct_user_turn = (not is_mid_turn) and (current_sig != last_sig)
            is_new_user_turn = (not is_short_or_continuation) and is_distinct_user_turn
            if is_mid_turn and not is_distinct_user_turn:
                active_turn = max(turn_num, 1)
                tx_keys: set[str] = set()
                if has_tx or payload.get("transcriptPath") or payload.get("transcript_path"):
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
                try:
                    atomic_write_json(hints_file, ledger)
                except OSError as exc:
                    sys.stderr.write(f"[Harness PreInvocation] Failed to write `{hints_file}`: {exc}\n")
                routes_fast = "; ".join(directive for _key, directive in matched_routes)
                msg_fast = (
                    f"[Harness Ecosystem Routing] Relevant subagent(s) / MCP server(s): {routes_fast}. "
                    "Invoke or call them automatically when the task touches these boundaries."
                )
                return {"injectSteps": [{"systemMessage": {"systemMessage": msg_fast}}]}

            state_dirty = False
            if is_distinct_user_turn:
                turn_num += 1
                last_sig = current_sig
                state_dirty = True
            active_turn = max(turn_num, 1)
            new_keys: set[str] = set()

            is_question_only = _is_pure_readonly_or_question_prompt(hint_scan_text, explicit_text)
            if workspaces and not is_aux_readonly:
                all_inspect_ok = True
                for ws in workspaces:
                    inspect_ok, recovery = _call_recovery_hint(
                        ws,
                        conv_id,
                        first_turn_in_conv=first_turn_in_conv,
                        is_mid_turn=is_mid_turn,
                        is_question_only=is_question_only,
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
                hint_scan_text,
                workspaces,
                seen_turns,
                is_short_or_continuation=is_short_or_continuation,
                is_new_user_turn=is_new_user_turn,
                has_explicit_cmd=has_explicit_cmd,
                active_turn=active_turn,
                explicit_text=explicit_text,
                is_readonly_meta_question=is_question_only,
                _turn_cache=turn_cache,
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
                suppress_workspace_domain_hints=is_question_only,
                _turn_cache=turn_cache,
            )

            if (
                not is_mid_turn
                and is_distinct_user_turn
                and not is_aux_readonly
                and not is_short_or_continuation
            ):
                try:
                    ctx_advisory = _evaluate_predictive_handoff_advisory(
                        payload,
                        workspaces,
                        scan_text,
                        explicit_text,
                        raw_prompt,
                        seen_turns,
                        active_turn,
                    )
                except Exception as exc:
                    sys.stderr.write(
                        f"[Harness PreInvocation] Non-fatal predictive handoff error ({type(exc).__name__}): {exc}\n"
                    )
                    ctx_advisory = None
                if ctx_advisory is not None:
                    new_keys.add(ctx_advisory[1])

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

            if ctx_advisory is not None and not hints_persisted:
                ctx_advisory = None

            if pending_acks and hints_persisted:
                for ack_ws, ack_seq_val in pending_acks:
                    _acknowledge_interrupted_flight(ack_ws, ack_seq_val, conv_id=conv_id)
    except (OSError, TimeoutError) as exc:
        sys.stderr.write(f"[Harness PreInvocation] Failed to lock `{hints_file}` ({type(exc).__name__}): {exc}\n")
        if is_mid_turn:
            if has_tx or payload.get("transcriptPath") or payload.get("transcript_path"):
                tx_sig_fb = _detect_transcript_tool_signals(payload)
                if tx_sig_fb is not None:
                    route_tuple_fb = _ROUTE_HINT_BY_KEY.get(tx_sig_fb[0])
                    if route_tuple_fb is not None:
                        matched_routes.append(route_tuple_fb)
            if not matched_routes:
                return {}
        else:
            fb_question_only = _is_pure_readonly_or_question_prompt(hint_scan_text, explicit_text)
            if not is_aux_readonly:
                for ws in workspaces:
                    _inspect_ok, recovery = _call_recovery_hint(
                        ws,
                        conv_id,
                        first_turn_in_conv=False,
                        is_mid_turn=False,
                        is_question_only=fb_question_only,
                    )
                    if recovery is not None:
                        recovery_msgs.append(recovery[1])
            matched, matched_routes = _collect_invocation_skill_hints(
                hint_scan_text,
                workspaces,
                {},
                is_short_or_continuation=is_short_or_continuation,
                is_new_user_turn=not is_short_or_continuation,
                has_explicit_cmd=has_explicit_cmd,
                active_turn=1,
                explicit_text=explicit_text,
                is_readonly_meta_question=fb_question_only,
                _turn_cache=turn_cache,
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
                suppress_workspace_domain_hints=fb_question_only,
                _turn_cache=turn_cache,
            )

    if not recovery_msgs and not matched and not matched_routes and ctx_advisory is None:
        return {}

    parts: List[str] = list(recovery_msgs)
    if matched:
        items = "; ".join(
            f"`{name}` ({_resolve_hint_skill_path(rel, workspaces, _turn_cache=turn_cache)} — {desc})"
            for name, rel, desc in matched
        )
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
    if ctx_advisory is not None and ctx_advisory[0] == 2:
        parts.append(ctx_advisory[2])

    inject_steps: List[Dict[str, Any]] = []
    if parts:
        inject_steps.append({"systemMessage": {"systemMessage": " ".join(parts)}})
    if ctx_advisory is not None and ctx_advisory[0] == 1:
        inject_steps.append(
            {
                "systemMessage": {
                    "systemMessage": "",
                    "metadata": {"user_markdown": ctx_advisory[2]},
                }
            }
        )
    return {"injectSteps": inject_steps} if inject_steps else {}


def __getattr__(name: str) -> Any:
    if name == "SKILL_HINTS":
        rx_cache: Dict[str, re.Pattern[str]] = getattr(_match_hint_pattern, "_rx_cache", {})
        compiled_skills: Tuple[Tuple[str, str, re.Pattern[str], str], ...] = tuple(
            (s_name, s_rel, rx_cache.setdefault(pat_str, re.compile(pat_str, re.IGNORECASE)), summary)
            for s_name, s_rel, pat_str, summary in _SKILL_HINTS_RAW
        )
        globals()["SKILL_HINTS"] = compiled_skills
        return compiled_skills
    if name == "ECOSYSTEM_ROUTING_HINTS":
        rx_cache = getattr(_match_hint_pattern, "_rx_cache", {})
        compiled_routes: Tuple[Tuple[str, re.Pattern[str], str], ...] = tuple(
            (r_key, rx_cache.setdefault(pat_str, re.compile(pat_str, re.IGNORECASE)), directive)
            for r_key, pat_str, directive in _ECOSYSTEM_ROUTING_HINTS_RAW
        )
        globals()["ECOSYSTEM_ROUTING_HINTS"] = compiled_routes
        return compiled_routes
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> List[str]:
    return sorted(set(globals()) | {"SKILL_HINTS", "ECOSYSTEM_ROUTING_HINTS"})
