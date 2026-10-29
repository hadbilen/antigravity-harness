---
name: technical-writing
description: >-
  Technical documentation architecture, Diataxis mode separation (Tutorial, How-To, Reference, Explanation),
  executable code-example verification, API reference completeness, and changelog discipline. Invoke with
  /technical-writing or when authoring or auditing developer docs, READMEs, runbooks, API references, tutorials,
  or release notes ("teknik dokümantasyon", "kullanım kılavuzu", "doküman yaz", "sürüm notları"). Not for
  marketing landing pages (use 'antislop-copywriting') or architectural decision records (use
  'architecture-decision-records').
---

# Technical Writing: Verified, Mode-Separated Documentation

Technical documentation fails when it mixes learning tutorials with exhaustive reference tables, presents unverified commands that fail on copy-paste, or buries prerequisites beneath marketing filler. This skill enforces structural mode separation, executable example verification, and high-signal technical prose.

## 1. Classify the Document Mode Before Writing (Diataxis)

Every document or top-level section serves exactly one of four reader states. State the chosen mode before drafting and never mix two modes inside the same section:

1. **Tutorial (Learning-Oriented):**
   - *Reader state:* A newcomer learning by doing under guidance.
   - *Contract:* Walk through one deterministic, end-to-end concrete example from a stated starting state to a visible result. Omit edge-case branches, configuration alternatives, and conceptual digressions; link out to Reference or Explanation sections instead.
2. **How-To Guide (Task-Oriented):**
   - *Reader state:* A practitioner with a specific goal or operational problem (including incident runbooks).
   - *Contract:* Start with prerequisites and target outcome; provide numbered, copy-pasteable steps and the verification command that proves the task succeeded; include rollback or recovery steps for mutating operations.
3. **Reference (Information-Oriented):**
   - *Reader state:* A developer looking up exact signatures, flags, parameters, return types, defaults, or error codes while working.
   - *Contract:* Mirror the structure of the codebase or Command-Line Interface (CLI) parser. Every public flag, parameter, configuration key, default value, type, and error status must match the source of truth verbatim.
4. **Explanation (Understanding-Oriented):**
   - *Reader state:* An engineer evaluating architecture, trade-offs, design rationale, or system boundaries.
   - *Contract:* Explain causal mechanisms, constraints, and why a design was chosen over alternatives; keep step-by-step commands out of conceptual explanations.

## 2. Executable Documentation Gate (Zero Unverified Snippets)

Code blocks and shell commands in documentation are executable contracts, not decorative illustrations:

- **Source-of-Truth Verification:** Before documenting a function signature, CLI flag, environment variable, or configuration key, inspect the actual parser, schema, or type definition in the repository (`skills/harness/SKILL.md` §2). Never write flags, options, or subcommands from memory.
- **Execute or Parse Every Snippet:** Run shell commands (`--help`, `--dry-run`, or in a temporary directory) and parse syntax-checked code snippets or configuration blocks (`.json`, `.toml`, `.yaml`) before delivery. If a snippet requires external credentials or production services and cannot be executed locally, declare it explicitly in the Verification Gap Declaration (`GEMINI.md` Rule 8).
- **Show Input and Expected Output:** Separate the command the user runs from the output it prints (either in separate blocks or with explicit comments) so copying the block never feeds output lines back into the shell.
- **Local Link Integrity:** Every relative link and `file://` reference must resolve to an existing file in the workspace (enforced by automated gates), and any `#heading` fragment must match an actual heading slug in the target document (verified during review).

## 3. Cognitive Load & Prose Hygiene

- **Lead with the Prerequisite and Outcome:** Open every guide with what must already be installed or configured and what state the reader will reach at the end.
- **One Concept Per Step:** Each numbered step performs one logical action and states how to verify it before moving on.
- **Abbreviation Discipline (`GEMINI.md` Rule 4):** Spell out every domain term or protocol in full before its abbreviation on first use, and keep at most one abbreviation per sentence.
- **Anti-Slop Technical Profile:** Run `skills/antislop-copywriting/scripts/check_synthetic_markers.py --profile technical` (or `~/.gemini/config/skills/antislop-copywriting/scripts/check_synthetic_markers.py --profile technical`, with `--lang tr` or `--lang auto` for Turkish documentation) on drafted Markdown files to strip signposting announcements (*"In this section we will explore"*, *"İşte bilmeniz gerekenler"*), chatbot leftovers, and brochure inflation while preserving normal engineering tables and lists (`skills/antislop-copywriting/SKILL.md`).

## 4. Changelog & Release Note Discipline (`CHANGELOG.md`)

When authoring release notes or `CHANGELOG.md` entries:

- **Order by Reader Impact:** Group entries under `Breaking Changes`, `Security`, `Added`, `Changed`, `Fixed`, and `Deprecated`.
- **Actionable Breaking Changes:** Every breaking change must show the old usage, the new usage, and the exact migration command or edit required.
- **Observable Behavior Only:** Describe what changed for callers, operators, or end users. Do not list internal variable renames or test-file restructuring as user-facing features.

## 5. Delivery Checklist

Before delivering technical documentation, verify:
- [ ] Each section follows a single Diataxis mode (Tutorial, How-To, Reference, or Explanation) without mode mixing.
- [ ] Every documented CLI flag, configuration key, and function signature was verified against the codebase source of truth.
- [ ] Code snippets and structured configuration blocks were executed or syntax-parsed, or declared under `Not verified` (`GEMINI.md` Rule 8).
- [ ] Relative links and repository paths resolve cleanly (`scripts/meta_audit.py` Pass 2).
- [ ] `python3 skills/antislop-copywriting/scripts/check_synthetic_markers.py --profile technical <file>` (or `python3 ~/.gemini/config/skills/antislop-copywriting/scripts/check_synthetic_markers.py --profile technical <file>`) exits `0`.
