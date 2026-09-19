# Changelog

All notable changes to Antigravity Harness are documented in this file and detailed in release notes.

## [1.2.4] - 2026-09-19
### Fixed & Hardened
- **Windows NTFS Specific Rights:** Replaced broad `(W)` denial with `(WD,AD,DE,DC)` to preserve `READ_CONTROL` for binary reading and integrity verification under lock (`guard/os_adapter.py`).
- **Recursive Subdirectory Unlock:** Added `/t /c /q` to Windows `icacls` unlock routines to cleanly strip inherited deny ACEs across subdirectories (`guard/os_adapter.py`).
- **Directory Lock Detection:** Added probe file verification for directory locks on Windows (`guard/os_adapter.py`).
- **ASCII-Safe Console Output:** Replaced Unicode status characters with standardized `[OK]` and `[WARN]` markers for CP1252 / Windows terminal resilience (`guard/cli.py`, `guard/integrity.py`).
- **Repository Root Cleanliness:** Reorganized root directory bloat into `installers/`, `docs/`, and `docs/releases/`.
- See detailed notes: [docs/releases/RELEASE_NOTES_v1.2.4.md](docs/releases/RELEASE_NOTES_v1.2.4.md)

## [1.2.3] - 2026-09-19
### Added & Hardened
- **State-Synchronized Rollback:** Full-state snapshot restoration with extraneous file pruning (`guard/snapshot.py`).
- **Isolated Cryptographic Trust Anchor:** External baseline path support via `ANTIGRAVITY_INTEGRITY_FILE` (`guard/integrity.py`).
- **Stale Lock Recovery & Doctor:** Automatic recovery for crash-induced unshielded states and `agy-guard doctor [--fix]` diagnostic routine (`guard/os_adapter.py`, `guard/cli.py`).
- **Cross-Platform CI Matrix:** Automated GitHub Actions workflows for Linux, macOS, and Windows (`.github/workflows/ci.yml`).
- See detailed notes: [docs/releases/RELEASE_NOTES_v1.2.3.md](docs/releases/RELEASE_NOTES_v1.2.3.md)

## [1.2.2] - 2026-09-19
### Maintenance
- Synchronized upstream skill commits (chisle, everything-claude-code) and canonical manifest update.

## [1.2.1] - 2026-09-19
### Hardened
- Atomic lock-aware mutations for baseline and snapshot operations while write shield is engaged.

## [1.2.0] - 2026-09-19
### Added
- **Antigravity Guard Suite:** Cross-platform OS write protection, cryptographic FIM, lightweight snapshots, and Desktop GUI (`guard/`).
- See detailed notes: [docs/releases/RELEASE_NOTES_v1.2.0.md](docs/releases/RELEASE_NOTES_v1.2.0.md)

## [1.1.0] - 2026-09-19
### Added
- **Universal Bidirectional AI Agent Bridge (`porter.py`):** Lossless rule, skill, and agent transpiler supporting Claude Code, Cursor, Aider, Universal `AGENTS.md`, and generic platforms.
- **Pre-Flight Suitability & Adaptability Analyzer (`porter/analyzer.py`):** Scoring engine (0–100) evaluating constitutional alignment and platform compatibility prior to file creation or mutation.
- **Constitutional Sanitizer (`porter/sanitizer.py`):** Automated sanitization stripping sycophantic instructions, conversational fluff, and test-weakening directives from imported rules.
- **Lossless Universal Canonical Manifest Engine (`porter/manifest.py` & `.harness/manifest.json`):** Single-source compilation capturing the entire harness state.
- **SSRF Network Immunity:** Strict RFC-1918, link-local metadata (169.254.169.254), loopback, and IPv6 DNS resolution validation in remote rule fetching.
- **Rule 16 External Rule Ingestion Invariant:** Codified external rule ingestion gates in `GEMINI.md`.
- **`vibecoder` Skill:** Product-first, vibe-oriented rapid prototyping skill for non-coders and exploratory builders.
- **`research` Subagent:** Isolated read-only subagent for heavy documentation and external API schema ingestion without parent context pollution.

## [1.0.4] - 2026-09-19
### Added & Hardened
- **Universal Cross-Platform Installers:** Zero-dependency `install.py` supporting Windows, Linux, macOS, and FreeBSD with NTFS junction and copy fallbacks, alongside strict POSIX `install.sh`.
- **Popper's Falsification Gate (Rule 8):** Added deterministic baseline checks and edge verification requirement before concluding null-action or task completion.
- **Out-of-Band Meta-Diagnosis (Rule 13):** Added circuit breaker escalation dispatching isolated diagnostic subagents (`Model: 'pro'`) upon repeating execution failures or oscillation.
- **Session Boundary & Handoff Protocol:** Standardized `HANDOFF.template.md` at project root for Tier 2/3 task continuity and context saturation freezes (>25 turns).
- **Subagent Hardening:** Protected hook timeouts, eliminated shell hanging issues, and harmonized cross-platform telemetry.

## [1.0.1] - 2026-09-19
### Changed & Hardened
- **User Interaction Language (Rule 6):** Refactored constitution to communicate in the user's prompt language while internal system directives, engineering rigor, computational gates, and invariants remain canonical in English.
- **Upstream & Platform Collision Invariant (Rule 15):** Enforced unconditional precedence of local constitutional rules and custom skills over upstream runtime prompts and directive drift.
- **Failure Logging Protocol (`MISTAKES.md`):** Automated structured logging for regressions, root-cause analyses, impacts, and preventive invariants.

## [1.0.0] - 2026-09-19
### Added
- **Initial Release of Antigravity Harness:** Production-grade engineering harness, behavioral constitution, and autonomous multi-agent ecosystem for Google Antigravity.
- **Global Behavioral Constitution (`GEMINI.md`):** Discourse & Communication Principles (Rule 1-6), Epistemic Objectivity & Anti-Sycophancy (Rule 7-8), Proportional Gate Escalation (Tier 1/2/3), Goodhart's Immutable Test Invariant (Rule 9), and Process & Context Hygiene (Rule 10-14).
- **Core Autonomous Subagents:** `consistency-auditor`, `specification-gap-auditor`, `security-boundary-verifier`, `silent-failure-hunter`, `build-error-resolver`.
- **Engineering Skill Ecosystem (17 Built-in Skills):**
  - `harness`: Autonomous engineering harness, computational verification gates, task lifecycle.
  - `audit`: Structural, consistency, and security boundary audit engine.
  - `deep-grill`: Relentless architectural trade-off and edge-case interview engine.
  - `diagnosing-bugs`: Seven-phase root-cause analysis and reproducible feedback loops.
  - `security-review`: Defensive security review, vulnerability scanners, and OWASP checklists.
  - `antislop` Suite: Comprehensive UI quality filter (38 rules, WCAG AA contrast, layout mobile, copywriting, and comment hygiene).
  - `procoder` & `unlazy`: Tier-3 depth completion engines, acceptance gates, and sprint chains.
  - `architecture-decision-records`: Automated architectural decision log.
  - `silk-design`: Kinetic motion, fluid typography, and design token toolbox.
  - `chisle`: Maximum-efficiency, minimal-fluff dev mode.
  - `database-migrations`: Schema change patterns, rollbacks, and zero-downtime deployments.
  - `upstream-auditor`: Staging and model drift auditor tracking 7 community skill repositories.
- **Design Contract (`DESIGN.md`):** Default engineering baseline (ENERGY 2 / RHYTHM 2 / MOTION 2, Dark Zinc palette, 5 mandatory component states, zero mobile horizontal overflow).
