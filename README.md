# Antigravity Harness

> **A deterministic engineering harness, behavioral constitution, and universal ecosystem bridge for AI coding agents.**

Antigravity Harness bridges the gap between raw LLM intelligence and deterministic software engineering. While underlying models provide raw reasoning power, this harness enforces the execution discipline, verification gates, context hygiene, behavioral invariants, and cross-platform portability required for reliable, production-grade autonomous development across Google Antigravity, Claude Code, Cursor, Windsurf, Aider, Hermes, and open-source models.

---

## The Problem: Why This Exists

Agentic coding tools frequently stumble into four failure modes:

1. **The Sycophancy Trap:** Agents reflexively agree with user premises, gloss over architectural flaws, and bury actionable diagnosis under polite conversational filler.
2. **Test Weakening (Goodhart's Curse):** When encountering a failing test, agents often edit the assertion, skip the test (`skip`), or mock the contract just to get a green exit code.
3. **AI-Slop Explosion:** Generating generic purple SaaS templates, unverified placeholder metrics ("10,000+ happy users"), and ignoring accessibility (WCAG AA) standards.
4. **Context Bloat & Analysis Paralysis:** Reading megabytes of raw log files into conversation history, causing severe context rot, looping regressions, and hallucinated solutions.
5. **Ecosystem Fragmentation & Information Decay:** Rules written for one tool (Cursor, Claude, Antigravity) cannot be shared without manual rewriting, and multi-hop migrations (A -> B -> C) suffer from the "Telephone Game" effect, diluting engineering rigor.

**Antigravity Harness** eliminates these behaviors through computational gates, an immutable test invariant, independent auditor subagents, and a bidirectional lossless transpiler.

---

## The Six Pillars

```
                     ┌───────────────────────────────────────────────┐
                     │          The Engineering Constitution         │
                     │  - Proportional Gate Escalation (Tier 1/2/3)  │
                     │  - The Immutable Test Invariant (No Weaken)   │
                     │  - Think in Code (Zero Context Bloat)         │
                     │  - External Rule Ingestion Invariant (Rule 16)│
                     └───────────────────────┬───────────────────────┘
                                             │
       ┌──────────────────┬──────────────────┼──────────────────┬──────────────────┐
       ▼                  ▼                  ▼                  ▼                  ▼
 ┌──────────────┐ ┌─────────────────┐ ┌──────────────┐ ┌──────────────────┐ ┌──────────────────┐
 │  Autonomous  │ │  Modular Skill  │ │ Baseline UI  │ │ Universal Bridge │ │Antigravity Guard │
 │  Subagents   │ │     System      │ │   Contract   │ │   & Porter CLI   │ │(agy-guard CLI/GUI│
 │ (6 Auditors) │ │   (20 Skills)   │ │(Antislop UI) │ │ (Lossless Trans) │ │Write Protect/FIM)│
 └──────────────┘ └─────────────────┘ └──────────────┘ └──────────────────┘ └──────────────────┘
```

### 1. The Engineering Constitution (`GEMINI.md`)
- **Proportional Gate Escalation:** Eliminates over-engineering. Tier 1 (<20 lines) bypasses planning artifacts. Tier 2 (3–8 files) triggers Blast Radius Mapping and Call-Graph Reachability checks. Tier 3 (>8 files or auth/schema changes) mandates the full harness pipeline.
- **The Immutable Test Invariant:** An agent is strictly prohibited from altering test assertions or skipping tests to pass a gate. Tests must target contract boundaries (*seams*), not private implementation details. Source code must fix the test—never the reverse.
- **Think in Code Context Hygiene:** The agent must never dump whole files or massive logs into the context window. It parses and filters state using targeted shell pipelines (`grep`, `jq`, `awk`), scripts bulk inspections, and isolates streams.
- **Circuit Breaker & Out-of-Band Meta-Diagnosis:** Caps fix passes to ~10% blast radius, halts editing loops upon detecting oscillation, and dispatches an isolated clean-context diagnostic subagent instead of engaging in token-wasting in-band argumentation.
- **Verification Gap & Falsification Gate (Popper's Invariant):** Enforces explicit declaration of unverified boundaries upon delivery and actively guards against premature closure by verifying no discriminating falsification checks were left unexecuted.
- **Session Boundary & Handoff Continuity (`HANDOFF.md`):** Mandates fresh chat sessions following major deliveries, generating a standardized `HANDOFF.md` summary to prevent attention degradation without losing architectural context.
- **External Rule Ingestion Invariant (`Rule 16`):** Prohibits blind mutation of external rules; mandatorily enforces read-only Pre-Flight Suitability inspection.

### 2. Independent Auditor Subagents (`/agents`)
The primary model cannot grade its own work. Specialized read-only subagents evaluate risk boundaries prior to delivery:
* **`silent-failure-hunter`:** Scans for swallowed exceptions (`catch {}`), missing logs, and dangerous fallback returns.
* **`security-boundary-verifier`:** Executes concrete negative test cases against IDOR, injection vectors, SSRF, and concurrency (TOCTOU) race conditions.
* **`specification-gap-auditor`:** Identifies unhandled edge cases, omissions in requirements, and vague adjectives (*"fast"*, *"scalable"*).
* **`consistency-auditor`:** Detects axiomatic contradictions, circular dependencies, and broken cross-references across multi-volume specifications.
* **`build-error-resolver`:** Proactively isolates TypeScript and compiler breaks with minimal, non-architectural diffs.
* **`research`:** Ingests large external documentation (>50 KB) and explores broad codebases in an isolated sandbox, returning distilled decision matrices without polluting the primary context window.

### 3. Baseline Design Contract (`DESIGN.md`)
A purpose-built visual contract for software interfaces:
* **Craftsmanship Standard:** Every shadow, icon, border, and color must pass a single-sentence functional justification test.
* **WCAG AA Compliance:** Strict 4.5:1 text contrast and 3:1 input border contrast against calibrated zinc/slate neutral surfaces.
* **Dial Configuration:** `ENERGY 2 / RHYTHM 2 / MOTION 2` (automatically steps down to `MOTION 1` if the user enables `prefers-reduced-motion`).
* **5 Mandatory Component States:** Every data component must handle `Default`, `Loading`, `Empty`, `Error`, and `Success` explicitly.

### 4. Modular Skill Ecosystem (`/skills`)
20 modular capability packages providing specialized execution modes:
* **`harness`:** Enforces computational verification gates (typecheck, lint, test, reachability).
* **`porter`:** Universal ecosystem adapter, suitability analyzer, and transpiler.
* **`vibecoder`:** Product-first, vibe-oriented rapid prototyping with zero-friction HTML delivery.
* **`unlazy`:** Deep completion engine for massive 10+ file refactors using Depth Trees and ledger-based verification.
* **`deep-grill`:** Socratic trade-off interviewer that rigorously probes edge cases before code is written.
* **`chisle`:** Ultra-terse, zero-fluff development mode that optimizes for maximum signal per token.
* **`procoder`:** Senior developer sprint scaffolding, specifications, and backlog tracking.
* **`antislop` (Suite of 6):** Filters out AI aesthetic slop across UI, code comments, copywriting, ergonomics, and mobile layout.
* **`diagnosing-bugs`:** Systematic seven-phase root-cause analysis preventing speculative code edits.
* **`upstream-auditor`:** Background watchdog that tracks model updates, Antigravity runtime changes, and community skill commits every 72 hours.
* **`database-migrations`:** Safe, zero-downtime database migration patterns and rollbacks.
* **`security-review`:** OWASP and authorization boundary security review.
* **`architecture-decision-records`:** Structured ADR recording and maintenance.
* **`silk-design`:** Physics-based kinetic UI formulas for marketing heroes (MOTION 3 only).
* **`audit`:** Self-calibrating structural, consistency, and boundary audit engine.

### 5. Universal Ecosystem Bridge & Transpiler (`porter.py` & `.harness/`)
The bridge enables seamless two-way portability between Antigravity and any external AI coding environment:
* **Pre-Flight Suitability & Adaptability Gate:** Analyzes incoming rules for constitutional alignment, sycophancy, AI-slop, and ecosystem redundancy before touching a single file.
* **Lossless Canonical Manifest (`.harness/manifest.json`):** Machine-readable single source of truth preserving all 20 skills, 6 subagents, and constitution rules across multi-hop migrations (A -> B -> C) with zero information decay.
* **Target Emitters:** Generates native configurations for Claude Code (`CLAUDE.md` + `.claude/commands/`), Cursor (`.cursor/rules/*.mdc`), Universal Open Standard (`AGENTS.md`), Aider (`CONVENTIONS.md` + `.aider.conf.yml`), and generic environments (Hermes, Cline, etc.).

### 6. Antigravity Guard (`agy-guard`) — OS-Level Governance Suite
`antigravity-guard` (`guard.py`, `guard/`, `bin/agy-guard`) acts as the system-level shield and companion application for your Antigravity environment:
* **Cross-Platform Write Protection:** Locks `~/.gemini/config/` against tampering by hallucinating models, unauthorized subprocesses, or rogue third-party IDE extensions using native OS primitives:
  * **Linux:** POSIX permission lockdown (0555/0444) + `chattr +i` ext4/xfs immutable flags.
  * **macOS:** BSD user-immutable flags (`chflags uchg` / `nouchg`).
  * **Windows:** NTFS Access Control Lists (`icacls /deny Everyone:(W,D)`).
* **Cryptographic File Integrity Monitor (FIM):** Maintains a deterministic SHA-256 Merkle baseline, instantly detecting modified, added, or deleted files across your custom environment.
* **1-Click Atomic Snapshot & Rollback:** Automatically captures state snapshots before any external rule ingestion or experimental configuration changes, enabling instant 1-click restoration.
* **Porter Staging Gate:** Visual and CLI bridge for `porter.py`. Provides split diff viewers, pre-flight score cards, and atomic "Unlock -> Ingest Sanitized Rule -> Re-lock" workflows.
* **Upstream Auditor Watchdog:** Proactively monitors git HEADs across the 7 tracked community repositories and checks model drift with zero LLM token consumption.
* **Dual Interface (CLI + GUI):** Full terminal workflow (`agy-guard status`, `lock`, `unlock`, `verify`, `snapshot`, `porter`, `upstream`) paired with a high-contrast, WCAG AA compliant desktop GUI (`guard.gui` / `antigravity-guard.desktop`).

---

## Directory Structure

```text
antigravity-harness/
├── GEMINI.md                          # The Global Engineering & Behavioral Constitution
├── DESIGN.md                          # Global Baseline Design Contract
├── hooks.json                         # Pre-invocation lifecycle hooks
├── install.py                         # Universal cross-platform installer (Windows, Linux, macOS, BSD)
├── install.sh                         # POSIX Unix installer (Linux, macOS, FreeBSD)
├── LICENSE                            # MIT License
├── README.md                          # Complete documentation & architecture guide
├── guard.py                           # Antigravity Guard CLI & GUI root launcher
├── porter.py                          # Universal Bidirectional Bridge & CLI Transpiler
├── .harness/
│   └── manifest.json                  # Lossless machine-readable canonical manifest
├── bin/                               # Native OS launcher executables
│   ├── agy-guard                      # POSIX shell executable (Linux / macOS)
│   ├── agy-guard.bat                  # Windows CMD batch launcher
│   └── agy-guard.ps1                  # Windows PowerShell launcher
├── guard/                             # Antigravity Guard core engine
│   ├── os_adapter.py                  # Cross-platform write protection (Linux, macOS, Windows)
│   ├── integrity.py                   # Cryptographic File Integrity Monitor (SHA-256)
│   ├── snapshot.py                    # Lightweight snapshot and rollback engine
│   ├── porter_bridge.py               # Bridge to Porter suitability & staging gate
│   ├── upstream.py                    # Bridge to Upstream Auditor watchdog
│   ├── cli.py                         # Rich command-line interface
│   └── gui.py                         # Dark-mode desktop GUI (Tkinter / DESIGN.md compliant)
├── tests/                             # Automated test suite
│   └── test_guard.py                  # Unit tests for Guard, OS adapter, FIM, and Porter
├── porter/                            # Core transpiler and analyzer modules
│   ├── analyzer.py                    # Pre-flight suitability and adaptability analyzer
│   ├── sanitizer.py                   # Constitutional de-slop & invariant filter
│   ├── manifest.py                    # Canonical manifest compiler
│   ├── parsers/                       # Format auto-detection (MDC, flat, generic)
│   └── emitters/                      # Native generators (Claude, Cursor, Universal, Aider)
├── agents/                            # 6 autonomous subagent specifications
│   ├── build-error-resolver.md
│   ├── consistency-auditor.md
│   ├── research.md
│   ├── security-boundary-verifier.md
│   ├── silent-failure-hunter.md
│   └── specification-gap-auditor.md
├── skills/                            # 20 modular capability packages
│   ├── antislop/                      # Core anti-slop design filter
│   ├── antislop-code/                 # Code comment hygiene
│   ├── antislop-copywriting/          # Anti-hype copy rules
│   ├── antislop-human/                # Accessibility & contrast rules
│   ├── antislop-layoutmobile/         # Mobile reflow & touch targets
│   ├── antislop-ui/                   # UI components & motion rules
│   ├── architecture-decision-records/ # Structured ADR engine
│   ├── audit/                         # Defensive specification & boundary audit
│   ├── chisle/                        # Minimalist zero-fluff dev mode
│   ├── database-migrations/           # Zero-downtime database patterns
│   ├── deep-grill/                    # Socratic architecture interviewer
│   ├── diagnosing-bugs/               # 7-phase root-cause debugging
│   ├── harness/                       # Computational verification pipeline
│   ├── porter/                        # Ecosystem adapter and suitability engine
│   ├── procoder/                      # Senior dev backlog & sprint chain
│   ├── security-review/               # OWASP & boundary security checklist
│   ├── silk-design/                   # Kinetic motion toolkit (MOTION 3 only)
│   ├── unlazy/                        # Tier-3 depth tree execution engine
│   ├── upstream-auditor/              # 72h model & skill sync watchdog
│   └── vibecoder/                     # Product-first rapid prototyping engine
└── templates/
    ├── HANDOFF.template.md            # Standardized cross-session handoff protocol
    └── config.example.json            # Sanitized user configuration template
```

---

## Universal Bridge CLI (`porter.py`) Usage

`porter.py` requires zero external dependencies and runs natively on Python 3.8+:

### 1. Pre-Flight Inspection (Read-Only)
Analyze any external rule, prompt, or URL before adding it to your setup:
```bash
python porter.py inspect path/to/external-rule.mdc
python porter.py inspect https://raw.githubusercontent.com/.../conventions.md
python porter.py inspect path/to/rules.md --json
```

### 2. Sanitized Ingestion (Import)
Import and clean an external rule into a native harness skill or subagent:
```bash
# Import as a modular skill
python porter.py import path/to/tailwind-rules.mdc --as-skill tailwind-v4

# Preview without writing files
python porter.py import path/to/rules.md --as-skill test-skill --dry-run
```

### 3. Outward Transpilation (Export)
Generate native configuration files for your target coding assistant or IDE:
```bash
# Export for Claude Code (CLAUDE.md + .claude/commands/)
python porter.py export --target claude --out ./

# Export for Cursor (.cursor/rules/*.mdc)
python porter.py export --target cursor --out ./

# Export for Universal Open Standard (AGENTS.md)
python porter.py export --target universal --out ./

# Export for Aider (CONVENTIONS.md + .aider.conf.yml)
python porter.py export --target aider --out ./

# Export all targets simultaneously
python porter.py export --target all --out ./export/
```

### 4. Canonical Manifest Generation
Compile the lossless machine-readable manifest (bundling all 20 skills and 76+ auxiliary subfiles):
```bash
python porter.py manifest
```

### 5. Machine-Enforced Invariant Guard (`verify_invariants.py`)
Deterministically verify code diffs and repositories against constitutional invariants (Goodhart's test weakening invariant, WCAG contrast, supply-chain checks):
```bash
# Verify current git diff
python scripts/verify_invariants.py --diff

# Full repository audit
python scripts/verify_invariants.py --all
```

---

## Quickstart & Installation

Clone the repository to your local machine:

```bash
git clone https://github.com/hadbilen/antigravity-harness.git ~/.gemini/antigravity-harness
cd ~/.gemini/antigravity-harness
```

### Option 1: Unix Fast Path (Linux, macOS, FreeBSD)

Runs natively via the POSIX `/bin/sh` shell with zero external dependencies, creating clean symlinks in `~/.gemini/config/` (existing files are safely backed up):

```bash
chmod +x install.sh
./install.sh
```

### Option 2: Windows & Universal Engine (Python)

Uses the Python standard library (zero third-party dependencies). On Windows, it handles NTFS symlinks with automatic fallback to directory junctions (`mklink /J`) or copies if Developer Mode permissions are absent:

```bash
# Windows (PowerShell or Command Prompt)
python install.py

# Unix / macOS / FreeBSD
python3 install.py
```

---

## Antigravity Guard (`agy-guard`) Quickstart

Once installed, `agy-guard` is available globally in your PATH (or via `python3 guard.py`):

```bash
# 1. Check environment security and file integrity
agy-guard status

# 2. Lock environment against writes (chattr +i / chmod 0555 / icacls)
agy-guard lock

# 3. Temporarily unlock for manual editing or maintenance
agy-guard unlock

# 4. Verify cryptographic SHA-256 baseline (detect tampered files)
agy-guard verify

# 5. Capture a timestamped snapshot of your configuration
agy-guard snapshot create --label "pre_experiment"

# 6. Inspect an external rule with Porter Suitability Gate
agy-guard porter inspect https://example.com/some_rule.md

# 7. Atomic Staging & Ingestion (Snapshots -> Unlocks -> Ingests -> Updates FIM -> Re-locks)
agy-guard porter stage ./custom_rule.md

# 8. Check tracked community repositories for upstream changes (zero LLM token cost)
agy-guard upstream check

# 9. Launch Desktop GUI
agy-guard gui
```

---

## Community Lineage & Acknowledgments

Antigravity Harness is a synthesis and hardening of collective wisdom from the open web and developer communities:

* **Reddit Communities:** Grounded in real-world debates, prompt failure post-mortems, and workflow experiments shared across [r/ChatGPTCoding](https://www.reddit.com/r/ChatGPTCoding/), [r/ClaudeAI](https://www.reddit.com/r/ClaudeAI/), and [r/LocalLLaMA](https://www.reddit.com/r/LocalLLaMA/).
* **Tracked Upstream Open-Source Projects:**
  * `miqdadbadjuber/anti-slop` — Foundational anti-slop design concepts.
  * `JayPokale/Chisle` — Terse, high-signal developer persona.
  * `Leonxlnx/unlazy` — Depth tree task completion mechanics.
  * `azrtydxb/procoder` — Senior developer backlog and sprint structures.
  * `bendrape1-byte/silk-design` — Physics-based kinetic UI formulas.
  * `affaan-m/everything-claude-code` — Architectural decisions and migration checklists.
  * `mattpocock/skills` — Socratic interview and debugging methodologies.

Rather than isolated snippets, this repository hardens these concepts into an integrated, zero-sycophancy execution environment.

---

## Contributing & License

Contributions, edge-case boundary tests, and additional auditor subagents are welcome! Please ensure any submitted skill passes the `antislop` copy filter and adheres to the `Think in Code` context hygiene standard.

Licensed under the [MIT License](LICENSE).
