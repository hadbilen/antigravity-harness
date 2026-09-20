# Antigravity Harness

[![Release](https://img.shields.io/badge/release-v1.2.9-blue.svg)](https://github.com/hadbilen/antigravity-harness/releases/tag/v1.2.9)
[![CI Matrix](https://img.shields.io/badge/CI-Linux%20%7C%20macOS%20%7C%20Windows-success.svg)](https://github.com/hadbilen/antigravity-harness/actions)
[![Python Stdlib](https://img.shields.io/badge/dependencies-zero%20external-brightgreen.svg)](https://github.com/hadbilen/antigravity-harness)
[![Design Standard](https://img.shields.io/badge/UI-WCAG%20AA%20%7C%20antislop-orange.svg)](DESIGN.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **OS-level write protection, cryptographic integrity governance, and deterministic engineering harness for AI coding agents.**

Antigravity Harness bridges the gap between raw LLM intelligence and deterministic production software engineering. While modern models provide powerful reasoning, autonomous agents left unshielded suffer from **environment mutation drift**, **sycophancy**, **test weakening (Goodhart's Curse)**, and **context bloat**.

Antigravity Harness resolves these vulnerabilities through operating system write protection, cryptographic file integrity monitoring, full-state snapshot rollbacks, an immutable behavioral constitution, independent auditor subagents, and a bidirectional ecosystem bridge across Google Antigravity, Claude Code, Cursor, Windsurf, Aider, and generic platforms.

---

## The Problem: Why This Exists

Autonomous coding agents frequently encounter five systemic failure modes:

1. **Environment Mutation Drift & Rogue Writes:** Hallucinating agents, rogue sub-processes, or third-party IDE extensions can quietly overwrite prompt contracts, disable linting gates, or inject unverified skills into `~/.gemini/config/`.
2. **The Sycophancy Trap:** Models reflexively agree with user premises, gloss over critical architectural flaws, and bury actionable diagnosis under polite conversational filler.
3. **Test Weakening (Goodhart's Curse):** When encountering a failing test, agents often edit the assertions, skip tests (`skip`), or weaken error boundaries just to manufacture a green exit code.
4. **Context Bloat & Analysis Paralysis:** Reading megabytes of raw logs and entire codebases into the conversation window triggers attention degradation, looping regressions, and hallucinated fixes.
5. **Ecosystem Fragmentation & Information Decay:** Directives configured for one tool cannot be ported without manual rewriting, causing severe specification decay across multi-hop migrations (A -> B -> C).

---

## Architectural Pillars

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

---

## 1. Flagship: Antigravity Guard (`agy-guard` CLI & GUI)

`antigravity-guard` (`guard/`, `guard.py`, `bin/agy-guard`) is the **system-level shield and governance companion application** for your autonomous AI development environment. It guarantees tamper-resistance, deterministic rollbacks, and zero-token upstream drift detection.

### OS-Level Write Shield (`guard/os_adapter.py`)
Locks configuration directories (`~/.gemini/config/`) against unauthorized modification using native operating system primitives:
* **Linux:** POSIX permission lockdown (`chmod a-w` / `0555` user-space lock) paired with optional ext4/xfs immutable flags (`chattr -R +i`).
* **macOS:** Native BSD user-immutable flags (`chflags -R uchg` / `nouchg`).
* **Windows:** NTFS Access Control Lists (`icacls`) with granular specific rights `(WD,AD,DE,DC)` preventing file addition, modification, and deletion while strictly preserving `READ_CONTROL` for hashing under lock. Recursively strips inherited deny ACEs via `/t /c /q`.

### Automated Health & Auto-Healing (`agy-guard doctor [--fix]`)
A dedicated diagnostic routine that audits the health of the development harness:
* Inspects write shield state, trust anchor placement, FIM integrity, and snapshot inventory.
* Detects crash-induced unshielded environments (SIGKILL, abnormal exits) and automatically heals stale exposures via `--fix` / `--recover`.

### Full-State Snapshot Rollback & Extraneous Pruning (`guard/snapshot.py`)
Standard backup utilities merely overwrite existing files, leaving rogue files introduced after the backup intact. Antigravity Guard performs **true bidirectional state synchronization**:
* Computes complete filesystem diffs between the snapshot and current tree.
* Recursively prunes extraneous files and rogue directories introduced after the snapshot was captured.
* Preserves critical infrastructure (`.guard_snapshots`, `__pycache__`, `.git`, `.guard_integrity.json`, emergency backups).

### Isolated Cryptographic Trust Anchor (`guard/integrity.py`)
* Computes deterministic SHA-256 Merkle baselines across all constitutional files, skills, subagents, and configurations.
* Supports hosting the integrity baseline outside the protected directory via `ANTIGRAVITY_INTEGRITY_FILE` (or `~/.gemini/.guard_integrity.json`), physically decoupling the baseline from the target configuration to eliminate simultaneous tampering.

### Dual Operational Interfaces (Ergonomic CLI + Dark GUI)
* **Full CLI Workflow (`bin/agy-guard`):** `status`, `lock`, `unlock`, `verify`, `rebaseline`, `snapshot`, `porter`, `doctor`, `upstream`, and `gui`.
* **Zero-Dependency Desktop GUI (`guard/gui.py`):** Built strictly on Python's native standard library (`tkinter` / `ttk`). Follows `DESIGN.md` (ENERGY 2 / RHYTHM 2 / Dark Zinc palette) with verified WCAG AA contrast, real-time FIM auditing, and split-diff external rule staging.

---

## 2. The Engineering Constitution (`GEMINI.md`)

The core behavioral constitution eliminates context bloat, analysis paralysis, and AI sycophancy:

* **Proportional Gate Escalation:** Eliminates excessive ceremony for small changes while strictly locking down large ones:
  * *Tier 1 (1–2 files, <20 lines):* Direct edits, no planning artifacts, zero subagent dispatch.
  * *Tier 2 (3–8 files):* Implementation plans, blast radius mapping, call-graph reachability, and persistent execution checklists.
  * *Tier 3 (>8 files or auth/schema modifications):* Full harness workflow, trade-off interviews (`deep-grill`), ADR documentation, depth trees (`unlazy`), and pre-delivery independent auditor subagent dispatch.
* **The Immutable Test Invariant (Goodhart's Invariant):** Agents are strictly forbidden from relaxing assertions, skipping tests (`skip`), or commenting out assertions to pass verification gates. Tests must target public interface seams—source code must fix the test, never the reverse.
* **Think in Code Context Hygiene:** Agents must never dump raw multi-megabyte files into conversation context. They isolate streams, use targeted Unix pipelines (`grep`, `jq`, `awk`), and execute one-off inspection scripts in scratch directories.
* **Circuit Breaker & Out-of-Band Meta-Diagnosis:** Caps modifications to ~10% blast radius per fix pass. If 3 consecutive iterations oscillate or repeat identical failures, the parent halts and dispatches an isolated diagnostic subagent (`Model: 'pro'`) with an unpolluted context.
* **Popper's Falsification Gate (Rule 8):** Before claiming completion or asserting that no changes are needed (Null-Action), the agent must execute baseline falsification checks to actively challenge the working hypothesis.
* **Session Boundary Protocol (`HANDOFF.md`):** Mandates fresh chat sessions following major deliveries or upon reaching ~25 turns to prevent attention degradation without losing architectural context.

---

## 3. Autonomous Auditor Subagents (`/agents`)

The primary model cannot objectively grade its own work. Specialized read-only subagents evaluate risk boundaries prior to delivery:

* **`silent-failure-hunter`:** Scans code for swallowed exceptions (`catch {}`), missing logs, empty fallbacks, and unhandled promises.
* **`security-boundary-verifier`:** Verifies authorization boundaries, IDOR, input validation, SSRF immunity, and race conditions (TOCTOU).
* **`specification-gap-auditor`:** Detects unhandled edge cases, missing error branches, and ambiguous adjectives (*"fast"*, *"robust"*) in requirements.
* **`consistency-auditor`:** Evaluates multi-volume specifications and schemas for axiomatic contradictions, circular dependencies, and broken cross-references.
* **`build-error-resolver`:** Analyzes compiler and TypeScript errors in an isolated context, producing minimal, non-architectural diffs.
* **`research`:** Ingests large external documentation (>50 KB) and complex codebases in an isolated sandbox, returning distilled decision matrices without polluting the primary session context.

---

## 4. Universal Ecosystem Bridge & Transpiler (`porter.py` & `.harness/`)

A bidirectional bridge enabling lossless rule portability between Antigravity and any external AI coding platform:

* **Pre-Flight Suitability & Adaptability Gate:** Analyzes external rules (`.mdc`, `.cursorrules`, `CLAUDE.md`) before writing files, scoring them 0–100 on constitutional alignment and platform fit.
* **Constitutional Sanitizer (`porter/sanitizer.py`):** Automatically strips conversational sycophancy, AI-slop, and test-weakening directives from imported rules.
* **SSRF Protection:** Enforces strict RFC-1918, link-local metadata (`169.254.169.254`), loopback, and IPv6 DNS resolution validation during remote rule ingestion.
* **Lossless Canonical Manifest (`.harness/manifest.json`):** Single-source compilation bundling all 20 skills, 6 subagents, and constitution rules across multi-hop migrations with zero information decay.
* **Native Emitters:** Generates idiomatic configs for Claude Code (`CLAUDE.md` + `.claude/commands/`), Cursor (`.cursor/rules/*.mdc`), Universal Standard (`AGENTS.md`), Aider (`CONVENTIONS.md`), and generic environments.

---

## 5. Modular Skill Ecosystem (`/skills`)

20 specialized capability packages providing focused execution modes:

* **`harness`:** Autonomous engineering harness, computational verification gates, task lifecycle.
* **`porter`:** Ecosystem adapter, suitability analyzer, and transpiler.
* **`vibecoder`:** Product-first, vibe-oriented rapid prototyping with zero-friction HTML delivery.
* **`unlazy`:** Deep completion engine for massive 10+ file refactors using Depth Trees and ledger-based verification.
* **`deep-grill`:** Socratic trade-off interviewer that rigorously probes edge cases before code is written.
* **`chisle`:** Ultra-terse, zero-fluff development mode that optimizes for maximum signal per token.
* **`procoder`:** Senior developer sprint scaffolding, specifications, and backlog tracking.
* **`antislop` (Suite of 6):** Comprehensive design and copy quality filter:
  * `antislop`: Core 38-rule filter and delivery gate.
  * `antislop-ui`: UI layout, token systems, and component states.
  * `antislop-code`: Intelligent comment hygiene.
  * `antislop-copywriting`: Anti-hype, honest copywriting guidelines.
  * `antislop-human`: Accessibility, WCAG AA contrast checker MCP tool.
  * `antislop-layoutmobile`: Mobile reflow, zero horizontal overflow, touch targets.
* **`diagnosing-bugs`:** Systematic seven-phase root-cause analysis preventing speculative code edits.
* **`upstream-auditor`:** Background watchdog that tracks model updates, Antigravity runtime changes, and community skill commits every 72 hours.
* **`database-migrations`:** Safe, zero-downtime database migration patterns and rollbacks.
* **`security-review`:** OWASP and authorization boundary security review.
* **`architecture-decision-records`:** Structured ADR recording and maintenance.
* **`silk-design`:** Physics-based kinetic UI formulas for marketing heroes (MOTION 3 only).
* **`audit`:** Self-calibrating structural, consistency, and boundary audit engine.

---

## 6. Baseline Design Contract (`DESIGN.md`)

A purpose-built visual contract for software interfaces:
* **Craftsmanship Standard:** Every shadow, icon, border, and color must pass a single-sentence functional justification test.
* **WCAG AA Compliance:** Strict 4.5:1 text contrast and 3:1 input border contrast against calibrated zinc/slate neutral surfaces.
* **Dial Configuration:** `ENERGY 2 / RHYTHM 2 / MOTION 2` (automatically steps down to `MOTION 1` if `prefers-reduced-motion` is active).
* **5 Mandatory Component States:** Every data component must handle `Default`, `Loading`, `Empty`, `Error`, and `Success` explicitly.

---

## Directory Structure

```text
antigravity-harness/
├── GEMINI.md                          # The Global Engineering & Behavioral Constitution
├── DESIGN.md                          # Global Baseline Design Contract
├── CHANGELOG.md                       # Comprehensive changelog from v1.0.0 through v1.2.4
├── hooks.json                         # Pre-invocation lifecycle hooks
├── install.py                         # Universal cross-platform installer (Windows, Linux, macOS, BSD)
├── install.sh                         # POSIX Unix installer (Linux, macOS, FreeBSD)
├── LICENSE                            # MIT License
├── README.md                          # Complete architecture & documentation guide
├── guard.py                           # Antigravity Guard CLI & GUI root launcher
├── porter.py                          # Universal Bidirectional Bridge & Transpiler CLI
├── .github/
│   └── workflows/ci.yml               # Multi-OS CI Matrix (Linux, macOS, Windows / Python 3.10-3.12)
├── .harness/
│   └── manifest.json                  # Lossless machine-readable canonical manifest
├── bin/                               # Native OS launcher executables
│   ├── agy-guard                      # POSIX shell executable (Linux / macOS)
│   ├── agy-guard.bat                  # Windows CMD batch launcher
│   └── agy-guard.ps1                  # Windows PowerShell launcher
├── installers/                        # System menu and desktop integration
│   └── antigravity-guard.desktop      # Linux XDG Desktop Application entry
├── guard/                             # Antigravity Guard core engine
│   ├── os_adapter.py                  # Cross-platform write protection (Linux, macOS, Windows)
│   ├── integrity.py                   # Cryptographic File Integrity Monitor (SHA-256)
│   ├── test_boundary.py               # Deterministic Test & Config Trust Boundary Guard
│   ├── provenance.py                  # Run Provenance & Execution Audit Trail Manifest
│   ├── snapshot.py                    # Full-state snapshot and extraneous pruning engine
│   ├── porter_bridge.py               # Bridge to Porter suitability & staging gate
│   ├── upstream.py                    # Bridge to Upstream Auditor watchdog
│   ├── cli.py                         # Rich command-line interface
│   └── gui.py                         # Dark-mode desktop GUI (Tkinter / DESIGN.md compliant)
├── porter/                            # Universal transpiler & analyzer modules
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
├── tests/                             # Automated multi-platform test suite
│   └── test_guard.py                  # Unit tests for Guard, OS adapter, FIM, and Porter
└── templates/
    ├── HANDOFF.template.md            # Standardized cross-session handoff protocol
    └── config.example.json            # Sanitized user configuration template
```

---

## Quickstart & Installation

Clone the repository:

```bash
git clone https://github.com/hadbilen/antigravity-harness.git ~/.gemini/antigravity-harness
cd ~/.gemini/antigravity-harness
```

### Option 1: Unix Fast Path (Linux, macOS, FreeBSD)

```bash
chmod +x install.sh
./install.sh
```

### Option 2: Windows & Universal Engine (Python)

Zero third-party dependencies. On Windows, it handles NTFS symlinks with automatic fallback to directory junctions (`mklink /J`) or copies:

```bash
# Windows (PowerShell or Command Prompt)
python install.py

# Unix / macOS / Linux
python3 install.py
```

---

## Antigravity Guard (`agy-guard`) Usage

Once installed, `agy-guard` is globally available in your PATH:

```bash
# 1. Run environment health check and auto-heal stale exposures
agy-guard doctor --fix

# 2. Check environment write shield and file integrity
agy-guard status

# 3. Lock environment against writes (chattr +i / chmod 0555 / icacls)
agy-guard lock

# 4. Temporarily unlock for manual editing or maintenance
agy-guard unlock

# 5. Verify cryptographic SHA-256 baseline (detect modified/added/deleted files)
agy-guard verify

# 6. Capture a timestamped snapshot of your configuration
agy-guard snapshot create --label "pre_experiment"

# 7. Restore snapshot with full state synchronization (prunes extraneous files)
agy-guard snapshot restore <snapshot_id>

# 8. Inspect an external rule with the Porter Suitability Gate
agy-guard porter inspect https://example.com/some_rule.md

# 9. Atomic Staging & Ingestion (Snapshots -> Unlocks -> Ingests -> Re-locks)
agy-guard porter stage ./custom_rule.md

# 10. Check tracked community repositories for upstream changes (zero token cost)
agy-guard upstream check

# 11. Enable Pre-Session Boot Sentinel (Runs before AI IDEs or models start)
agy-guard startup enable

# 12. Inspect Boot Sentinel registration status
agy-guard startup status

# 13. Snapshot workspace test & configuration trust boundary
agy-guard test-boundary snapshot

# 14. Verify test suite immutability (detect fixture, timeout, or mock tampering)
agy-guard test-boundary verify --mode bugfix

# 15. Verify 2x isolated reproducibility for targeted tests (eliminate flakiness)
agy-guard test-boundary run-reproducible --cmd "pytest tests/test_core.py"

# 16. Generate session execution provenance manifest (.harness/provenance.json)
agy-guard provenance generate

# 17. Launch the Desktop GUI
agy-guard gui
```

---

## Universal Bridge CLI (`porter.py`) Usage

```bash
# Pre-flight suitability inspection (read-only scoring 0-100)
python3 porter.py inspect path/to/external-rule.mdc
python3 porter.py inspect https://raw.githubusercontent.com/.../conventions.md

# Import and sanitize external rule into native skill or subagent
python3 porter.py import path/to/tailwind-rules.mdc --as-skill tailwind-v4
python3 porter.py import path/to/rules.md --as-skill test-skill --dry-run

# Export configuration to target coding assistant
python3 porter.py export --target claude --out ./export/claude
python3 porter.py export --target cursor --out ./export/cursor
python3 porter.py export --target universal --out ./export/universal
python3 porter.py export --target all --out ./export/

# Compile the lossless canonical manifest
python3 porter.py manifest
```

---

## Verification & Continuous Integration

Every commit and pull request is automatically tested across **Linux, macOS, and Windows** on Python 3.10, 3.11, and 3.12:

```bash
# Run 21 unit tests covering OS adapters, FIM, doctor, snapshots, and Porter
python3 -m unittest discover -s tests -v

# Run deterministic invariant verification
python3 scripts/verify_invariants.py --all

# Verify active git diff against constitutional constraints
python3 scripts/verify_invariants.py --diff
```

---

## Community Lineage & Acknowledgments

Antigravity Harness synthesizes and hardens insights from real-world engineering debates and open-source projects:

* **Reddit Communities:** Grounded in prompt failure post-mortems and workflow experiments from [r/ChatGPTCoding](https://www.reddit.com/r/ChatGPTCoding/), [r/ClaudeAI](https://www.reddit.com/r/ClaudeAI/), and [r/LocalLLaMA](https://www.reddit.com/r/LocalLLaMA/).
* **Tracked Open-Source Projects:**
  * `miqdadbadjuber/anti-slop` — Foundational anti-slop design concepts.
  * `JayPokale/Chisle` — Terse, high-signal developer persona.
  * `Leonxlnx/unlazy` — Depth tree task completion mechanics.
  * `azrtydxb/procoder` — Senior developer backlog and sprint structures.
  * `bendrape1-byte/silk-design` — Physics-based kinetic UI formulas.
  * `affaan-m/everything-claude-code` — Architectural decisions and migration checklists.
  * `mattpocock/skills` — Socratic interview and debugging methodologies.

---

## Contributing & License

Contributions, boundary tests, and additional auditor subagents are welcome! Please ensure any submitted skill passes the `antislop` copy filter and adheres to the `Think in Code` context hygiene standard.

Licensed under the [MIT License](LICENSE).
