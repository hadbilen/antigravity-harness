# Antigravity Harness

> **A deterministic engineering harness, behavioral constitution, and autonomous subagent ecosystem for Google Antigravity.**

Antigravity Harness bridges the gap between raw LLM intelligence and deterministic software engineering. While underlying models provide raw reasoning power, this harness enforces the execution discipline, verification gates, context hygiene, and behavioral invariants required for reliable, production-grade autonomous development.

---

## The Problem: Why This Exists

Agentic coding tools frequently stumble into three failure modes:

1. **The Sycophancy Trap:** Agents reflexively agree with user premises, gloss over architectural flaws, and bury actionable diagnosis under polite conversational filler.
2. **Test Weakening (Goodhart's Curse):** When encountering a failing test, agents often edit the assertion, skip the test (`skip`), or mock the contract just to get a green exit code.
3. **AI-Slop Explosion:** Generating generic purple SaaS templates, unverified placeholder metrics ("10,000+ happy users"), and ignoring accessibility (WCAG AA) standards.
4. **Context Bloat & Analysis Paralysis:** Reading megabytes of raw log files into conversation history, causing severe context rot and hallucinated solutions.

**Antigravity Harness** eliminates these behaviors through computational gates, an immutable test invariant, and independent auditor subagents.

---

## The Four Pillars

```
                     ┌───────────────────────────────────────────────┐
                     │          The Engineering Constitution         │
                     │  - Proportional Gate Escalation (Tier 1/2/3)  │
                     │  - The Immutable Test Invariant (No Weaken)   │
                     │  - Think in Code (Zero Context Bloat)         │
                     └───────────────────────┬───────────────────────┘
                                             │
               ┌─────────────────────────────┼─────────────────────────────┐
               ▼                             ▼                             ▼
┌─────────────────────────────┐┌───────────────────────────┐┌─────────────────────────────┐
│    Autonomous Subagents     ││   Modular Skill System    ││   Baseline Design Contract  │
│ - silent-failure-hunter     ││ - harness & unlazy (Gates)││ - Zero purple-gradient slop │
│ - security-boundary-verifier││ - deep-grill (Interview)  ││ - Strict WCAG AA contrast   │
│ - specification-gap-auditor ││ - procoder & chisle       ││ - ENERGY/RHYTHM/MOTION dials│
│ - consistency-auditor       ││ - antislop (6 UI modules) ││ - 5 mandatory UI states     │
│ - build-error-resolver      ││ - upstream-auditor (72h)  ││ - Mobile horizontal lock    │
└─────────────────────────────┘└───────────────────────────┘└─────────────────────────────┘
```

### 1. The Engineering Constitution (`GEMINI.md`)
- **Proportional Gate Escalation:** Eliminates over-engineering. Tier 1 (<20 lines) bypasses planning artifacts. Tier 2 (3–8 files) triggers Blast Radius Mapping and Call-Graph Reachability checks. Tier 3 (>8 files or auth/schema changes) mandates the full harness pipeline.
- **The Immutable Test Invariant:** An agent is strictly prohibited from altering test assertions or skipping tests to pass a gate. Tests must target contract boundaries (*seams*), not private implementation details. Source code must fix the test—never the reverse.
- **Think in Code Context Hygiene:** The agent must never dump whole files or massive logs into the context window. It parses and filters state using targeted shell pipelines (`grep`, `jq`, `awk`).
- **Circuit Breaker & Oscillation Guard:** Caps fix passes to ~10% blast radius and halts editing loops when code oscillations (state A <-> B) or repeating errors are detected.
- **Failure Logging (`MISTAKES.md`):** Every defect is logged with Root Cause, Impact, and Preventive Invariant. Patterns recurring 3 times are promoted to permanent constitutional rules.

### 2. Independent Auditor Subagents (`/agents`)
The primary model cannot grade its own work. Specialized read-only subagents evaluate risk boundaries prior to delivery:
* **`silent-failure-hunter`:** Scans for swallowed exceptions (`catch {}`), missing logs, and dangerous fallback returns.
* **`security-boundary-verifier`:** Executes concrete negative test cases against IDOR, injection vectors, SSRF, and concurrency (TOCTOU) race conditions.
* **`specification-gap-auditor`:** Identifies unhandled edge cases, omissions in requirements, and vague adjectives (*"fast"*, *"scalable"*).
* **`consistency-auditor`:** Detects axiomatic contradictions, circular dependencies, and broken cross-references across multi-volume specifications.
* **`build-error-resolver`:** Proactively isolates TypeScript and compiler breaks with minimal, non-architectural diffs.

### 3. Baseline Design Contract (`DESIGN.md`)
A purpose-built visual contract for software interfaces:
* **Craftsmanship Standard:** Every shadow, icon, border, and color must pass a single-sentence functional justification test.
* **WCAG AA Compliance:** Strict 4.5:1 text contrast and 3:1 input border contrast against calibrated zinc/slate neutral surfaces.
* **Dial Configuration:** `ENERGY 2 / RHYTHM 2 / MOTION 2` (automatically steps down to `MOTION 1` if the user enables `prefers-reduced-motion`).
* **5 Mandatory Component States:** Every data component must handle `Default`, `Loading`, `Empty`, `Error`, and `Success` explicitly.

### 4. Modular Skill Ecosystem (`/skills`)
18 modular skills providing specialized execution modes:
* **`harness`:** Enforces computational verification gates (typecheck, lint, test, reachability).
* **`unlazy`:** Deep completion engine for massive 10+ file refactors using Depth Trees and ledger-based verification.
* **`deep-grill`:** Socratic trade-off interviewer that rigorously probes edge cases before code is written.
* **`chisle`:** Ultra-terse, zero-fluff development mode that optimizes for maximum signal per token.
* **`procoder`:** Senior developer sprint scaffolding, specifications, and backlog tracking.
* **`antislop` (Suite of 6):** Filters out AI aesthetic slop across UI, code comments, copywriting, ergonomics, and mobile layout.
* **`diagnosing-bugs`:** Systematic seven-phase root-cause analysis preventing speculative code edits.
* **`upstream-auditor`:** Background watchdog that tracks model updates, Antigravity runtime changes, and community skill commits every 72 hours.

---

## Directory Structure

```text
antigravity-harness/
├── GEMINI.md                          # The Global Engineering & Behavioral Constitution
├── DESIGN.md                          # Global Baseline Design Contract
├── hooks.json                         # Pre-invocation lifecycle hooks
├── install.sh                         # Automated symlink installer
├── LICENSE                            # MIT License
├── README.md                          # Complete documentation & architecture guide
├── agents/                            # 5 independent auditor subagent specifications
│   ├── build-error-resolver.md
│   ├── consistency-auditor.md
│   ├── security-boundary-verifier.md
│   ├── silent-failure-hunter.md
│   └── specification-gap-auditor.md
├── skills/                            # 18 modular capability packages
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
│   ├── procoder/                      # Senior dev backlog & sprint chain
│   ├── security-review/               # OWASP & boundary security checklist
│   ├── silk-design/                   # Kinetic motion toolkit (MOTION 3 only)
│   ├── unlazy/                        # Tier-3 depth tree execution engine
│   └── upstream-auditor/              # 72h model & skill sync watchdog
└── templates/
    └── config.example.json            # Sanitized user configuration template
```

---

## Quickstart & Installation

### Option 1: Automated Symlink Installer (Recommended)

Clone the repository and run the installation script. This symlinks the constitution, design system, subagents, and skills directly into your local `~/.gemini/config/` without overwriting existing files (existing assets are safely backed up):

```bash
git clone https://github.com/<your-username>/antigravity-harness.git ~/.gemini/antigravity-harness
cd ~/.gemini/antigravity-harness
chmod +x install.sh
./install.sh
```

### Option 2: Manual Installation

If you prefer to configure components manually:
1. Link `GEMINI.md` and `DESIGN.md` into `~/.gemini/config/`.
2. Copy or symlink `agents/*.md` into `~/.gemini/config/agents/`.
3. Copy or symlink `skills/*` into `~/.gemini/config/skills/`.
4. Copy `hooks.json` to `~/.gemini/config/hooks.json`.

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
