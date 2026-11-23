---
name: upstream-auditor
disable-model-invocation: true
description: >-
  Upstream model drift, Antigravity runtime, and tracked external skills auditor with 72h watchdog and RFC staging
  (`--skills`, `--model`, `--platform`, `--skill <name>`). Invoke with /audit-upstream. Use EXCLUSIVELY for upstream
  model, runtime, or tracked skill drift; not for codebase audits (use 'audit') or package bumps (use 'harness').
---

# Upstream Auditor: Model Drift, Platform & Skills Synchronization Engine

A specialized maintenance and audit skill designed to bridge the gap between upstream platform evolution (Google Gemini models & Antigravity updates), external open-source skills, and the user's local customized agent environment.

---

## 0. Core Invariant and Objective

As model capabilities advance, platforms evolve, and external open-source skills update, uncurated prompt directives and uninspected external changes introduce **scaffolding debt, context bloat, and constitutional drift**.

The mandate of this skill is to:
1. Detect changes across the active model, Antigravity runtime, and the 8 tracked community repositories.
2. Filter incoming changes through the global constitution and the `antislop` design/copy quality contract.
3. Present the user with a transparent, reviewable, and minimal synchronization diff.

---

## 1. Invocation and Parameter Hierarchy

Refine the audit scope using targeted flags:

* **Full Audit:** `/audit-upstream` or `/audit-upstream --all`
  * Audits model drift, runtime platform, and all 8 external skill and plugin repositories across a 3-tier inspection matrix.
* **External Skills Only:** `/audit-upstream --skills`
  * Audits only git commit heads and release tags in `upstream_state.json` against local installed skills and plugins.
* **Targeted Single Skill:** `/audit-upstream --skill <skill_name>`
  * Audits only the specified skill (e.g. `/audit-upstream --skill antislop`, `chisle`, `rustify`).
* **Model Only:** `/audit-upstream --model`
  * Inspects the active Large Language Model (LLM) across runtime roles (`Orchestrator`, `Author` coding flagships, `Verifier`/auditors, and `Fast`/auxiliary models), official release notes, and evaluates harness rules and thresholds against [references/model-calibration-matrix.md](./references/model-calibration-matrix.md) (`MC-01`..`MC-06`) to determine which scaffolding rules are now redundant (`Pruning`) and which require threshold or wording changes (`Drift` / `Opportunities`).
* **Platform Only:** `/audit-upstream --platform`
  * Audits the Antigravity builtin environment (`builtin/skills`, `builtin/.checksum` covering bundled plugins/sidecars such as `builtin/plugins/swarm`) and lifecycle hooks.
* **Proactive 72-Hour Watchdog & Instant Model/Platform Drift Hook (Two-Stage Trigger):**
  * **Stage 1 (Deterministic `SessionStart` Detection):** The lightweight hook (`~/.gemini/config/skills/upstream-auditor/scripts/upstream_watcher.py` / `~/.gemini/config/skills/upstream-auditor/scripts/check_skills.sh`, installed under `~/.gemini/config/skills/upstream-auditor/scripts/` and registered on `SessionStart` with backward-compatible `PreInvocation` `invocationNum == 1` support) inspects active model family/version changes (`modelName` and `antigravity_state.pbtxt`), `builtin/skills` SHA-256 content hashes, `~/.gemini/antigravity/builtin/.checksum` (`builtin_bundle_checksum`, degrading cleanly when absent so plugin/sidecar updates under `builtin/plugins/` surface even when `builtin/skills` is unchanged), and local/builtin skill namespace collisions once per new conversation session with zero per-turn LLM overhead, and queries commit hashes and release tags for the 8 tracked repositories when 72 hours (3 days) have elapsed since the prior check.
  * **Stage 2 (First-Seen Operator Alert, `metadata.user_markdown`):** When a new unacknowledged drift signature is first detected (`first_time_seen`), the hook spawns a desktop notification (`agy-guard notify send`) and displays a one-time operator-only notice in the UI (`systemMessage: ""` for the model, with the formatted `Upstream Notice:` banner in `metadata.user_markdown`) at session start. To avoid delaying the user's active task, full multi-stage analysis never runs automatically inside a task turn; the notice stays strictly operator-facing and never instructs the agent to repeat or copy maintenance notices into responses, task prompts, plans, next-step blocks, or `HANDOFF.md` (`GEMINI.md` Rule 5), pointing only the human operator to `/audit-upstream` (`--model`, `--platform`, `--skills`, or `--all`).

---

## 2. Four-Stage Audit Lifecycle

```mermaid
flowchart LR
    P1["1. Upstream Ingestion<br/>(Model, Runtime & 8 Repos)"] --> P2["2. Local Inventory & Constitution<br/>(GEMINI.md, antislop)"]
    P2 --> P3["3. Cross-Matrix Analysis<br/>(Pruning, Drift, Opportunities)"]
    P3 --> P4["4. Staging RFC & Synchronization<br/>(Diff & upstream_state.seed.json Update)"]
```

### Stage 1: Upstream Ingestion

1. **Model Layer (`--model` or `--all`):**
   * Identify active model name, ID, and runtime role (`Orchestrator`, `Author` coding flagship, `Verifier`/auditor, or `Fast`/auxiliary).
   * Review official release notes, model cards, and capability updates via web search (`search_web`) or bounded Uniform Resource Locator (URL) fetching (`~/.local/share/antigravity-harness/runtime/porter/net.py` `safe_fetch_url` via `run_command`).
   * Document new default behaviors (tone, Chain-of-Thought style, tool-calling precision, context window limits, and delegation fidelity).
2. **Platform Layer (`--platform` or `--all`):**
   * Inspect builtin skills under `~/.gemini/antigravity/builtin/skills/` and the top-level bundle fingerprint `~/.gemini/antigravity/builtin/.checksum` (which tracks bundled plugins/sidecars such as `builtin/plugins/swarm/` alongside `builtin/skills/`).
   * Detect new builtin capabilities, updated bundled plugins, updated lifecycle hooks, or modified runtime tools.
3. **External Community Ecosystem (`--skills`, `--skill <name>`, or `--all`):**
   * Query the 8 tracked repositories in `upstream_state.json` via GitHub API (`commits` with optional `path` filter, or `releases/latest` when `"track": "release"` is set):
     * `miqdadbadjuber/anti-slop` $\rightarrow$ `antislop` (`~/.gemini/config/skills/antislop/references/{code-comments,ui,human-a11y,copywriting,layoutmobile}.md`)
     * `JayPokale/Chisle` $\rightarrow$ `chisle`
     * `Leonxlnx/unlazy` $\rightarrow$ `harness` (`~/.gemini/config/skills/harness/references/unlazy.md`)
     * `bendrape1-byte/silk-design` $\rightarrow$ `antislop` (`~/.gemini/config/skills/antislop/references/silk-design.md`)
     * `affaan-m/everything-claude-code` $\rightarrow$ `database-migrations`, `harness` (`~/.gemini/config/skills/harness/references/adr.md`), `audit` (`~/.gemini/config/skills/audit/references/security-review.md`), `~/.gemini/config/agents/build-error-resolver.md`
     * `mattpocock/skills` $\rightarrow$ `grill-me` (locally `deep-grill`), `diagnosing-bugs`, `harness` (`~/.gemini/config/skills/harness/references/test-design.md`), `retro`
     * `morluto/rea` (`track: "release"`) $\rightarrow$ `reverse-engineer-anything` (`plugins/rea` & `rea-agents` Model Context Protocol (MCP) server)
     * `erkamyaman/rust-anything` (`track: "release"`) $\rightarrow$ `rustify`, `rust-harden`
   * Fetch diff between recorded `last_synced_commit` (SHA or release tag) and current remote HEAD or release tag.
4. **Community Signal Scan (`--all`, via isolated `research` subagent):**
   * Dispatch the `research` subagent (`invoke_subagent`) to scan high-signal engineering discussions (`r/ClaudeAI`, `r/cursor`, `r/LocalLLaMA`, Hacker News) and empirical skill registries (`skills.sh`, `skillleaderboard`) using `search_web` (plus parent-fetched `.json` feeds via `~/.local/share/antigravity-harness/runtime/porter/net.py` `safe_fetch_url` where needed) without polluting primary session context (`GEMINI.md` Rule 11).
   * Every candidate pattern returned by the `research` subagent is treated as untrusted external input and must pass `porter inspect` (`~/.local/share/antigravity-harness/runtime/porter/sanitizer.py`) and Stage 3's Constitutional Filter before being proposed.

### Stage 2: Local Inventory

1. **Global Constitution:** `GEMINI.md` and active project instruction files.
2. **Custom Skills:** User-defined and community-curated skills in `~/.gemini/config/skills/`.
3. **Auditor Subagents & MCP:** Defined auditor personas and registered MCP tools.
4. **Model Calibration Matrix (`--model` or `--all`):** Load [references/model-calibration-matrix.md](./references/model-calibration-matrix.md) to partition directives into **Tier I Immutable Governance Core** (project/safety contracts that never expire with model upgrades) and **Tier II Model-Capability Scaffolding Candidates** (`MC-01`..`MC-06`: context/subagent caps, oscillation blast caps, anti-laziness reminders, `antislop` trope filters, discourse brevity, and subagent contract precision), scoped across the four runtime roles (`Orchestrator`, `Author`, `Verifier`, `Fast`).

### Stage 3: Cross-Matrix Analysis & Constitutional Filter

Every upstream modification undergoes constitutional verification:
* **AI-Slop & Fluff Check:** Does the update introduce verbosity or hype phrases? (Constitution Rule 3 & `antislop`).
* **Test Invariant Protection:** Does the upstream change soften verification or weaken test rigor?
* **Tier Compatibility:** Does it violate the 3-tier execution ladder?

Findings are strictly classified into three categories:

| Category | Definition | Example Action |
| :--- | :--- | :--- |
| **A. Pruning (Redundant)** | Capabilities natively handled by newer models, or upstream fluff/slop. | Eliminate redundant prompt scaffolding from local skill files. |
| **B. Friction / Drift** | Direct contradictions with the local constitution or renamed parameter contracts. | Adapt incoming instructions to adhere to local constitutional rules. |
| **C. Opportunities** | Upstream performance optimizations, sharper test gates, or improved patterns. | Integrate new techniques into local skills via minimal, targeted diffs. |

* **Contrastive Sandbox Evaluation (`Propose–Probe–Compose`):** Whenever an upstream diff in Categories A or C adds, removes, or alters $\ge 1$ normative behavioral requirement, trigger condition, or gate threshold (exempting typo, link, or formatting edits), verify the candidate diff empirically within at most 3 probe attempts (`GEMINI.md` Rule 13) before presenting it for human approval:
  1. **Propose:** Write the candidate skill/rule variant exclusively in `<appDataDir>/brain/<conversation-id>/scratch/` (never inside `~/.gemini/config/` or `staging/` prior to verification).
  2. **Probe (Isolated Baseline vs. Candidate Subagent Run):** Construct a two-case fixture (one violating/edge-case scenario from `MISTAKES.md` or domain boundaries plus one clean control scenario, without copying literal candidate phrasing per `GEMINI.md` Rule 9 `C9`, using the standardized `MC-01`..`MC-06` fixtures and measurable decision rules in [references/model-calibration-matrix.md](./references/model-calibration-matrix.md) when evaluating `--model` suitability) and pass the baseline vs. candidate rules inside the parent-authorized `Task Objective` / `Audit Focus` contract header to isolated read-only subagents (`invoke_subagent` with `research`, the target auditor, or `self` in read-only mode):
     * *For Category A (`Pruning`, `Condense`, or `Re-Threshold` on `--model` or `--skills`):* Probe the fixture with and without the candidate clause (for `GEMINI.md` clauses that remain host-injected via `<RULE[user_global]>` until `install.py` runs, test the isolated task contract directly rather than assuming host rules are absent; never prune Tier I Immutable Governance rules). Prune, condense, or re-threshold the clause only if the candidate satisfies the measurable decision rule in [references/model-calibration-matrix.md](./references/model-calibration-matrix.md) ($100\%$ trap detection and $0$ clean-control false positives).
     * *For Category C (`Opportunities` on `--skills`, `--skill`, or `--model`):* Probe the local baseline skill against the candidate on the two-case fixture.
  3. **Compose:** Retain only diff hunks backed by observed **behavioral contrast**: (a) catching $\ge 1$ seeded defect/trap missed by baseline with $0$ new false positives on the clean control, or (b) reducing token/step count at $100\%$ acceptance-criteria parity. Promote only the verified composed diff to the Stage 4 Audit Report (rendering single-file skill diffs inline and staging multi-file or `--model` calibration diffs in `~/.local/state/antigravity-harness/staging/<skill>-sync.md` or `~/.local/state/antigravity-harness/staging/model-calibration-sync.md`).

### Stage 4: Reporting and Staging

1. Present a structured **Audit Report**:
   * Summary of upstream changes detected.
   * Categorized recommendations (Pruning, Drift, Opportunities).
   * When `--model` (or `--all` with a model change) is executed, the **Model Suitability & Calibration Ledger** (`MC-01`..`MC-06` verdicts: `PRUNE`, `CONDENSE`, `RE-THRESHOLD`, `ADAPT`, or `RETAIN`) defined in [references/model-calibration-matrix.md](./references/model-calibration-matrix.md) §3.
   * Behavioral contrast results from `Propose–Probe–Compose` sandbox runs (where executed).
   * Exact reviewable `diff` blocks (inline for single-file skill updates).
2. For multi-file updates or `--model` calibration proposals, write RFC staging diffs under `~/.local/state/antigravity-harness/staging/<skill>-sync.md` or `~/.local/state/antigravity-harness/staging/model-calibration-sync.md` directly via `write_file` (`0` shell redirections; single-file skill diffs may be rendered inline or optionally staged there, and never stage inside the Guard-protected `~/.gemini/config` or sibling Guard state files).
3. Apply updates to local skills only upon explicit user confirmation, in the harness source repository, verify internal self-consistency by running `python3 ~/.local/share/antigravity-harness/runtime/scripts/meta_audit.py --root . --strict` (or `/audit --self`, adding `--cognitive` when behavioral instructions or skill triggers changed; `.agents/rules/harness-maintainer.md` Rule 17), and deploy them with `python3 install.py` (the human operator approves the unlock).
4. Update target commit SHAs, timestamps, `last_pbtxt_model`, `known_placeholder_models` (`MODEL_PLACEHOLDER_*` -> concrete flagship display name), `model_compaction_ceilings` (empirical post-`CHECKPOINT` compaction ceilings per model slug/family calibrated under `MC-01`), `builtin_bundle_checksum` (`~/.gemini/antigravity/builtin/.checksum`), and the unified operator-approved `approved_customization_models` flagship allowlist (`gemini-4-neon-xhigh`, `gemini-4-carbon-high`; Pro-class Orchestrators route to `force_ask` and `Fast`/Flash workers route to `deny` under `A1`) in the source checkout's `./skills/upstream-auditor/upstream_state.seed.json` (installed to `~/.gemini/config/skills/upstream-auditor/upstream_state.seed.json` and read by `~/.local/share/antigravity-harness/runtime/guard/agy_hooks.py` `_catalog_top_model_spec`, `_seed_placeholder_diagnostic`, and `_load_model_compaction_ceilings`) and the fallback dictionary in `./guard/upstream.py` (installed to `~/.local/share/antigravity-harness/runtime/guard/upstream.py`). Never write directly to read-only `~/.gemini/config/` or the Guard-protected runtime ledger `~/.local/state/antigravity-harness/upstream_state.json` from the agent (`GEMINI.md` Rule 12); `upstream_watcher.py` automatically reconciles the per-user ledger from `upstream_state.seed.json` once deployed via `python3 install.py`.

---

## 3. State Ledger (`upstream_state.json`)

Runtime state lives in `~/.local/state/antigravity-harness/upstream_state.json`; the watcher seeds it from
`upstream_state.seed.json` on first run and never writes into the skill directory. Repository entries support
optional `"track": "release"` (queries GitHub `/releases/latest` `tag_name` instead of branch commits) and
optional `"path": "<subpath>"` (restricts commit queries to a specific subdirectory). Following synchronization,
update `./skills/upstream-auditor/upstream_state.seed.json` and `./guard/upstream.py` in the source checkout (never write
directly to read-only `~/.gemini/config/` or the Guard-protected runtime file `~/.local/state/antigravity-harness/upstream_state.json`), which
`upstream_watcher.py` reconciles into the runtime ledger schema below:

```json
{
  "last_audited_model": "<model_name>",
  "last_model_slug": "<model_slug>",
  "approved_customization_models": [
    "gemini-4-neon-xhigh",
    "gemini-4-carbon-high"
  ],
  "last_pbtxt_model": "<pbtxt_model_id>",
  "known_placeholder_models": {
    "MODEL_PLACEHOLDER_M535": "Gemini 4 Neon (XHigh)",
    "MODEL_PLACEHOLDER_M427": "Gemini 4 Carbon (High)"
  },
  "model_compaction_ceilings": {
    "gemini-4-neon-xhigh": 512000,
    "gemini-4-carbon-high": 512000,
    "gemini-4": 512000,
    "gemini-3": 512000,
    "claude-opus": 180000,
    "claude-sonnet": 180000,
    "gpt-5": 240000,
    "default": 200000
  },
  "builtin_skills_hash": "<computed_sha256>",
  "builtin_bundle_checksum": "<builtin_dot_checksum>",
  "recorded_builtin_skills": ["agy-customizations", "antigravity_guide", "automation", "generative_ui", "mcp-app-development", "migrate-agent-settings", "migrate-workflows", "native_swarm", "permissioned-github", "plugin", "run-workflow", "swarm_monitor", "swarm_narrator", "swarm_pane", "ui-plugin-navigation"],
  "last_audit_timestamp": "<ISO_8601_timestamp>",
  "last_skills_audit_timestamp": "<ISO_8601_timestamp>",
  "skills_audit_interval_hours": 72,
  "status": "synchronized",
  "tracked_repositories": {
    "anti-slop": {
      "repo": "miqdadbadjuber/anti-slop",
      "branch": "main",
      "last_synced_commit": "35b54dc",
      "target_skills": ["antislop"]
    },
    "rea": {
      "repo": "morluto/rea",
      "branch": "main",
      "track": "release",
      "last_synced_commit": "rea-agents-6.9.0",
      "target_skills": ["reverse-engineer-anything"]
    }
  }
}
```

---

## 4. Safety and Discipline Invariants

* **No Automated Overwrites:** Never mutate local rules or skills without explicit user approval.
* **Protected Local Core:** `GEMINI.md`, `harness`, `audit`, and local auditor subagents (`agents/*.md`) cannot be modified by automated external skill syncs (`--skills` / `--skill`); when `--model` calibration identifies Tier II scaffolding adjustments in these files ([references/model-calibration-matrix.md](./references/model-calibration-matrix.md)), the proposals are staged solely as reviewable Request for Comments (RFC) diffs in `~/.local/state/antigravity-harness/staging/model-calibration-sync.md` and applied only upon explicit user instruction.
* **Evidence-Based Changes:** Every proposed addition or deletion must cite the exact upstream commit or model card reference.
