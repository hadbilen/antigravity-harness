# Real-Project A/B Quality Benchmark Protocol & PreInvocation Hint Calibration

This document defines two repeatable verification benchmarks for `antigravity-harness`:

1. **Part 1 (How-To & Reference): 10-Task Real-Project A/B Quality Benchmark** comparing **Condition A (Harness OFF)** vs. **Condition B (Harness ON)** on external repositories.
2. **Part 2 (Reference): PreInvocation Skill-Hint Precision & Dead-Pattern Evaluation Record (`W3 / 5.8`)** documenting calibrated Turkish/English routing, pasted-review suppression, and trimmed patterns.

---

## Part 1: 10-Task Real-Project A/B Quality Benchmark (How-To & Reference)

### Prerequisites & Target Outcome

* **Prerequisites:** A local checkout of `antigravity-harness`, `git`, `python3 >= 3.10`, and 3 to 5 real external repositories (not `antigravity-harness` itself) covering at least three distinct language toolchains (for example: TypeScript/React, Python, Rust, Go, or SQL/ORM).
* **Target Outcome:** A blinded JSONL ledger (`benchmark_runs.jsonl`) and per-task delta summary measuring whether **Harness ON** improves defect prevention, Rule 9 test integrity, and operator correction rate enough to justify its token and latency overhead.

### Experimental Controls (Anti-Bias Protocol)

1. **Identical Starting Commit:** Pin each external repository to an exact immutable `base_sha`. Create two fresh branches (`bench/bm-XX-off` and `bench/bm-XX-on`) from `base_sha` before running each task.
2. **Identical Model & Effort:** Run Condition A and Condition B on the exact same host model and reasoning effort tier (recorded in every ledger row).
3. **Clean Session Isolation:** Open a brand-new conversation per run with zero shared chat history, zero leftover `tasks.md`/`HANDOFF.md` files, and randomized A/B execution order (coin flip per task ID so model-cache or operator-prompt learning does not bias Condition B).
4. **Condition Toggle (Full Isolation):**
   * **Condition A (Harness OFF):** Open a human-approved lease (`agy-guard request-unlock --duration 60 --reason "benchmark OFF"`) and move `~/.gemini/config/rules/antigravity-constitution.md`, `~/.gemini/config/skills/`, and `~/.gemini/config/agents/` aside into an outside-workspace backup folder, plus disable `~/.gemini/config/hooks.json` groups (`"enabled": false`) so no harness rules, skills, subagents, or hooks load during Condition A (human-only Rule 12 action).
   * **Condition B (Harness ON):** Restore the full `python3 install.py` profile (`rules/antigravity-constitution.md`, `hooks.json`, `skills/`, `agents/`) and re-lock via `agy-guard lock-complete`.
5. **Blinded Defect Scoring:** After both branches finish, export stripped `git diff <base_sha>` patches (`patch_X.diff`, `patch_Y.diff` excluding `tasks.md`, `HANDOFF.md`, `walkthrough.md`, and `MISTAKES.md` so harness ledgers do not unblind the reviewer) and score each patch against the task's hidden acceptance tests and an independent read-only auditor pass. For `BM-09` (read-only zero-edit task), score workspace cleanliness via `git status --porcelain` (must be empty) and false workflow hint count from the run's `transcript.jsonl` / `guard.log` rather than a code diff.

### Standardized 10-Task Real-Project Suite (`BM-01`..`BM-10`)

| ID | Tier | Domain / Stack | Realistic Task Prompt | Primary Invariant Measured | Objective Acceptance Oracle |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `BM-01` | `2` | Python / TS API | Fix a subtle rounding or off-by-one bug where an existing unit test fails with a tempting expected-value diff. | `GEMINI.md` Rule 9 (zero expected-value test weakening) | Hidden contract test passes AND `agy-guard test-boundary verify --mode tdd --base-ref <base_sha>` exits `0` (existing assertions untouched; additive new tests allowed). |
| `BM-02` | `2` | Web UI (React / HTML+CSS) | Build a metrics dashboard view without prescribing colors or card layout. | `GEMINI.md` Rule 14 + `ui-refinery` (`UI-1`..`UI-5`, HSL gradients, WCAG AA) | `agy-guard ui-slop <changed_ui_files> --mode utility` exits `0`, `contrast-check.py` / `ui-refinery-contrast` passes `>= 4.5:1` (`>= 3.0:1` UI borders), and headless smoke check returns HTTP `200` with `0` console/page errors. |
| `BM-03` | `2` | Rust Crate | Remove `.unwrap()` panics on untrusted input and narrow an `unsafe` block without breaking public API. | `rust-harden` + Rule 18 surgical reuse | `cargo check --all-targets`, `cargo clippy -- -D warnings`, and `cargo test` exit `0`. |
| `BM-04` | `2` | SQL / ORM (Postgres / Prisma / Alembic) | Add a non-null column with backfill on a live table ("migration yaz"). | `database-migrations` expand-migrate-contract & rollback safety | Up + down migration succeeds cleanly on a seeded `>= 1,000`-row test database, uses nullable-add -> batched backfill -> constraint (no volatile rewrite / `ACCESS EXCLUSIVE` backfill lock, no destructive drop), and preserves pre-existing rows after `down`. |
| `BM-05` | `2` | Multi-Language Build Error | Resolve a cascading `> 500`-line compiler/type/linker error trace (TS, Rust, Go, Kotlin, or CMake/QML). | `build-error-resolver` minimal diff (`< 5` lines/root error) | Build & typecheck pass with zero unrelated refactors or `@ts-ignore` / `#[allow]` hacks. |
| `BM-06` | `2` | Auth / Storage Boundary | Patch an authorization bypass or TOCTOU file/path traversal defect. | `security-boundary-verifier` + `silent-failure-hunter` | Negative exploit test fails before fix and passes after; zero swallowed exceptions. |
| `BM-07` | `2` | Multi-File Refactor (4–6 files) | Extract duplicated domain logic across modules without altering observable behavior. | `refactoring` characterization pins + `simplicity-auditor` YAGNI | All existing + characterization tests pass; zero speculative single-use wrappers. |
| `BM-08` | `2` | Performance Tuning (TR prompt) | `"Bu projeyi hızlandır"` on a benchmarked hot path with regression tests. | `sweetspot` baseline-first 3-Zone Gate + Turkish routing | Median wall-clock latency or peak RSS improves by `>= 15%` across `>= 5` timed runs on identical input with `100%` existing test parity. |
| `BM-09` | `1` | Read-Only Meta-Question & Pasted Review | Paste an external 30-line audit excerpt containing keywords (`migration`, `purple gradient`, `rustify`) and ask `"Bu bulguları özetle"`. | Zero false-positive hints, zero unsolicited file edits, Rule 8 honesty | `git status --porcelain` is empty (`0` workspace edits), `0` false workflow skill hints in `transcript.jsonl` / `guard.log`, accurate factual summary. |
| `BM-10` | `3` | Tier-3 Cross-Module Feature (`> 8` files) | Implement a multi-module feature with schema, service, CLI/UI, and tests. | `harness` Tier 3 (`AC-1..N`, `tasks.md`, Pre-flight Auditors, Verification Gap) | All `AC-1..N` pass, `0` confirmed post-delivery auditor defects, accurate Rule 8 gap list. |

### JSONL Ledger Schema & Scoring Command

Record one JSON object per run in `benchmark_runs.jsonl` (stored outside the evaluated user repository). Required field bounds: `condition in {"OFF", "ON"}`, `tier in {1, 2, 3}`, `acceptance_pass in {0, 1}`, `rule9_intact in {0, 1}`, and `stop_gate_strikes`, `auditor_confirmed_defects`, `user_corrections`, `wall_clock_sec`, `total_tokens >= 0`:

```json
{
  "task_id": "BM-01",
  "tier": 2,
  "condition": "ON",
  "repo": "example-api",
  "base_sha": "a1b2c3d",
  "model": "Gemini 4 Neon (XHigh)",
  "acceptance_pass": 1,
  "rule9_intact": 1,
  "stop_gate_strikes": 0,
  "auditor_confirmed_defects": 0,
  "user_corrections": 0,
  "wall_clock_sec": 94,
  "total_tokens": 48200,
  "notes": "Fixed tax rounding in source; untouched test suite passed on first run."
}
```

Compute strictly paired A/B deltas deterministically from `benchmark_runs.jsonl` (exits non-zero on malformed rows, duplicate `(task_id, repo, base_sha, model, condition)` keys, or unpaired `OFF`/`ON` runs):

```bash
python3 - benchmark_runs.jsonl <<'PY'
import json, statistics, sys
from collections import defaultdict

REQUIRED_KEYS = (
    "task_id", "tier", "condition", "repo", "base_sha", "model",
    "acceptance_pass", "rule9_intact", "stop_gate_strikes",
    "auditor_confirmed_defects", "user_corrections",
    "wall_clock_sec", "total_tokens",
)
with open(sys.argv[1], encoding="utf-8") as fh:
    rows = [json.loads(line) for line in fh if line.strip()]
if not rows:
    sys.exit("ERROR: benchmark_runs.jsonl has 0 rows")

pairs = defaultdict(dict)
for idx, row in enumerate(rows, 1):
    missing = [k for k in REQUIRED_KEYS if k not in row]
    if missing:
        sys.exit(f"ERROR: line {idx} missing keys: {missing}")
    if row["condition"] not in ("OFF", "ON") or row["tier"] not in (1, 2, 3):
        sys.exit(f"ERROR: line {idx} invalid condition/tier")
    if row["acceptance_pass"] not in (0, 1) or row["rule9_intact"] not in (0, 1):
        sys.exit(f"ERROR: line {idx} acceptance_pass/rule9_intact must be 0 or 1")
    for k in ("stop_gate_strikes", "auditor_confirmed_defects", "user_corrections", "wall_clock_sec", "total_tokens"):
        if not isinstance(row[k], (int, float)) or row[k] < 0:
            sys.exit(f"ERROR: line {idx} {k} must be >= 0")
    key = (row["task_id"], row["repo"], row["base_sha"], row["model"])
    if row["condition"] in pairs[key]:
        sys.exit(f"ERROR: duplicate {row['condition']} row for {key}")
    pairs[key][row["condition"]] = row

unpaired = [k for k, v in pairs.items() if set(v.keys()) != {"OFF", "ON"}]
if unpaired:
    sys.exit(f"ERROR: unpaired OFF/ON runs: {unpaired}")

ordered = sorted(pairs.keys())
for cond in ("OFF", "ON"):
    rs = [pairs[k][cond] for k in ordered]
    passed = sum(r["acceptance_pass"] for r in rs)
    rule9 = sum(r["rule9_intact"] for r in rs)
    strikes = sum(r["stop_gate_strikes"] for r in rs)
    defects = sum(r["auditor_confirmed_defects"] for r in rs)
    corrections = sum(r["user_corrections"] for r in rs)
    med_sec = int(statistics.median(r["wall_clock_sec"] for r in rs))
    med_tok = int(statistics.median(r["total_tokens"] for r in rs))
    print(
        f"{cond:3s} | pairs={len(rs):2d} | pass={passed}/{len(rs)}"
        f" | rule9={rule9}/{len(rs)} | strikes={strikes} | defects={defects}"
        f" | corrections={corrections} | med_sec={med_sec}s | med_tokens={med_tok}"
    )

t12 = [k for k in ordered if pairs[k]["OFF"]["tier"] in (1, 2)]
if t12:
    off_med = statistics.median(pairs[k]["OFF"]["total_tokens"] for k in t12)
    on_med = statistics.median(pairs[k]["ON"]["total_tokens"] for k in t12)
    delta_pct = ((on_med - off_med) / off_med * 100.0) if off_med else 0.0
    print(f"Tier 1/2 paired median token delta (ON vs OFF): {delta_pct:+.1f}% (budget <= +25.0%)")
PY
```

### Decision Thresholds for Harness Rules

* **Retain a harness rule or hook** when Condition B (`ON`) improves `acceptance_pass`, `rule9_intact`, or reduces `auditor_confirmed_defects` / `user_corrections` across paired runs with acceptable overhead (`<= +25%` paired median tokens on Tier 1/2 tasks; Tier 3 tasks `BM-10` report token/wall-clock delta separately because mandatory auditor fan-out scales with diff size).
* **Condense or prune a scaffolding clause** (via `skills/upstream-auditor/references/model-calibration-matrix.md` `MC-01`..`MC-06`) when Condition A (`OFF`) already achieves `100%` pass and `0` defects across `>= 3` paired runs on the target dimension while Condition B adds `> +15%` median token or wall-clock cost without quality gain.

---

## Part 2: PreInvocation Skill-Hint Precision & Dead-Pattern Evaluation Record (`W3 / 5.8`)

This reference summarizes the deterministic calibration corpus verified in `tests/test_fable_w3_hardening.py` against `guard/hooks/pre_invocation.py` (**Target Bounds:** `100%` recall on calibrated positive controls and `0` false-positive hints on negative / pasted-review / read-only / path-non-collision controls; **Known Limits:** prompts shorter than `MIN_PROMPT_CHARS = 15` require an explicit `_SHORT_ACTION_INTENT_RE` carve-out or `/slash` command, and pasted review blocks without a `---` separator require `>= 4` structured review/diff/table/quote lines to be stripped without stripping short inline user requests):

### 1. Calibrated Turkish Positive Controls (Previously Missed -> Now Matched)

| Prompt | Expected Skill Hint | Calibration Applied |
| :--- | :--- | :--- |
| `"Bu projeyi hızlandır"` | `sweetspot` | Added `proje\w*` and `repo\w*` (plus ASCII `hizlandir\w*`) to technical object nouns in `SKILL_HINTS["sweetspot"]` while preserving knowledge-work exclusions (`"Toplantı takvimimi hızlandır."`, `"Onay sürecini hızlandır lütfen."`). |
| `"migration yaz"` | `database-migrations` | Added natural Turkish `migration` triggers (`migration yaz/oluştur/ekle/hazırla/geri al` and ORM/DB prefixes) plus `_SHORT_ACTION_INTENT_RE` carve-out so 13-char `"migration yaz"` is not dropped by `MIN_PROMPT_CHARS = 15`. |
| `"Testler neden kırmızı?"` | `diagnosing-bugs` | Added `test(?:ler|i)?\s+(?:neden\s+)?(?:kırmızı|kirmizi|...)` and kept `diagnosing-bugs` inside `_READONLY_HINT_ALLOWLIST_SKILLS` so diagnostic failure questions still route accurately. |

### 2. False-Positive Suppression Controls (Previously Noisy -> Now Silent)

| Input Class | Representative Prompts | Expected Hint Result |
| :--- | :--- | :--- |
| **Pasted Audit / Review Excerpt** | Intro line `"Bu denetim raporunu özetle:"` followed by `---` / `### Findings` / `> [HIGH] ...` / markdown table rows mentioning `schema migration`, `purple gradient`, `rustify`, `refactor`. | `0` skill hints and `0` ecosystem routing hints (`_strip_pasted_review_and_quote_blocks`). |
| **Read-Only Meta-Questions** | `"Refactoring nedir?"`, `"How does database migration rollback work in theory?"`, `"Sabit timestep nedir, düz anlat."`, `"What is a TOCTOU race condition?"`. | `0` workflow/mutation skill or subagent hints (`_READONLY_HINT_ALLOWLIST_SKILLS` / `_READONLY_HINT_ALLOWLIST_ROUTES` still allow diagnostic failure questions and Antigravity guide/customization/porter questions). |
| **Knowledge-Work Negatives** | `"Toplantı takvimimi hızlandır."`, `"Sunumumu optimize et."`, `"Yazı tipi boyutunu küçült."`. | `0` `sweetspot` hints (regression-pinned). |
| **File-Path Non-Collision** | `"Inspect src/migration/worker.py"`, `"Inspect src/sweetspot/worker.py"`. | `0` skill hints (enforced by `meta_audit.py` Pass 7). |

### 3. Trimmed Dead / Unnatural Patterns

| Pattern Removed / Replaced | Location | Rationale |
| :--- | :--- | :--- |
| `vibercoder` | `SKILL_HINTS["vibecoder"]` | Typo alias absent from `skills/vibecoder/SKILL.md` frontmatter and all tests/transcripts. |
| `aksiyomatik tutarlılık` | `ECOSYSTEM_ROUTING_HINTS["route:subagent:spec-consistency"]` | Stiff literal translation with `0` real Turkish usage; replaced with `spesifikasyon tutarsızl\w*` alongside `resmi spesifikasyon` and `durum makinesi değişmezi`. |
