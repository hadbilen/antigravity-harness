# ADR-0017: Plumbwork Clean Major Cutover (`v3.0.0`), UI Refinery & Motion Physics Separation, and Maintenance Diagnostics

**Date**: 2026-11-24
**Status**: accepted
**Amends**: [ADR-0015](0015-external-audit-hardening-host-contract-parity-and-measurement.md) & [ADR-0016](0016-hybrid-modular-plugin-architecture.md) (rebrands user-facing repository, CLI, environment, XDG/FHS, and package surfaces to vendor-neutral `plumbwork` / `plumb-guard` / `plumb-porter` and separates the UI/copy/motion/prototyping bundle into `ui-refinery` + `motion-physics`, while preserving ADR-0015's 25-subcommand Guard freeze, 5-emitter Porter freeze, `guard/agy_hooks.py <= 32,768` UTF-8 byte budget, and ADR-0016's Hybrid Modular Plugin Architecture)
**Deciders**: Human Operator (`tugay`), Harness Maintainers
**Proposed By**: User (vendor-neutral `Plumbwork` rebrand, `Option B` clean `v3.0.0` cutover, `UI Refinery` separation) & Model (Gemini 4 Neon, XHigh: 4-window cutover architecture, fail-closed provenance boundaries, JSONC `doctor` diagnostics)
**Approved By**: User
**Authority**: User Constraint (`D1`–`D4` product/brand cutover & separation) & Model Recommendation (`D5`–`D8` diagnostic, attribution, audit, and release seams)

## Context

Two naming and packaging conflicts block clean standalone Marketplace publication and long-term cross-IDE portability after [ADR-0016](0016-hybrid-modular-plugin-architecture.md) (`v2.4.0`):

1. **Vendor-Coupled Harness Branding:** The repository, CLI binaries (`agy-guard`, `agy-porter`), environment variables (`AGY_GUARD_*`), XDG/FHS directories (`antigravity-harness`, `antigravity-guard`), constitution filename (`rules/antigravity-constitution.md`), and Linux packages carry Google Antigravity vendor prefixes even though the harness targets cross-agent portability via `porter` and standalone plugin packs (`v1/plugin.json` explicitly bans vendor brand prefixes).
2. **Upstream Namespace Squatting (`antislop` & `silk-design`):** Upstream `miqdadbadjuber/anti-slop` ships its own official Antigravity plugin door under the `antislop` plugin/skill name and `/antislop*` slash triggers, while our adapted bundle also incorporates MIT-licensed `bendrape1-byte/silk-design` (`silk-design`). Shipping our heavily customized bundle under `plugins/antislop` and `skills/antislop` collides directly with third-party upstream installations and creates a deletion hazard during uninstall or flat/hybrid switches.

The decision-driving constraint is **executing a clean SemVer `v3.0.0` vendor-neutral cutover (`Plumbwork`) and conflict-free plugin separation (`UI Refinery` + `motion-physics`) with fail-closed third-party preservation, zero runtime shim bloat, zero breach of `ADR-0015`/`ADR-0016` surface freezes (`25` Guard subcommands, `5` Porter emitters, `guard/agy_hooks.py <= 32,768 B` with `0` net new facade exports), and zero silent test weakening (`GEMINI.md` Rule 9)**.

## Decision

We adopt a 4-window (`W1..W4`) clean major cutover (`v3.0.0`, Decisions `D1..D8`) executed on standalone branch `feat/v3-plumbwork-ui-refinery`:

1. **Clean `v3.0.0` Major Cutover (`D1`, Option B):** Ship a single clean SemVer `3.0.0` major release with zero `v3.0.x` runtime compatibility shims (`agy-*` CLI aliases, `AGY_GUARD_*` env fallbacks, or live XDG directory migration). Existing `v2.x` operators follow a documented 2-command upgrade path in `CHANGELOG.md` (legacy `--uninstall` + clean `v3.0.0` install), assisted by read-only `doctor` legacy-residue warnings. Every green window (`W1..W4`) regenerates `.harness/manifest.json`, synchronizes `README.md` test counts, runs full local gates, and commits cleanly onto `feat/v3-plumbwork-ui-refinery`.
2. **Canonical Vendor-Neutral Brand, CLI, Env & Path Surfaces (`D2`):**
   - Project & repository: **`Plumbwork`** (`plumbwork`, `https://github.com/hadbilen/plumbwork`).
   - CLIs & launchers: **`plumb-guard`**, **`plumb-porter`**, and `bin/plumb-guard{,.bat,.ps1}` (launcher marker `"plumbwork launcher"`).
   - Environment variables: **`PLUMB_GUARD_STATE_DIR`**, **`PLUMB_GUARD_DATA_DIR`**, **`PLUMB_GUARD_NOTIFY`**, **`PLUMB_GUARD_NO_TRAY`**, and **`PLUMBWORK_SHARE_DIR`** (all isolated in `tests/hermetic.py` and `scripts/meta_audit.py` Pass 7).
   - Filesystem & boot sentinels: XDG `~/.local/{state,share}/plumbwork`, FHS `/usr/share/plumbwork` and `/usr/lib/plumb-guard`, Windows `%LOCALAPPDATA%\Programs\plumb-guard`, global constitution rule `rules/plumbwork-constitution.md`, and boot sentinels `plumb-guard-boot.service`, `com.plumbwork.guard` (`com.plumbwork.guard.plist`), and `PlumbworkGuardBootSentinel`.
3. **Antigravity Host Contracts & Internal Packages Preserved (`D3`):** Keep third-party Google Antigravity host contracts verbatim (`GEMINI.md`, `~/.gemini/config/`, `ANTIGRAVITY_CONFIG_DIR`, `AGY_RECORD_HOST_FIXTURES`, `antigravity` environment type, `https://antigravity.google/schemas/v1/plugin.json`) and preserve internal Python import packages (`guard/`, `porter/`, and `guard/agy_hooks.py` filename). Enforce `0` net new facade exports in `guard/agy_hooks.py` (`<= 32,768` UTF-8 bytes, max line `<= 160` chars).
4. **UI Refinery & Motion Physics Separation + Fail-Closed Third-Party Preservation (`D4`):**
   - Separate the UI/copy/motion/prototyping bundle from `antislop` / `silk-design` into **`ui-refinery`** (`displayName: "UI Refinery"`, `skills/ui-refinery/`, `guard/plugin_assets/ui-refinery.svg`, Cursor rule `10-design-ui-refinery.mdc`) and **`motion-physics`** (`references/motion-physics.md`, `references/motion-physics/`).
   - Expose the bundled WCAG contrast MCP under key `"contrast"` in Hybrid mode (live `ui-refinery_contrast`, avoiding double prefixing) and `"ui-refinery-contrast"` in Flat mode (`SERVER_NAME = "ui-refinery-contrast"`).
   - Remove all `/antislop*` and `/silk-design` slash triggers; route `/ui-refinery`, `/ui-audit`, `/copy-polish`, `/a11y-check`, `/mobile-layout`, `/code-comments`, and `/motion-physics`.
   - **Fail-Closed Third-Party Preservation:** Never add `"antislop"` to `CONSOLIDATED_SKILL_SLUGS`, and remove unconditional name-only deletion and Porter rejection for `antislop*` / `silk-design` global skills so upstream installs coexist safely. Retire legacy harness-owned `plugins/antislop` or global `skills/antislop` strictly through shared fail-closed positive-provenance helpers (reject symlinks; require positive `hadbilen/plumbwork` or legacy `hadbilen/antigravity-harness` provenance whenever `plugin.json` exists, never allowing stale receipts to override non-harness/JSONC/missing-URL manifests; for global `skills/antislop`, require both receipt tracking and positive harness content markers, leaving unreceipted copies to read-only `doctor` warnings).
5. **Read-Only `doctor` Diagnostics (`D5`, `0` New CLI Subcommands):**
   - **JSONC-Aware Duplicate Plugin-`name` Collision Check (`W1`):** Inspect non-symlink subdirectories under `<root>/plugins/` using `O_NOFOLLOW` + `fstat` (`S_ISREG`, `<= 256 KiB`), strip JSONC `//` / `/* */` comments and trailing commas outside string literals, default omitted/blank `name` to `dir.name`, warn on non-string `name` or unreadable/oversized/malformed manifests without raising unhandled exceptions, and emit a collision warning whenever two or more directories resolve to the same case-insensitive plugin `name`.
   - **Read-Only Legacy-Residue & Native Deny Checks (`W3`):** Warn (read-only) if legacy `~/.local/{state,share}/antigravity-harness`, `rules/antigravity-constitution.md`, legacy boot sentinels (`agy-guard-boot.service`, `com.antigravity.guard.plist`, Windows `AntigravityGuardBootSentinel`), legacy CLI launchers, or unreceipted legacy harness `plugins/antislop`/`skills/antislop*`/`skills/silk-design` remain on disk, and update `_check_native_deny_rules()` to verify `plumb-guard unlock` and `--no-verify`.
6. **Prominent Upstream Attribution & Dual-Token Standalone Validation (`D6`):** Generated plugin `README.md` emits `## Upstream Credits & Attribution` directly after `## Included components` for packs containing adapted MIT upstreams (`ui-refinery`: `miqdadbadjuber/anti-slop` & `bendrape1-byte/silk-design`; `rust-suite`: `erkamyaman/rust-anything`). The tops of `skills/ui-refinery/SKILL.md` and `skills/ui-refinery/references/motion-physics.md` carry concise MIT upstream credits alongside updated `THIRD_PARTY_NOTICES.md` rows. Standalone pack validation rejects both `plumb-guard`/`plumbwork` and legacy `agy-guard`/`antigravity-harness` path/command leaks (including fenced comments, with an explicit FHS fallback carve-out strictly for `/usr/share/plumbwork/skills/media-studio/scripts/media_qc.py` in `media-studio`).
7. **Honest Upstream-Auditor Sync & Verifiable Audit Ledger (`D7`):** Every upstream SHA/tag bump in `skills/upstream-auditor/upstream_state.seed.json` (and fallback dictionary in `guard/upstream.py`) requires concrete commit/diff inspection recorded below. In `W1`, keep `anti-slop.target_skills: ["antislop"]` until `W2` renames the skill directory, and keep `rea` honestly pinned at `rea-agents-6.9.0` while local `~/.gemini/config/plugins/rea/` remains at `6.9.0`.
8. **Linux Upgrade Continuity, CI Gating & Pre-Tag Repo Rename (`D8`):** Linux `plumb-guard` packages install `/usr/bin/plumb-{guard,porter}`, `/usr/lib/plumb-guard`, `/usr/share/plumbwork`, `plumb-guard.{desktop,svg}`, and `plumb-guard` bash completion, declaring `.deb` `Provides`/`Conflicts`/`Replaces: antigravity-guard`, `.rpm` `Provides: antigravity-guard = %{version}-%{release}` + `Obsoletes: antigravity-guard < 3.0.0`, Arch `PKGBUILD` `provides`/`replaces`/`conflicts=('antigravity-guard')` with unquoted `cd "$srcdir"/*-"$pkgver"`, and `.PKGINFO` `provides`/`replaces`/singular `conflict = antigravity-guard`. `.github/workflows/ci.yml` switches to `PLUMB_GUARD_NOTIFY: "off"`, `dist/plumb-guard-*`, and `"Plumbwork $TAG"`. Release sequencing enforces: push branch -> manual `workflow_dispatch` 5-job CI green on branch -> merge to `main` -> `main` CI green -> rename GitHub repo `hadbilen/antigravity-harness` -> `hadbilen/plumbwork` -> tag & push `v3.0.0`.

## Upstream Audit Ledger (`W1`, 2026-11-24)

Concrete inspection of the 5 repositories scoped for `W1` (live status queried via GitHub API and local `~/.gemini/config/plugins/rea/plugin.json` + `rea --version`):

| Repo | Commit / Release Range | Accepted | Rejected + Reason |
| :--- | :--- | :--- | :--- |
| `mattpocock/skills` | `5863806..abeeaf9` (4 commits) | Synced `last_synced_commit` to `abeeaf9` (zero changes to tracked `deep-grill`, `diagnosing-bugs`, `test-design`, or `retro`). | `skills/in-progress/software-factory/SKILL.md` (untracked in-progress upstream skill) and Node `scripts/check-frontmatter.mjs` (`scripts/meta_audit.py` already validates all YAML frontmatter in pure stdlib Python). |
| `miqdadbadjuber/anti-slop` | `35b54dc..7f6a03d` (6 commits, `3.2.30 -> 3.2.32`) | Synced `last_synced_commit` to `7f6a03d` while keeping `target_skills: ["antislop"]` until `W2` completes `ui-refinery` separation (zero changes to the 40 rules, Delivery Gate, or WCAG math). | Upstream Qoder/Qwen Code npm installer doors (`.qoder-plugin/plugin.json`, `cli/lib/install.mjs`), version-only `contrast-mcp.py` bump, and upstream self-update doc lines (not applicable to our harness/standalone plugin packaging). |
| `JayPokale/Chisle` | `b2e1658..69e2a3b` (47 commits; spans `bda2483` `v3.14.2` through live HEAD `69e2a3b`; verified `0` commits under `skills/`, `AGENTS.md`, `CLAUDE.md`, `rules/`) | Synced `last_synced_commit` to `69e2a3b` (no prompt/skill prose changes to `skills/chisle/SKILL.md`). | Node `PreToolUse` command-rewriting wrapper (`hooks/chisle-run.js`) and `PostToolUse` RTK-style output truncation (violates pure-stdlib Python invariant, conflicts with `GEMINI.md` Rule 5 full error/test output preservation, and rewrites commands across our Governance Shield permission boundary); interactive `gh` star/follow installer prompt (unwanted network nag); benchmark/README SVG assets. |
| `affaan-m/everything-claude-code` | `d2ef268..4adeee6` (selectively audited tracked targets: `skills/database-migrations/SKILL.md` 5 commits `3d99184`..`4032747`, `.agents/skills/security-review/SKILL.md` 1 commit `b54d8ba`, `agents/build-error-resolver.md` 0 commits) | Synced `last_synced_commit` to `4adeee6`. Applied two PostgreSQL correctness fixes to `skills/database-migrations/SKILL.md` (`ADD COLUMN` takes `ACCESS EXCLUSIVE` lock + `SET LOCAL lock_timeout`, volatile defaults still rewrite on PG 11+, populated `NOT NULL` without default raises SQLSTATE `23502`; Expand-Contract column rename deploys dual-write and drains old-only writers BEFORE bounded `IS DISTINCT FROM` backfill and retains dual-write through the rollback window) and tightened the CSP checklist item in `skills/audit/references/security-review.md` with `base-uri 'self'`, `object-src 'none'`, and `frame-ancestors 'none'`. | Standalone `examples/postgres-*.sql` fixture files (keep `database-migrations` concise and self-contained without unexecuted fixture debt); Zod v4 `error.issues` TS snippet and `$1` placeholder workaround in `security-review` (our checklist reference has no framework-specific Zod or literal `$1` SQL snippets); all untracked ECC skills outside our tracked target list. |
| `morluto/rea` | Local `rea-agents-6.9.0` vs. remote `rea-agents-6.10.1` | None: kept `last_synced_commit` honestly pinned at `rea-agents-6.9.0`. | Bumping to `rea-agents-6.10.1` rejected under `GEMINI.md` Rule 8 (Honest Sync): verified local `~/.gemini/config/plugins/rea/plugin.json` (`"version": "6.9.0"`) and `rea --version` (`6.9.0`) have not been upgraded by the operator. |

*Scope Boundary Note (Rule 8):* `Leonxlnx/unlazy` (`1667149`) and `bendrape1-byte/silk-design` (`0f530f0`) were verified up-to-date on 2026-11-24. `erkamyaman/rust-anything` showed remote `v4.0.0` vs. local `v2.1.0`; because it is outside `W1`'s 5-repo audit scope, it remains honestly pinned at `v2.1.0` without an unaudited bump.

## Alternatives Considered

### Alternative 1: Ship `v3.0.x` Runtime Compatibility Shims & Live XDG Auto-Migration (Option A)
- **Pros**: Allows in-place upgrades from `v2.4.x` without running legacy `--uninstall` first; old `agy-guard` / `AGY_GUARD_*` scripts keep working temporarily.
- **Cons**: Duplicates env-var, CLI, and state-dir resolution across the security boundary (`guard/hooks/`, `guard/paths.py`, `guard/startup.py`), threatens the `guard/agy_hooks.py <= 32,768 B` budget, introduces crash-recovery complexity for partial `~/.local/{state,share}` migrations, and creates split-brain governance states where old and new baselines coexist.
- **Why not**: Rejected by operator decision (`Option B`): clean SemVer `3.0.0` major cutover eliminates dual-brand security-surface complexity in favor of a deterministic 2-command upgrade guide and read-only `doctor` legacy-residue warnings.

### Alternative 2: Retain `antislop` and `silk-design` Names for Our Bundled Plugin & Slash Triggers
- **Pros**: Zero skill/plugin renames and zero `W2` contract-test updates.
- **Cons**: Directly squats on upstream `miqdadbadjuber/anti-slop`'s official Antigravity plugin namespace, collides on `/antislop*` slash triggers, and risks destructive overwrites or deletions when an operator installs upstream `antislop` alongside our harness.
- **Why not**: Rejected because the decision-driving conflict-free coexistence and upstream-respect constraint outweighs one-time rename churn.

### Alternative 3: Rename Internal Python Modules (`guard/`, `porter/`, `guard/agy_hooks.py`) and Host Contracts
- **Pros**: Removes every remaining `agy` / `antigravity` token inside internal Python filenames.
- **Cons**: Renaming Google Antigravity host contracts (`GEMINI.md`, `~/.gemini/config/`, `ANTIGRAVITY_CONFIG_DIR`, `v1/plugin.json`) breaks the host runtime outright; renaming internal Python modules (`guard/agy_hooks.py`) churns every import and historical test seam with zero user-facing benefit.
- **Why not**: Rejected on YAGNI and host-contract preservation grounds (`D3`).

### Alternative 4: Add a `plumb-guard plugin-update` Network Auto-Updater Subcommand or `syn` AST Lock Linter
- **Pros**: Automates third-party plugin updates from CLI; mechanically inspects Rust lock usage via custom `syn` AST tooling.
- **Cons**: Violates `ADR-0015`'s 25-subcommand Guard freeze, expands supply-chain attack surface, and duplicates native Antigravity Marketplace management; a custom `syn` AST linter adds high maintenance boilerplate already superseded by single-ownership design, `clippy::await_holding_lock`, and `loom`.
- **Why not**: Rejected under `ADR-0015` surface freeze and `GEMINI.md` Rule 4 (YAGNI).

## Consequences

### Positive
- Eliminates vendor lock-in from brand, CLI, package, and documentation surfaces while keeping Antigravity host integrations intact.
- Eliminates namespace and slash-command collisions with upstream `miqdadbadjuber/anti-slop` and `bendrape1-byte/silk-design`, preserving third-party `plugins/antislop` and global `skills/antislop` fail-closed.
- Gives operators clear, prominent MIT upstream attribution in generated plugin `README.md`s and skill headers.
- Adds zero-subcommand JSONC-aware duplicate plugin-`name` collision detection and read-only legacy-residue warnings to `doctor`.
- Preserves `ADR-0015`/`ADR-0016` surface freezes (`25` subcommands, `5` emitters, `guard/agy_hooks.py <= 32,768 B`, `0` net new facade exports).

### Negative
- Breaking `v3.0.0` major cutover requires `v2.x` operators to run legacy `--uninstall` before installing `v3.0.0` (2 commands, documented in `CHANGELOG.md`).
- Requires authorized contract-test updates in `W2` (up to `19` files for `ui-refinery`/`motion-physics`) and `W3` (up to `38` files for `plumbwork`), strictly verified via a `W4` detached-worktree trusted-boundary check against `30b9a27` base tests.

### Risks
- **Unintended Stale Legacy Brand Tokens:** Mitigated by executing bulk renames via a deterministic scratch script in `W3` followed by a full-token allowlist stale-brand scanner (`0` unexempted hits).
- **Accidental Third-Party `antislop` Deletion:** Mitigated by removing `"antislop"` / `antislop*` / `silk-design` from unconditional name-only cleanup and testing 4 fail-closed positive-provenance cases across both `plugins/antislop` and global `skills/antislop` in `W2`.
- **Premature Repo Rename or Untested Release Tag:** Mitigated by `D8` enforcing 5-job `workflow_dispatch` branch CI green before merging to `main`, and renaming GitHub repo `hadbilen/antigravity-harness` -> `hadbilen/plumbwork` before pushing tag `v3.0.0`.
- **Hook Cold-Start Latency or Size Regression:** Mitigated by `guard/agy_hooks.py <= 32,768 B` (`0` net new exports) and `W4`'s same-host `N=15` (`3` warmup) A/B benchmark (`<= +15%` median delta vs `main`, `p95 <= 250 ms`).

## Failure Modes & Rollback
- **Per-Window Code Rollback:** Work lands sequentially on isolated feature branch `feat/v3-plumbwork-ui-refinery` with clean per-window commits (`W1..W4`); any window regression can be reverted cleanly (`git revert` / branch reset) without affecting `main` @ `30b9a27`.
- **Live Desktop Canary Rollback (`W4`):** Before executing legacy `--uninstall` and live `v3.0.0 --plugins` installation, the human operator copies `~/.gemini/config`, `~/.local/state/antigravity-harness`, and `~/.local/share/antigravity-harness` to an external backup directory outside `~/.gemini` so full host state can be restored deterministically if any live host anomaly surfaces.
- **Unreceipted or Third-Party Plugin Collision:** `doctor` never mutates `<root>/plugins/` or legacy state directories; duplicate plugin `name` collisions, non-string manifests, symlinks, oversized (`> 256 KiB`) or unreadable (`chmod 000`) files emit bounded read-only warnings without crashing.
