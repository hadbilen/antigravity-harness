# Antigravity Harness

[![Release](https://img.shields.io/badge/release-v1.4.0-blue.svg)](https://github.com/hadbilen/antigravity-harness/releases)
[![CI](https://github.com/hadbilen/antigravity-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/hadbilen/antigravity-harness/actions/workflows/ci.yml)
[![Runtime](https://img.shields.io/badge/core%20runtime-Python%20stdlib%20only-brightgreen.svg)](#dependencies)
[![Design Standard](https://img.shields.io/badge/UI-WCAG%20AA%20%7C%20antislop-orange.svg)](DESIGN.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **A behavioral constitution, auditor subagents, a rule transpiler, and a write-protection /
> integrity-monitoring companion (`agy-guard`) for AI coding agents.**

Autonomous coding agents suffer from **environment mutation drift**, **sycophancy**, **test weakening
(Goodhart's Curse)**, **context bloat**, and **ecosystem fragmentation**. Antigravity Harness counters
them with an engineering constitution (`GEMINI.md`), 21 modular skills, 7 independent auditor
subagents, Porter (a rule importer/exporter for Claude Code, Cursor, Aider and `AGENTS.md` tools),
and Antigravity Guard, which write-protects the governance files, detects drift, and gates changes
behind human confirmation.

---

## What Guard does and does not protect against (threat model)

Guard runs as **your own OS user**. Read this before relying on it:

| Protects against | Does NOT protect against |
|---|---|
| Accidental edits and tools that respect file permissions | A process running as your user that deliberately restores write bits (`chmod u+w`) |
| In-place edits of top-level files (`GEMINI.md`, `hooks.json`, …) and any change inside `skills/`, `agents/`, `templates/` | Deleting and recreating a top-level file: the config root stays writable for Antigravity's own saves, so this is only *detected* (FIM), not blocked |
| Headless / unattended agents: administration commands (`unlock`, `rebaseline`, `snapshot restore` / `prune`, lowering an environment policy, `notify disable`, `startup enable` / `disable`, `porter stage`, …) refuse without a human typing `yes` in a terminal or approving in the GUI | An agent that can drive an interactive terminal *and* chooses to ignore the constitution |
| Silent drift: the SHA-256 baseline (outside the protected tree) reports modified, added, deleted and unreadable files | An attacker who can rewrite both the files **and** the per-user baseline (it is not signed) |
| Forgotten maintenance windows: leases relock automatically when they expire (failed relocks are retried and alerted), and changes made during an unattended window wait for review instead of being trusted | `root` / administrators, or kernel-level tampering |
| Untraceable decisions: approvals, refusals, locks, leases, rebaselines, restores, boot checks and every WARNING/CRITICAL alert are appended to an audit log (`~/.local/state/antigravity-harness/logs/guard.log`) | Rewriting that log: it lives in your user's state directory and is not signed |

For a real boundary, make the policy files immutable with root (`sudo chattr +i`), keep them root-owned,
or enforce policy on the host side (e.g. an Antigravity `PreToolUse` hook that denies writes to the
governance tree). `agy-guard status` shows which protection kind is active
(`USER-SPACE LOCK (advisory against the same OS user)` vs `IMMUTABLE (chattr +i, root)`).

---

## The Problem: Why This Exists

1. **Environment Mutation Drift & Rogue Writes:** agents, sub-processes or IDE extensions quietly overwrite prompt contracts or inject unverified skills into `~/.gemini/config/`.
2. **The Sycophancy Trap:** models reflexively agree with user premises and bury the diagnosis under polite filler.
3. **Test Weakening (Goodhart's Curse):** when a test fails, agents are tempted to edit assertions or skip tests to manufacture a green exit code.
4. **Context Bloat & Analysis Paralysis:** dumping megabytes of logs into the context window degrades attention and causes looping fixes.
5. **Ecosystem Fragmentation:** directives written for one tool are rewritten by hand for the next and decay along the way.

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
  │   Auditor    │ │  Modular Skill  │ │ Baseline UI  │ │  Porter bridge   │ │Antigravity Guard │
  │  Subagents   │ │     System      │ │   Contract   │ │ (verified export)│ │ (lock/FIM/lease) │
  └──────────────┘ └─────────────────┘ └──────────────┘ └──────────────────┘ └──────────────────┘
```

---

## 1. Antigravity Guard (`agy-guard` CLI & GUI)

### Governance write shield (`guard/os_adapter.py`, `guard/environment.py`)
Guard locks the **governance seams** of `~/.gemini/config/` — `GEMINI.md`, `AGENTS.md`, `DESIGN.md`,
`MISTAKES.md`, `hooks.json`, `mcp_config.json`, `skills/`, `agents/`, `templates/`, `.harness/`. Antigravity's
own runtime state (`config.json`, `projects/`, `sidecars/`, `plugins/`, `cache`) stays writable, and so does
the root directory: Antigravity saves `config.json` by atomic replace (new file + rename), which a read-only
root would break. Top-level files therefore resist in-place edits, but a process that deletes and recreates
one is not stopped; the integrity baseline reports it.
* **Linux:** strips write bits (user-space lock); adds `chattr +i` only when run as root.
* **macOS:** BSD user-immutable flag (`chflags uchg` / `nouchg`) plus permission lockdown.
* **Windows:** NTFS deny ACEs `(WD,AD,DE,DC)` plus `attrib +R`; status is read from the ACL, not by writing probe files.
* Symlinks are **never followed**: a symlink pointing outside the tree is reported as *unprotected*
  (install in copy mode to protect it), and a config root that is itself a symlink is refused instead of
  locking the link target. Original permission modes are recorded (under a cross-process lock) and restored on
  unlock; a world-write bit is never restored from the record, and entries that were already read-only come
  back owner-writable.
* `lock` returns a non-zero exit code and lists the reasons whenever protection is only partial.

### Integrity baseline (`guard/integrity.py`)
* A flat `path -> SHA-256` map per environment, stored in `~/.local/state/antigravity-harness/integrity/`
  (outside the protected tree; `ANTIGRAVITY_INTEGRITY_FILE` overrides it for the global environment).
* Records symlinks as links (retargeting is detected), reports unreadable files, ignores installer backups and
  legacy Guard files **at the top level only** (a `backup_*` folder inside `skills/` is monitored), rejects
  malformed baselines as corrupt, and archives the previous baseline on every rebaseline. It detects drift; it
  is not a signature.
* Changes made during a lease that expired unattended are recorded as **pending review**: `status` and `verify`
  show `[REVIEW]` until an approved `agy-guard rebaseline` accepts them (anything changed afterwards is
  reported as ordinary drift).

### Snapshots & verified restore (`guard/snapshot.py`)
* Snapshots of the governance scope live in `~/.local/share/antigravity-harness/snapshots/` with a content manifest.
* Restore verifies the snapshot against its content manifest (snapshots without one are refused), refuses to
  write through destination symlinks, always takes a pre-restore backup first, swaps entries with a journal
  (rolled back on failure, with relock failures reported), and re-establishes the baseline.
* `prune` keeps N snapshots **per kind** (manual, pre-restore, pre-ingest, boot forensics) and requires human
  approval. `node_modules` is not copied into snapshots.

### Multi-environment registry (`guard/environment.py`)
* Discovers Claude Code, Codex / `AGENTS.md`, Cursor and Aider workspaces through their **rule files only**
  (`CLAUDE.md`, `.claude/agents|commands|skills`, `AGENTS.md`, `.cursorrules`, `.cursor/rules`, …), never the
  tools' own runtime state (sessions, memory, `settings.local.json`). The home directory is never treated as a
  workspace, and the GUI asks for a project folder. Ids include a path hash so two projects with the same folder
  name never collide; ambiguous ids are rejected. Whole-directory seams registered by 1.3.x are migrated.
* Policies: `enforced`, `monitored`, `disabled` (`agy-guard env policy <id> <policy>`). Other agents'
  environments start as `monitored` (integrity reports, no chmod); lowering a policy requires human approval,
  and a non-enforced environment is reported as NOT protected instead of "locked".
* The registry lives in the per-user state directory, so results never depend on the current directory.

### Human-approved, time-bounded leases (`guard/lease.py`)
* `agy-guard request-unlock --duration 60` asks a human to approve in the terminal (or the GUI); headless
  requests are rejected. There is no auto-approve flag.
* The record is persisted **before** unlocking and re-checked under the store lock, so two requests can never
  both be granted; a detached watcher (logging to `logs/lease-watcher.log`) relocks when the lease expires, and
  every Guard command also expires overdue leases. Several environments can hold leases at the same time.
* Closing relocks first and removes only the record of **that** lease. A successful close writes a change
  report (`~/.local/state/antigravity-harness/lease_reports/<id>.json`); the window's changes become pending
  review, or are accepted at once when a human closes the window with `agy-guard lock-complete` and confirms.
  A failed relock keeps the record, raises a CRITICAL notification and is retried (up to 5 times, 60 s apart).
  A corrupt lease store fails closed: it is set aside and every enforced environment is re-locked.

### Notifications (`guard/notifier.py`)
* `notify-send` (Linux), `osascript` (macOS), PowerShell balloon tips (Windows); message text is passed as
  data (argv / environment), never interpolated into code. Falls back to the terminal.
* Cooldowns: `CRITICAL` none, `WARNING` 30 minutes, `INFO` 24 hours. `agy-guard notify quiet` passes
  CRITICAL only; `agy-guard notify disable` silences everything (force never overrides it) and requires human
  approval; WARNING and CRITICAL events still reach the audit log. `agy-guard notify send` lets hooks reach the
  human instead of the agent's context.

### Audit trail (`guard/audit_log.py`)
* One JSON object per line in `~/.local/state/antigravity-harness/logs/guard.log` (1 MiB × 5 rotation, mode
  0600): approvals and refusals, locks and unlocks, policy changes, lease grants/closes/relock failures,
  baselines and pending reviews, snapshot create/restore/prune, boot checks, notification settings and every
  WARNING/CRITICAL notification (including suppressed ones). Logging never blocks an operation.

### Boot sentinel, doctor and GUI
* `agy-guard startup enable` (human approval) registers a systemd user unit / launchd agent / scheduled task
  (least privilege on Windows) that runs `boot-check`: it locks **first**, then verifies; on drift it captures a
  forensic snapshot (identical drift is not copied again; the newest 3 are kept), sends a CRITICAL notification
  and never rebaselines. Enabling reports failure when systemctl/launchctl fails. (Ordering before the
  graphical session is best-effort.)
* `agy-guard doctor [--fix]` (checks in `guard/doctor.py`) reports protection gaps, legacy baselines/snapshots
  inside the config tree, world-writable sources, symlink installs, relock-watcher errors and risky Antigravity
  permission grants (counts only).
* **Full CLI Workflow (20 subcommands):** `status`, `lock`, `unlock`, `verify`, `rebaseline`, `snapshot`, `porter`, `upstream`, `startup`, `boot-check`, `gui`, `doctor`, `test-boundary`, `provenance`, `env`, `request-unlock`, `lock-complete`, `drift`, `self-audit`, `notify` (plus the internal `lease-tick` used by the lease watcher).
* **Desktop GUI (`guard/gui.py`):** Tkinter/ttk, `DESIGN.md` dark palette; long operations (verify,
  rebaseline, restore, drift analysis) run off the UI thread, tray callbacks are marshalled onto the Tk loop,
  administration actions go through the same approval gate (and audit log) as the CLI, snapshot files open as
  read-only `.txt` copies (never executed), and the window only hides to the tray while a tray icon is running.
* **Upstream watchdog (`skills/upstream-auditor/scripts/upstream_watcher.py`):** the PreInvocation hook sends
  an operator-only notice once per change (a desktop notification plus one context line that tells the agent not
  to act on it or copy maintenance commands into task prompts); `upstream_watcher.py --ack` silences it until
  something changes again, `--status` shows the current reasons. Network checks have a hard deadline.

---

## 2. The Engineering Constitution (`GEMINI.md`)

About 10 KB of always-on invariants (17 numbered rules); procedures live in the skills and mechanical checks
in Guard and `scripts/`.

* **Proportional Gate Escalation:** Tier 1 (1–2 files, <20 lines) direct edits; Tier 2 (3–8 files) plans,
  blast-radius maps and checklists; Tier 3 (>8 files or auth/schema changes) the full workflow with
  `deep-grill`, ADRs and auditor subagents.
* **The Immutable Test Invariant:** relaxing assertions or skipping tests to pass gates is forbidden; new
  regression tests are always allowed.
* **Delivery Block:** one compact end-of-phase block (verified / not verified, the next step only at phase ends
  or handoffs, progress as criteria met, never percentages); maintenance notices never enter task prompts.
* **Handoffs carry a goal and exit criteria** and are triggered by observable events (milestone done, circuit
  breaker, >500-line trace, repeated user correction), not by a guessed "context saturation".
* **Circuit Breaker**, **Popper's Falsification Gate**, **Null-Action** (no change without a violated rule or a
  measured failure) and **Think in Code**.
* **Guard administration is human-only (Rule 12)** and upstream collisions are reported to the user
  instead of being silently resolved (Rule 15).

---

## 3. Auditor Subagents (`/agents`)

Seven role definitions whose read-only behavior is specified in their prompts. Each declares `access:`
(`read-only` or `read-exec`); the Claude Code export turns it into a `tools:` allow-list, other hosts apply
their own tool policies:

* **`silent-failure-hunter`:** swallowed exceptions, missing logs, empty fallbacks, unhandled promises.
* **`security-boundary-verifier`:** authorization boundaries, IDOR, input validation, SSRF, TOCTOU.
* **`specification-gap-auditor`:** unhandled edge cases, missing error branches, vague adjectives.
* **`consistency-auditor`:** contradictions, circular dependencies, broken cross-references.
* **`meta-auditor`:** runs the 6-pass harness self-audit (`scripts/meta_audit.py`).
* **`build-error-resolver`:** isolates compiler/type failures and proposes minimal diffs.
* **`research`:** digests large external documentation in an isolated context.

---

## 4. Porter: rule inspection, import and export (`porter.py`, `.harness/manifest.json`)

* **Pre-flight gate:** scores external rules (`.mdc`, `.cursorrules`, `CLAUDE.md`, …) 0–100 before anything is written.
* **Negation-aware sanitizer (`porter/sanitizer.py`):** classifies every match as prohibited (kept), affirmative
  (neutralised, e.g. "skip the failing tests", "use --no-verify", "ignore previous instructions") or uncertain
  (kept and listed as `NEEDS_REVIEW`, never deleted). Negation is clause-scoped, so "Skipping tests is never OK"
  survives while "Don't hesitate to skip failing tests" does not.
* **Archive inspection (`porter/archive.py`):** `porter.py inspect bundle.zip` inspects a ZIP without
  extracting or installing anything: member count, total size and compression-ratio limits, path traversal,
  symlink, encrypted and nested-archive members, and a suitability report for each rule file.
* **SSRF-hardened fetcher (`porter/net.py`):** http/https only, globally routable destinations only
  (CGNAT, link-local, private, 6to4/NAT64, IPv4-mapped/-compatible/-translated loopback are rejected), DNS
  pinning against rebinding, per-redirect validation, proxies ignored, an overall deadline, 10 MB cap.
* **Canonical manifest:** all 21 skills with every support file, executable bit and in-skill symlink, all 7
  subagents, the templates, the constitution and the design contract. CI fails if the committed manifest is
  stale (`porter.py manifest --check`).
* **Verified export:** Claude Code (`CLAUDE.md`, `.claude/skills/`, `.claude/agents/` with `tools:`, verbatim
  copies in `.claude/harness/agents/`), Cursor (`.cursor/rules/*.mdc` with valid YAML + `.cursor/skills/`),
  Universal (`AGENTS.md` + `.agents/`), Aider (`CONVENTIONS.md`, `.aider.conf.yml`, `.aider/`), Generic
  (`RULES.md`, `skills/`, `agents/`). Skills, support files (with their executable bits), templates and agents
  are exported with LF line endings and checked for parity by the self-audit; `hooks.json` is Antigravity-only
  and is not exported. Existing files are only overwritten with `--force`.
* **Staging gate:** `agy-guard porter stage` binds the reviewed content hash to the written content, refuses
  destination symlinks, snapshots first and re-locks afterwards; `porter.py import` only writes into this
  source repository (review it with `git diff`).

---

## 5. Modular Skill Ecosystem (`/skills`)

21 capability packages:

* **`harness`:** engineering harness, verification gates, task lifecycle.
* **`porter`:** ecosystem adapter, suitability analyzer, transpiler.
* **`vibecoder`:** product-first rapid prototyping with zero-friction HTML delivery.
* **`unlazy`:** Tier 3 (>8 files) deep completion engine with depth trees and ledger-based verification.
* **`deep-grill`:** Socratic trade-off interviewer: product and business-rule boundaries first, `[TBD]`
  parking, paraphrase check-ins, a decision ledger ending in exit criteria.
* **`visualizer`:** chooses the lens (structure, flow, state/rules, journey) and abstraction for a diagram;
  simple cases as Mermaid, interactive ones handed to the built-in `generative_ui`.
* **`chisle`:** terse, zero-fluff development mode (presentation only; never bypasses gates).
* **`procoder`:** sprint scaffolding for repositories that contain `.procoder/`.
* **`antislop` suite (6):** `antislop` (core 38-rule filter), `antislop-ui`, `antislop-code`,
  `antislop-copywriting` (with a deterministic scanner for signs of AI-written prose, English and Turkish),
  `antislop-human` (WCAG contrast checker + MCP tool), `antislop-layoutmobile`.
* **`diagnosing-bugs`**, **`upstream-auditor`**, **`database-migrations`**, **`security-review`**,
  **`architecture-decision-records`**, **`silk-design`**, **`audit`**.

Third-party origins and licenses are listed in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

---

## 6. Baseline Design Contract (`DESIGN.md`)

* Every visual element passes a one-sentence functional justification test.
* WCAG AA: 4.5:1 text, 3:1 control borders and disabled text; the "Measured Contrast Pairs" table is
  recomputed by the self-audit, so stated ratios cannot drift from reality.
* Dials `ENERGY 2 / RHYTHM 2 / MOTION 2` (stepping down under `prefers-reduced-motion`) and five mandatory data states.

---

## Directory Structure

```text
antigravity-harness/
├── GEMINI.md / DESIGN.md / MISTAKES.md   # Constitution, design contract, harness incident log
├── CHANGELOG.md / CONTRIBUTING.md / THIRD_PARTY_NOTICES.md / LICENSE
├── hooks.json                             # Reference PreInvocation hook (the installer writes an absolute path)
├── install.py / install.sh                # Installer (install.sh is a POSIX wrapper around install.py)
├── guard.py / porter.py                   # CLI entry points
├── .github/workflows/ci.yml               # 3 OS x Python 3.10-3.14, lint, trusted-boundary, release
├── .harness/manifest.json                 # Canonical manifest (checked by CI)
├── bin/                                   # agy-guard launchers (POSIX, .bat, .ps1)
├── installers/                            # PyInstaller build, Linux packages (.deb/.rpm/Arch), desktop entry
├── guard/                                 # Guard: os_adapter, environment, integrity, snapshot, lease,
│                                          #   notifier, approval, audit_log, doctor, paths, startup,
│                                          #   test_boundary, provenance, porter_bridge, upstream, cli, gui, tray
├── porter/                                # analyzer, sanitizer, frontmatter, manifest, net, archive, emitters/
├── scripts/
│   ├── meta_audit.py                      # 6-pass harness self-audit (Rule 17)
│   └── verify_invariants.py               # Deterministic invariant scan
├── agents/                                # 7 auditor subagent definitions
├── skills/                                # 21 skills (the upstream watcher lives in skills/upstream-auditor/scripts/)
├── tests/                                 # Hermetic unittest suite (342 tests)
└── templates/                             # HANDOFF, MISTAKES and config templates
```

Runtime state never lives in the repository: registry, baselines, leases, lock-mode records and the
upstream ledger are in `~/.local/state/antigravity-harness/`; snapshots and the installed runtime in
`~/.local/share/antigravity-harness/` (`XDG_STATE_HOME` / `XDG_DATA_HOME` are honoured).

---

## Quickstart & Installation

### Recommended: install from a source checkout (all platforms)

```bash
git clone https://github.com/hadbilen/antigravity-harness.git
cd antigravity-harness
python3 install.py          # Windows: python install.py   |   POSIX alternative: ./install.sh
```

The default **copy mode** installs real files into `~/.gemini/config` (so Guard can lock them), copies the
Guard runtime to `~/.local/share/antigravity-harness/runtime`, writes `agy-guard` / `agy-porter` launchers
to `~/.local/bin` (Windows: `%LOCALAPPDATA%\Programs\antigravity-guard\*.cmd`), merges the upstream hook
into `hooks.json` without dropping other hooks, backs replaced files up **outside** the config tree
(together with snapshots, baselines and backups left inside it by 1.3.0 and earlier),
establishes the integrity baseline and locks the governance scope. Re-running it over a locked scope asks
a human to confirm. Options: `--link` (developer symlink mode, cannot be locked), `--binary` (also install
the checksum-verified standalone binary), `--no-lock`, `--enable-startup`, `--dry-run`.

### Linux packages and standalone binaries

Release assets (see [GitHub Releases](https://github.com/hadbilen/antigravity-harness/releases)) ship with a
`.sha256` file each — verify before installing:

```bash
sha256sum -c antigravity-guard_1.4.0_amd64.deb.sha256
sudo apt install ./antigravity-guard_1.4.0_amd64.deb
```

Binaries are built for `linux-x86_64`, `macos-arm64` and `windows-x86_64`; `install.py --binary` downloads
the matching one only if its checksum matches. On other platforms (e.g. FreeBSD) the Python runtime is used.

---

## Antigravity Guard (`agy-guard`) Usage

```bash
# Health check (and re-lock / establish a missing baseline)
agy-guard doctor --fix

# Protection, integrity and lease status
agy-guard status

# Lock the governance seams; verify integrity
agy-guard lock
agy-guard verify

# Maintenance: prefer a time-bounded lease (human approval, automatic relock)
agy-guard request-unlock --duration 120 --reason "update skills"
agy-guard lock-complete            # relock now; offers to accept the window's changes

# Permanent unlock and accepting the current state require human confirmation
agy-guard unlock
agy-guard rebaseline

# Snapshots
agy-guard snapshot create --label pre_experiment
agy-guard snapshot list
agy-guard snapshot restore --id <snapshot_id>

# Porter gate
agy-guard porter inspect https://example.com/some_rule.md
agy-guard porter stage ./custom_rule.md

# Upstream repositories (zero LLM tokens)
agy-guard upstream check

# Other environments
agy-guard env detect --path ~/projects/my-app
agy-guard env list
agy-guard env policy antigravity monitored
agy-guard drift

# Test trust boundary and reproducibility
agy-guard test-boundary snapshot
agy-guard test-boundary verify --mode tdd
agy-guard test-boundary verify --base-ref origin/main
agy-guard test-boundary run-reproducible --cmd "pytest tests/test_core.py" --passes 2
agy-guard provenance generate

# Boot sentinel, notifications, self-audit, GUI
agy-guard startup enable
agy-guard boot-check
agy-guard notify quiet
agy-guard self-audit --strict
agy-guard gui

# Upstream watchdog notice: show the reasons, then silence it once reviewed
python3 ~/.gemini/config/skills/upstream-auditor/scripts/upstream_watcher.py --status
python3 ~/.gemini/config/skills/upstream-auditor/scripts/upstream_watcher.py --ack
```

Administration commands exit with code `3` when no human confirmation was given.

---

## Porter CLI (`porter.py` / `agy-porter`) Usage

```bash
# Read-only suitability inspection (a .zip is inspected without extracting anything)
python3 porter.py inspect path/to/external-rule.mdc
python3 porter.py inspect path/to/rule-bundle.zip --json

# Import into THIS repository (review with git diff, then deploy with install.py)
python3 porter.py import path/to/rules.md --as-skill test-skill --dry-run
python3 porter.py import path/to/tailwind-rules.mdc --as-skill tailwind-v4

# Export (refuses to overwrite existing files unless --force)
python3 porter.py export --target claude --out ./export/claude
python3 porter.py export --target all --out ./export/

# Regenerate / check the canonical manifest
python3 porter.py manifest
python3 porter.py manifest --check
```

---

## Verification & Continuous Integration

CI runs on Linux, macOS and Windows with Python 3.10–3.14 (actions pinned to commit SHAs, Python build tools
pinned to exact versions; apt packages come from the runner image). Pull requests additionally run the
**candidate code against the base branch's own tests and graders** in a clean worktree, and verify that
existing tests were only extended, never weakened. Workflow runs for pull requests from forks wait for the
maintainer's approval, and their result is advisory (see [`CONTRIBUTING.md`](CONTRIBUTING.md)).

```bash
# Hermetic unit test suite (342 tests)
python3 -m unittest discover -s tests -v

# Harness self-audit (Rule 17); --strict also fails on warnings
python3 scripts/meta_audit.py --all --strict

# Deterministic invariant scan / diff check
python3 scripts/verify_invariants.py --all
python3 scripts/verify_invariants.py --diff --base-ref origin/main
```

---

## Dependencies

The Guard, Porter and grader code uses only the Python standard library (3.10+). Optional extras: `tkinter`
for the GUI, `pystray` + `Pillow` or PyGObject/AppIndicator for the tray icon, and PyYAML (used by the
self-audit when present). The standalone binaries bundle `pystray` and `Pillow` via PyInstaller.

---

## Community Lineage & Acknowledgments

Grounded in prompt-failure post-mortems from [r/ChatGPTCoding](https://www.reddit.com/r/ChatGPTCoding/),
[r/ClaudeAI](https://www.reddit.com/r/ClaudeAI/) and [r/LocalLLaMA](https://www.reddit.com/r/LocalLLaMA/),
and on these open-source projects (licenses in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)):
`miqdadbadjuber/anti-slop`, `JayPokale/Chisle`, `Leonxlnx/unlazy`, `azrtydxb/procoder`,
`bendrape1-byte/silk-design`, `affaan-m/everything-claude-code`, `mattpocock/skills`.

---

## Contributing & License

Suggestions and pull requests are welcome; the maintainer decides what is merged (see
[`CONTRIBUTING.md`](CONTRIBUTING.md)). Every change must pass `python3 -m unittest discover -s tests`,
`python3 scripts/meta_audit.py --all --strict` and `python3 porter.py manifest --check`. Release tags are never
moved and release assets are never replaced. MIT licensed.

Licensed under the [MIT License](LICENSE).
