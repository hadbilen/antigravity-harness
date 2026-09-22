# Antigravity Harness

[![Release](https://img.shields.io/badge/release-v1.3.1-blue.svg)](https://github.com/hadbilen/antigravity-harness/releases)
[![CI](https://github.com/hadbilen/antigravity-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/hadbilen/antigravity-harness/actions/workflows/ci.yml)
[![Runtime](https://img.shields.io/badge/core%20runtime-Python%20stdlib%20only-brightgreen.svg)](#dependencies)
[![Design Standard](https://img.shields.io/badge/UI-WCAG%20AA%20%7C%20antislop-orange.svg)](DESIGN.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **A behavioral constitution, auditor subagents, a rule transpiler, and a write-protection /
> integrity-monitoring companion (`agy-guard`) for AI coding agents.**

Autonomous coding agents suffer from **environment mutation drift**, **sycophancy**, **test weakening
(Goodhart's Curse)**, **context bloat**, and **ecosystem fragmentation**. Antigravity Harness counters
them with an engineering constitution (`GEMINI.md`), 20 modular skills, 7 independent auditor
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
| Headless / unattended agents: administration commands (`unlock`, `rebaseline`, `snapshot restore`, `porter stage`, …) refuse without a human typing `yes` in a terminal or approving in the GUI | An agent that can drive an interactive terminal *and* chooses to ignore the constitution |
| Silent drift: the SHA-256 baseline (outside the protected tree) reports modified, added, deleted and unreadable files | An attacker who can rewrite both the files **and** the per-user baseline (it is not signed) |
| Forgotten maintenance windows: leases relock automatically when they expire | `root` / administrators, or kernel-level tampering |

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
  (install in copy mode to protect it). Original permission modes are recorded and restored exactly on unlock.
* `lock` returns a non-zero exit code and lists the reasons whenever protection is only partial.

### Integrity baseline (`guard/integrity.py`)
* A flat `path -> SHA-256` map per environment, stored in `~/.local/state/antigravity-harness/integrity/`
  (outside the protected tree; `ANTIGRAVITY_INTEGRITY_FILE` overrides it for the global environment).
* Records symlinks as links (retargeting is detected), reports unreadable files, ignores installer backups,
  and archives the previous baseline on every rebaseline. It detects drift; it is not a signature.

### Snapshots & verified restore (`guard/snapshot.py`)
* Snapshots of the governance scope live in `~/.local/share/antigravity-harness/snapshots/` with a content manifest.
* Restore verifies the snapshot, refuses to write through destination symlinks, always takes a pre-restore
  backup first, swaps entries with a journal (rolled back on failure), and re-establishes the baseline.
* `prune` keeps N snapshots **per kind** (manual, pre-restore, pre-ingest, boot forensics).

### Multi-environment registry (`guard/environment.py`)
* Discovers Claude Code, Codex / `AGENTS.md`, Cursor and Aider workspaces; ids include a path hash so
  two projects with the same folder name never collide; ambiguous ids are rejected.
* Policies: `enforced`, `monitored`, `disabled` (`agy-guard env policy <id> <policy>`).
* The registry lives in the per-user state directory, so results never depend on the current directory.

### Human-approved, time-bounded leases (`guard/lease.py`)
* `agy-guard request-unlock --duration 60` asks a human to approve in the terminal (or the GUI); headless
  requests are rejected. There is no auto-approve flag.
* The record is persisted **before** unlocking; a detached watcher relocks when the lease expires, and every
  Guard command also expires overdue leases. Several environments can hold leases at the same time.
* Closing relocks first; only a successful relock writes a change report
  (`~/.local/state/antigravity-harness/lease_reports/<id>.json`) and a new baseline. A failed relock keeps
  the lease record and raises a CRITICAL notification.

### Notifications (`guard/notifier.py`)
* `notify-send` (Linux), `osascript` (macOS), PowerShell balloon tips (Windows); message text is passed as
  data (argv / environment), never interpolated into code. Falls back to the terminal.
* Cooldowns: `CRITICAL` none, `WARNING` 30 minutes, `INFO` 24 hours. `agy-guard notify quiet` passes
  CRITICAL only; `agy-guard notify disable` silences everything (force never overrides it).

### Boot sentinel, doctor and GUI
* `agy-guard startup enable` registers a systemd user unit / launchd agent / scheduled task that runs
  `boot-check`: on drift it captures a forensic snapshot, keeps the scope locked, sends a CRITICAL
  notification and never rebaselines. (Ordering before the graphical session is best-effort.)
* `agy-guard doctor [--fix]` reports protection gaps, legacy baselines/snapshots inside the config tree,
  world-writable sources, symlink installs and risky Antigravity permission grants (counts only).
* **Full CLI Workflow (20 subcommands):** `status`, `lock`, `unlock`, `verify`, `rebaseline`, `snapshot`, `porter`, `upstream`, `startup`, `boot-check`, `gui`, `doctor`, `test-boundary`, `provenance`, `env`, `request-unlock`, `lock-complete`, `drift`, `self-audit`, `notify` (plus the internal `lease-tick` used by the lease watcher).
* **Desktop GUI (`guard/gui.py`):** Tkinter/ttk, `DESIGN.md` dark palette; long operations run off the UI
  thread, tray callbacks are marshalled onto the Tk loop, and unlock / rebaseline / lease actions ask for confirmation.

---

## 2. The Engineering Constitution (`GEMINI.md`)

* **Proportional Gate Escalation:** Tier 1 (1–2 files, <20 lines) direct edits; Tier 2 (3–8 files) plans,
  blast-radius maps and checklists; Tier 3 (>8 files or auth/schema changes) the full workflow with
  `deep-grill`, ADRs, `unlazy`/`procoder` and auditor subagents.
* **The Immutable Test Invariant:** relaxing assertions or skipping tests to pass gates is forbidden; new
  regression tests are always allowed.
* **Think in Code:** filter with `grep`/`jq`/`awk` or small scripts instead of dumping raw files into context.
* **Circuit Breaker & Out-of-Band Meta-Diagnosis**, **Popper's Falsification Gate**, and the
  **Session Boundary Protocol** (`HANDOFF.md` after major deliveries or ~25 turns).
* **Guard administration is human-only (Rule 12)** and upstream collisions are reported to the user
  instead of being silently resolved (Rule 15).

---

## 3. Auditor Subagents (`/agents`)

Seven role definitions whose read-only behavior is specified in their prompts (tool restrictions depend on the host platform):

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
* **Negation-aware sanitizer (`porter/sanitizer.py`):** neutralises directives such as "skip the failing
  tests" or "mark failing tests as xfail" while keeping protective rules such as "never skip tests"; it is a
  pattern filter, so every result is shown for human review.
* **SSRF-hardened fetcher (`porter/net.py`):** http/https only, globally routable destinations only
  (CGNAT, link-local, private, 6to4/NAT64 and IPv4-mapped loopback are rejected), DNS pinning against
  rebinding, per-redirect validation, proxies ignored, 10 MB cap.
* **Canonical manifest:** all 20 skills with every support file and in-skill symlink, all 7 subagents, the
  constitution and the design contract. CI fails if the committed manifest is stale (`porter.py manifest --check`).
* **Verified export:** Claude Code (`CLAUDE.md`, `.claude/skills/`, `.claude/agents/`), Cursor
  (`.cursor/rules/*.mdc` with valid YAML + `.cursor/skills/`), Universal (`AGENTS.md` + `.agents/`), Aider
  (`CONVENTIONS.md`, `.aider.conf.yml`, `.aider/`), Generic (`RULES.md`, `skills/`, `agents/`). Skills,
  support files and agents are exported verbatim and the self-audit checks parity by content. Existing
  files are only overwritten with `--force`.
* **Staging gate:** `agy-guard porter stage` binds the reviewed content hash to the written content, refuses
  destination symlinks, snapshots first and re-locks afterwards; `porter.py import` only writes into this
  source repository (review it with `git diff`).

---

## 5. Modular Skill Ecosystem (`/skills`)

20 capability packages:

* **`harness`:** engineering harness, verification gates, task lifecycle.
* **`porter`:** ecosystem adapter, suitability analyzer, transpiler.
* **`vibecoder`:** product-first rapid prototyping with zero-friction HTML delivery.
* **`unlazy`:** Tier 3 (>8 files) deep completion engine with depth trees and ledger-based verification.
* **`deep-grill`:** Socratic trade-off interviewer.
* **`chisle`:** terse, zero-fluff development mode (presentation only; never bypasses gates).
* **`procoder`:** sprint scaffolding for repositories that contain `.procoder/`.
* **`antislop` suite (6):** `antislop` (core 38-rule filter), `antislop-ui`, `antislop-code`,
  `antislop-copywriting`, `antislop-human` (WCAG contrast checker + MCP tool), `antislop-layoutmobile`.
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
├── CHANGELOG.md / THIRD_PARTY_NOTICES.md / LICENSE
├── hooks.json                             # Reference PreInvocation hook (the installer writes an absolute path)
├── install.py / install.sh                # Installer (install.sh is a POSIX wrapper around install.py)
├── guard.py / porter.py                   # CLI entry points
├── .github/workflows/ci.yml               # 3 OS x Python 3.10-3.14, lint, trusted-boundary, release
├── .harness/manifest.json                 # Canonical manifest (checked by CI)
├── bin/                                   # agy-guard launchers (POSIX, .bat, .ps1)
├── installers/                            # PyInstaller build, Linux packages (.deb/.rpm/Arch), desktop entry
├── guard/                                 # Guard: os_adapter, environment, integrity, snapshot, lease,
│                                          #   notifier, approval, paths, startup, test_boundary, provenance,
│                                          #   porter_bridge, upstream, cli, gui, tray
├── porter/                                # analyzer, sanitizer, frontmatter, manifest, net, emitters/
├── scripts/
│   ├── meta_audit.py                      # 6-pass harness self-audit (Rule 17)
│   └── verify_invariants.py               # Deterministic invariant scan
├── agents/                                # 7 auditor subagent definitions
├── skills/                                # 20 skills (the upstream watcher lives in skills/upstream-auditor/scripts/)
├── tests/                                 # Hermetic unittest suite (179 tests)
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
sha256sum -c antigravity-guard_1.3.1_amd64.deb.sha256
sudo apt install ./antigravity-guard_1.3.1_amd64.deb
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
agy-guard lock-complete

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
```

Administration commands exit with code `3` when no human confirmation was given.

---

## Porter CLI (`porter.py` / `agy-porter`) Usage

```bash
# Read-only suitability inspection
python3 porter.py inspect path/to/external-rule.mdc

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

CI runs on Linux, macOS and Windows with Python 3.10–3.14 (all actions pinned to commit SHAs, build tools
pinned to exact versions). Pull requests additionally run the **candidate code against the base branch's
own tests and graders** in a clean worktree, and verify that existing tests were only extended, never edited.

```bash
# Hermetic unit test suite (179 tests)
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

Contributions, boundary tests and additional auditor subagents are welcome. Every change must pass
`python3 -m unittest discover -s tests`, `python3 scripts/meta_audit.py --all --strict` and
`python3 porter.py manifest --check`. Release tags are never moved and release assets are never replaced.

Licensed under the [MIT License](LICENSE).
