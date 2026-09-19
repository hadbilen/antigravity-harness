# Task Checklist: Porter Ecosystem Bridge & v1.1.0 Release

- [x] Phase 1: Core Porter Engine Development
  - [x] Create persistent task checklist (`tasks.md`)
  - [x] Implement `porter/models.py` (data structures)
  - [x] Implement `porter/sanitizer.py` (constitutional de-slop & invariant filter)
  - [x] Implement `porter/analyzer.py` (pre-flight suitability & adaptability analyzer)
  - [x] Implement `porter/manifest.py` (lossless universal canonical manifest)
  - [x] Implement parsers (`porter/parsers/`: `generic_parser.py`, `mdc_parser.py`, `flat_parser.py`)
  - [x] Implement emitters (`porter/emitters/`: `claude.py`, `cursor.py`, `universal.py`, `aider.py`, `generic.py`)
  - [x] Implement `porter/__init__.py` and root CLI `porter.py`
- [x] Phase 2: Antigravity Skill & Harness Invariants
  - [x] Create `skills/porter/SKILL.md` (natural language routing, pre-flight gate, interactive prompt)
  - [x] Update `GEMINI.md` with External Rule Ingestion Invariant (Rule 16)
  - [x] Update `install.py` & `install.sh` to symlink/copy porter into active environments
  - [x] Update `README.md` for v1.1.0 architecture & usage guide
- [x] Phase 3: Verification & Local Testing
  - [x] Test CLI commands (`inspect`, `import`, `export --target all`, `manifest`)
  - [x] Verify installer execution (`install.py` and `install.sh`)
  - [x] Verify active configuration update (`~/.gemini/config/`)
- [x] Phase 4: Remote Push & GitHub v1.1.0 Release
  - [x] Review git status & commit all changes with conventional commit
  - [x] Push `origin main`
  - [x] Create annotated git tag `v1.1.0` & push tag
  - [x] Publish rich GitHub release with pre-v1.0.4 style comprehensive release notes
  - [x] Generate `walkthrough.md`

- [x] Phase 5: v1.1.1 Hardening & Production Maturation
  - [x] Update version to 1.1.1 across repo (`porter/__init__.py`, `porter.py`, `models.py`, `install.py`, etc.)
  - [x] Implement SSRF & private IP protection in `porter.py` (`fetch_target_content`)
  - [x] Implement lossless skill subfiles (`scripts/`, `assets/`, `references/`) in `porter/manifest.py`
  - [x] Harden `porter/sanitizer.py` to scrub/comment out test weakening & sycophancy directives
  - [x] Fix metadata synchronization ("18 skills" -> dynamic count) in `analyzer.py` and `models.py`
  - [x] Harden `skills/upstream-auditor/scripts/upstream_watcher.py` (respect `ANTIGRAVITY_CONFIG_DIR`, retry backoff on network failure)
  - [x] Fix cross-platform portability in `hooks.json` and `install.py`
  - [x] Add `scripts/verify_invariants.py` for machine-enforced test invariants and diff checks
  - [x] Regenerate `.harness/manifest.json` with full subfiles
- [x] Phase 6: v1.2.0 Antigravity Guard (`agy-guard`) Governance Suite & Write Protection
  - [x] Design cross-platform OS write protection adapter (`guard/os_adapter.py`)
  - [x] Build cryptographic SHA-256 File Integrity Monitor (`guard/integrity.py`)
  - [x] Implement atomic snapshot and rollback engine (`guard/snapshot.py`)
  - [x] Build Porter Staging Gate & visual diff bridge (`guard/porter_bridge.py`)
  - [x] Implement Upstream Auditor watchdog bridge (`guard/upstream.py`)
  - [x] Build rich CLI interface (`guard/cli.py`, `guard.py`)
  - [x] Build dark-mode desktop GUI adhering to `DESIGN.md` (`guard/gui.py`, `antigravity-guard.desktop`)
  - [x] Create multi-platform launchers (`bin/agy-guard`, `bin/agy-guard.bat`, `bin/agy-guard.ps1`)
  - [x] Update installers (`install.py`, `install.sh`) to link `guard` and install launcher to `~/.local/bin/agy-guard`
  - [x] Bump version to 1.2.0 across `.harness/manifest.json`, `porter/__init__.py`, `guard/__init__.py`, `README.md`
  - [x] Create automated unit tests (`tests/test_guard.py`) and verify invariants
  - [x] Git commit, tag `v1.2.0`, push to `origin/main`
  - [x] Publish rich GitHub release `v1.2.0`



