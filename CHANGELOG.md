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
- **Antigravity Guard Suite:** Cross-platform OS write protection, cryptographic FIM, lightweight snapshots, and Desktop GUI.
- See detailed notes: [docs/releases/RELEASE_NOTES_v1.2.0.md](docs/releases/RELEASE_NOTES_v1.2.0.md)
