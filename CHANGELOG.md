# Changelog

All notable changes to Antigravity Harness are documented in this file and detailed in release notes.

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
