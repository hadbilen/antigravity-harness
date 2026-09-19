# Antigravity Harness v1.2.4 — Windows NTFS Governance Patch, Recursive Unlocks & Root Repository Hygiene

A cross-platform reliability, Windows NTFS access control hardening, and repository cleanliness patch release for **Antigravity Harness** and **Antigravity Guard (`agy-guard`)**.

v1.2.4 resolves edge-case permission constraints discovered on Windows NTFS filesystems during cryptographic verification under lock, adds recursive directory unlock routines, protects console logging against Unicode encoding crashes in non-UTF-8 terminals, and standardizes repository root hierarchy and hygiene.

---

### Key Improvements in v1.2.4

#### 1. Windows NTFS Specific Rights & Preserved READ_CONTROL (`guard/os_adapter.py`)
* **Specific Rights Protection:** Replaced broad `(W)` write-denial with granular specific rights `(WD,AD,DE,DC)` via `icacls`.
* **READ_CONTROL Preservation:** The generic `W` right on Windows includes `READ_CONTROL`. Denying `W` prevented opening files for binary read (`rb`), triggering false `PermissionError` exceptions during baseline hashing on locked files. Granular rights ensure files remain readable and verifiable while strictly blocking file creation, appending, and deletion.

#### 2. Recursive Subdirectory Unlock on Windows (`guard/os_adapter.py`)
* **Recursive ACE Removal:** Updated `icacls ... /remove:d` to append `/t /c /q` flags.
* **Inheritance Cleared:** Ensures all inherited and nested deny Access Control Entries (ACEs) across subdirectories are fully purged during unlock routines.

#### 3. Windows Directory Lock Probe (`guard/os_adapter.py`)
* **Dynamic Probe Verification:** Because Windows does not clear `stat.S_IWRITE` on directories, `is_locked()` on Windows now verifies directory write status by attempting to write a temporary probe file (`.guard_probe.tmp`), reliably detecting directory-level NTFS write barriers.

#### 4. ASCII-Safe Terminal Status Output (`guard/cli.py`, `guard/integrity.py`)
* **CP1252 / Non-UTF8 Resilience:** Replaced Unicode status characters with standardized `[OK]` and `[WARN]` markers, preventing runtime `UnicodeEncodeError` crashes on default Windows terminal environments.

#### 5. Repository Root Hygiene & Architectural Cleanup
* **Root De-cluttering:** Relocated auxiliary configuration and metadata files:
  * `antigravity-guard.desktop` moved to `installers/antigravity-guard.desktop`
  * `HANDOFF.md` moved to `docs/HANDOFF.md`
  * Release notes aggregated into `docs/releases/`
  * `tasks.md` removed from git tracking and protected in `.gitignore`
* **Unified Changelog:** Established root `CHANGELOG.md` tracking all historical releases from `v1.0.0` through `v1.2.4`.

---

### Installation & Upgrading

#### Upgrading an Existing Installation

```bash
cd ~/.gemini/antigravity-harness
git pull origin main

# Unix / macOS / Linux
chmod +x install.sh
./install.sh

# Windows / Cross-Platform
python3 install.py
```

#### CLI Verification

Verify Antigravity Guard v1.2.4 and run the health check:

```bash
# Run environment health check and auto-heal
agy-guard doctor --fix

# Check environment security and write protection
agy-guard status

# Run cryptographic file integrity verification
agy-guard verify

# Run automated test suite
python3 -m unittest discover -s tests -v

# Run deterministic invariant verification
python3 scripts/verify_invariants.py --all
```
