# Antigravity Harness v1.2.3 — State-Synchronized Rollback, Isolated Trust Anchor & Cross-Platform CI Matrix

A security hardening and governance milestone release elevating **Antigravity Harness** and **Antigravity Guard (`agy-guard`)** from basic write protection and copy-based snapshots into a **true full-state rollback engine, isolated cryptographic trust anchor, and cross-platform continuous integration framework**.

v1.2.3 addresses and resolves all key architectural findings identified in independent peer audits: eliminating file leakage during snapshot rollback, allowing cryptographic integrity baselines to live outside the protected target boundary, detecting and healing crash-induced stale unlock states, and establishing an automated multi-platform CI matrix across Linux, macOS, and Windows.

---

### Core Philosophy: True State Parity & Resilient Governance

In autonomous AI agent environments, write barriers and snapshots are only as dependable as their edge recovery guarantees:
1. **True State Synchronization:** When an experimental rule, rogue process, or failed ingestion corrupts the environment, a rollback must return the filesystem to the exact prior state. Simply overwriting matching files is insufficient; unauthorized files and directories created *after* the snapshot must be deterministically pruned.
2. **Trust Domain Separation:** A cryptographic baseline stored inside the very directory it monitors shares the write privileges of that directory. True tamper evidence requires supporting isolated trust anchors outside the protected target path.
3. **Crash Resilience:** If an operating system process terminates abruptly (SIGKILL, power failure) during a maintenance window, the environment must not stay silently unlocked. Boot diagnostics must detect stale exposures and safely re-lock the system.

**v1.2.3 enforces all three invariants mechanically.**

---

### What's New in v1.2.3

#### 1. Full-State Snapshot Rollback & Extraneous File Pruning (`guard/snapshot.py`)
* **State Parity Restoration:** Refactored `SnapshotEngine.restore_snapshot()` to compute a bidirectional diff between the snapshot and current filesystem state.
* **Extraneous File Pruning:** Any files or subdirectories introduced into the configuration tree after the snapshot was captured are recursively pruned during rollback.
* **Preserved Infrastructure:** Safely retains essential infrastructure items (`.guard_snapshots`, `__pycache__`, `.git`, `.guard_integrity.json`, and emergency `.backup_*` records) while ensuring 100% state parity for all managed rules, skills, and agents.

#### 2. Isolated Cryptographic Trust Anchor (`guard/integrity.py`)
* **External Anchor Resolution:** `FileIntegrityMonitor` now supports hosting the SHA-256 integrity baseline outside the protected directory via `ANTIGRAVITY_INTEGRITY_FILE` or standard user dotfile location (`~/.gemini/.guard_integrity.json`).
* **Isolation Diagnostics:** Added `is_isolated` inspection property to verify whether the cryptographic baseline is physically isolated from the target tree, preventing simultaneous config-and-baseline tampering.

#### 3. Stale Unlock Recovery & `agy-guard doctor` Diagnostic Routine (`guard/os_adapter.py`, `guard/cli.py`)
* **Stale Lock Recovery:** Added `OSProtectionAdapter.recover_stale_lock()` to detect unshielded environments resulting from abnormal crashes or incomplete maintenance workflows, safely re-engaging OS-level write protection.
* **Ergonomic Doctor Command:** Added `agy-guard doctor [--fix]`:
  * Audits OS write shield status, trust anchor placement, FIM integrity, and snapshot inventory.
  * Automatically heals stale unlocked states and missing baselines when invoked with `--fix` / `--recover`.

#### 4. Multi-Platform GitHub Actions CI Matrix (`.github/workflows/ci.yml`)
* **Comprehensive Multi-OS Matrix:** Establishes automated CI workflows running on `ubuntu-latest`, `macos-latest`, and `windows-latest` across Python 3.10, 3.11, and 3.12.
* **Continuous Invariant Gates:** Executes the expanded 21-test unit suite (`tests/test_guard.py`) and deterministic invariant verification (`scripts/verify_invariants.py --all`) on every commit and pull request.

#### 5. Expanded Test Suite & Verification (`tests/test_guard.py`)
* Added `test_restore_snapshot_prunes_extraneous_files` validating deletion of rogue files and directories on rollback.
* Added `test_isolated_trust_anchor` validating out-of-tree baseline creation and verification.
* Added `test_recover_stale_lock` verifying automatic shield re-engagement.
* Added `test_doctor_command` validating the full diagnostic and auto-healing lifecycle.

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

Verify Antigravity Guard v1.2.3 and run the health check:

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
