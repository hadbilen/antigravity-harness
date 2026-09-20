#!/usr/bin/env python3
"""
guard.py — Antigravity Guard (agy-guard) CLI & GUI Root Launcher
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.

Usage:
  python3 guard.py status                     # View write-protection and multi-environment status
  python3 guard.py lock [--env <id>|--all]    # Lock environment(s) with OS write protection
  python3 guard.py unlock [--env <id>|--all]  # Unlock environment(s) for maintenance
  python3 guard.py verify [--env <id>|--all]  # Check SHA-256 file integrity (FIM)
  python3 guard.py rebaseline                 # Update trusted SHA-256 integrity baseline
  python3 guard.py env list                   # List tracked agent environments and policies
  python3 guard.py env detect                 # Auto-discover coding agent governance seams
  python3 guard.py request-unlock --env <id>  # Request human-authorized temporary lease unlock
  python3 guard.py lock-complete              # Signal maintenance completion and re-lock
  python3 guard.py drift [--env <id>]         # Analyze drift across multi-environment baselines
  python3 guard.py self-audit [--json]        # Run autonomous harness meta-consistency audit
  python3 guard.py snapshot create --label X  # Create local state snapshot
  python3 guard.py snapshot list              # List available snapshots
  python3 guard.py porter inspect <path/url>  # Inspect rule with Porter suitability gate
  python3 guard.py porter stage <path/url>    # Staging & atomic promotion gate
  python3 guard.py upstream check             # Check 7 tracked repos (zero LLM token cost)
  python3 guard.py test-boundary snapshot     # Snapshot workspace test & config trust boundary
  python3 guard.py test-boundary verify       # Verify test suite immutability (bugfix/tdd)
  python3 guard.py test-boundary run-reproducible --cmd "<cmd>" # Verify 2x test reproducibility
  python3 guard.py provenance generate        # Generate execution provenance manifest
  python3 guard.py startup status             # Manage Pre-Session Boot Sentinel startup
  python3 guard.py boot-check                 # Headless boot verification and lock enforcement
  python3 guard.py doctor [--fix]             # Environment health check & auto-healing
  python3 guard.py gui                        # Launch desktop GUI
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Add repository root to python path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from guard.cli import main

if __name__ == "__main__":
    sys.exit(main())
