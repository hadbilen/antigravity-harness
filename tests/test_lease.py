"""
tests/test_lease.py — Test Lease-Based Human-in-the-Loop Unlock Protocol
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly the Python standard library.
"""


from __future__ import annotations

import hermetic  # noqa: F401  (isolates HOME/state before guard is imported)

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from guard.environment import AgentEnvironment, EnvironmentRegistry
from guard.lease import LeaseManager, UnlockLease
from guard.notifier import GuardNotifier
from guard.os_adapter import OSProtectionAdapter


class TestLeaseManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.config_dir = self.root / ".harness"
        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.env_config = self.config_dir / "environments.json"
        self.lease_file = self.config_dir / ".active_lease.json"
        self.notify_cache = self.config_dir / ".notify_cache.json"

        # Create mock adapter to avoid actually locking files in test tempdir
        self.mock_adapter = MagicMock(spec=OSProtectionAdapter)
        self.mock_adapter.lock.return_value = (True, "Mock locked")
        self.mock_adapter.unlock.return_value = (True, "Mock unlocked")
        self.mock_adapter.is_locked.return_value = True

        self.registry = EnvironmentRegistry(
            config_path=self.env_config,
            workspace_dir=self.root,
            os_adapter=self.mock_adapter,
        )

        # Register a test environment
        self.test_env = AgentEnvironment(
            id="test_env",
            name="Test Environment",
            platform_type="claude",
            root_path=str(self.root),
            governance_paths=["test_rule.md"],
            policy="enforced",
        )
        self.registry.register_environment(self.test_env)
        (self.root / "test_rule.md").write_text("# Test Rule", encoding="utf-8")

        self.notifier = GuardNotifier(cache_file=self.notify_cache, enabled=False)
        self.scheduled = []
        self.manager = LeaseManager(
            registry=self.registry,
            notifier=self.notifier,
            lease_file=self.lease_file,
            scheduler=lambda lease, manager: (self.scheduled.append(lease.lease_id) or True, "test scheduler"),
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_request_unlock_rejected_without_approval(self):
        ok, msg, lease = self.manager.request_unlock(
            env_id="test_env",
            reason="Testing rejection",
            duration_seconds=30,
            interactive=False,
        )
        self.assertFalse(ok)
        self.assertIsNone(lease)
        self.assertIn("rejected", msg.lower())
        self.assertIsNone(self.manager.get_active_lease())

    def test_request_unlock_auto_approved(self):
        ok, msg, lease = self.manager.request_unlock(
            env_id="test_env",
            reason="Automated test pass",
            duration_seconds=60,
            approver=lambda request: True,
        )
        self.assertTrue(ok)
        self.assertIsNotNone(lease)
        self.assertEqual(lease.env_id, "test_env")
        self.assertEqual(lease.duration_seconds, 60)
        self.assertTrue(lease.is_active)
        self.mock_adapter.unlock.assert_called()
        self.assertEqual(self.scheduled, [lease.lease_id])

        # Check persistence
        active = self.manager.get_active_lease()
        self.assertIsNotNone(active)
        self.assertEqual(active.lease_id, lease.lease_id)

    def test_complete_lease_relocks_early(self):
        ok, _, lease = self.manager.request_unlock(
            env_id="test_env",
            reason="Early complete test",
            duration_seconds=60,
            approver=lambda request: True,
        )
        self.assertTrue(ok)

        # Signal early completion
        comp_ok, comp_msg = self.manager.complete_lease(env_id="test_env")
        self.assertTrue(comp_ok)
        self.mock_adapter.lock.assert_called()

        # Active lease should now be expired / cleared
        self.assertIsNone(self.manager.get_active_lease())

    def test_check_and_expire_leases_on_timeout(self):
        # Create a lease that expired in the past
        past_time = time.time() - 100
        expired_lease = UnlockLease(
            lease_id="expired1",
            env_id="test_env",
            env_name="Test Environment",
            reason="Testing expiry",
            duration_seconds=10,
            granted_at=past_time,
            expires_at=past_time + 10,
            target_paths=[str(self.root / "test_rule.md")],
            is_active=True,
        )
        self.lease_file.write_text(json.dumps(expired_lease.to_dict(), indent=2), encoding="utf-8")

        # Calling get_active_lease or check_and_expire_leases should detect expiry
        expired_list = self.manager.check_and_expire_leases()
        self.assertEqual(len(expired_list), 1)
        self.assertEqual(expired_list[0].lease_id, "expired1")
        self.mock_adapter.lock.assert_called()
        self.assertIsNone(self.manager.get_active_lease())


if __name__ == "__main__":
    unittest.main()
