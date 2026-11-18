import unittest

from scripts.security_provider_inventory import (
    InventoryError,
    Posture,
    ProviderObservation,
    ProviderStatus,
    SecurityCategory,
    assess_device_category,
)


class SecurityProviderInventoryTests(unittest.TestCase):
    def observation(self, status=ProviderStatus.HEALTHY, **overrides):
        values = {
            "tenant_id": "tenant-a",
            "device_id": "device-a",
            "provider_id": "vendor.edr",
            "display_name": "Existing Endpoint Protection",
            "category": SecurityCategory.MALWARE_PROTECTION,
            "status": status,
            "evidence_source": "configured vendor connector",
            "observed_at_unix_ms": 100_000,
            "product_identity_known": True,
            "capabilities": ("malware_protection", "quarantine"),
        }
        values.update(overrides)
        return ProviderObservation(**values)

    def assess(self, items, **kwargs):
        args = {
            "tenant_id": "tenant-a",
            "device_id": "device-a",
            "category": SecurityCategory.MALWARE_PROTECTION,
            "observations": items,
            "now_unix_ms": 100_000,
            "max_age_ms": 60_000,
        }
        args.update(kwargs)
        return assess_device_category(**args)

    def test_existing_provider_and_capabilities_are_reported(self):
        result = self.assess([self.observation()])
        self.assertEqual(result.posture, Posture.REPORTED_HEALTHY)
        self.assertTrue(result.product_identity_known)
        self.assertEqual(result.capabilities, ("malware_protection", "quarantine"))

    def test_alert_overrides_healthy(self):
        result = self.assess([
            self.observation(),
            self.observation(ProviderStatus.ALERT, provider_id="vendor.second"),
        ])
        self.assertEqual(result.posture, Posture.ALERT)

    def test_no_provider_is_advice_not_an_install_or_remediation_action(self):
        result = self.assess([self.observation(ProviderStatus.NOT_MONITORED)])
        self.assertEqual(result.posture, Posture.NO_PROVIDER_REPORTED)
        self.assertIn("ask the administrator", result.recommendation)

    def test_stale_future_or_missing_evidence_is_unverified(self):
        stale = self.observation(observed_at_unix_ms=1)
        future = self.observation(observed_at_unix_ms=200_000)
        self.assertEqual(self.assess([stale]).posture, Posture.UNVERIFIED)
        self.assertEqual(self.assess([future]).posture, Posture.UNVERIFIED)
        self.assertEqual(self.assess([]).posture, Posture.UNVERIFIED)

    def test_cross_tenant_or_device_evidence_is_rejected(self):
        for field, value in (("tenant_id", "tenant-b"), ("device_id", "device-b")):
            with self.subTest(field=field):
                with self.assertRaisesRegex(InventoryError, "cross-tenant"):
                    self.assess([self.observation(**{field: value})])

    def test_bounds_are_enforced(self):
        with self.assertRaisesRegex(InventoryError, "limit exceeded"):
            self.assess([self.observation() for _ in range(65)])
        with self.assertRaisesRegex(InventoryError, "timestamp"):
            self.assess([self.observation(observed_at_unix_ms=True)])

    def test_capabilities_are_deduplicated_and_sorted(self):
        item = self.observation(capabilities=("quarantine", "malware_protection", "quarantine"))
        result = self.assess([item])
        self.assertEqual(result.capabilities, ("malware_protection", "quarantine"))


if __name__ == "__main__":
    unittest.main()
