import unittest

from scripts.security_provider_inventory import (
    InventoryError,
    Posture,
    ProviderObservation,
    ProviderStatus,
    SecurityCategory,
    UpdatePosture,
    UpdateStatus,
    assess_device_category,
    build_operator_inventory_payload,
    observation_from_validated_connector_record,
    to_operator_inventory_record,
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
        self.assertEqual(result.update_posture, UpdatePosture.NOT_REPORTED)

    def test_provider_reported_outdated_security_intelligence_is_a_warning(self):
        result = self.assess([self.observation(
            update_status=UpdateStatus.OUT_OF_DATE,
            update_checked_at_unix_ms=99_000,
            update_channel="security_intelligence",
        )])
        self.assertEqual(result.posture, Posture.REPORTED_HEALTHY)
        self.assertEqual(result.update_posture, UpdatePosture.OUT_OF_DATE)
        self.assertIn("out of date", result.update_recommendation)
        self.assertIn("antivirus", result.update_recommendation)

    def test_current_update_state_requires_fresh_provider_evidence(self):
        current = self.observation(
            update_status=UpdateStatus.CURRENT,
            update_checked_at_unix_ms=99_000,
        )
        self.assertEqual(self.assess([current]).update_posture, UpdatePosture.CURRENT)
        stale = self.observation(
            update_status=UpdateStatus.CURRENT,
            update_checked_at_unix_ms=1,
        )
        self.assertEqual(self.assess([stale]).update_posture, UpdatePosture.UNVERIFIED)

    def test_missing_update_evidence_never_claims_current(self):
        result = self.assess([self.observation()])
        self.assertNotEqual(result.update_posture, UpdatePosture.CURRENT)
        self.assertIn("cannot verify", result.update_recommendation)

    def test_firewall_feed_reported_outdated_is_a_security_warning(self):
        item = self.observation(
            category=SecurityCategory.FIREWALL,
            update_status=UpdateStatus.OUT_OF_DATE,
            update_checked_at_unix_ms=99_000,
            update_channel="firewall_signatures",
        )
        result = self.assess([item], category=SecurityCategory.FIREWALL)
        self.assertEqual(result.update_posture, UpdatePosture.OUT_OF_DATE)
        self.assertIn("firewall", result.update_recommendation)
        self.assertIn("rule/signature feeds", result.update_recommendation)

    def test_mixed_current_and_unknown_providers_never_claim_all_current(self):
        current = self.observation(
            update_status=UpdateStatus.CURRENT,
            update_checked_at_unix_ms=99_000,
        )
        unknown = self.observation(provider_id="vendor.second")
        result = self.assess([current, unknown])
        self.assertEqual(result.update_posture, UpdatePosture.UNVERIFIED)

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

    def test_direct_observations_reject_invalid_identity_and_capability_fields(self):
        with self.assertRaisesRegex(InventoryError, "product-identity flag"):
            self.assess([self.observation(product_identity_known="false")])
        with self.assertRaisesRegex(InventoryError, "capability list"):
            self.assess([self.observation(capabilities=("bad\\ncapability",))])
        with self.assertRaisesRegex(InventoryError, "category or health status"):
            self.assess([self.observation(status="healthy")])
        with self.assertRaisesRegex(InventoryError, "observation record"):
            self.assess([{"provider_id": "untrusted"}])
        with self.assertRaisesRegex(InventoryError, "provider identifier"):
            self.assess([self.observation(provider_id="p" * 97)])
        with self.assertRaisesRegex(InventoryError, "capability list"):
            self.assess([self.observation(capabilities=("c" * 97,))])

    def test_invalid_update_timestamp_is_rejected(self):
        item = self.observation(
            update_status=UpdateStatus.CURRENT,
            update_checked_at_unix_ms=True,
        )
        with self.assertRaisesRegex(InventoryError, "update-check timestamp"):
            self.assess([item])

    def test_validated_connector_record_maps_to_enrolled_device_posture(self):
        record = {
            "tenant_id": "tenant-a",
            "provider_id": "vendor.edr",
            "record_id": "record-001",
            "observed_at_unix_ms": 100_000,
            "fields": {
                "category": "malware_protection",
                "status": "healthy",
                "product_identity_known": "true",
                "capabilities": '["malware_protection","quarantine"]',
                "update_status": "out_of_date",
                "update_checked_at_unix_ms": "99000",
                "update_channel": "security_intelligence",
                "display_name": "Existing Endpoint Protection",
            },
        }
        item = observation_from_validated_connector_record(
            authenticated_tenant_id="tenant-a",
            enrolled_device_id="device-a",
            expected_provider_id="vendor.edr",
            record=record,
        )
        self.assertEqual(item.device_id, "device-a")
        result = self.assess([item])
        self.assertEqual(result.update_posture, UpdatePosture.OUT_OF_DATE)

    def test_operator_payload_preserves_outdated_and_unknown_update_states(self):
        outdated = self.observation(
            update_status=UpdateStatus.OUT_OF_DATE,
            update_checked_at_unix_ms=99_000,
            update_channel="security_intelligence",
        )
        unknown = self.observation(provider_id="vendor.firewall", category=SecurityCategory.FIREWALL)
        payload = build_operator_inventory_payload(
            authenticated_tenant_id="tenant-a",
            observations=[outdated, unknown],
            now_unix_ms=100_000,
            max_age_ms=60_000,
        )
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["providers"][0]["update_posture"], "out_of_date")
        self.assertEqual(payload["providers"][0]["evidence_freshness"], "fresh")
        self.assertEqual(payload["providers"][1]["update_posture"], "not_reported")
        self.assertIsNone(payload["providers"][1]["update_checked_at_unix_ms"])

    def test_operator_payload_never_exports_stale_health_or_stale_update_as_current(self):
        stale = self.observation(
            observed_at_unix_ms=1,
            update_status=UpdateStatus.CURRENT,
            update_checked_at_unix_ms=99_000,
        )
        record = to_operator_inventory_record(stale, now_unix_ms=100_000, max_age_ms=60_000)
        self.assertEqual(record["status"], "healthy")
        self.assertEqual(record["evidence_freshness"], "stale")
        self.assertEqual(record["update_posture"], "unverified")
        self.assertIsNone(record["update_checked_at_unix_ms"])

    def test_operator_payload_rejects_cross_tenant_and_duplicate_provider_records(self):
        with self.assertRaisesRegex(InventoryError, "cross-tenant"):
            build_operator_inventory_payload(
                authenticated_tenant_id="tenant-a",
                observations=[self.observation(tenant_id="tenant-b")],
                now_unix_ms=100_000,
                max_age_ms=60_000,
            )
        item = self.observation()
        with self.assertRaisesRegex(InventoryError, "duplicate"):
            build_operator_inventory_payload(
                authenticated_tenant_id="tenant-a",
                observations=[item, item],
                now_unix_ms=100_000,
                max_age_ms=60_000,
            )

    def test_connector_mapping_rejects_cross_tenant_and_provider_spoofing(self):
        record = {
            "tenant_id": "tenant-b",
            "provider_id": "vendor.edr",
            "observed_at_unix_ms": 100_000,
            "fields": {"category": "malware_protection", "status": "healthy"},
        }
        with self.assertRaisesRegex(InventoryError, "cross-tenant"):
            observation_from_validated_connector_record(
                authenticated_tenant_id="tenant-a",
                enrolled_device_id="device-a",
                expected_provider_id="vendor.edr",
                record=record,
            )
        record["tenant_id"] = "tenant-a"
        record["provider_id"] = "unconfigured.provider"
        with self.assertRaisesRegex(InventoryError, "provider identity"):
            observation_from_validated_connector_record(
                authenticated_tenant_id="tenant-a",
                enrolled_device_id="device-a",
                expected_provider_id="vendor.edr",
                record=record,
            )

    def test_connector_mapping_never_accepts_device_identity_from_payload(self):
        record = {
            "tenant_id": "tenant-a",
            "provider_id": "vendor.edr",
            "observed_at_unix_ms": 100_000,
            "fields": {
                "category": "malware_protection",
                "status": "healthy",
                "device_id": "attacker-device",
            },
        }
        item = observation_from_validated_connector_record(
            authenticated_tenant_id="tenant-a",
            enrolled_device_id="trusted-enrolled-device",
            expected_provider_id="vendor.edr",
            record=record,
        )
        self.assertEqual(item.device_id, "trusted-enrolled-device")

    def test_connector_mapping_rejects_malformed_capabilities_and_update_timestamps(self):
        record = {
            "tenant_id": "tenant-a",
            "provider_id": "vendor.edr",
            "observed_at_unix_ms": 100_000,
            "fields": {
                "category": "malware_protection",
                "status": "healthy",
                "capabilities": '["malware_protection", 7]',
            },
        }
        with self.assertRaisesRegex(InventoryError, "capability list"):
            observation_from_validated_connector_record(
                authenticated_tenant_id="tenant-a",
                enrolled_device_id="device-a",
                expected_provider_id="vendor.edr",
                record=record,
            )
        record["fields"]["capabilities"] = "[]"
        record["fields"]["update_checked_at_unix_ms"] = "not-a-time"
        with self.assertRaisesRegex(InventoryError, "update-check timestamp"):
            observation_from_validated_connector_record(
                authenticated_tenant_id="tenant-a",
                enrolled_device_id="device-a",
                expected_provider_id="vendor.edr",
                record=record,
            )


if __name__ == "__main__":
    unittest.main()
