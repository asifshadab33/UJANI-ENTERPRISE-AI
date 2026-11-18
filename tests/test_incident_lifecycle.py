import unittest

from scripts.incident_lifecycle import (
    IncidentAction,
    IncidentError,
    IncidentSnapshot,
    IncidentState,
    TransitionCommand,
    transition_incident,
)


class IncidentLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.incident = IncidentSnapshot("tenant-a", "incident-1", "device-1")

    def command(self, action, **overrides):
        values = {
            "tenant_id": "tenant-a",
            "actor_role": "tenant_admin",
            "action": action,
            "expected_version": self.incident.version,
            "evidence_ref": "evidence-1",
        }
        values.update(overrides)
        return TransitionCommand(**values)

    def test_triage_advances_version_without_executing_actions(self):
        result = transition_incident(self.incident, self.command(IncidentAction.TRIAGE))
        self.assertEqual(result.state, IncidentState.TRIAGED)
        self.assertEqual(result.version, 1)
        self.assertEqual(self.incident.state, IncidentState.OBSERVED)

    def test_wrong_tenant_and_stale_version_are_rejected(self):
        with self.assertRaisesRegex(IncidentError, "tenant boundary"):
            transition_incident(self.incident, self.command(IncidentAction.TRIAGE, tenant_id="tenant-b"))
        with self.assertRaisesRegex(IncidentError, "stale"):
            transition_incident(self.incident, self.command(IncidentAction.TRIAGE, expected_version=9))

    def test_rejects_boolean_and_non_integer_versions(self):
        for version in (True, 0.0, -1):
            with self.subTest(version=version):
                with self.assertRaisesRegex(IncidentError, "version"):
                    transition_incident(self.incident, self.command(
                        IncidentAction.TRIAGE, expected_version=version,
                    ))

    def test_consent_and_approval_flags_must_be_explicit_booleans(self):
        for field in ("tenant_admin_opt_in", "device_owner_opt_in",
                      "approval_digest_valid", "controller_receipt_valid"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(IncidentError, "explicit booleans"):
                    transition_incident(self.incident, self.command(
                        IncidentAction.TRIAGE, **{field: "true"},
                    ))

    def test_incident_version_is_bounded_for_storage_safety(self):
        incident = IncidentSnapshot(
            "tenant-a", "incident-1", "device-1", version=(1 << 63),
        )
        with self.assertRaisesRegex(IncidentError, "version"):
            transition_incident(incident, self.command(
                IncidentAction.TRIAGE, expected_version=(1 << 63),
            ))

    def test_suspension_requires_both_opt_ins_and_digest_approval(self):
        incomplete = self.command(IncidentAction.REQUEST_COMPUTE_SUSPENSION, tenant_admin_opt_in=True)
        with self.assertRaisesRegex(IncidentError, "both required"):
            transition_incident(self.incident, incomplete)
        unapproved = self.command(
            IncidentAction.REQUEST_COMPUTE_SUSPENSION,
            tenant_admin_opt_in=True, device_owner_opt_in=True,
        )
        with self.assertRaisesRegex(IncidentError, "digest-bound"):
            transition_incident(self.incident, unapproved)

    def test_suspension_request_and_confirmation_are_separate(self):
        requested = transition_incident(self.incident, self.command(
            IncidentAction.REQUEST_COMPUTE_SUSPENSION,
            tenant_admin_opt_in=True, device_owner_opt_in=True,
            approval_digest_valid=True,
        ))
        self.assertEqual(requested.state, IncidentState.COMPUTE_SUSPENSION_REQUESTED)
        pending_cmd = self.command(
            IncidentAction.CONFIRM_COMPUTE_SUSPENSION,
            actor_role="trusted_controller", expected_version=requested.version,
            controller_receipt_valid=True,
        )
        confirmed = transition_incident(requested, pending_cmd)
        self.assertEqual(confirmed.state, IncidentState.COMPUTE_SUSPENSION_CONFIRMED)

    def test_cannot_claim_suspension_without_controller_receipt(self):
        requested = transition_incident(self.incident, self.command(
            IncidentAction.REQUEST_COMPUTE_SUSPENSION,
            tenant_admin_opt_in=True, device_owner_opt_in=True,
            approval_digest_valid=True,
        ))
        with self.assertRaisesRegex(IncidentError, "controller receipt"):
            transition_incident(requested, self.command(
                IncidentAction.CONFIRM_COMPUTE_SUSPENSION,
                actor_role="trusted_controller", expected_version=requested.version,
            ))

    def test_recovery_requires_confirmed_suspension_and_approval(self):
        with self.assertRaisesRegex(IncidentError, "before suspension"):
            transition_incident(self.incident, self.command(
                IncidentAction.BEGIN_RECOVERY, approval_digest_valid=True,
            ))

    def test_evidence_reference_is_mandatory_and_bounded(self):
        with self.assertRaisesRegex(IncidentError, "evidence reference"):
            transition_incident(self.incident, self.command(IncidentAction.TRIAGE, evidence_ref="../secret"))

    def test_unprivileged_actor_cannot_triage(self):
        with self.assertRaisesRegex(IncidentError, "not authorised"):
            transition_incident(self.incident, self.command(
                IncidentAction.TRIAGE, actor_role="viewer",
            ))


if __name__ == "__main__":
    unittest.main()
