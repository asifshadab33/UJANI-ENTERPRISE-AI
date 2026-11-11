import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from collective_defence_policy import (
    DefenceSignalRequest, defence_signal_denials, may_share_defence_signal,
)


class CollectiveDefencePolicyTests(unittest.TestCase):
    def request(self, **changes):
        values = dict(
            organization_enabled=True, participant_enabled=True,
            signal_type="malware_hash", contains_file_content=False,
            contains_personal_data=False, operator_approved=True,
        )
        values.update(changes)
        return DefenceSignalRequest(**values)

    def test_requires_both_opt_ins_and_approved_indicator(self):
        self.assertTrue(may_share_defence_signal(self.request()))

    def test_denies_without_either_opt_in(self):
        denials = defence_signal_denials(self.request(
            organization_enabled=False, participant_enabled=False))
        self.assertIn("organization_opt_in_missing", denials)
        self.assertIn("participant_opt_in_missing", denials)

    def test_rejects_content_personal_data_and_unknown_signal(self):
        denials = defence_signal_denials(self.request(
            signal_type="raw_file", contains_file_content=True,
            contains_personal_data=True))
        self.assertTrue({"signal_type_not_allowlisted", "file_content_prohibited",
                         "personal_data_prohibited"}.issubset(denials))

    def test_rejects_truthy_non_boolean_consent_and_unknown_classification(self):
        denials = defence_signal_denials(self.request(
            organization_enabled=1, participant_enabled="yes",
            contains_file_content=None, contains_personal_data=None,
            operator_approved=1))
        self.assertTrue({"organization_opt_in_missing", "participant_opt_in_missing",
                         "file_content_prohibited", "personal_data_prohibited",
                         "operator_approval_missing"}.issubset(denials))


if __name__ == "__main__":
    unittest.main()
