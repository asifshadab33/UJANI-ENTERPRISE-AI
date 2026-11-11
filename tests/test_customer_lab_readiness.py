import unittest
from scripts.customer_lab_readiness import REQUIRED_EVIDENCE, missing_lab_evidence, lab_ready

class CustomerLabReadinessTests(unittest.TestCase):
    def test_empty_evidence_blocks_customer_acceptance(self):
        self.assertFalse(lab_ready(set()))
        self.assertEqual(set(missing_lab_evidence(set())), REQUIRED_EVIDENCE)

    def test_all_required_customer_lab_evidence_is_required(self):
        self.assertTrue(lab_ready(set(REQUIRED_EVIDENCE)))

    def test_missing_customer_signoff_blocks_readiness(self):
        evidence = set(REQUIRED_EVIDENCE) - {"customer_lab_signoff"}
        self.assertFalse(lab_ready(evidence))
        self.assertEqual(missing_lab_evidence(evidence), ["customer_lab_signoff"])

if __name__ == "__main__":
    unittest.main()
