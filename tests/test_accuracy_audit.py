import unittest
from pathlib import Path

from accuracy_audit import DEFAULT_LABELS, audit_document, risk_shortfall, run_audit

PROJECT_DIR = Path(__file__).resolve().parent.parent


class RiskShortfallTests(unittest.TestCase):
    """risk_shortfall is the metric that closes the gap false_low cannot see:
    false_low only fires when actual_risk is exactly "Low", so a document
    expected High that computes Medium is invisible to it and to every other
    metric in run_audit. See accuracy_audit.risk_shortfall.
    """

    def test_downgrade_trips_shortfall(self):
        self.assertTrue(risk_shortfall("High", "Medium"))
        self.assertTrue(risk_shortfall("High", "Low"))
        self.assertTrue(risk_shortfall("Medium", "Low"))

    def test_over_reporting_does_not_trip_shortfall(self):
        # Expected Medium, computed High fails safe and must never be flagged.
        self.assertFalse(risk_shortfall("Medium", "High"))
        self.assertFalse(risk_shortfall("Low", "High"))
        self.assertFalse(risk_shortfall("Low", "Medium"))

    def test_matching_expectation_does_not_trip_shortfall(self):
        self.assertFalse(risk_shortfall("High", "High"))
        self.assertFalse(risk_shortfall("Medium", "Medium"))

    def test_missing_expected_risk_does_not_trip_shortfall(self):
        self.assertFalse(risk_shortfall(None, "Low"))
        self.assertFalse(risk_shortfall(None, "High"))

    def test_unknown_actual_risk_does_not_trip_shortfall(self):
        # actual_risk == "Unknown" means extraction was gated (Partial/Failed) and
        # blocks external LLM use outright -- it is not a claim of lower risk, so
        # it must never register as a shortfall regardless of what was expected.
        self.assertFalse(risk_shortfall("High", "Unknown"))
        self.assertFalse(risk_shortfall("Medium", "Unknown"))


class AuditDocumentRiskShortfallTests(unittest.TestCase):
    """Exercises risk_shortfall through audit_document() against a real fixture,
    proving the new metric fires independently of false_low on a document whose
    engine-computed risk genuinely is Medium.
    """

    def test_expected_high_actual_medium_trips_shortfall_not_false_low(self):
        # bare_names_expert_report currently computes Medium in the real gold set
        # (contextual-signal terms alone clear the Medium threshold). Overriding
        # only the expectation here simulates "gold expects High, engine reports
        # Medium" -- exactly the case false_low cannot see, without touching the
        # real gold labels file.
        item = {
            "id": "bare_names_expert_report_shortfall_probe",
            "path": "../tests/fixtures/bare_names_expert_report.txt",
            "expected_residual_risk": "High",
            "labels": [],
        }
        result = audit_document(item, DEFAULT_LABELS)

        self.assertEqual(result["actual_residual_risk"], "Medium")
        self.assertTrue(result["risk_shortfall"], "expected High vs actual Medium must trip risk_shortfall")
        self.assertFalse(result["false_low"], "false_low must stay False since actual_risk is not Low")

    def test_expected_medium_actual_high_does_not_trip_shortfall(self):
        # Sanity check in the opposite direction: over-reporting is not a shortfall.
        item = {
            "id": "commercial_contract_over_report_probe",
            "path": "../tests/fixtures/commercial_contract.txt",
            "expected_residual_risk": "Medium",
            "labels": [],
        }
        result = audit_document(item, DEFAULT_LABELS)

        self.assertEqual(result["actual_residual_risk"], "High")
        self.assertFalse(result["risk_shortfall"])
        self.assertFalse(result["false_low"])


class GoldSetRiskShortfallRegressionTests(unittest.TestCase):
    """After the lease_agreement gold-label correction (Task 2), the full gold
    set must report risk_shortfall_count == 0 alongside the pre-existing
    false_low_count == 0.
    """

    def test_gold_set_has_no_risk_shortfall(self):
        report = run_audit(DEFAULT_LABELS)

        self.assertEqual(report["metrics"]["false_low_count"], 0)
        self.assertEqual(report["metrics"]["risk_shortfall_count"], 0)
        self.assertEqual(report["metrics"]["recall"], 1.0)
        self.assertEqual(report["metrics"]["false_negative_count"], 0)


if __name__ == "__main__":
    unittest.main()
