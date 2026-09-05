"""The unauthenticated landing page quotes no accuracy figure.

/welcome is the one page anyone can read without logging in. The gold set behind
the accuracy audit is 17 synthetic documents written by the same people who wrote
the rules, so a recall of 1.0 against it is a regression guard, not a property
of the detector on real filings — and a bare number above the fold travels
without that qualifier. Until a real labelled corpus exists, the numbers stay in
accuracy_report.json and behind login. These tests keep them there.

The figures the page does quote are structural properties of the code; where one
can be derived from the code, the test derives it rather than trusting the copy.
"""

import re
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import tests.env_setup  # noqa: F401  -- must precede "import app"

import app as app_module
from blueprints import landing
from legal_analyzer import privacy

# Words that mark a stat as an accuracy measurement rather than a design property.
ACCURACY_WORDS = re.compile(r"recall|precision|accuracy|audit|false[- ]?low|gold", re.IGNORECASE)
# The shape of a ratio: 1.0, 0.70, 0.88. Counts are integers.
RATIO = re.compile(r"^\d+\.\d+$")


class LandingStatsTests(unittest.TestCase):
    def test_no_stat_is_an_accuracy_figure(self) -> None:
        for stat in landing.STATS:
            with self.subTest(stat=stat):
                self.assertIsNone(ACCURACY_WORDS.search(stat["label"]), stat)
                self.assertIsNone(RATIO.match(stat["value"]), stat)

    def test_release_condition_count_matches_the_gate(self) -> None:
        """The 'conditions' stat is derived, not typed.

        Fail every condition at once and count what the gate reports; the page
        must quote that number. If a condition is added to or removed from
        external_llm_gate_policy, this fails until the copy follows.
        """
        gate = privacy.external_llm_gate_policy(
            residual_risk={"level": "High"},
            findings=[{"category": "natural_person_name", "risk": "CRITICAL"}],
            extraction_status={"status": "Partial", "blocks_external_llm": True},
            redaction_completed=False,
            human_review_approved=False,
            auto_mode_enabled=False,
            ocr_status="pending",
        )
        condition_count = len(gate["failed_conditions"])
        self.assertGreaterEqual(condition_count, 5, gate)  # sanity: everything failed

        matches = [s for s in landing.STATS if "Conditions" in s["label"]]
        self.assertEqual(len(matches), 1, landing.STATS)
        self.assertEqual(matches[0]["value"], str(condition_count))


class LandingPageTests(unittest.TestCase):
    def setUp(self) -> None:
        # /welcome reads nothing from the database, but the app's before_request
        # still readies one; point it at a throwaway so the test never touches
        # db/legal_documents.db. Same pattern as tests/test_csrf.py.
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "test.db"
        conn = sqlite3.connect(self.db_path)
        conn.executescript(Path("db/schema.sql").read_text(encoding="utf-8"))
        conn.commit()
        conn.close()
        self.original_db_path = app_module.DB_PATH
        app_module.DB_PATH = self.db_path
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())
        self.addCleanup(self.restore)
        self.client = app_module.app.test_client()

    def restore(self) -> None:
        app_module.DB_PATH = self.original_db_path
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())

    def test_welcome_is_served_without_a_session(self) -> None:
        response = self.client.get("/welcome")
        self.assertEqual(response.status_code, 200)

    def test_rendered_page_quotes_no_accuracy_figure(self) -> None:
        """Guards the template as well as STATS — a number typed straight into
        landing.html would pass the STATS test and still be quoted."""
        body = self.client.get("/welcome").get_data(as_text=True)
        self.assertIsNone(re.search(r"\b(recall|precision)\b", body, re.IGNORECASE), "accuracy word on /welcome")
        # A ratio next to a stat label. Version strings and CSS values are not
        # inside the stats grid, so scope the check to it.
        stats_block = re.search(r'class="landing__stats"(.*?)</section>', body, re.DOTALL)
        self.assertIsNotNone(stats_block, "stats section missing from /welcome")
        values = re.findall(r'landing__stat-value">\s*([^<]+?)\s*<', stats_block.group(1))
        self.assertTrue(values, "no stat values rendered")
        for value in values:
            self.assertIsNone(RATIO.match(value), f"ratio {value!r} quoted on the public page")


if __name__ == "__main__":
    unittest.main()
