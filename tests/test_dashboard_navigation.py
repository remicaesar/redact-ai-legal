"""The dashboard's navigation says where you are, and its URLs keep working.

Three of the five "Workspace" nav items were never destinations: Review Queue,
OCR Queue and DOCX QA were this same dashboard with a querystring, and the
sidebar went on highlighting "Dashboard" while the user stood on one. They are
filter chips above the table now.

Turning a nav item into a chip is only safe if the URL it pointed at still
filters, because those URLs are bookmarks. So the tests below pin both halves:

1. no sidebar entry is a querystring view of another page (the contradiction),
2. every URL the retired rail could produce still narrows the document list.

The second half is the one worth breaking on purpose: delete a filter branch in
`blueprints/documents.py` and it goes red, which is how we know it is measuring
the filter and not just the HTTP status.
"""

import re
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import tests.env_setup  # noqa: F401  -- sets LEGAL_ANALYZER_SECRET_KEY before app is imported
import app as app_module
from werkzeug.security import generate_password_hash

TEMPLATE_DIR = Path("templates")
# studio.html is excluded here on purpose: its sidebar is being rewritten by
# the review-loop work, and this task did not touch it.
SHELL_TEMPLATES = ["index.html", "matters.html", "matter.html", "audit.html", "settings.html"]
NAV_ITEM = re.compile(r'<a class="nav-item[^"]*"[^>]*href="([^"]+)"[^>]*>(?:<span[^>]*>.*?</span>)?([^<]*)</a>')


class SidebarListsPlacesTests(unittest.TestCase):
    """A nav item is a place. A querystring over the same page is a view."""

    def test_no_sidebar_entry_is_a_querystring_view(self) -> None:
        for name in SHELL_TEMPLATES:
            markup = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
            for href, label in NAV_ITEM.findall(markup):
                with self.subTest(template=name, label=label.strip()):
                    self.assertNotIn("?", href)

    def test_exactly_one_nav_item_is_marked_current(self) -> None:
        for name in SHELL_TEMPLATES:
            markup = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
            with self.subTest(template=name):
                self.assertEqual(markup.count('class="nav-item active"'), 1)
                self.assertEqual(markup.count('aria-current="page"'), 1)

    def test_the_dashboard_marks_the_dashboard_as_current(self) -> None:
        markup = (TEMPLATE_DIR / "index.html").read_text(encoding="utf-8")
        active = re.search(r'<a class="nav-item active"[^>]*href="([^"]+)"', markup)
        self.assertIsNotNone(active)
        self.assertEqual(active.group(1), "/")


class DashboardSurfaceTests(unittest.TestCase):
    """What the work surface stopped carrying, and what took its place."""

    def setUp(self) -> None:
        self.markup = (TEMPLATE_DIR / "index.html").read_text(encoding="utf-8")

    def test_the_filter_rail_is_gone(self) -> None:
        self.assertNotIn("filter-btn", self.markup)
        self.assertNotIn("filter-block", self.markup)

    def test_the_terminology_glossary_card_is_gone_but_the_definitions_are_not(self) -> None:
        self.assertNotIn("Terminology guardrail", self.markup)
        # Each definition now hangs on the term it defines.
        self.assertIn("{{ terminology.redaction.description }}", self.markup)
        self.assertIn("{{ terminology.pseudonymization.description }}", self.markup)
        self.assertIn("{{ terminology.de_identification.description }}", self.markup)
        self.assertIn("{{ terminology.anonymization.description }}", self.markup)

    def test_the_two_immovable_stat_tiles_are_gone(self) -> None:
        self.assertNotIn("Document categories", self.markup)
        self.assertNotIn("Detected clients", self.markup)

    def test_re_extraction_sits_below_the_table_not_beside_it(self) -> None:
        maintenance = self.markup.index('class="maintenance"')
        table = self.markup.index('<div class="table-wrap">')
        self.assertGreater(maintenance, table)

    def test_the_status_message_wraps_instead_of_truncating(self) -> None:
        rule = re.search(r"\.pipeline-status \{(.*?)\}", self.markup, re.S)
        self.assertIsNotNone(rule)
        self.assertIn("white-space: normal", rule.group(1))
        # The old cell was a nowrap pill with text-overflow: ellipsis, which is
        # what clipped a 385 px message into a 260 px column.
        self.assertNotIn("pipeline-pill", self.markup)


class RetiredFilterUrlsStillFilterTests(unittest.TestCase):
    """Every URL the old rail could produce is a bookmark someone may hold.

    The chips cover three of them; the rest are rendered as named "Filtered by"
    pills. Either way the server must still narrow the list, so this asserts on
    the row ids that come back, not on the status code.
    """

    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "test.db"
        self.original_db_path = app_module.DB_PATH
        app_module.DB_PATH = self.db_path
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())
        self.addCleanup(self.restore)

        conn = sqlite3.connect(self.db_path)
        conn.executescript(Path("db/schema.sql").read_text(encoding="utf-8"))
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("reviewer", generate_password_hash("secret"), "reviewer"),
        )
        rows = [
            (1, "pending.docx", ".docx", "pending_review", "not_required", "Complete", "High",
             "Blocked until redaction is completed and reviewed"),
            (2, "scan.pdf", ".pdf", "needs_ocr", "queued", "Partial", "Unknown",
             "Blocked until extraction is complete"),
            (3, "cleared.docx", ".docx", "approved_for_external_llm", "not_required", "Complete", "Low",
             "Allowed for external LLM use after completed redaction and approval."),
            (4, "note.txt", ".txt", "pending_review", "not_required", "Complete", "Medium",
             "Needs review before external LLM use"),
        ]
        for doc_id, filename, ext, review_status, ocr_status, extraction, risk, readiness in rows:
            conn.execute(
                """
                INSERT INTO documents (
                    id, filename, filepath, file_extension, file_size, title,
                    extraction_status, residual_risk, external_llm_readiness,
                    human_review_required, review_status, ocr_status
                ) VALUES (?, ?, ?, ?, 100, ?, ?, ?, ?, 1, ?, ?)
                """,
                (doc_id, filename, f"/tmp/{filename}", ext, filename, extraction, risk, readiness,
                 review_status, ocr_status),
            )
        conn.commit()
        conn.close()
        self.client = app_module.app.test_client()
        self.client.post("/login", data={"username": "reviewer", "password": "secret"})

    def restore(self) -> None:
        app_module.DB_PATH = self.original_db_path
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())

    def ids_for(self, query: str) -> list[int]:
        response = self.client.get(f"/api/documents?{query}&page=1&page_size=50")
        self.assertEqual(response.status_code, 200)
        return sorted(doc["id"] for doc in response.json["documents"])

    def test_every_chip_url_filters(self) -> None:
        # The three chips, by the exact querystring each one writes.
        self.assertEqual(self.ids_for("review_status=pending_review"), [1, 4])
        self.assertEqual(self.ids_for("review_status=needs_ocr"), [2])
        self.assertEqual(self.ids_for("readiness=Blocked"), [1, 2])

    def test_the_retired_nav_urls_still_filter(self) -> None:
        # /?review_status=pending_review was "Review Queue".
        self.assertEqual(self.ids_for("review_status=pending_review"), [1, 4])
        # /?ocr_status=queued was "OCR Queue".
        self.assertEqual(self.ids_for("ocr_status=queued"), [2])
        # /?file_type=.docx was "DOCX QA"; it has no chip and no longer has a
        # rail button, and it must still work.
        self.assertEqual(self.ids_for("file_type=.docx"), [1, 3])

    def test_the_dimensions_dropped_from_the_ui_still_filter(self) -> None:
        self.assertEqual(self.ids_for("risk=Medium"), [4])
        self.assertEqual(self.ids_for("extraction_status=Partial"), [2])
        self.assertEqual(self.ids_for("ocr_status=not_required"), [1, 3, 4])

    def test_an_unfiltered_dashboard_still_lists_everything(self) -> None:
        self.assertEqual(self.ids_for(""), [1, 2, 3, 4])

    def test_status_is_the_widest_column_on_the_rendered_page(self) -> None:
        markup = self.client.get("/").data.decode("utf-8")
        widths = {
            label: int(width)
            for width, label in re.findall(r'style="width: (\d+)%">([A-Za-z]+)</th>', markup)
        }
        self.assertIn("Status", widths)
        self.assertEqual(max(widths.values()), widths["Status"])

    def test_the_client_column_appears_only_when_a_document_has_a_client(self) -> None:
        # No client roster is configured here, so the column that would read "-"
        # on every row is not rendered at all -- that width goes to Status.
        self.assertNotIn(b">Client</th>", self.client.get("/").data)

        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT INTO clients (id, name) VALUES (1, 'Synthetic Holding A.S.')")
        conn.execute("UPDATE documents SET client_id = 1 WHERE id = 1")
        conn.commit()
        conn.close()
        self.assertIn(b">Client</th>", self.client.get("/").data)

    def test_the_dashboard_page_renders_for_a_retired_url(self) -> None:
        for query in ("review_status=pending_review", "ocr_status=queued", "file_type=.docx"):
            with self.subTest(query=query):
                response = self.client.get(f"/?{query}")
                self.assertEqual(response.status_code, 200)
                # The page reads its own querystring; nothing is dropped on the
                # way in, so the chip or the "Filtered by" pill can show it.
                self.assertIn(b"initializeFiltersFromUrl", response.data)


if __name__ == "__main__":
    unittest.main()
