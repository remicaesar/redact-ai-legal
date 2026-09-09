"""One review pane, and what it must still be able to do.

The studio used to mount three complete review panes at once -- a guided card,
a by-type list, and a bulk table -- plus a fourth renderer that replaced the
list for PDFs and retitled the panel. They differed in *capability*, not just
layout: on a 29-finding document the mode the product opened in cost 29 clicks,
the by-type list cost 14, and the bulk table could not finish at all, because
its only approve button covered LOW and MEDIUM. So the reviewer had to discover
that one mode was twice as fast as the default and a third was a dead end.

They are now one pane. These tests pin the four things that merge could
plausibly have cost, and one thing it must NOT have done:

1. All four finding decisions stay reachable from the pane -- and 'dismissed'
   (the detector was wrong) stays distinct from 'retained' (the detector was
   right, the risk is accepted). Collapsing those two once let a real
   identifier through the gate.
2. Undo stays reachable, and from the row rather than only from a toast that
   disappears.
3. The pane is one renderer for both formats, with one title.
4. Every pending PDF box stays reviewable from the same pane.
5. Deciding a finding does NOT decide its boxes. That merge is deferred: it is
   the one change that alters when a safeguard fires, and pdf_export_blockers()
   refuses on unreviewed boxes for a reason.
"""

import re
import unittest
from pathlib import Path

from blueprints.review import FINDING_ACTION_STATUSES

STUDIO = Path("templates/studio.html")


def js_function(markup: str, signature: str) -> str:
    """The body of one top-level function in the studio's inline script."""
    start = markup.index(signature)
    end = markup.index("\n        }", start)
    return markup[start:end]


class SingleReviewPaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.markup = STUDIO.read_text(encoding="utf-8")

    def test_the_three_panes_and_their_switcher_are_gone(self) -> None:
        """Not hidden, not vestigial -- absent."""
        for retired in (
            "guidedReviewPane",
            "groupReviewPane",
            "bulkReviewPane",
            "guidedModeButton",
            "groupModeButton",
            "bulkModeButton",
            "setReviewMode",
            "renderBulkReviewTable",
            "renderFindingGroups",
        ):
            with self.subTest(retired=retired):
                self.assertNotIn(retired, self.markup)

    def test_one_renderer_serves_both_file_formats(self) -> None:
        """renderReviewQueue() was a second renderer writing to the same element."""
        self.assertIn("function renderReviewList()", self.markup)
        self.assertNotIn("function renderReviewQueue(", self.markup)
        self.assertNotIn("function buildReviewQueue(", self.markup)

    def test_the_panel_is_not_retitled_by_file_type(self) -> None:
        """A lawyer's model of the main workspace must not depend on the upload.

        The title is markup, not something the script writes: the panel was
        "Review Queue" for a PDF and "Findings" for a DOCX. (The sidebar link
        of the same name goes to the dashboard filter and is a different thing.)
        """
        self.assertIn('<h2 id="findingsTitle">Findings</h2>', self.markup)
        self.assertNotIn("getElementById('findingsTitle')", self.markup)
        self.assertNotIn('getElementById("findingsTitle")', self.markup)


class EveryDecisionStaysReachableTests(unittest.TestCase):
    """The pane must offer a control for every decision the server accepts.

    Tied to FINDING_ACTION_STATUSES rather than a hand-written list, so a
    decision added to the API without a control in the pane fails here.
    """

    def setUp(self) -> None:
        self.markup = STUDIO.read_text(encoding="utf-8")
        # The row's controls are built from a table of decisions plus the
        # renderer that lays them out; read both as one surface.
        self.row_actions = self.markup[
            self.markup.index("const ROW_DECISIONS = [") :
            self.markup.index("function findingCarriesDecision(")
        ]

    def test_a_row_offers_every_decision_the_api_accepts(self) -> None:
        # 'reject' is a back-compat alias for 'dismiss' and 'pending' is undo,
        # which has its own control asserted below.
        decisions = set(FINDING_ACTION_STATUSES) - {"reject", "pending"}
        self.assertEqual(decisions, {"approve", "dismiss", "retain"})
        # Decision buttons come from the table; undo and edit are literals.
        offered = set(re.findall(r"data-row-action=\"(\w+)\"", self.row_actions))
        offered |= set(re.findall(r"action: '(\w+)'", self.row_actions))
        for decision in decisions:
            with self.subTest(decision=decision):
                self.assertIn(decision, offered)

    def test_dismiss_and_retain_are_still_two_different_answers(self) -> None:
        """Not one 'reject'. The wording has to make the difference unmissable."""
        self.assertNotEqual(
            FINDING_ACTION_STATUSES["dismiss"], FINDING_ACTION_STATUSES["retain"]
        )
        self.assertIn("Not sensitive", self.row_actions)
        self.assertIn("Keep unredacted", self.row_actions)

    def test_undo_is_offered_on_the_row_that_carries_a_decision(self) -> None:
        """undoFinding() existed but was only ever reachable from a toast."""
        self.assertIn('data-row-action="undo"', self.row_actions)
        self.assertIn("function undoFinding(", self.markup)

    def test_a_reviewer_can_still_add_a_finding_the_detector_missed(self) -> None:
        """The fourth decision: 'added_by_reviewer'."""
        self.assertIn('id="manualText"', self.markup)
        self.assertIn("addFinding(event)", self.markup)

    def test_replacement_text_and_the_reviewer_note_stay_reachable(self) -> None:
        """Moved behind an affordance so the decision comes first -- not removed."""
        self.assertIn('data-row-action="edit"', self.row_actions)
        self.assertIn('id="assistantEditDetails"', self.markup)
        self.assertIn('id="assistantReplacement"', self.markup)
        self.assertIn('id="assistantReviewerNote"', self.markup)
        self.assertIn("function openSelectedFindingEditor()", self.markup)

    def test_the_whole_document_batch_is_not_capped_by_risk(self) -> None:
        """The dead end: the only approve-many button covered LOW and MEDIUM.

        The endpoint has always accepted an unfiltered batch. The pane now
        passes an empty risk list, so CRITICAL and HIGH are reachable too.
        """
        toolbar = js_function(self.markup, "function renderReviewPaneToolbar()")
        self.assertIn('data-doc-action="approve"', toolbar)
        self.assertNotIn("LOW", toolbar)
        self.assertNotIn("MEDIUM", toolbar)
        listener = js_function(self.markup, "function initializeReviewPaneListeners()")
        self.assertIn("batchReview(docButton.dataset.docAction, [])", listener)


class BoxReviewStaysItsOwnStepTests(unittest.TestCase):
    """The PDF half. Boxes render on the row; they are not decided by it."""

    def setUp(self) -> None:
        self.markup = STUDIO.read_text(encoding="utf-8")

    def test_every_pending_box_is_reviewable_from_the_pane(self) -> None:
        boxes = js_function(self.markup, "function reviewRowBoxesHtml(finding)")
        self.assertIn('data-box-action="approve"', boxes)
        self.assertIn('data-box-action="reject"', boxes)
        # A box a reviewer drew has no finding behind it and must not vanish.
        manual = js_function(self.markup, "function manualBoxGroupHtml(regions)")
        self.assertIn('data-box-action="approve"', manual)
        self.assertIn("function manualBoxRowHtml(region)", self.markup)

    def test_a_reviewer_can_still_draw_a_missed_box(self) -> None:
        self.assertIn("function startPdfDraw(", self.markup)
        self.assertIn('id="pdfDrawCategory"', self.markup)

    def test_deciding_a_finding_does_not_decide_its_boxes(self) -> None:
        """The safeguard the captain deferred merging.

        reviewAssistantAction() used to fork on '.pdf' and send the finding's
        regions to the box endpoint along with the finding. Neither the
        finding-decision path nor the per-category batch may touch a region
        endpoint any more.
        """
        for signature in (
            "async function reviewAssistantAction(action)",
            "async function findingAction(findingId, action)",
            "async function batchReviewGroup(group, action)",
        ):
            with self.subTest(path=signature):
                body = js_function(self.markup, signature)
                self.assertNotIn("pdf/regions", body)

    def test_the_box_decision_has_its_own_call(self) -> None:
        boxes = js_function(self.markup, "async function reviewBoxes(regionIds, action)")
        self.assertIn("pdfBatchReview", boxes)


if __name__ == "__main__":
    unittest.main()
