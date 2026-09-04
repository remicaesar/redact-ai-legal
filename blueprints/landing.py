"""Public marketing landing page.

The only unauthenticated page in the app besides /login. It reads nothing from
the database and renders no document data, so it is safe to serve anonymously.

Page copy lives here rather than in the template so the claims sit in reviewable
Python next to a note about what substantiates them.
"""

from __future__ import annotations

from flask import Blueprint, render_template

landing_bp = Blueprint("landing", __name__)

# Figures quoted on the page. These come from the repo's own tooling -- keep them
# in step with `python3 accuracy_audit.py` output rather than editing by feel.
# "mini-gold" is deliberate: the gold set is synthetic and small, and the audit's
# own recommendation warns against reading it as a production accuracy claim.
STATS = [
    {"value": "1.0", "label": "Recall on the mini-gold accuracy audit"},
    {"value": "0", "label": "False-low findings, incl. post-OCR"},
    {"value": "12", "label": "File types: DOCX, PDF, UDF, XLSX, PPTX…"},
    {"value": "0", "label": "Documents sent to a hosted LLM without review"},
]

FEATURES = [
    {
        "tone": "accent",
        "title": "Redaction Studio",
        "text": "Grouped findings, batch approve/reject, coordinate-level PDF review, and export gates in one workspace.",
    },
    {
        "tone": "success",
        "title": "Local-first OCR",
        "text": "OCR runs locally and never touches findings or export readiness until a reviewer explicitly accepts it.",
    },
    {
        "tone": "warning",
        "title": "Matter Workspaces",
        "text": "Group documents by client and matter, with a full artifact timeline and sanitized audit trail.",
    },
    {
        "tone": "ink",
        "title": "Local only",
        "text": "All processing, storage, and exports happen on this machine — no document content leaves it unreviewed.",
    },
]

# Rendered after "Built for", not "Privacy teams use Redact AI for". The latter
# is a customer claim, and there are no customers; the use cases are what the
# workflow is designed to handle, which is a claim the repo can actually back.
ROTATING_WORDS = [
    "discovery productions",
    "client intake files",
    "court filings",
    "GDPR subject requests",
    "vendor contracts",
    "internal investigations",
]

STEPS = [
    {
        "title": "Upload",
        "text": "DOCX, PDF, UDF, TXT/MD, images, XLSX, PPTX, or ZIP — assigned to a matter or left unassigned.",
    },
    {
        "title": "Classify & detect",
        "text": "Local extraction and privacy analysis run immediately, flagging identifiers and residual risk.",
    },
    {
        "title": "Review",
        "text": "A reviewer approves or rejects findings, resolves OCR, and draws or confirms redaction boxes.",
    },
    {
        "title": "Export",
        "text": "Gated release: only ships when extraction, risk, and human review conditions are all satisfied.",
    },
]

# Mirrors the release gate in legal_analyzer/privacy.py. If that gate changes,
# change this too -- a marketing page that overstates the gate is the exact
# failure mode the project's terminology discipline exists to prevent.
GATES = [
    {"title": "Extraction complete", "text": "partial or failed extraction keeps residual risk at Unknown."},
    {"title": "Residual risk is Low", "text": "and zero critical findings remain unreviewed."},
    {"title": "No direct identifiers remain", "text": "and redaction is marked complete."},
    {"title": "Human review approved", "text": "unless an explicit auto-mode is enabled."},
]

# Framed as "Designed around", NOT "Aligned to" / "Compliant with". Nothing here
# has been certified or audited, and this project deliberately avoids claiming a
# status it has not established.
STANDARDS = ["GDPR", "KVKK", "HIPAA Safe Harbor", "ISO 27001 practices", "Attorney–client privilege"]


@landing_bp.route("/welcome")
def welcome():
    return render_template(
        "landing.html",
        stats=STATS,
        features=FEATURES,
        rotating_words=ROTATING_WORDS,
        steps=STEPS,
        gates=GATES,
        standards=STANDARDS,
    )
