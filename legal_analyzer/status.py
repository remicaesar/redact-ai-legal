"""One user-facing pipeline status derived from the raw workflow fields.

The documents table tracks four overlapping enums (extraction_status,
ocr_status, review_status, external_llm_readiness) plus booleans. This module
collapses them into a single ``pipeline_stage`` and a plain-English
``pipeline_message`` that says what to do next, so the UI never asks users to
reconcile raw state-machine fields. It only *reads* state — the release gate
itself stays in ``privacy.refresh_release_state``; when a document is blocked,
the message surfaces that gate's own first failed condition rather than
re-deriving policy here.
"""

from __future__ import annotations

import json

# Stages, roughly in workflow order. The UI may color/group by these.
STAGE_NEEDS_OCR = "needs_ocr"
STAGE_OCR_REVIEW = "ocr_review"
STAGE_NEEDS_REVIEW = "needs_review"
STAGE_READY_TO_FINALIZE = "ready_to_finalize"
STAGE_AWAITING_APPROVAL = "awaiting_approval"
STAGE_READY = "ready"
STAGE_BLOCKED = "blocked"


def _gate_from_profile(privacy_profile) -> dict:
    if isinstance(privacy_profile, str):
        try:
            privacy_profile = json.loads(privacy_profile or "{}")
        except (TypeError, ValueError):
            privacy_profile = {}
    return (privacy_profile or {}).get("external_llm_gate", {}) or {}


def compute_pipeline_status(
    doc,
    pending_findings: int = 0,
    pending_pdf_regions: int = 0,
) -> dict:
    """Return {"pipeline_stage", "pipeline_message"} for a documents row.

    ``doc`` is any mapping with the documents-table fields (sqlite3.Row or
    dict). ``privacy_profile`` may be the stored JSON string, a parsed dict,
    or absent (list queries skip the large JSON column; blocked messages then
    fall back to the stored ``external_llm_readiness`` text).
    """
    data = dict(doc)
    extraction_status = data.get("extraction_status") or "Unknown"
    ocr_status = data.get("ocr_status") or "not_required"
    redaction_completed = bool(data.get("redaction_completed"))
    review_approved = bool(data.get("human_review_approved"))
    auto_mode = bool(data.get("auto_mode_enabled"))
    gate = _gate_from_profile(data.get("privacy_profile"))

    if ocr_status == "completed":
        return {
            "pipeline_stage": STAGE_OCR_REVIEW,
            "pipeline_message": "OCR text is ready — review it, then accept or reject.",
        }
    if extraction_status != "Complete" and ocr_status != "accepted":
        if ocr_status == "failed":
            message = "OCR failed — retry it or supply reviewed text."
        elif ocr_status == "rejected":
            message = "OCR output was rejected — rerun OCR or supply reviewed text."
        elif ocr_status == "processing":
            message = "OCR is running — results will need your review."
        else:
            message = "Text extraction is incomplete — run OCR before review."
        return {"pipeline_stage": STAGE_NEEDS_OCR, "pipeline_message": message}

    if pending_findings or pending_pdf_regions:
        parts = []
        if pending_findings:
            parts.append(f"{pending_findings} finding{'s' if pending_findings != 1 else ''}")
        if pending_pdf_regions:
            parts.append(f"{pending_pdf_regions} PDF redaction box{'es' if pending_pdf_regions != 1 else ''}")
        verb = "needs" if pending_findings + pending_pdf_regions == 1 else "need"
        return {
            "pipeline_stage": STAGE_NEEDS_REVIEW,
            "pipeline_message": f"{' and '.join(parts)} {verb} your review.",
        }

    if not redaction_completed:
        return {
            "pipeline_stage": STAGE_READY_TO_FINALIZE,
            "pipeline_message": "All items are reviewed — mark redaction complete.",
        }
    if not (review_approved or auto_mode):
        return {
            "pipeline_stage": STAGE_AWAITING_APPROVAL,
            "pipeline_message": "Redaction is complete — approve the review to finish.",
        }

    readiness = data.get("external_llm_readiness") or ""
    if gate.get("allowed") or (not gate and readiness.startswith("Allowed")):
        return {
            "pipeline_stage": STAGE_READY,
            "pipeline_message": "Ready — download the reviewed redacted version.",
        }
    failed = gate.get("failed_conditions") or []
    if failed:
        message = f"Blocked — {failed[0].rstrip('.')}."
        if len(failed) > 1:
            message += f" ({len(failed) - 1} more condition{'s' if len(failed) > 2 else ''} unmet.)"
    elif readiness:
        message = f"Blocked — {readiness.rstrip('.')}."
    else:
        message = "Blocked — release-gate state is unavailable; reset and re-run review."
    return {"pipeline_stage": STAGE_BLOCKED, "pipeline_message": message}
