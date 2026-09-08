"""The one post-decision rendering of a document, shared by every surface.

There used to be three answers to "what will the redacted file look like", and
they disagreed on the same document with the same review decisions:

- the browser review canvas derived its own rendering in JavaScript, replacing
  each finding's recorded OFFSETS and letting the NARROWEST span win an overlap;
- the "Preview TXT / Preview DOCX" server preview shipped the DETECTION-TIME
  ``redacted_preview``, which replaced offsets too, resolved overlaps the other
  way round, and ignored the reviewer's decisions entirely;
- the exported reviewed DOCX -- the actual deliverable -- replaced every STRING
  match of each approved sample.

Measured on one synthetic Turkish petition: 5 differing hunks over 27 lines
between the preview and the export, and all three pairwise combinations
disagreeing within the first 12 lines. The lawyer approved against a rendering
that was not the deliverable and had no way to tell.

Two remain. The preview export was deleted rather than kept in agreement: a
rebuilt, non-layout-preserving ``<name>_redacted.txt`` headed
``PRIVACY-REVIEWED REDACTED EXPORT`` reads as the deliverable and is not one,
and before any review decision its body was the unredacted source. Reverting it
to the detection-time snapshot would have restored the opposite lie -- claiming
a dismissed finding was removed -- so there was no honest version to keep.

This module is the single answer. ``plan_segments`` resolves the post-decision
text ONCE, server-side, through ``docx_redactor.resolve_redaction_regions`` --
the same function ``redact_docx`` uses -- and every surface renders what it
returns. The canvas no longer decides anything; it draws segments.

``tests/test_app_workflow.py`` pins the address-context boundary result on both
of the surviving surfaces through this module, before and after review, so a
regression in the boundary is caught where the reviewer would meet it rather
than only in the detector's own output.

``build_redacted_preview`` in ``privacy.py`` is deliberately untouched. It is the
DETECTION-time measurement the accuracy audit and the stored privacy profile are
calibrated on, in the same way ``residual_risk`` is, and it answers a different
question: what did the detector find, before anyone reviewed it.
"""

from __future__ import annotations

from dataclasses import dataclass

from legal_analyzer.docx_redactor import RedactionTarget, resolve_redaction_regions

__all__ = ["PlanTarget", "PlanSegment", "plan_segments", "plan_text", "targets_from"]


@dataclass(frozen=True)
class PlanTarget:
    """An approved finding, as the resolver sees it plus what it came from."""

    text: str
    replacement: str
    finding_id: int | None = None
    category: str | None = None
    review_status: str | None = None


@dataclass(frozen=True)
class PlanSegment:
    """One run of the document, already resolved.

    ``text`` is what every surface renders for this run -- a placeholder for a
    redacted run, the original characters otherwise. ``source_text`` is what the
    run covers in the source, which the canvas needs for its title tooltips and
    nothing else renders.
    """

    kind: str  # "text" | "redacted" | "marked"
    text: str
    source_text: str
    start: int
    end: int
    finding_id: int | None = None
    finding_ids: tuple[int, ...] = ()
    category: str | None = None
    review_status: str | None = None

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "text": self.text,
            "source_text": self.source_text,
            "start": self.start,
            "end": self.end,
            "finding_id": self.finding_id,
            "finding_ids": list(self.finding_ids),
            "category": self.category,
            "review_status": self.review_status,
        }


def targets_from(findings: list[dict], redacted_statuses: frozenset[str] | set[str]) -> list[PlanTarget]:
    """Approved findings, in the order and shape the resolver expects.

    Mirrors ``app.redaction_targets_for_document`` -- same statuses, same
    replacement precedence -- so the plan and the DOCX export cannot be handed
    different target sets. The rows here carry the finding id as well, which the
    export path has no use for and the canvas needs to stay clickable.
    """
    targets: list[PlanTarget] = []
    for finding in findings:
        sample = finding.get("sample") or ""
        if not sample:
            continue
        if (finding.get("review_status") or "pending") not in redacted_statuses:
            continue
        targets.append(
            PlanTarget(
                text=sample,
                replacement=finding.get("replacement_text") or finding.get("placeholder") or "[REDACTED]",
                finding_id=finding.get("id"),
                category=finding.get("category"),
                review_status=finding.get("review_status"),
            )
        )
    return targets


def _resolved_finding_spans(text: str, findings: list[dict]) -> list[tuple[int, int, dict]]:
    """Where each finding sits in ``text``, for attribution and for marking.

    A recorded offset is trusted only when it still frames its own sample.
    Offsets belong to the extraction that detection ran on; a re-extraction, an
    accepted OCR page or a reviewer-added finding can leave them stale, and a
    stale offset that still points somewhere would mark the wrong words. The
    sample is then located by search instead -- the same fallback the canvas
    already applied, kept because it is right, and moved server-side with the
    rest of the decision.
    """
    resolved: list[tuple[int, int, dict]] = []
    for finding in findings:
        sample = finding.get("sample") or ""
        start = finding.get("start_offset")
        end = finding.get("end_offset")
        if (
            isinstance(start, int)
            and isinstance(end, int)
            and 0 <= start < end <= len(text)
            and (not sample or text[start:end] == sample)
        ):
            resolved.append((start, end, finding))
            continue
        if not sample:
            continue
        index = text.find(sample)
        if index == -1:
            continue
        resolved.append((index, index + len(sample), finding))
    return resolved


def plan_segments(
    text: str,
    findings: list[dict],
    redacted_statuses: frozenset[str] | set[str],
    style: str = "placeholder",
) -> list[PlanSegment]:
    """Resolve ``text`` under the current review decisions, once, for everyone.

    Approved findings are resolved first, by the shared string-match resolver:
    they define the deliverable, so nothing may take a character away from them.
    Every other finding is then laid into the gaps left over, clipped, so the
    canvas keeps a clickable span for a pending or dismissed finding without
    that span ever contradicting what the export will do. Where a pending
    finding sits wholly inside an approved region there is no gap and no marked
    segment -- correctly: those characters are leaving the document, and the
    finding is still reachable from the findings list.

    Gap ordering is (start, then widest), the same tie-break the resolver uses,
    so a marked span never depends on which surface is drawing it.
    """
    targets = targets_from(findings, redacted_statuses)
    regions = resolve_redaction_regions(
        text,
        [RedactionTarget(target.text, target.replacement) for target in targets],
        style,
    )
    spans = _resolved_finding_spans(text, findings)
    overlapping_ids = _overlap_index(spans)

    marks = [
        (start, end, finding)
        for start, end, finding in spans
        if (finding.get("review_status") or "pending") not in redacted_statuses
    ]

    segments: list[PlanSegment] = []
    cursor = 0
    for start, end, replacement, target_index in regions:
        _fill_gap(segments, text, cursor, start, marks, overlapping_ids)
        target = targets[target_index]
        segments.append(
            PlanSegment(
                kind="redacted",
                text=replacement,
                source_text=text[start:end],
                start=start,
                end=end,
                finding_id=target.finding_id,
                finding_ids=overlapping_ids(start, end),
                category=target.category,
                review_status=target.review_status,
            )
        )
        cursor = end
    _fill_gap(segments, text, cursor, len(text), marks, overlapping_ids)
    return segments


def _overlap_index(spans: list[tuple[int, int, dict]]):
    def ids_for(start: int, end: int) -> tuple[int, ...]:
        return tuple(
            finding["id"]
            for span_start, span_end, finding in spans
            if finding.get("id") is not None and span_start < end and start < span_end
        )

    return ids_for


def _fill_gap(
    segments: list[PlanSegment],
    text: str,
    gap_start: int,
    gap_end: int,
    marks: list[tuple[int, int, dict]],
    overlapping_ids,
) -> None:
    if gap_end <= gap_start:
        return
    clipped = sorted(
        (
            (max(start, gap_start), min(end, gap_end), finding)
            for start, end, finding in marks
            if start < gap_end and gap_start < end
        ),
        key=lambda item: (item[0], -(item[1] - item[0])),
    )
    cursor = gap_start
    for start, end, finding in clipped:
        if end <= cursor:
            continue
        start = max(start, cursor)
        if start > cursor:
            segments.append(_plain(text, cursor, start))
        segments.append(
            PlanSegment(
                kind="marked",
                text=text[start:end],
                source_text=text[start:end],
                start=start,
                end=end,
                finding_id=finding.get("id"),
                finding_ids=overlapping_ids(start, end),
                category=finding.get("category"),
                review_status=finding.get("review_status") or "pending",
            )
        )
        cursor = end
    if cursor < gap_end:
        segments.append(_plain(text, cursor, gap_end))


def _plain(text: str, start: int, end: int) -> PlanSegment:
    return PlanSegment(kind="text", text=text[start:end], source_text=text[start:end], start=start, end=end)


def plan_text(
    text: str,
    findings: list[dict],
    redacted_statuses: frozenset[str] | set[str],
    style: str = "placeholder",
) -> str:
    """The post-decision text: what the reviewed export will read."""
    return "".join(segment.text for segment in plan_segments(text, findings, redacted_statuses, style))
