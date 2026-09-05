"""DOCX export quality checks for reviewed redaction artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile, ZipFile
# Parts of an uploaded DOCX are parsed with defusedxml, not stdlib xml.etree:
# xml.etree expands internal entities, so a small crafted part can exhaust memory.
from defusedxml.ElementTree import ParseError, fromstring as safe_fromstring
from defusedxml.common import DefusedXmlException

from legal_analyzer.docx_redactor import (
    TEXT_TAG,
    WORD_NS,
    RedactionTarget,
    contains_case_insensitive,
    is_docx_text_part,
    purge_target_pattern_cache,
)

PARAGRAPH_TAG = f"{{{WORD_NS}}}p"
TABLE_TAG = f"{{{WORD_NS}}}tbl"


@dataclass(frozen=True)
class PartStats:
    text: str
    text_node_count: int
    nonempty_text_node_count: int
    character_count: int
    paragraph_count: int
    table_count: int
    parse_error: bool = False


def analyze_docx_export_quality(
    source_path: str | Path,
    redacted_docx: bytes,
    targets: list[RedactionTarget],
    sensitive_samples: list[str] | None = None,
    retained_count: int = 0,
) -> dict:
    """Compare original and redacted DOCX structure without exposing source text.

    ``targets`` is what the redactor was asked to replace. ``sensitive_samples``
    is every finding sample whose presence in the output would be unexpected,
    and it is what leakage is measured against. The two differ, and the
    difference is the whole point: measuring leakage only against the targets
    made this QA pass structurally unable to see a finding that was never made
    a target, so a document exported with a cleartext TCKN in it reported
    ``overall_status: "pass"`` and ``leakage_count: 0``. Callers that only have
    the target list keep the old behaviour.

    ``retained_count`` is how many findings a reviewer deliberately left
    unredacted ('retained'). Those samples are excluded from the leakage set
    because their presence is the expected outcome, so without this count the
    report on a document carrying a retained national ID would be an
    unqualified pass. A nonzero count keeps the report off "pass" and is stated
    in the checks, so a reviewer reading the QA output can see it.
    """
    try:
        with ZipFile(source_path, "r") as source_zip, ZipFile(BytesIO(redacted_docx), "r") as redacted_zip:
            source_names = set(source_zip.namelist())
            redacted_names = set(redacted_zip.namelist())
            source_parts = docx_text_part_stats(source_zip)
            redacted_parts = docx_text_part_stats(redacted_zip)
    except (BadZipFile, FileNotFoundError):
        return {
            "overall_status": "fail",
            "summary": "DOCX package could not be opened for export QA.",
            "checks": [],
            "leakage_count": 0,
            "part_reports": [],
            "visual_renderer": "not_configured",
        }

    missing_parts = sorted(source_names - redacted_names)
    added_parts = sorted(redacted_names - source_names)
    part_reports = compare_part_stats(source_parts, redacted_parts)
    sensitive_texts = {target.text for target in targets if target.text}
    sensitive_texts.update(text for text in (sensitive_samples or []) if text)
    leaked_samples = leaked_sample_count(redacted_parts, sensitive_texts)
    unapplied_targets = unapplied_target_count(source_parts, targets)
    # Both counts above compile every sensitive text through the shared matcher,
    # which leaves it in re's module-level cache as a readable pattern string.
    # The QA pass is the end of the export path, so drop it here.
    purge_target_pattern_cache()
    warnings = quality_warnings(
        missing_parts, added_parts, part_reports, leaked_samples, unapplied_targets, retained_count
    )
    overall = "fail" if leaked_samples or missing_parts else "warn" if warnings else "pass"

    return {
        "overall_status": overall,
        "summary": quality_summary(overall, warnings),
        "checks": checks(
            overall, missing_parts, added_parts, leaked_samples, unapplied_targets, part_reports, retained_count
        ),
        "leakage_count": leaked_samples,
        "retained_count": retained_count,
        "unapplied_target_count": unapplied_targets,
        "target_count": len([target for target in targets if target.text]),
        "sensitive_sample_count": len(sensitive_texts),
        "missing_package_parts": missing_parts[:25],
        "added_package_parts": added_parts[:25],
        "part_reports": part_reports,
        "visual_renderer": "not_configured",
        "visual_note": "This QA pass compares DOCX package and Word XML structure. Pixel/page visual comparison can be added when a local Office renderer is configured.",
    }


def docx_text_part_stats(archive: ZipFile) -> dict[str, PartStats]:
    stats: dict[str, PartStats] = {}
    for name in archive.namelist():
        if not is_docx_text_part(name):
            continue
        stats[name] = xml_part_stats(archive.read(name))
    return stats


def xml_part_stats(xml_bytes: bytes) -> PartStats:
    try:
        root = safe_fromstring(xml_bytes)
    except (ParseError, DefusedXmlException):
        return PartStats("", 0, 0, 0, 0, 0, parse_error=True)

    text_nodes = [node.text or "" for node in root.iter(TEXT_TAG)]
    text = "".join(text_nodes)
    return PartStats(
        text=text,
        text_node_count=len(text_nodes),
        nonempty_text_node_count=sum(1 for item in text_nodes if item),
        character_count=len(text),
        paragraph_count=sum(1 for _ in root.iter(PARAGRAPH_TAG)),
        table_count=sum(1 for _ in root.iter(TABLE_TAG)),
    )


def compare_part_stats(source: dict[str, PartStats], redacted: dict[str, PartStats]) -> list[dict]:
    reports = []
    for name in sorted(set(source) | set(redacted)):
        before = source.get(name)
        after = redacted.get(name)
        if before is None or after is None:
            reports.append({"part_name": name, "status": "warn", "message": "Text part changed presence."})
            continue
        text_node_delta = after.text_node_count - before.text_node_count
        paragraph_delta = after.paragraph_count - before.paragraph_count
        table_delta = after.table_count - before.table_count
        parse_error = before.parse_error or after.parse_error
        status = "fail" if parse_error else "warn" if any([text_node_delta, paragraph_delta, table_delta]) else "pass"
        reports.append(
            {
                "part_name": name,
                "status": status,
                "text_nodes_before": before.text_node_count,
                "text_nodes_after": after.text_node_count,
                "nonempty_text_nodes_before": before.nonempty_text_node_count,
                "nonempty_text_nodes_after": after.nonempty_text_node_count,
                "character_delta": after.character_count - before.character_count,
                "paragraph_delta": paragraph_delta,
                "table_delta": table_delta,
                "parse_error": parse_error,
            }
        )
    return reports


def leaked_sample_count(redacted_parts: dict[str, PartStats], sensitive_texts: set[str]) -> int:
    """Count sensitive samples that are still readable in the redacted output.

    Matching is case-insensitive and shares ``contains_case_insensitive`` with
    the redactor on purpose. An exact search here would report 0 leaks for
    precisely the survivors the case-insensitive redactor now removes, so the
    QA blind spot would outlive the fix.
    """
    redacted_text = "\n".join(part.text for part in redacted_parts.values())
    return sum(1 for text in sensitive_texts if contains_case_insensitive(redacted_text, text))


def unapplied_target_count(source_parts: dict[str, PartStats], targets: list[RedactionTarget]) -> int:
    """Count approved targets whose text never appeared in the source at all.

    leaked_sample_count only inspects the output, so a target that matched
    nothing to begin with (for example two adjacent table-cell names that
    merged into a span the redactor never treated as contiguous text) looks
    identical to one that was successfully removed: absent from the redacted
    text, leakage_count 0, QA passes. This checks the other side: did the
    target text exist in the source in the first place.

    Uses the redactor's matcher, so a target the redactor found in a different
    case counts as applied rather than raising a spurious "never appeared in
    the source" warning.
    """
    source_text = "\n".join(part.text for part in source_parts.values())
    unique_targets = {target.text for target in targets if target.text}
    return sum(1 for text in unique_targets if not contains_case_insensitive(source_text, text))


def quality_warnings(
    missing_parts: list[str],
    added_parts: list[str],
    part_reports: list[dict],
    leaked_samples: int,
    unapplied_targets: int = 0,
    retained_count: int = 0,
) -> list[str]:
    warnings = []
    if leaked_samples:
        warnings.append("Sensitive source text still appears in the redacted DOCX.")
    if retained_count:
        warnings.append(
            "One or more findings were deliberately retained unredacted, so real identifiers remain "
            "in this export by reviewer decision. This is not a clean export."
        )
    if unapplied_targets:
        warnings.append(
            "One or more approved findings were not found in the source document, so nothing was "
            "removed for them. Their presence in this report is not evidence of redaction — review "
            "the document manually for those findings."
        )
    if missing_parts:
        warnings.append("The redacted DOCX is missing package parts from the source.")
    if added_parts:
        warnings.append("The redacted DOCX has package parts not present in the source.")
    if any(report["status"] != "pass" for report in part_reports):
        warnings.append("One or more Word text parts changed structural counts.")
    return warnings


def checks(
    overall: str,
    missing_parts: list[str],
    added_parts: list[str],
    leaked_samples: int,
    unapplied_targets: int,
    part_reports: list[dict],
    retained_count: int = 0,
) -> list[dict]:
    structural_changes = sum(1 for report in part_reports if report["status"] != "pass")
    return [
        {
            "name": "Sensitive source text removed",
            "status": "fail" if leaked_samples else "pass",
            "detail": f"{leaked_samples} undecided finding sample(s) still detected in redacted DOCX.",
        },
        {
            "name": "Identifiers deliberately retained",
            "status": "warn" if retained_count else "pass",
            "detail": (
                f"{retained_count} finding(s) were retained unredacted by reviewer decision, so their "
                "text is still in this export. Retained samples are excluded from the leakage count "
                "above — a zero there does not mean the export is free of identifiers."
            ),
        },
        {
            "name": "Approved targets matched in source",
            "status": "warn" if unapplied_targets else "pass",
            "detail": (
                f"{unapplied_targets} approved target(s) were not found in the source document at all, "
                "so nothing was redacted for them; their absence from the output is not evidence of removal."
            ),
        },
        {
            "name": "DOCX package parts preserved",
            "status": "fail" if missing_parts else "warn" if added_parts else "pass",
            "detail": f"{len(missing_parts)} missing part(s), {len(added_parts)} added part(s).",
        },
        {
            "name": "Word text structure preserved",
            "status": "warn" if structural_changes else "pass",
            "detail": f"{structural_changes} text part(s) changed text-node, paragraph, table, or parse counts.",
        },
        {
            "name": "Reviewed native export status",
            "status": overall,
            "detail": "QA checks are based on DOCX structure and redacted text coverage, not a full visual render.",
        },
    ]


def quality_summary(overall: str, warnings: list[str]) -> str:
    if overall == "pass":
        return "DOCX export QA passed: package parts and Word text structure are preserved, no finding was retained unredacted, and no undecided finding sample was detected in the output."
    if overall == "fail":
        return "DOCX export QA failed. Review the checks before using this export."
    return "DOCX export QA found warnings. The reviewed DOCX is risk-reduced, but layout should be inspected."
