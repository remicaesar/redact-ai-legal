"""Coordinate-based PDF redaction helpers."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

import fitz  # type: ignore


@dataclass(frozen=True)
class PdfRegion:
    page_number: int
    x0: float
    y0: float
    x1: float
    y1: float
    category: str = "manual_sensitive_text"
    source: str = "manual"
    finding_id: int | None = None
    sample: str | None = None
    region_id: int | None = None


def clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def normalized_region(page_number: int, rect: fitz.Rect, page_rect: fitz.Rect, **kwargs) -> PdfRegion:
    width = page_rect.width or 1
    height = page_rect.height or 1
    return PdfRegion(
        page_number=page_number,
        x0=clamp(rect.x0 / width),
        y0=clamp(rect.y0 / height),
        x1=clamp(rect.x1 / width),
        y1=clamp(rect.y1 / height),
        **kwargs,
    )


def denormalized_rect(region: PdfRegion, page_rect: fitz.Rect) -> fitz.Rect:
    x0 = min(region.x0, region.x1) * page_rect.width
    x1 = max(region.x0, region.x1) * page_rect.width
    y0 = min(region.y0, region.y1) * page_rect.height
    y1 = max(region.y0, region.y1) * page_rect.height
    return fitz.Rect(x0, y0, x1, y1)


def find_pdf_regions(path: Path, findings: list[dict]) -> list[PdfRegion]:
    regions: list[PdfRegion] = []
    with fitz.open(path) as doc:
        for finding in findings:
            sample = (finding.get("sample") or "").strip()
            if not sample:
                continue
            for page_index, page in enumerate(doc, start=1):
                for rect in page.search_for(sample):
                    regions.append(
                        normalized_region(
                            page_index,
                            rect,
                            page.rect,
                            category=finding.get("category") or "sensitive_text",
                            source="ocr" if finding.get("source") == "ocr" else "detected_text",
                            finding_id=finding.get("id"),
                            sample=sample,
                        )
                    )
    return regions


def redact_pdf(path: Path, regions: list[PdfRegion]) -> bytes:
    by_page: dict[int, list[PdfRegion]] = {}
    for region in regions:
        by_page.setdefault(region.page_number, []).append(region)
    with fitz.open(path) as doc:
        for page_number, page_regions in sorted(by_page.items()):
            if page_number < 1 or page_number > doc.page_count:
                continue
            page = doc[page_number - 1]
            applied = False
            for region in page_regions:
                rect = denormalized_rect(region, page.rect)
                if rect.is_empty or rect.get_area() <= 0:
                    continue
                page.add_redact_annot(rect, fill=(0, 0, 0))
                applied = True
            if applied:
                page.apply_redactions()
        for page in doc:
            annot = page.first_annot
            while annot:
                next_annot = annot.next
                page.delete_annot(annot)
                annot = next_annot
        doc.set_metadata({})
        buffer = BytesIO()
        doc.save(buffer, garbage=4, deflate=True, clean=True)
        return buffer.getvalue()


def extract_pdf_text_from_bytes(data: bytes) -> str:
    with fitz.open(stream=data, filetype="pdf") as doc:
        return "\n".join(page.get_text("text") for page in doc)


def pdf_metadata_from_bytes(data: bytes) -> dict:
    with fitz.open(stream=data, filetype="pdf") as doc:
        return dict(doc.metadata or {})


def count_pdf_annotations(data: bytes) -> int:
    count = 0
    with fitz.open(stream=data, filetype="pdf") as doc:
        for page in doc:
            annot = page.first_annot
            while annot:
                count += 1
                annot = annot.next
    return count


def render_page_thumbnail(doc: fitz.Document, page_number: int, width: int = 220) -> str:
    page = doc[page_number - 1]
    zoom = width / max(page.rect.width, 1)
    pixmap = page.get_pixmap(matrix=fitz.Matrix(zoom, zoom))
    return base64.b64encode(pixmap.tobytes("png")).decode("ascii")


def visual_qa_thumbnails(source_path: Path, data: bytes, regions: list[PdfRegion]) -> dict:
    page_number = min((region.page_number for region in regions), default=1)
    try:
        with fitz.open(source_path) as source_doc:
            if not 1 <= page_number <= source_doc.page_count:
                page_number = 1
            before = render_page_thumbnail(source_doc, page_number)
        with fitz.open(stream=data, filetype="pdf") as redacted_doc:
            after = render_page_thumbnail(redacted_doc, min(page_number, redacted_doc.page_count))
    except Exception as exc:  # rendering support can vary by build; QA must not crash on it
        return {
            "status": "skipped",
            "note": f"Visual QA thumbnails were skipped because local rendering failed: {type(exc).__name__}.",
        }
    return {
        "status": "rendered",
        "page_number": page_number,
        "before_png_base64": before,
        "after_png_base64": after,
        "note": "Thumbnails are review aids only; text-extraction checks above are the security-relevant QA.",
    }


def analyze_pdf_redaction_quality(
    source_path: Path,
    data: bytes,
    regions: list[PdfRegion],
    region_state: dict | None = None,
    qa_target: str = "freshly_generated",
) -> dict:
    text_after = extract_pdf_text_from_bytes(data)
    leaked = []
    for region in regions:
        sample = (region.sample or "").strip()
        if sample and sample in text_after:
            leaked.append({"region_id": region.region_id, "finding_id": region.finding_id, "category": region.category})
    metadata = pdf_metadata_from_bytes(data)
    metadata_leaks = {key: value for key, value in metadata.items() if value}
    annotation_count = count_pdf_annotations(data)
    state = region_state or {}
    unreviewed = int(state.get("pending") or 0)
    checks = [
        {
            "name": "Approved PDF regions applied",
            "status": "pass" if regions else "fail",
            "detail": f"{len(regions)} reviewed region(s) were applied.",
        },
        {
            "name": "Approved sensitive text not extractable (includes OCR text layers)",
            "status": "pass" if not leaked else "fail",
            "detail": f"{len(leaked)} approved sample(s) remain extractable.",
        },
        {
            "name": "PDF metadata scrubbed",
            "status": "pass" if not metadata_leaks else "warn",
            "detail": "Metadata is empty." if not metadata_leaks else "Some non-empty metadata remains.",
        },
        {
            "name": "No annotations or comments remain",
            "status": "pass" if annotation_count == 0 else "fail",
            "detail": "No annotations remain in the redacted output."
            if annotation_count == 0
            else f"{annotation_count} annotation(s)/comment(s) remain and may carry sensitive text.",
        },
        {
            "name": "All PDF boxes reviewed",
            "status": "pass" if unreviewed == 0 else "fail",
            "detail": "No pending PDF redaction boxes."
            if unreviewed == 0
            else f"{unreviewed} PDF box(es) are still pending review.",
        },
    ]
    if any(check["status"] == "fail" for check in checks):
        overall = "fail"
    elif any(check["status"] == "warn" for check in checks):
        overall = "warn"
    else:
        overall = "pass"
    with fitz.open(source_path) as source_doc:
        source_page_count = source_doc.page_count
    return {
        "format": "pdf",
        "style": "black_box",
        "overall_status": overall,
        "summary": "Reviewed PDF redaction QA completed.",
        "qa_target": qa_target,
        "region_count": len(regions),
        "leakage_count": len(leaked),
        "leaked_regions": leaked,
        "metadata_leak_count": len(metadata_leaks),
        "annotation_count": annotation_count,
        "region_state": state,
        "checks": checks,
        "source_page_count": source_page_count,
        "visual_qa": visual_qa_thumbnails(source_path, data, regions),
    }
