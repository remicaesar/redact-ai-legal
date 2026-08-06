"""Local-first OCR helpers for extraction review workflows."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory


@dataclass(frozen=True)
class OCRToken:
    """One recognized word with normalized (0-1) page coordinates."""

    text: str
    x0: float
    y0: float
    x1: float
    y1: float
    confidence: float | None = None
    source: str = "tesseract_tsv"


@dataclass(frozen=True)
class OCRPage:
    page_number: int
    text: str
    confidence: float | None = None
    source: str = "local"
    tokens: tuple[OCRToken, ...] = ()


SUPPORTED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"}


def _png_dimensions(path: Path) -> tuple[int, int]:
    with open(path, "rb") as handle:
        header = handle.read(24)
    if len(header) < 24 or header[12:16] != b"IHDR":
        raise RuntimeError(f"Could not read PNG dimensions from {path.name}.")
    width = int.from_bytes(header[16:20], "big")
    height = int.from_bytes(header[20:24], "big")
    if not width or not height:
        raise RuntimeError(f"PNG {path.name} reports empty dimensions.")
    return width, height


def parse_tesseract_tsv(tsv_text: str, image_width: int, image_height: int) -> tuple[str, list[OCRToken]]:
    """Parse tesseract TSV output into reconstructed plain text plus word tokens.

    TSV rows at level 5 are words; text lines are rebuilt from block/paragraph/line ids
    so the reconstructed text matches what detector offsets expect reasonably closely.
    """
    tokens: list[OCRToken] = []
    lines: dict[tuple[int, int, int], list[str]] = {}
    for row in tsv_text.splitlines()[1:]:
        parts = row.split("\t")
        if len(parts) < 12:
            continue
        try:
            level = int(parts[0])
            block, par, line = int(parts[2]), int(parts[3]), int(parts[4])
            left, top, width, height = int(parts[6]), int(parts[7]), int(parts[8]), int(parts[9])
            conf = float(parts[10])
        except ValueError:
            continue
        word = parts[11].strip()
        if level != 5 or not word:
            continue
        lines.setdefault((block, par, line), []).append(word)
        tokens.append(
            OCRToken(
                text=word,
                x0=max(0.0, min(1.0, left / image_width)),
                y0=max(0.0, min(1.0, top / image_height)),
                x1=max(0.0, min(1.0, (left + width) / image_width)),
                y1=max(0.0, min(1.0, (top + height) / image_height)),
                confidence=conf / 100 if conf >= 0 else None,
            )
        )
    text = "\n".join(" ".join(words) for _, words in sorted(lines.items()))
    return text, tokens


def token_regions_for_sample(tokens: list[OCRToken] | tuple[OCRToken, ...], sample: str) -> list[dict]:
    """Find token spans matching a whitespace-normalized sample; return bounding rects.

    Matching is exact on the normalized word sequence, so a multi-word sample maps to
    the union box of the covered tokens. Returns [] when the sample is not present,
    which callers must treat as \"no coordinates known\" rather than \"nothing to redact\".
    """
    def norm(word: str) -> str:
        return word.strip(".,;:!?()[]{}<>\"'")

    words = [norm(token.text) for token in tokens]
    sample_words = [norm(word) for word in (sample or "").split()]
    sample_words = [word for word in sample_words if word]
    if not sample_words or len(sample_words) > len(words):
        return []
    matches = []
    for start in range(len(words) - len(sample_words) + 1):
        if words[start : start + len(sample_words)] == sample_words:
            span = list(tokens[start : start + len(sample_words)])
            matches.append(
                {
                    "x0": min(token.x0 for token in span),
                    "y0": min(token.y0 for token in span),
                    "x1": max(token.x1 for token in span),
                    "y1": max(token.y1 for token in span),
                    "confidence": min((token.confidence for token in span if token.confidence is not None), default=None),
                }
            )
    return matches


def ocr_from_review_text(text: str, confidence: float | None = 1.0) -> list[OCRPage]:
    """Build OCR pages from reviewer-provided text for deterministic local review/tests."""
    clean = (text or "").strip()
    if not clean:
        return []
    return [OCRPage(page_number=1, text=clean, confidence=confidence, source="reviewer_supplied")]


def run_local_ocr(path: str | Path, language: str = "tur+eng", timeout: int = 90) -> list[OCRPage]:
    """Run OCR using local command-line tools when available.

    PDF OCR uses pdftoppm to render page images and tesseract to extract text.
    Image OCR calls tesseract directly. No external hosted service is used.
    """
    source_path = Path(path)
    if not source_path.exists():
        raise FileNotFoundError(f"Source file was not found: {source_path}")
    if not shutil.which("tesseract"):
        raise RuntimeError("Local OCR requires the tesseract command. Install it with: brew install tesseract tesseract-lang (includes Turkish).")

    ext = source_path.suffix.lower()
    if ext == ".pdf":
        return _ocr_pdf(source_path, language, timeout)
    if ext in SUPPORTED_IMAGE_EXTENSIONS:
        text, tokens = _ocr_image(source_path, language, timeout)
        return [OCRPage(page_number=1, text=text, confidence=None, source="tesseract", tokens=tuple(tokens))] if text.strip() else []
    raise RuntimeError(f"OCR is not supported for {ext or 'unknown'} files in this phase.")


def _ocr_image(image_path: Path, language: str, timeout: int) -> tuple[str, list[OCRToken]]:
    """OCR one image, preferring TSV output so word coordinates are captured.

    Falls back to plain-text OCR when TSV output is unavailable; callers must then
    treat the page as text-only (no coordinates), which fails closed at PDF export.
    """
    if image_path.suffix.lower() == ".png":
        try:
            width, height = _png_dimensions(image_path)
            tsv = _run_tesseract(image_path, language, timeout, output_format="tsv")
            text, tokens = parse_tesseract_tsv(tsv, width, height)
            if text.strip():
                return text, tokens
        except RuntimeError:
            pass
    return _run_tesseract(image_path, language, timeout), []


def _ocr_pdf(path: Path, language: str, timeout: int) -> list[OCRPage]:
    if not shutil.which("pdftoppm"):
        raise RuntimeError("PDF OCR requires the pdftoppm command to render pages locally.")

    with TemporaryDirectory() as tmp:
        prefix = Path(tmp) / "page"
        result = subprocess.run(
            ["pdftoppm", "-png", str(path), str(prefix)],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            raise RuntimeError((result.stderr or "pdftoppm failed").strip())

        pages: list[OCRPage] = []
        for page_number, image_path in enumerate(sorted(Path(tmp).glob("page-*.png")), start=1):
            text, tokens = _ocr_image(image_path, language, timeout)
            if text.strip():
                pages.append(
                    OCRPage(
                        page_number=page_number,
                        text=text.strip(),
                        confidence=None,
                        source="tesseract",
                        tokens=tuple(tokens),
                    )
                )
        return pages


def _run_tesseract(path: Path, language: str, timeout: int, output_format: str | None = None) -> str:
    command = ["tesseract", str(path), "stdout", "-l", language]
    if output_format:
        command.append(output_format)
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0 and language != "eng":
        fallback = ["tesseract", str(path), "stdout", "-l", "eng"]
        if output_format:
            fallback.append(output_format)
        result = subprocess.run(
            fallback,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or "tesseract failed").strip())
    return result.stdout or ""
