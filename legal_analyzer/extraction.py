"""Best-effort local text extraction for legal documents."""

from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from html import unescape
from pathlib import Path
from xml.etree import ElementTree


def normalize_text(text: str) -> str:
    """Collapse whitespace without changing words."""
    return re.sub(r"\s+", " ", text or "").strip()


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"}


def extract_text(path: str | Path, max_chars: int = 400_000) -> tuple[str, str | None]:
    """Return extracted text and an optional warning.

    Extractors are probed one character past the cap so truncation is detected
    and reported as a warning: silently dropping a document tail would leave it
    unscanned while the document still looks fully extracted.
    """
    p = Path(path)
    ext = p.suffix.lower()
    probe = max_chars + 1
    try:
        if ext == ".docx":
            text, warning = extract_docx_text(p, probe), None
        elif ext == ".pdf":
            text = extract_pdf_text(p, probe)
            warning = None if text else "PDF text extraction returned no text; OCR may be required."
        elif ext == ".udf":
            text = extract_udf_text(p, probe)
            warning = None if text else "UDF text extraction returned no text; manual review or OCR-derived text may be required."
        elif ext in {".txt", ".md"}:
            text, warning = p.read_text(encoding="utf-8", errors="ignore")[:probe], None
        elif ext == ".zip":
            text, warning = extract_zip_text(p, probe)
        elif ext == ".pptx":
            text = extract_pptx_text(p, probe)
            warning = None if text else "PPTX extraction returned no text."
        elif ext == ".xlsx":
            text = extract_xlsx_text(p, probe)
            warning = None if text else "XLSX extraction returned no text."
        elif ext == ".doc":
            text, warning = extract_doc_text(p, probe)
        elif ext in IMAGE_EXTENSIONS:
            return "", "Image files carry no text layer; queue OCR to extract text locally."
        else:
            return "", "Text extraction is not enabled for this file type."
    except Exception as exc:  # pragma: no cover - defensive for corrupt files
        return "", f"Text extraction failed: {exc}"

    if len(text) > max_chars:
        text = text[:max_chars]
        cap_note = (
            f"Text extraction was truncated at {max_chars} characters; content beyond this point "
            "was NOT scanned for sensitive data. Review the remainder manually."
        )
        warning = f"{warning} {cap_note}" if warning else cap_note
    return text, warning


def extract_docx_text(path: Path, max_chars: int) -> str:
    """Extract visible text from DOCX XML using the standard library."""
    chunks: list[str] = []
    with zipfile.ZipFile(path) as archive:
        names = [n for n in archive.namelist() if n.startswith("word/") and n.endswith(".xml")]
        for name in names:
            if name not in {"word/document.xml", "word/footnotes.xml", "word/endnotes.xml", "word/comments.xml"}:
                continue
            root = ElementTree.fromstring(archive.read(name))
            for node in root.iter():
                if node.tag.endswith("}t") and node.text:
                    chunks.append(node.text)
                elif node.tag.endswith("}tab"):
                    chunks.append("\t")
                elif node.tag.endswith("}br") or node.tag.endswith("}p"):
                    chunks.append("\n")
            if sum(len(c) for c in chunks) > max_chars:
                break
    return normalize_text(" ".join(chunks))[:max_chars]


def extract_pdf_text(path: Path, max_chars: int) -> str:
    """Extract PDF text with local tools when available."""
    if shutil.which("pdftotext"):
        result = subprocess.run(
            ["pdftotext", "-layout", str(path), "-"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.stdout:
            return normalize_text(result.stdout)[:max_chars]

    try:
        from pypdf import PdfReader  # type: ignore
    except Exception:
        return ""

    chunks = []
    reader = PdfReader(str(path))
    for page in reader.pages:
        chunks.append(page.extract_text() or "")
        if sum(len(c) for c in chunks) > max_chars:
            break
    return normalize_text(" ".join(chunks))[:max_chars]


def extract_udf_text(path: Path, max_chars: int) -> str:
    """Extract text from Turkish UYAP/UDF-style files without rewriting the source."""
    chunks: list[str] = []
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            names = [
                name
                for name in sorted(archive.namelist())
                if not name.endswith("/")
                and Path(name).suffix.lower() in {"", ".xml", ".txt", ".html", ".htm", ".content"}
            ]
            for name in names:
                try:
                    chunks.append(text_from_possible_markup(decode_bytes(archive.read(name))))
                except Exception:
                    continue
                if sum(len(chunk) for chunk in chunks) > max_chars:
                    break
    else:
        chunks.append(text_from_possible_markup(decode_bytes(path.read_bytes())))
    return normalize_text(" ".join(chunk for chunk in chunks if chunk))[:max_chars]


ZIP_MEMBER_EXTENSIONS = {".docx", ".pdf", ".txt", ".md", ".udf", ".pptx", ".xlsx", ".doc"}
ZIP_MAX_MEMBERS = 50
ZIP_MAX_MEMBER_BYTES = 25_000_000
ZIP_MAX_TOTAL_BYTES = 100_000_000


def extract_zip_text(path: Path, max_chars: int) -> tuple[str, str | None]:
    """Extract text from supported documents inside a ZIP container.

    Nested ZIPs are skipped (bomb guard) and members are extracted to a
    temporary directory so the per-format extractors can run unchanged.
    """
    import tempfile

    chunks: list[str] = []
    notes: list[str] = []
    handled = 0
    total_bytes = 0
    with zipfile.ZipFile(path) as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        for info in members:
            member_ext = Path(info.filename).suffix.lower()
            if member_ext not in ZIP_MEMBER_EXTENSIONS:
                if member_ext == ".zip":
                    notes.append(f"{info.filename}: nested ZIPs are not extracted")
                continue
            if handled >= ZIP_MAX_MEMBERS:
                notes.append("member limit reached; remaining files were not extracted")
                break
            if info.file_size > ZIP_MAX_MEMBER_BYTES or total_bytes + info.file_size > ZIP_MAX_TOTAL_BYTES:
                notes.append(f"{info.filename}: skipped (size limit)")
                continue
            handled += 1
            total_bytes += info.file_size
            with tempfile.TemporaryDirectory() as tmp:
                safe_name = Path(info.filename).name or f"member{handled}{member_ext}"
                target = Path(tmp) / safe_name
                target.write_bytes(archive.read(info))
                member_text, member_warning = extract_text(target, max_chars)
            if member_text:
                chunks.append(f"[{info.filename}]\n{member_text}")
            if member_warning:
                notes.append(f"{info.filename}: {member_warning}")
            if sum(len(chunk) for chunk in chunks) > max_chars:
                break
    text = "\n\n".join(chunks)[:max_chars]
    if not handled:
        return text, "ZIP archive contains no extractable document types."
    warning = "; ".join(notes) if notes else None
    if not text:
        warning = warning or "ZIP members produced no extractable text."
    return text, warning


def extract_pptx_text(path: Path, max_chars: int) -> str:
    """Extract slide and notes text runs from PPTX XML."""
    chunks: list[str] = []
    with zipfile.ZipFile(path) as archive:
        names = sorted(
            name for name in archive.namelist()
            if (name.startswith("ppt/slides/slide") or name.startswith("ppt/notesSlides/")) and name.endswith(".xml")
        )
        for name in names:
            root = ElementTree.fromstring(archive.read(name))
            for node in root.iter():
                if node.tag.endswith("}t") and node.text:
                    chunks.append(node.text)
            chunks.append("\n")
            if sum(len(c) for c in chunks) > max_chars:
                break
    return normalize_text(" ".join(chunks))[:max_chars]


def extract_xlsx_text(path: Path, max_chars: int) -> str:
    """Extract shared strings, inline strings, and raw cell values from XLSX.

    Raw numeric values are included on purpose: identifiers such as TCKN or
    account numbers are frequently stored as numbers in payroll/finance sheets.
    """
    chunks: list[str] = []
    with zipfile.ZipFile(path) as archive:
        shared: list[str] = []
        if "xl/sharedStrings.xml" in archive.namelist():
            root = ElementTree.fromstring(archive.read("xl/sharedStrings.xml"))
            for si in root:
                shared.append(" ".join(node.text for node in si.iter() if node.tag.endswith("}t") and node.text))
        chunks.extend(shared)
        sheet_names = sorted(n for n in archive.namelist() if n.startswith("xl/worksheets/sheet") and n.endswith(".xml"))
        for name in sheet_names:
            root = ElementTree.fromstring(archive.read(name))
            for cell in root.iter():
                if not cell.tag.endswith("}c"):
                    continue
                cell_type = cell.get("t", "")
                for child in cell:
                    if child.tag.endswith("}v") and child.text and cell_type != "s":
                        chunks.append(child.text)
                    elif child.tag.endswith("}is"):
                        chunks.append(" ".join(node.text for node in child.iter() if node.tag.endswith("}t") and node.text))
            if sum(len(c) for c in chunks) > max_chars:
                break
    return normalize_text(" ".join(chunk for chunk in chunks if chunk))[:max_chars]


def extract_doc_text(path: Path, max_chars: int) -> tuple[str, str | None]:
    """Extract legacy .doc text via macOS textutil when available."""
    if not shutil.which("textutil"):
        return "", "Legacy .doc extraction requires the macOS textutil command; convert to DOCX or install a converter."
    result = subprocess.run(
        ["textutil", "-convert", "txt", "-stdout", str(path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return "", "Legacy .doc conversion produced no text; convert the file to DOCX and re-upload."
    return normalize_text(result.stdout)[:max_chars], None


def decode_bytes(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-16", "iso-8859-9", "cp1254"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="ignore")


def text_from_possible_markup(raw: str) -> str:
    text = raw.replace("\x00", " ").strip()
    if not text:
        return ""
    if "<" in text and ">" in text:
        xml_text = parse_xml_text(text)
        if xml_text:
            return xml_text
        text = re.sub(r"<[^>]+>", " ", text)
    return unescape(text)


def parse_xml_text(text: str) -> str:
    candidates = [text]
    if not text.lstrip().startswith("<"):
        first_tag = text.find("<")
        if first_tag >= 0:
            candidates.append(text[first_tag:])
    candidates.append(f"<root>{text}</root>")

    for candidate in candidates:
        try:
            root = ElementTree.fromstring(candidate)
        except ElementTree.ParseError:
            continue
        return unescape(" ".join(part for part in root.itertext() if part and part.strip()))
    return ""
