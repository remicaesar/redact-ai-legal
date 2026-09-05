"""Best-effort local text extraction for legal documents."""

from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from html import unescape
from pathlib import Path

# XML parts of uploaded archives are parsed with defusedxml, not the standard
# library's `xml.etree`. The 25 MB decompressed-size cap in
# `read_capped_member` stops decompression bombs but cannot stop entity
# expansion: a few-kilobyte "billion laughs" part satisfies the byte cap and
# then expands during parsing. defusedxml refuses DTDs and entity definitions
# outright, which closes that path.
from defusedxml.ElementTree import ParseError, fromstring as safe_fromstring
from defusedxml.common import DefusedXmlException

from legal_analyzer.docx_redactor import is_docx_text_part


def normalize_layout(text: str) -> str:
    """Normalize whitespace while preserving line and column structure.

    This used to collapse every run of whitespace (including newlines) to a
    single space, which silently destroyed the document's line structure on
    every binary format (DOCX/PDF/UDF/PPTX/XLSX/DOC all route through here;
    .txt input never did). Two things depend on that structure surviving:

    - Several detection rules in `privacy.py` bound their trailing-context
      match with `[^.\\n]` or `[^\\n]` so a finding stops at the end of its
      line (health_data, criminal_allegation, privileged_or_confidential,
      court_or_authority, address). With no newlines left, that guard never
      fires and a finding's sample can run past the line it belongs to into
      unrelated text -- which then can't be redacted, because redaction is
      exact-substring match against the original document.
    - `turkish_names._best_name_run` treats a tab or a run of 2+ spaces as a
      column boundary, so two names side by side in a signature block or
      table don't get merged into one bogus span. Collapsing those runs to a
      single space erases the boundary.

    So: normalize line endings, drop stray control characters, collapse long
    runs of blank lines, and strip trailing whitespace -- but never touch a
    run of spaces or tabs that sits within a line; that spacing is load-bearing.
    """
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    text = re.sub(r"[ \t]+(?=\n)", "", text)  # trailing whitespace at end of line
    text = re.sub(r"\n{3,}", "\n\n", text)  # collapse runs of 3+ blank lines
    return text.strip()


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"}

# Cap on the bytes decompressed out of a single container member before it is
# parsed. The parser hands the whole part to expat in one call, so an
# over-compressed member (kilobytes on disk expanding to gigabytes in memory)
# is a denial-of-service vector at parse time. ZipInfo.file_size is declared by
# the archive itself and so cannot be trusted for this; the cap is enforced on
# the bytes actually read. This cap is independent of the defusedxml import
# above: a byte cap stops decompression bombs, defusedxml stops entity
# expansion, and neither substitutes for the other.
ZIP_MEMBER_READ_LIMIT = 25_000_000


def read_capped_member(archive: zipfile.ZipFile, name: str) -> bytes:
    """Read one container member, refusing anything past ZIP_MEMBER_READ_LIMIT."""
    with archive.open(name) as handle:
        data = handle.read(ZIP_MEMBER_READ_LIMIT + 1)
    if len(data) > ZIP_MEMBER_READ_LIMIT:
        raise ValueError(
            f"Container member '{name}' decompresses past the {ZIP_MEMBER_READ_LIMIT}-byte "
            "extraction limit and was not parsed."
        )
    return data


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
            text, warning = extract_docx_text(p, probe)
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
            text, skipped = extract_pptx_text(p, probe)
            warning = combine_warnings(skipped, None if text else "PPTX extraction returned no text.")
        elif ext == ".xlsx":
            text, skipped = extract_xlsx_text(p, probe)
            warning = combine_warnings(skipped, None if text else "XLSX extraction returned no text.")
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


# ---------------------------------------------------------------------------
# OOXML container scanning
#
# DOCX, XLSX and PPTX share one rule, learned from the DOCX header/footer leak:
# a part is scanned, deliberately ignored, or it warns -- there is no fourth
# case. The old allowlists skipped everything they did not recognize and still
# reported extraction Complete, so a letterhead in `word/header1.xml`, a print
# header in `xl/worksheets/sheet1.xml` and a SmartArt body in
# `ppt/diagrams/data1.xml` each vanished with no warning at all: the reviewer
# saw zero findings, approved the document, and the release gate then cleared a
# client name and a TCKN for external LLM use.
#
# Each format therefore declares two positive lists -- the parts it reads and
# the parts it deliberately ignores -- and anything in NEITHER warns, which
# degrades extraction_status below `Complete` and blocks external LLM release.
# That is the point: the next unhandled text-bearing part (a chart, an embedded
# workbook, a textbox in a custom part) degrades loudly instead of vanishing.
#
# The benign lists are structural or presentational only: styling, layout,
# fonts, numbering, theme, embedded media, relationship graphs, package
# metadata. Nothing on them holds text a reader sees as content, so warning on
# them would make the warning worthless. Parts that DO hold user-authored
# strings this code does not read -- comment-author rosters, custom-XML data
# islands, pivot and chart caches, embedded workbooks, macro projects -- are
# deliberately left off the benign lists so they warn.

# `customXml/itemPropsN.xml` is the schema/GUID descriptor paired 1:1 with a
# `customXml/itemN.xml` data island. The descriptor is structural; the item
# itself can hold content-control-bound text, so it stays off every list.
OOXML_BENIGN_PARTS = frozenset({"[Content_Types].xml"})
OOXML_BENIGN_PREFIXES = ("docProps/", "customXml/itemProps")
OOXML_BENIGN_SUFFIXES = (".rels",)

MAX_REPORTED_SKIPPED_PARTS = 5


def unscanned_parts(names: list[str], is_text_part, is_benign_part) -> list[str]:
    """Container members that are neither read nor known-benign, sorted by name."""
    return sorted(
        name
        for name in names
        if not name.endswith("/") and not is_text_part(name) and not is_benign_part(name)
    )


def summarize_parts(names: list[str]) -> str:
    """Name the first few members, then count the rest, so a warning stays readable."""
    shown = ", ".join(names[:MAX_REPORTED_SKIPPED_PARTS])
    if len(names) > MAX_REPORTED_SKIPPED_PARTS:
        shown += f", and {len(names) - MAX_REPORTED_SKIPPED_PARTS} more"
    return shown


def skipped_parts_warning(skipped: list[str]) -> str | None:
    """Warn about container parts that were not scanned, naming the first few."""
    if not skipped:
        return None
    return (
        f"{len(skipped)} document part(s) were not scanned for sensitive data: "
        f"{summarize_parts(skipped)}. Text in these parts was NOT extracted; review them manually."
    )


def combine_warnings(*warnings: str | None) -> str | None:
    """Join the warnings that fired, dropping the ones that did not."""
    kept = [warning for warning in warnings if warning]
    return " ".join(kept) if kept else None


def parts_in_reading_order(names: list[str], is_text_part, order: tuple[str, ...]) -> list[str]:
    """Order the text-bearing parts by `order`, then by name within each rank.

    `order` is the format's list of text-part prefixes, read as page order: a
    part's rank is the position of the first prefix it matches. Sorting within
    a rank is lexicographic, so `slide10` precedes `slide2` -- deterministic,
    which is what matters here.
    """
    ranked = []
    for name in names:
        if not is_text_part(name):
            continue
        rank = next((index for index, prefix in enumerate(order) if name.startswith(prefix)), len(order))
        ranked.append((rank, name))
    return [name for _, name in sorted(ranked)]


def ooxml_text_lines(root) -> list[str]:
    """One line per text-carrying node, for parts whose structure is not modelled.

    Covers the three shapes the auxiliary parts use: `<a:t>` (drawing and
    textbox runs), `<text>` (Excel threaded comments, classic PowerPoint
    comments) and `<author>` (Excel comment authors, which are person names).
    """
    return [
        node.text
        for node in root.iter()
        if node.tag.endswith(("}t", "}text", "}author")) and node.text and node.text.strip()
    ]


DOCX_BENIGN_PARTS = OOXML_BENIGN_PARTS | {
    "word/styles.xml",
    "word/stylesWithEffects.xml",
    "word/settings.xml",
    "word/webSettings.xml",
    "word/fontTable.xml",
    "word/numbering.xml",
    "word/commentsExtended.xml",
    "word/commentsIds.xml",
    "word/commentsExtensible.xml",
}
DOCX_BENIGN_PREFIXES = OOXML_BENIGN_PREFIXES + ("word/theme/", "word/media/", "word/fonts/")

# Read order, as a reader meets the text on the page: letterhead, body, the
# notes hanging off the body, then the page footer. Each part starts on its own
# line and is separated from the previous one by a blank line.
#
# The line break is the load-bearing part. `normalize_layout` preserves
# newlines and several detection rules in `privacy.py` bound their trailing
# context with `[^.\n]`/`[^\n]`, so a finding that starts in the header stops
# at the end of the header line instead of running into the first body line --
# where its sample would span the seam and stop matching anything redaction can
# substring-match in the source. The extra blank line on top of that keeps the
# seam visible and holds even for a part whose text is not wrapped in a `<w:p>`
# (the parser tolerates that; see the trailing flush in extract_docx_text),
# where the paragraph boundary alone would not.
#
# The set of parts that carry text is `docx_redactor.is_docx_text_part`,
# imported rather than restated: extraction must read exactly what redaction
# can rewrite, and two hand-maintained copies of that set drift, which is a
# hole in either direction.
DOCX_TEXT_PART_ORDER = (
    "word/header",
    "word/document.xml",
    "word/footnotes.xml",
    "word/endnotes.xml",
    "word/comments.xml",
    "word/footer",
)


def is_benign_docx_part(name: str) -> bool:
    """True for DOCX parts that are structural/presentational and carry no document text."""
    return (
        name in DOCX_BENIGN_PARTS
        or name.startswith(DOCX_BENIGN_PREFIXES)
        or name.endswith(OOXML_BENIGN_SUFFIXES)
    )


def extract_docx_text(path: Path, max_chars: int) -> tuple[str, str | None]:
    """Extract visible text from DOCX XML using the standard library, one line per paragraph.

    Runs within a paragraph are accumulated and only flushed to a new line on
    a paragraph or explicit line-break boundary, so a name or address split
    across sibling `<w:r>` runs (formatting, spell-check markers) stays on one
    line instead of being torn apart by the line separator.

    Headers, footers, footnotes, endnotes and comments are read alongside the
    body: Turkish legal practice puts firm letterhead in the header and the
    case/file number in the footer almost universally. Any part that is neither
    read nor known-benign returns a warning, which degrades extraction_status
    below `Complete` and blocks external LLM release.
    """
    lines: list[str] = []
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if not name.endswith("/")]
        skipped = unscanned_parts(names, is_docx_text_part, is_benign_docx_part)
        for name in parts_in_reading_order(names, is_docx_text_part, DOCX_TEXT_PART_ORDER):
            root = safe_fromstring(read_capped_member(archive, name))
            if lines:
                lines.append("")  # part separator, see DOCX_TEXT_PART_ORDER
            current: list[str] = []
            for node in root.iter():
                if node.tag.endswith("}t") and node.text:
                    current.append(node.text)
                elif node.tag.endswith("}tab"):
                    current.append("\t")
                elif node.tag.endswith("}br") or node.tag.endswith("}p"):
                    lines.append("".join(current))
                    current = []
            lines.append("".join(current))
            if sum(len(line) for line in lines) > max_chars:
                break
    return normalize_layout("\n".join(lines))[:max_chars], skipped_parts_warning(skipped)


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
            return normalize_layout(result.stdout)[:max_chars]

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
    return normalize_layout("\n".join(chunks))[:max_chars]


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
                    chunks.append(text_from_possible_markup(decode_bytes(read_capped_member(archive, name))))
                except Exception:
                    continue
                if sum(len(chunk) for chunk in chunks) > max_chars:
                    break
    else:
        chunks.append(text_from_possible_markup(decode_bytes(path.read_bytes())))
    return normalize_layout("\n".join(chunk for chunk in chunks if chunk))[:max_chars]


ZIP_MEMBER_EXTENSIONS = {".docx", ".pdf", ".txt", ".md", ".udf", ".pptx", ".xlsx", ".doc"}
ZIP_MAX_MEMBERS = 50
ZIP_MAX_MEMBER_BYTES = 25_000_000
ZIP_MAX_TOTAL_BYTES = 100_000_000


def extract_zip_text(path: Path, max_chars: int) -> tuple[str, str | None]:
    """Extract text from supported documents inside a ZIP container.

    Nested ZIPs are skipped (bomb guard) and members are extracted to a
    temporary directory so the per-format extractors can run unchanged.

    A member whose extension is not extractable is reported too, not dropped in
    silence: a bundle of one contract plus thirty scanned .jpg pages used to
    extract the contract and report Complete without ever mentioning the pages.
    """
    import tempfile

    chunks: list[str] = []
    notes: list[str] = []
    unextracted: list[str] = []
    handled = 0
    total_bytes = 0
    with zipfile.ZipFile(path) as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        for info in members:
            member_ext = Path(info.filename).suffix.lower()
            if member_ext not in ZIP_MEMBER_EXTENSIONS:
                if member_ext == ".zip":
                    notes.append(f"{info.filename}: nested ZIPs are not extracted")
                else:
                    unextracted.append(info.filename)
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
    if unextracted:
        notes.append(
            f"{len(unextracted)} member(s) were NOT extracted and were not scanned for "
            f"sensitive data: {summarize_parts(unextracted)}"
        )
    warning = "; ".join(notes) if notes else None
    if not text:
        warning = warning or "ZIP members produced no extractable text."
    return text, warning


# Read order, and the membership list, in one place: a part's rank is the
# position of the first prefix it matches. Recurring page furniture first --
# masters and layouts are where a deck's letterhead, firm name and standing
# footer live, exactly like a DOCX header -- then the slides in order, then the
# SmartArt bodies hanging off them, then speaker notes, then comments.
PPTX_TEXT_PART_PREFIXES = (
    "ppt/slideMasters/slideMaster",
    "ppt/slideLayouts/slideLayout",
    "ppt/notesMasters/notesMaster",
    "ppt/slides/slide",
    "ppt/diagrams/data",
    "ppt/notesSlides/notesSlide",
    "ppt/comments/",
)

PPTX_BENIGN_PARTS = OOXML_BENIGN_PARTS | {
    "ppt/presentation.xml",
    "ppt/presProps.xml",
    "ppt/viewProps.xml",
    "ppt/tableStyles.xml",
}
PPTX_BENIGN_PREFIXES = OOXML_BENIGN_PREFIXES + (
    "ppt/theme/",
    "ppt/media/",
    "ppt/fonts/",
    # SmartArt: `layout`, `colors` and `quickStyle` are presentational, and
    # `drawing` is the rendered cache of `data`, which IS read above.
    "ppt/diagrams/layout",
    "ppt/diagrams/colors",
    "ppt/diagrams/quickStyle",
    "ppt/diagrams/drawing",
)


def is_pptx_text_part(name: str) -> bool:
    return name.endswith(".xml") and name.startswith(PPTX_TEXT_PART_PREFIXES)


def is_benign_pptx_part(name: str) -> bool:
    """True for PPTX parts that are structural/presentational and carry no slide text."""
    return (
        name in PPTX_BENIGN_PARTS
        or name.startswith(PPTX_BENIGN_PREFIXES)
        or name.endswith(OOXML_BENIGN_SUFFIXES)
    )


def extract_pptx_text(path: Path, max_chars: int) -> tuple[str, str | None]:
    """Extract slide, master, layout, SmartArt, notes and comment text from PPTX XML.

    Mirrors extract_docx_text: runs are accumulated per paragraph (`<a:p>`) and
    only flushed to a new line at a paragraph or explicit break, so a text run
    split across sibling runs within one paragraph is not torn onto separate
    lines by the line separator. `<p:text>` (a classic comment) is a whole
    field rather than a run, so it flushes on its own line.

    SmartArt bodies in `ppt/diagrams/data*.xml` and the letterhead typed onto a
    slide master are fully visible slide content; both were skipped outright
    before. Any part that is neither read nor known-benign returns a warning.
    """
    lines: list[str] = []
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if not name.endswith("/")]
        skipped = unscanned_parts(names, is_pptx_text_part, is_benign_pptx_part)
        for name in parts_in_reading_order(names, is_pptx_text_part, PPTX_TEXT_PART_PREFIXES):
            root = safe_fromstring(read_capped_member(archive, name))
            if lines:
                lines.append("")  # part separator, see PPTX_TEXT_PART_PREFIXES
            current: list[str] = []
            for node in root.iter():
                if node.tag.endswith("}text") and node.text:
                    current.append(node.text)
                    lines.append("".join(current))
                    current = []
                elif node.tag.endswith("}t") and node.text:
                    current.append(node.text)
                elif node.tag.endswith("}br") or node.tag.endswith("}p"):
                    lines.append("".join(current))
                    current = []
            lines.append("".join(current))
            if sum(len(line) for line in lines) > max_chars:
                break
    return normalize_layout("\n".join(lines))[:max_chars], skipped_parts_warning(skipped)


XLSX_TEXT_PART_PREFIXES = (
    "xl/workbook.xml",
    "xl/sharedStrings.xml",
    "xl/worksheets/sheet",
    "xl/chartsheets/sheet",
    "xl/comments",
    "xl/threadedComments/",
    "xl/drawings/drawing",
)

XLSX_BENIGN_PARTS = OOXML_BENIGN_PARTS | {
    "xl/styles.xml",
    "xl/calcChain.xml",
}
XLSX_BENIGN_PREFIXES = OOXML_BENIGN_PREFIXES + (
    "xl/theme/",
    "xl/media/",
    "xl/printerSettings/",
    # Legacy comment-box anchors: shape geometry for the note popups whose text
    # lives in xl/comments*.xml, which IS read above.
    "xl/drawings/vmlDrawing",
)

# A worksheet's print header/footer is one string per region with `&L`/`&C`/`&R`
# section markers and formatting escapes (`&P` page number, `&"font,style"`,
# `&12` point size, `&KFF0000` colour, `&&` for a literal ampersand). The text
# between the codes is what a reader sees on the printed page -- in Turkish
# practice, the letterhead and the case/file number.
XLSX_HEADER_TAGS = ("}oddHeader", "}evenHeader", "}firstHeader")
XLSX_FOOTER_TAGS = ("}oddFooter", "}evenFooter", "}firstFooter")
_XLSX_LITERAL_AMPERSAND = "\x00"
_XLSX_FONT_CODE_RE = re.compile(r'&"[^"]*"')
_XLSX_COLOUR_CODE_RE = re.compile(r"&K(?:[0-9A-Fa-f]{6}|[0-9]{2}\+[0-9]{3})")
_XLSX_SIZE_CODE_RE = re.compile(r"&\d+")
_XLSX_SECTION_CODE_RE = re.compile(r"&[LCR]")
_XLSX_FIELD_CODE_RE = re.compile(r"&[A-Za-z]")


def is_xlsx_text_part(name: str) -> bool:
    return name.endswith(".xml") and name.startswith(XLSX_TEXT_PART_PREFIXES)


def is_benign_xlsx_part(name: str) -> bool:
    """True for XLSX parts that are structural/presentational and carry no sheet text."""
    return (
        name in XLSX_BENIGN_PARTS
        or name.startswith(XLSX_BENIGN_PREFIXES)
        or name.endswith(OOXML_BENIGN_SUFFIXES)
    )


def xlsx_header_footer_text(raw: str) -> str:
    """Strip Excel's print header/footer format codes, keeping the typed text.

    Section markers become tabs rather than spaces: `&L`/`&C`/`&R` are
    side-by-side print regions, and a tab is the column boundary
    `turkish_names._best_name_run` uses to stop two adjacent names merging into
    one bogus span -- the same reason DOCX signature-block spacing is preserved.
    """
    text = raw.replace("&&", _XLSX_LITERAL_AMPERSAND)
    text = _XLSX_FONT_CODE_RE.sub(" ", text)
    text = _XLSX_COLOUR_CODE_RE.sub(" ", text)
    text = _XLSX_SIZE_CODE_RE.sub(" ", text)
    text = _XLSX_SECTION_CODE_RE.sub("\t", text)
    text = _XLSX_FIELD_CODE_RE.sub(" ", text)
    return text.replace(_XLSX_LITERAL_AMPERSAND, "&").strip()


def xlsx_sheet_text(root) -> tuple[list[str], list[str], list[str]]:
    """Split one worksheet/chartsheet part into (print header, cells, print footer).

    Raw numeric values are included on purpose: identifiers such as TCKN or
    account numbers are frequently stored as numbers in payroll/finance sheets.
    """
    headers: list[str] = []
    cells: list[str] = []
    footers: list[str] = []
    for node in root.iter():
        if node.tag.endswith(XLSX_HEADER_TAGS) and node.text:
            headers.append(xlsx_header_footer_text(node.text))
        elif node.tag.endswith(XLSX_FOOTER_TAGS) and node.text:
            footers.append(xlsx_header_footer_text(node.text))
        elif node.tag.endswith("}c"):
            cell_type = node.get("t", "")
            for child in node:
                if child.tag.endswith("}v") and child.text and cell_type != "s":
                    cells.append(child.text)
                elif child.tag.endswith("}is"):
                    cells.append(" ".join(n.text for n in child.iter() if n.tag.endswith("}t") and n.text))
    return headers, cells, footers


def xlsx_workbook_names(root) -> list[str]:
    """Sheet tab names and defined (named-range) names, which are author-typed labels."""
    return [
        node.get("name")
        for node in root.iter()
        if node.tag.endswith(("}sheet", "}definedName")) and node.get("name")
    ]


def extract_xlsx_text(path: Path, max_chars: int) -> tuple[str, str | None]:
    """Extract every author-typed string an XLSX carries, not just its cells.

    Read order: the workbook's own labels (sheet tabs, named ranges), then the
    shared string table, then each sheet as print header -> cells -> print
    footer so a name in the letterhead stays next to the sheet it belongs to,
    then cell comments and textboxes.

    The print header/footer is the leak this covers: it lives inside the sheet
    part, so the part was read while `<headerFooter>` was skipped -- a client
    name and a TCKN in a sheet's letterhead extracted as nothing at all.
    """
    chunks: list[str] = []
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if not name.endswith("/")]
        skipped = unscanned_parts(names, is_xlsx_text_part, is_benign_xlsx_part)

        if "xl/workbook.xml" in names:
            root = safe_fromstring(read_capped_member(archive, "xl/workbook.xml"))
            chunks.extend(xlsx_workbook_names(root))

        if "xl/sharedStrings.xml" in names:
            root = safe_fromstring(read_capped_member(archive, "xl/sharedStrings.xml"))
            for si in root:
                chunks.append(" ".join(node.text for node in si.iter() if node.tag.endswith("}t") and node.text))

        sheet_parts = sorted(
            name for name in names
            if name.endswith(".xml")
            and name.startswith(("xl/worksheets/sheet", "xl/chartsheets/sheet"))
        )
        aux_parts = sorted(
            name for name in names
            if name.endswith(".xml")
            and name.startswith(("xl/comments", "xl/threadedComments/", "xl/drawings/drawing"))
        )
        for name in sheet_parts + aux_parts:
            root = safe_fromstring(read_capped_member(archive, name))
            if name in sheet_parts:
                headers, cells, footers = xlsx_sheet_text(root)
                chunks.extend(headers + cells + footers)
            else:
                chunks.extend(ooxml_text_lines(root))
            if sum(len(chunk) for chunk in chunks) > max_chars:
                break
    return normalize_layout("\n".join(chunk for chunk in chunks if chunk))[:max_chars], skipped_parts_warning(skipped)


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
    return normalize_layout(result.stdout)[:max_chars], None


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
            root = safe_fromstring(candidate)
        except (ParseError, DefusedXmlException):
            continue
        return unescape(" ".join(part for part in root.itertext() if part and part.strip()))
    return ""
