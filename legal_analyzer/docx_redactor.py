"""DOCX package-preserving redaction helpers."""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
from xml.etree import ElementTree

WORD_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
XML_SPACE_ATTR = "{http://www.w3.org/XML/1998/namespace}space"
TEXT_TAG = f"{{{WORD_NS}}}t"
DOCX_TEXT_PARTS = {
    "word/document.xml",
    "word/footnotes.xml",
    "word/endnotes.xml",
    "word/comments.xml",
}


@dataclass(frozen=True)
class RedactionTarget:
    text: str
    replacement: str


@dataclass(frozen=True)
class TextSpan:
    node: ElementTree.Element
    start: int
    end: int
    text: str


def is_docx_text_part(name: str) -> bool:
    return name in DOCX_TEXT_PARTS or (
        name.startswith("word/header") and name.endswith(".xml")
    ) or (
        name.startswith("word/footer") and name.endswith(".xml")
    )


def redact_docx(
    source_path: str | Path,
    targets: list[RedactionTarget],
    style: str = "placeholder",
) -> bytes:
    """Return a redacted DOCX while preserving unrelated package parts."""
    source = Path(source_path)
    output = BytesIO()
    normalized_style = normalize_style(style)

    with ZipFile(source, "r") as zin, ZipFile(output, "w", ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if is_docx_text_part(info.filename) and targets:
                data = redact_xml_part(data, targets, normalized_style)
            zout.writestr(info, data)
    return output.getvalue()


def normalize_style(style: str) -> str:
    return style if style in {"placeholder", "mask"} else "placeholder"


def replacement_for(target: RedactionTarget, style: str) -> str:
    if style == "mask":
        return "[REDACTED]"
    return target.replacement


def redact_xml_part(
    xml_bytes: bytes,
    targets: list[RedactionTarget],
    style: str = "placeholder",
) -> bytes:
    """Redact text in a Word XML part, including matches split across runs."""
    try:
        root = ElementTree.fromstring(xml_bytes)
    except ElementTree.ParseError:
        return xml_bytes

    text_nodes = [node for node in root.iter(TEXT_TAG)]
    if not text_nodes:
        return xml_bytes

    spans = build_text_spans(text_nodes)
    full_text = "".join(span.text for span in spans)
    replacements = collect_replacements(full_text, targets, normalize_style(style))
    if not replacements:
        return xml_bytes

    write_replacements_back(spans, replacements)
    ElementTree.register_namespace("w", WORD_NS)
    return ElementTree.tostring(root, encoding="utf-8", xml_declaration=True)


def build_text_spans(text_nodes: list[ElementTree.Element]) -> list[TextSpan]:
    spans: list[TextSpan] = []
    cursor = 0
    for node in text_nodes:
        node_text = node.text or ""
        spans.append(TextSpan(node=node, start=cursor, end=cursor + len(node_text), text=node_text))
        cursor += len(node_text)
    return spans


def collect_replacements(
    text: str,
    targets: list[RedactionTarget],
    style: str = "placeholder",
) -> list[tuple[int, int, str]]:
    matches: list[tuple[int, int, str]] = []
    for target in targets:
        if not target.text:
            continue
        start = 0
        while True:
            index = text.find(target.text, start)
            if index == -1:
                break
            matches.append((index, index + len(target.text), replacement_for(target, style)))
            start = index + len(target.text)

    selected: list[tuple[int, int, str]] = []
    cursor = -1
    for start, end, replacement in sorted(
        matches,
        key=lambda item: (item[0], -(item[1] - item[0])),
    ):
        if start < cursor:
            continue
        selected.append((start, end, replacement))
        cursor = end
    return selected


def write_replacements_back(spans: list[TextSpan], replacements: list[tuple[int, int, str]]) -> None:
    """Apply replacements to their original Word text nodes without flattening the part."""
    for span in spans:
        if span.end <= span.start and not span.text:
            continue

        intersecting = [
            replacement
            for replacement in replacements
            if replacement[0] < span.end and replacement[1] > span.start
        ]
        if not intersecting:
            continue

        chunks: list[str] = []
        cursor = 0
        for start, end, replacement in intersecting:
            local_start = max(start - span.start, 0)
            local_end = min(end - span.start, len(span.text))
            if local_start < cursor:
                local_start = cursor
            chunks.append(span.text[cursor:local_start])
            if span.start <= start < span.end:
                chunks.append(replacement)
            cursor = max(cursor, local_end)
        chunks.append(span.text[cursor:])
        span.node.text = "".join(chunks)
        preserve_space_if_needed(span.node)


def preserve_space_if_needed(node: ElementTree.Element) -> None:
    text = node.text or ""
    if text and (text[0].isspace() or text[-1].isspace()):
        node.set(XML_SPACE_ATTR, "preserve")
