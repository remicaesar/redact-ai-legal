"""DOCX package-preserving redaction helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
from xml.etree import ElementTree

# `ElementTree` above is used only for serialization (tostring/register_namespace)
# and type hints, which are safe. PARSING attacker-supplied DOCX bytes goes through
# defusedxml: stdlib xml.etree expands internal entities, so a few-KB "billion
# laughs" part exhausts memory. defusedxml refuses DTDs and entity definitions.
from defusedxml.ElementTree import fromstring as safe_fromstring
from defusedxml.common import DefusedXmlException

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

    try:
        with ZipFile(source, "r") as zin, ZipFile(output, "w", ZIP_DEFLATED) as zout:
            for info in zin.infolist():
                data = zin.read(info.filename)
                if is_docx_text_part(info.filename) and targets:
                    data = redact_xml_part(data, targets, normalized_style)
                zout.writestr(info, data)
    finally:
        # Matching compiles each approved target into re's module-level cache,
        # where the pattern string is a readable rendering of the target. Drop it
        # as soon as the export is done, including when the export blew up.
        purge_target_pattern_cache()
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
        root = safe_fromstring(xml_bytes)
    except (ElementTree.ParseError, DefusedXmlException):
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


# Turkish-aware matching of approved target text: case-insensitive, and folding
# the Turkish diacritics onto their plain letters.
#
# An exact substring search ships the identifier: a document that writes a
# company name in caps in a heading and in title case in the body has only the
# exact-case occurrence removed, and the other survives into the export. Both
# obvious fixes are wrong here.
#
# `text.lower().find(...)` corrupts offsets. `'İ'.lower()` is TWO characters
# ('i' + U+0307 COMBINING DOT ABOVE), so lowercasing changes the string length,
# and every index computed on the lowercased copy is wrong for the original as
# soon as an 'İ' appears before the match. `write_replacements_back` slices the
# ORIGINAL Word text nodes with these (start, end) spans, so a shifted offset
# silently blanks the wrong characters and leaves the identifier in place.
# Turkish legal documents are full of 'İ'.
#
# `re.IGNORECASE` happens to work today but is not a contract. CPython's re
# carries an internal case-equivalence table (sre's _equivalences) that, as of
# 3.13, does relate all four of i/I/ı/İ to each other -- measured, not assumed.
# That is wider than the Unicode *simple* case folding the re docs describe,
# under which 'İ' (U+0130) folds only to itself, and it is an undocumented
# implementation detail: nothing in the re documentation promises 'I' will keep
# matching 'ı'. The security property here is worth more than the six lines
# saved, so the i-family equivalence is spelled out below instead of inherited.
#
# So matching is done with an explicit per-character variant class, run over the
# ORIGINAL text, which makes every match offset valid by construction.

# The i-forms are treated as one equivalence class. Turkish pairs I/ı and İ/i;
# English pairs I/i. This codebase handles Turkish *and* English documents, so
# restricting 'I' to 'ı' alone would miss the English spelling of the same
# entity. The circumflex 'î' joins them rather than forming a group of its own:
# it marks vowel length on the same letter ("hâkim", "Kâzım", "mahkûm") and is
# dropped in running text exactly as freely as the dots are.
TURKISH_I_FORMS = frozenset("iIıİîÎ")

# The same argument extends to the Turkish diacritics. Turkish is routinely typed
# without them -- on ASCII keyboards, in systems that mangle them, in filings that
# simply do not bother -- so the same company appears as "ŞİRKETİ" in the heading
# and "SIRKETI" in the body. Matching only the exact glyphs redacts one and ships
# the other, which is the same bypass as the case one and, in real filings,
# probably the more common of the two. Each group holds every form in both cases
# -- the plain letter and each diacritic variant of it -- so folding and case
# compose without any extra logic: 'Ş' matches s, S, ş and Ş.
#
# This DELIBERATELY over-matches: "Kadir" also matches "Kadır", "acik" also
# matches "açık". That is accepted, not a defect to fix. Redaction is asymmetric
# -- over-redacting removes a word that did not need removing, under-redacting
# publishes an identifier -- so when the two spellings cannot be told apart, the
# tool errs toward removal. Narrowing any of these groups reopens a bypass.
#
# The circumflex vowels â/î/û ("Kâzım", "hâkim", "mahkûm") each join the group of
# their BASE letter instead of getting a group of their own. A separate
# frozenset("uUûÛ") reads as the obvious addition and silently breaks ü: the
# lookup table below is built last-group-wins, so 'u' and 'U' would stop
# resolving to the group holding 'Ü', and the diacritic-free target "unal" would
# no longer match "ÜNAL" -- reopening the bypass in the direction the tests
# happen not to enumerate. test_fold_groups_are_pairwise_disjoint pins this.
TURKISH_FOLD_GROUPS = (
    frozenset("aAâÂ"),
    frozenset("cCçÇ"),
    frozenset("gGğĞ"),
    TURKISH_I_FORMS,
    frozenset("oOöÖ"),
    frozenset("sSşŞ"),
    frozenset("uUüÜûÛ"),
)
TURKISH_FOLD_BY_CHAR = {char: group for group in TURKISH_FOLD_GROUPS for char in group}


def case_variants(char: str) -> tuple[str, ...]:
    """Return every single-character case and Turkish-fold variant of ``char``."""
    group = TURKISH_FOLD_BY_CHAR.get(char)
    if group is not None:
        return tuple(sorted(group))
    # str.upper()/str.lower() can widen a character ('ß'.upper() == 'SS',
    # 'İ'.lower() == 'i̇'); only single characters belong in a class.
    return tuple(sorted({char} | {form for form in (char.upper(), char.lower()) if len(form) == 1}))


def case_insensitive_pattern(text: str) -> re.Pattern[str]:
    """Compile ``text`` into a literal matcher ignoring case and Turkish diacritics.

    This is NOT uncached, and an earlier version of this docstring claimed it
    was. ``re.compile`` goes through ``re._compile``, which stores the result in
    the module-level ``re._cache`` and ``re._cache2`` dicts keyed by the pattern
    STRING. That key is the approved target spelled out as character classes --
    ``[Aa][Rr][Dd][Iiİı][CcÇç][ ][Tt]...`` -- from which the target is trivially
    recoverable, and with ``re._MAXCACHE`` at 512 it would sit there for the life
    of the interpreter. Measured on CPython 3.13, not assumed: after
    ``re.purge()``, one call here takes ``len(re._cache)`` from 0 to 1.

    So callers that compile approved-target or finding-sample text must call
    ``purge_target_pattern_cache()`` once the export or QA pass is done. The
    entry points in this package (``redact_docx``, ``analyze_docx_export_quality``,
    ``analyze_pdf_redaction_quality``) already do.
    """
    parts: list[str] = []
    for char in text:
        variants = case_variants(char)
        if len(variants) == 1:
            parts.append(re.escape(char))
        else:
            parts.append("[" + "".join(re.escape(variant) for variant in variants) + "]")
    return re.compile("".join(parts))


def find_case_insensitive(text: str, needle: str) -> list[tuple[int, int]]:
    """Return non-overlapping ``(start, end)`` spans of ``needle``, indexed into ``text``."""
    if not needle:
        return []
    return [(match.start(), match.end()) for match in case_insensitive_pattern(needle).finditer(text)]


def contains_case_insensitive(text: str, needle: str) -> bool:
    return bool(needle) and case_insensitive_pattern(needle).search(text) is not None


def purge_target_pattern_cache() -> None:
    """Drop compiled approved-target patterns out of ``re``'s module-level cache.

    ``case_insensitive_pattern`` leaves the target text, spelled as character
    classes, in ``re._cache``/``re._cache2`` as a dict KEY -- readable by anything
    that can read this process. ``re.purge()`` is the documented way to empty
    both, and it empties them for the whole process, not just for us.

    That is a cost, not a correctness problem. Compiled patterns held by
    reference (module-level ``re.compile`` results) are untouched. Call sites that
    pass a pattern STRING and lean on the cache -- privacy.py runs its 25
    DETECTION_RULES that way -- recompile once on their next call: measured at
    4.2ms against 1.8ms warm for one analyze_privacy() pass, once per export.
    An approved identifier sitting in a process-wide dict for the life of the
    interpreter is worth more than that.
    """
    re.purge()


def collect_replacements(
    text: str,
    targets: list[RedactionTarget],
    style: str = "placeholder",
) -> list[tuple[int, int, str]]:
    """Return sorted, disjoint ``(start, end, replacement)`` spans covering every match.

    Overlapping matches are CLIPPED, not dropped. Two approved targets really do
    overlap once diacritics fold: in "Yuklenici ACIK KADIR YILMAZ imzaladi.",
    both "AÇIK KADIR" and "KADIR YILMAZ" match, and the earlier-starting one wins
    the sort. Dropping the loser wholesale shipped the part of it the winner does
    not cover -- the surname survived in cleartext, and neither export QA check
    can see that, because both look for the WHOLE sample string and a surviving
    fragment is not it.

    So a match that starts inside the region already selected but ends past it
    still contributes its residual ``(cursor, end)``. A match that ends inside the
    selected region contributes nothing, which is correct: every character of it
    is already being replaced. The result stays sorted and non-overlapping, which
    is what write_replacements_back needs in order to slice the original Word
    text nodes with these offsets.
    """
    matches: list[tuple[int, int, str]] = []
    for target in targets:
        if not target.text:
            continue
        replacement = replacement_for(target, style)
        for start, end in find_case_insensitive(text, target.text):
            matches.append((start, end, replacement))

    selected: list[tuple[int, int, str]] = []
    cursor = 0
    for start, end, replacement in sorted(
        matches,
        key=lambda item: (item[0], -(item[1] - item[0])),
    ):
        if end <= cursor:
            continue
        selected.append((max(start, cursor), end, replacement))
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
