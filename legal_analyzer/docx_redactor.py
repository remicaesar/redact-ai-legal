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
TAB_TAG = f"{{{WORD_NS}}}tab"
BREAK_TAG = f"{{{WORD_NS}}}br"
PARAGRAPH_TAG = f"{{{WORD_NS}}}p"
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

    if next(root.iter(TEXT_TAG), None) is None:
        return xml_bytes

    spans = build_part_spans(root)
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


def build_part_spans(root: ElementTree.Element) -> list[TextSpan]:
    """Spans over a Word part, laid out the way ``extraction`` reads the same part.

    Concatenating the ``w:t`` nodes alone welds the last word of one paragraph
    onto the first word of the next -- "...HAKİMLİĞİNE" + "Dosya No: ..." became
    the single token "HAKİMLİĞİNEDosya". Two things break on that weld. A target
    can match ACROSS it, or fail to match at a boundary the reviewer can see; and
    ``expand_to_word_bounds`` reads the weld as one word, so redacting "Dosya No:
    2024/1187" swallowed "HAKİMLİĞİNE" with it.

    So paragraph and line breaks are carried as SYNTHETIC spans holding a "\n"
    and no node, and tabs as a "\t", exactly where ``extraction.extract_docx_text``
    puts them: it appends a line on entering each ``w:p`` (elements arrive in
    document order, so the separator precedes that paragraph's runs) and on each
    ``w:br``. The result is that this part's matching text and the text a
    reviewer sees in the canvas are the same string, which is the whole point --
    the same resolver run over both then produces the same decisions.

    A synthetic span owns no ``w:t`` node, so ``write_replacements_back`` never
    writes to one: a paragraph break is not a character the document contains and
    must not be replaced away. A redaction covering one keeps it.
    """
    spans: list[TextSpan] = []
    cursor = 0

    def add(node: ElementTree.Element | None, text: str) -> None:
        nonlocal cursor
        spans.append(TextSpan(node=node, start=cursor, end=cursor + len(text), text=text))
        cursor += len(text)

    for node in root.iter():
        if node.tag == TEXT_TAG:
            add(node, node.text or "")
        elif node.tag == TAB_TAG:
            add(None, "\t")
        elif node.tag in (BREAK_TAG, PARAGRAPH_TAG):
            add(None, "\n")
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


_WORD_CHAR_RE = re.compile(r"\w", re.UNICODE)


def _is_word_char(char: str) -> bool:
    return _WORD_CHAR_RE.match(char) is not None


def expand_to_word_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    """Widen ``(start, end)`` so it never cuts a word in half.

    A target is matched as a bare substring, so it can land in the MIDDLE of a
    word. Turkish is agglutinative and makes that the normal case rather than a
    corner: the party role "davalı" is a literal prefix of "davalıya" and
    "davalıdan", so replacing only the matched characters shipped
    "[PARTY_ROLE_2]ya tebliğ edilmiştir" -- a placeholder welded to an orphaned
    inflectional suffix, which is not text that survives a filing.

    Widening rather than requiring a word boundary is the deliberate choice.
    Requiring a boundary would simply stop redacting "davalıya", and under-
    redaction is the one outcome that must not happen: it is a privacy leak,
    while over-redaction costs a reviewer legibility. Widening also covers the
    other way a match lands mid-word -- a target that is a PREFIX OF A LONGER
    IDENTIFIER ("4561237896" inside "45612378965") would otherwise leave the
    remaining digits in cleartext, and neither export QA check can see that,
    because both look for the whole sample and a surviving fragment is not it.

    The cost, stated: the Turkish case suffix is consumed with the word, so the
    output reads "[PARTY_ROLE_2] tebliğ edilmiştir" rather than
    "[PARTY_ROLE_2]'ya tebliğ edilmiştir". Nothing is invented to replace it --
    writing an apostrophe the source never had would be fabricating text. Where
    the source DOES use the apostrophe Turkish orthography wants for a proper
    noun ("Karaduman'a"), no widening happens at all: an apostrophe is not a
    word character, so the match already ends on a boundary and the suffix is
    left alone.

    Only a run of word characters is crossed, so widening can never reach past
    a space, a period or a bracket into a neighbouring word.
    """
    if start < len(text) and _is_word_char(text[start]):
        while start > 0 and _is_word_char(text[start - 1]):
            start -= 1
    if end > 0 and end <= len(text) and _is_word_char(text[end - 1]):
        while end < len(text) and _is_word_char(text[end]):
            end += 1
    return start, end


def resolve_redaction_regions(
    text: str,
    targets: list[RedactionTarget],
    style: str = "placeholder",
) -> list[tuple[int, int, str, int]]:
    """THE post-decision redaction rule, shared by every rendering of a document.

    The browser review canvas and the exported reviewed DOCX both resolve their
    text through this one function, so that the document a lawyer approves is
    the document they receive. Before it existed the canvas replaced each
    finding's recorded OFFSETS while the export replaced every STRING match of
    each approved sample, and they disagreed on the same document with the same
    review decisions -- 5 differing hunks over 27 lines on one petition. (A
    third rendering, the "Preview TXT / Preview DOCX" server preview, has since
    been deleted outright rather than reconciled: it was a rebuilt artifact
    named and headed like the deliverable, and before any review decision its
    body was the unredacted source.)

    String matching is the surviving mechanism, for two reasons. Offsets are
    recorded against the EXTRACTED text and cannot be carried into a DOCX part,
    whose text is the concatenation of its ``w:t`` runs; and string matching
    covers repeat occurrences that detection missed, which is strictly more
    redaction. ``expand_to_word_bounds`` supplies the text fidelity the offset
    mechanism used to have for free.

    Returns sorted, disjoint ``(start, end, replacement, target_index)`` spans.
    ``target_index`` indexes ``targets`` and lets a caller attribute a region
    back to the finding that produced it; ``collect_replacements`` drops it.
    """
    matches: list[tuple[int, int, int, str, int]] = []
    for index, target in enumerate(targets):
        if not target.text:
            continue
        replacement = replacement_for(target, style)
        for raw_start, raw_end in find_case_insensitive(text, target.text):
            start, end = expand_to_word_bounds(text, raw_start, raw_end)
            matches.append((start, end, raw_end - raw_start, replacement, index))

    # Widest span wins a tie at the same start, then the widest span BEFORE
    # word-boundary widening, then the earliest target. The second term is what
    # keeps attribution honest: a MERSIS number "0123456789012345" and a VKN
    # "1234567890" nested one digit inside it widen to exactly the same span, and
    # without it whichever target happened to be listed first supplied the
    # placeholder -- the same characters would leave, labelled [VKN_1] instead of
    # [MERSIS_1]. Widening is a text-fidelity adjustment, not evidence that a
    # target covered more of the document. The last term only removes the
    # residual dependence on list order.
    selected: list[tuple[int, int, str, int]] = []
    cursor = 0
    for start, end, raw_width, replacement, index in sorted(
        matches,
        key=lambda item: (item[0], -(item[1] - item[0]), -item[2], item[4]),
    ):
        if end <= cursor:
            continue
        selected.append((max(start, cursor), end, replacement, index))
        cursor = end
    return selected


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

    The selection itself lives in ``resolve_redaction_regions``, which the
    browser canvas and the server preview call as well; this wrapper only drops
    the target index they use for attribution. Keeping one implementation is
    the point -- the export and the preview disagreeing about which characters
    go is exactly the defect that function exists to close.
    """
    return [
        (start, end, replacement)
        for start, end, replacement, _ in resolve_redaction_regions(text, targets, style)
    ]


def write_replacements_back(spans: list[TextSpan], replacements: list[tuple[int, int, str]]) -> None:
    """Apply replacements to their original Word text nodes without flattening the part.

    Each replacement's text is written exactly once, by the first span carrying a
    real ``w:t`` node that it intersects. That indirection exists because
    ``build_part_spans`` interleaves synthetic paragraph/tab spans owning no
    node: a region starting on one -- or on a node that a preceding region has
    already consumed -- would otherwise have had its placeholder dropped while
    its characters were still removed, which is silent UNDER-redaction with no
    visible marker left behind.
    """
    emitted: set[int] = set()
    for span in spans:
        if span.node is None:
            continue
        if span.end <= span.start and not span.text:
            continue

        intersecting = [
            (index, replacement)
            for index, replacement in enumerate(replacements)
            if replacement[0] < span.end and replacement[1] > span.start
        ]
        if not intersecting:
            continue

        chunks: list[str] = []
        cursor = 0
        for index, (start, end, replacement) in intersecting:
            local_start = max(start - span.start, 0)
            local_end = min(end - span.start, len(span.text))
            if local_start < cursor:
                local_start = cursor
            chunks.append(span.text[cursor:local_start])
            if index not in emitted:
                chunks.append(replacement)
                emitted.add(index)
            cursor = max(cursor, local_end)
        chunks.append(span.text[cursor:])
        span.node.text = "".join(chunks)
        preserve_space_if_needed(span.node)


def preserve_space_if_needed(node: ElementTree.Element) -> None:
    text = node.text or ""
    if text and (text[0].isspace() or text[-1].isspace()):
        node.set(XML_SPACE_ATTR, "preserve")
