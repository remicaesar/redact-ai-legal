"""Cautious privacy and confidentiality risk mapping for legal documents."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass

from .docx_redactor import TURKISH_I_FORMS
from .taxonomy import OUTPUT_POSITIONING, TERMINOLOGY

from legal_analyzer.turkish_names import COMPANY_SUFFIX_RE, detect_person_names, tr_fold

RISK_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
EXTERNAL_LLM_BLOCKED = "Blocked for external LLM use until redaction is completed and reviewed."
EXTERNAL_LLM_ALLOWED = "Allowed for external LLM use after completed redaction and approval."
DIRECT_IDENTIFIER_CATEGORIES = {
    "natural_person_name",
    "email_address",
    "phone_number",
    "turkish_national_id",
    "iban",
    "tax_number",
    "mersis_number",
    "bar_registration_number",
    "case_or_investigation_number",
    "address",
    "company_name",
}

# Canonical set of `privacy_findings.review_status` values. Anything else —
# including a value that merely looks plausible — must be treated as
# unresolved by the release gate: see review_gate_counts() in app.py.
#
# 'rejected' is deliberately absent. It used to carry two incompatible meanings
# the system could not tell apart, and it was split by migration 005 into:
#   'dismissed' — a false positive; the text is not sensitive and stays.
#   'retained'  — a real identifier the reviewer chose to leave unredacted.
# Nothing writes 'rejected' any more, so a row still carrying it is an
# unrecognised value, which the fail-closed logic below treats as unresolved and
# therefore blocking. That is the safe direction and it is intentional.
FINDING_REVIEW_STATUSES = {"pending", "approved", "dismissed", "retained", "added_by_reviewer"}

# The only review statuses whose sensitive text is actually removed from the
# exported document — redaction_targets_for_document() in app.py builds its
# target list from exactly these two. Every other status leaves the text in the
# output: 'dismissed'/'retained' are terminal for review purposes but the text
# stays either way, and 'pending'/NULL/an unrecognized value was never acted on
# at all.
REDACTED_REVIEW_STATUSES = {"approved", "added_by_reviewer"}

# Statuses that mean "this finding no longer counts against release", either
# because its text is gone from the export (approved/added_by_reviewer) or
# because the reviewer judged it not sensitive in the first place (dismissed).
# 'retained' is absent on purpose: the reviewer resolved it, but a real
# identifier is still sitting in the exported document. Both release-side
# measurements in review_gate_counts() (app.py) take the complement of this set,
# so they fail closed on NULL, 'pending', and any unrecognised value:
#   * the remaining-findings set feeding the residual-risk recompute, i.e.
#     unresolved ∪ retained;
#   * direct_identifiers_remaining, i.e. pending ∪ retained — a retained direct
#     identifier literally remains, which is what that gate condition asks.
RELEASE_CLEARED_REVIEW_STATUSES = {"approved", "added_by_reviewer", "dismissed"}

# Statuses that count as "the reviewer has made a decision about this finding",
# used by the workflow gates that ask whether a document is fully reviewed
# (mark_redacted in blueprints/review.py, get_exportable_docx in app.py).
# 'retained' belongs here — it is a decision, not an omission — and it is caught
# on the release side by RELEASE_CLEARED_REVIEW_STATUSES instead.
RESOLVED_REVIEW_STATUSES = {"approved", "dismissed", "retained", "added_by_reviewer"}


@dataclass(frozen=True)
class DetectionRule:
    category: str
    pattern: str
    risk: str
    action: str
    placeholder_prefix: str
    flags: int = re.IGNORECASE | re.UNICODE


# Per-category explanations shown to reviewers so a flag is never a bare label.
# "basis" describes HOW it was detected; "concern" why it carries re-identification
# or legal-sensitivity risk. Checksum-validated categories say so explicitly.
CATEGORY_EXPLANATIONS: dict[str, dict[str, str]] = {
    "natural_person_name": {
        "label": "Person name",
        "basis": "Matched a name following a professional title (Av., Dr., Sayın) or a party-role word (davacı, şüpheli, kiracı).",
        "concern": "Names are direct identifiers and the primary re-identification vector in legal documents.",
    },
    "email_address": {
        "label": "Email address",
        "basis": "Matched an email address pattern.",
        "concern": "A direct identifier that ties the document to a specific individual or organization.",
    },
    "phone_number": {
        "label": "Phone number",
        "basis": "Matched a Turkish mobile/landline number pattern.",
        "concern": "A direct contact identifier for a specific person.",
    },
    "turkish_national_id": {
        "label": "Turkish national ID (TCKN)",
        "basis": "Matched an 11-digit number that PASSED the official TCKN check-digit validation.",
        "concern": "A government identifier that uniquely identifies a citizen; among the most sensitive fields.",
    },
    "iban": {
        "label": "IBAN / bank account",
        "basis": "Matched a Turkish IBAN pattern (TR + 24 digits).",
        "concern": "A financial direct identifier linking the document to a specific account holder.",
    },
    "tax_number": {
        "label": "Tax number (VKN)",
        "basis": "Matched a VKN keyword followed by a 10-digit number that PASSED VKN check-digit validation.",
        "concern": "Uniquely identifies a taxpayer or company.",
    },
    "mersis_number": {
        "label": "MERSIS number",
        "basis": "Matched a 16-digit central registry (MERSIS) number.",
        "concern": "Uniquely identifies a registered legal entity.",
    },
    "bar_registration_number": {
        "label": "Bar registration",
        "basis": "Matched a bar/registry number keyword followed by digits.",
        "concern": "Identifies a specific attorney of record.",
    },
    "passport_number": {
        "label": "Passport number",
        "basis": "Matched a pasaport/passport keyword followed by a letter-and-digit passport number.",
        "concern": "A government-issued identifier that uniquely identifies a person.",
    },
    "account_number": {
        "label": "Bank account number",
        "basis": "Matched a hesap no keyword followed by a labelled account number.",
        "concern": "A financial identifier linking the document to a specific account holder.",
    },
    "social_media_handle": {
        "label": "Social media handle",
        "basis": "Matched an @handle pattern.",
        "concern": "A public, searchable identifier that ties the document to a specific individual.",
    },
    "vehicle_plate": {
        "label": "Vehicle plate",
        "basis": "Matched a plate-number shape adjacent to a plaka/plakalı/plakası keyword.",
        "concern": "Identifies a specific registered vehicle and, through it, its owner.",
    },
    "case_or_investigation_number": {
        "label": "Case / file number",
        "basis": "Matched a case-file keyword (Esas, Karar, Soruşturma, Takip, Yevmiye, UYAP) followed by a YYYY/NNN number.",
        "concern": "A contextual identifier that can re-identify the matter and its parties even without names.",
    },
    "court_or_authority": {
        "label": "Court / authority",
        "basis": "Matched a court, chamber, prosecutor's office, judgeship, or notary name.",
        "concern": "Narrows the matter to a specific venue, aiding re-identification in combination with dates and roles.",
    },
    "party_role": {
        "label": "Party role",
        "basis": "Matched a procedural role word (davacı, davalı, şüpheli, tanık, …).",
        "concern": "Role context combined with other fields can re-identify individuals; review before releasing.",
    },
    "address": {
        "label": "Address",
        "basis": "Matched an address fragment (mahalle, cadde, sokak, apartman, ilçe) with its leading street name.",
        "concern": "Location data is a strong quasi-identifier.",
    },
    "company_name": {
        "label": "Company name",
        "basis": "Matched a company name ending in a legal-form suffix (A.Ş., LİMİTED ŞİRKETİ, Ltd. Şti.).",
        "concern": "Identifies a specific legal entity that is a party to the matter.",
    },
    "date": {
        "label": "Date",
        "basis": "Matched a calendar date.",
        "concern": "Dates are quasi-identifiers; generalize unless legally necessary to keep the exact date.",
    },
    "money_amount": {
        "label": "Financial amount",
        "basis": "Matched a currency amount (TL, USD, EUR, …).",
        "concern": "Distinctive amounts can help re-identify a matter; keep only if legally necessary.",
    },
    "health_data": {
        "label": "Health data",
        "basis": "Matched health/medical context keywords (sağlık, hasta, tedavi, teşhis, …).",
        "concern": "Special-category personal data under KVKK; flagged for mandatory human legal review.",
    },
    "criminal_allegation": {
        "label": "Criminal allegation",
        "basis": "Matched criminal-context keywords (suç, şüpheli, sanık, soruşturma, …).",
        "concern": "Special-category data about alleged offences; flagged for mandatory human legal review.",
    },
    "privileged_or_confidential": {
        "label": "Privileged / confidential",
        "basis": "Matched privilege/confidentiality markers (müvekkil, vekil, gizli, ticari sır, …).",
        "concern": "May be attorney-client privileged or a trade secret; flagged for mandatory human legal review.",
    },
    "manual_sensitive_text": {
        "label": "Manual sensitive text",
        "basis": "Added by a reviewer, not by an automated rule.",
        "concern": "Reviewer judged this text sensitive enough to redact.",
    },
}

RISK_MEANINGS: dict[str, str] = {
    "CRITICAL": "Direct identifier or special-category data — must be removed or replaced before any external use, and blocks the external-LLM gate until resolved.",
    "HIGH": "Strong identifier or quasi-identifier — should be pseudonymized or generalized before release.",
    "MEDIUM": "Contextual quasi-identifier — generalize unless it is legally necessary to keep the exact value.",
    "LOW": "Low individual re-identification risk on its own, but still reviewed rather than assumed safe.",
}


def explain_category(category: str) -> dict[str, str]:
    """Return {label, basis, concern} for a finding category, with a safe default."""
    return CATEGORY_EXPLANATIONS.get(
        category,
        {
            "label": category.replace("_", " ").title() if category else "Finding",
            "basis": "Detected by the privacy scanner.",
            "concern": "Review whether this value could re-identify a person or matter.",
        },
    )


def finding_explanations() -> dict[str, object]:
    """Bundle the explanation maps for the review UI (sent once per page)."""
    return {
        "categories": CATEGORY_EXPLANATIONS,
        "risks": RISK_MEANINGS,
        "direct_identifiers": sorted(DIRECT_IDENTIFIER_CATEGORIES),
    }


# The catch-all court/authority rule. It fires on a bare institution SUFFIX
# ("Mahkemesi", "Hakimliği", "Noterliği", "Savcılığı") and then sweeps up to 120
# characters of the clause that follows, because the institution's own name is
# not part of the trigger. That is deliberate -- it is the only rule that sees
# an unnumbered or unfamiliar authority -- but it means that wherever one of the
# specific court rules below has already matched the full institution name, this
# rule reports a second, worse copy of the same institution starting at the
# suffix: "11. Aile Mahkemesi" reported again as "Mahkemesi Sayın Hakimliğine",
# "7. İş Mahkemesi" again as "Mahkemesi kararının temyiz incelemesinde, davacı
# işçi Hasan Demirci'nin" -- a fragment that carries no institution name and
# stores an unrelated person's name in the finding sample.
#
# _generic_court_matches() therefore skips a match of THIS rule that begins
# inside a span one of the name-anchored rules already matched, and resumes the
# scan at the END of that enclosing span rather than at the end of the skipped
# match. What is guaranteed as a result:
#
#   * a name-anchored court is never suppressed;
#   * the START of every authority mention lies inside at least one finding
#     span -- its own, or the name-anchored finding that encloses it -- so the
#     place name and institution stem can always be approved and redacted.
#     Not the whole mention: the Yargıtay/Danıştay rule's fixed 60-character
#     sweep can end mid-word, and the resume then lands where \b cannot match,
#     so the TAIL of that word ("lığına" of "Başsavcılığına") can fall outside
#     every finding. Measured on 15,000 adversarial sentences: 0 whole misses,
#     664 such tail fragments, none carrying an identifier.
#
# The resume is the load-bearing half. Dropping the match and letting
# re.finditer() continue is NOT equivalent: finditer is non-overlapping, so the
# scan would restart after the discarded 120-character match and any second,
# genuinely distinct authority inside it would never be offered again. That left
# "Kadıköy Cumhuriyet Başsavcılığı'na" with no finding of any kind in
# "İstanbul Anadolu 4. Asliye Ceza Mahkemesi kararı Kadıköy Cumhuriyet
# Başsavcılığı'na gönderilmiştir" -- and a span with no finding cannot be
# approved by a reviewer, so it is unredactable on export by construction.
GENERIC_COURT_SUFFIX_RULE = DetectionRule(
    "court_or_authority",
    r"\b(?:UYAP|cumhuriyet başsavcılığı|cumhuriyet bassavciligi|mahkemesi|savcılığı|savciligi|hakimliği|hakimligi|hâkimliği|noterliği|noterligi|valiliği|valiligi|kaymakamlığı|kaymakamligi|[İi]cra müdürlüğü|icra mudurlugu|ticaret sicili? müdürlüğü|ticaret sicili? mudurlugu|bölge adliye|bolge adliye|türk patent|turkpatent|kurumu)\b[^.\n]{0,120}",
    "HIGH",
    "Replace with consistent pseudonym or generalize",
    "COURT_AUTHORITY",
)

# One character of the trailing sweep used by health_data, criminal_allegation
# and privileged_or_confidential. It is "any character except a newline or a
# period", with three exceptions, each for a period that does NOT end a
# sentence: after a single capital letter ("T.C.", "A.Ş."), between two digits
# ("22.09.2025"), and after one of a short enumerated list of lowercase
# abbreviations ("Ltd. Şti.", "vb.", "Av."). Each is justified below.
#
# The plain [^.\n] class stopped the sweep at the first period of "T.C.", so in
# "hasta Leyla Kaya T.C. Kimlik No: 10000000146 kanser" the match ended at
# "Kaya T" and the diagnosis after the identifier -- the CRITICAL part of the
# clause -- got no finding at all, and therefore no way for a reviewer to
# approve it for redaction.
#
# Every other period still stops the sweep, so a real sentence boundary ends it:
# "hasta iyileşti. Yeni cümle Ahmet Yılmaz" stops after "iyileşti" and the name
# in the next sentence stays out of this finding. The exception is deliberately
# scoped with (?-i:...) because these rules run under re.IGNORECASE, which would
# otherwise make the character class match any letter and let a lowercase
# single-letter word ("a. bendi") through the stop. The leading \b keeps it to a
# one-letter word: the period in "iyileşti." follows "i", but there is no word
# boundary before that "i", so it remains a stop.
#
# Accepted cost, stated because the exception has one: a period ending an
# abbreviation is written exactly like a period ending a sentence that HAPPENS
# to end on an abbreviation ("... Yıldız Holding A.Ş. Sonraki cümlede ..."), and
# no regex can tell them apart. Measured on 336 generated probes of that shape,
# the sweep crossed into the next sentence in all 336, against 288 probes where
# it newly reached a diagnosis or allegation that no finding covered before.
# That is over-detection, which is the direction this engine is built to fail
# in: the extra segments are dismissible reviewer noise, they raise residual
# risk rather than lower it, direct identifiers inside them are still cut out by
# _cut_identifiers_from_context_findings, and build_redacted_preview clips
# rather than drops the findings they overlap, so nothing is printed raw. A
# missed CRITICAL clause has none of those consolations -- no reviewer is shown
# it, so nobody can approve it for redaction.
#
# Also asymmetric, harmlessly: "I." is crossed (word boundary before the
# single capital) while "II." is not (no boundary before the second I).
#
# The single-capital exception left two shapes as stops, and both cost the same
# reachable CRITICAL miss it was written to fix. They are exceptions two and
# three, added here with their own measurements.
#
# TWO: a date's period. The address rule has always allowed a period after a
# digit via a plain (?<=\d)\., but copying that verbatim is what made this a
# separate change: it also crosses an ordinal institution name, so
# "Müvekkil ... Kadıköy 2. Noterliği onaylı örneği" starts storing an authority
# name in a privileged_or_confidential sample -- the direction the identifier
# cut was added to move AWAY from. The two are separable on one character:
# a date's period sits BETWEEN digits ("22.09.2025") while an ordinal's is
# followed by a space ("Kadıköy 2. Noterliği"). (?<=\d)\.(?=\d) therefore
# crosses the date and leaves the ordinal a stop. Verified against all three
# pinned samples: the privileged one and the tied-address one are unchanged;
# only the medical one grows, across a date and no further, because the
# newline after "22.09.2025" stops the sweep.
#
# THREE: a lowercase abbreviation -- "Ltd. Şti.", "vb.", "Av.", "Dr.", the
# street-address forms -- whose period follows a lowercase letter and so gets
# no help from the single-capital rule. The clause after
# "Müvekkil Yıldız Ltd. Şti. ile gizli görüşme" was uncovered.
#
# These are ENUMERATED rather than generalised to "any short token", because a
# general rule would cross the period after every short sentence-final word. A
# variable-width alternation cannot go inside ONE lookbehind -- Python's re
# rejects it with "look-behind requires fixed-width pattern" -- so each entry
# gets its own fixed-width lookbehind, joined as alternatives.
#
# Each entry is case-insensitive: filings write "Ltd. Şti." in body text,
# "LTD. ŞTİ." in headers and "ltd. şti." when sloppy.
#
# The i-family letters are spelled out rather than left to (?i:). Python does
# relate i/I/ı/İ under IGNORECASE -- measured, not assumed -- but
# docx_redactor.py refuses to depend on that, calling it "an undocumented
# implementation detail: nothing in the re documentation promises 'I' will keep
# matching 'ı'", and enumerates TURKISH_I_FORMS by hand instead. The same
# argument applies here and the consequence is the same kind: if that folding
# ever narrows, "ŞTİ." stops being crossed and the clause after it loses the
# CRITICAL finding this exception exists to give it. "Şti" is the only entry
# containing an i-family letter, so the cost of taking the house rule's side is
# one expanded string, and _i_forms() below is what expands it.
#
# What each entry costs cannot be read off the gold set: 14 of the 15
# candidates appear zero times in it, and adding all of them singly or together
# moves gold-set precision by 0.0000. Priced on generated probes instead, the
# same way the single-capital exception was: each entry buys the clause after
# its own mid-sentence use (36/48 probes) and costs a crossing when a sentence
# genuinely ends on it (48/48) -- the A.Ş. trade above, unchanged in kind.
#
# Two candidates were dropped, because for them the sentence-final position is
# ordinary prose rather than a typographic coincidence:
#   * "No" -- English "no." ends sentences routinely and these rules run on
#     English documents too ("medical", "patient", "privileged" are triggers).
#     Its buy is thin: the common address form is "Sok. No: 5", already crossed
#     via "Sok" with no period after "No", and what follows "Esas No." is a
#     case number, a direct identifier the cut removes from the span anyway.
#   * "age" -- English "age." ends sentences, and the Turkish "a.g.e." is
#     written with a dot after every letter, so the single-token form this
#     would target is rare.
_CONTEXT_SWEEP_ABBREVIATIONS = (
    "Ltd", "Şti", "Sti",       # "Yıldız Ltd. Şti." -- both, since each stops the other.
                               # "Sti" is spelled out because _i_forms() expands the
                               # i-family and NOTHING else: it does not relate 'Ş' to 'S',
                               # and it must not be taught to. The company suffixes below
                               # fold that pair by hand as _S_FORMS, and they also
                               # deliberately do NOT fold it for "A.Ş." -- courts anonymise
                               # parties to their initials, so a diacritic-free "A.S." is
                               # more often a redacted person than a company. A blanket
                               # Ş/S fold inside _i_forms() would reach that decision and
                               # silently reverse it. Turkish is routinely typed without
                               # diacritics, so "Ltd. Sti." is ordinary, not a typo; before
                               # this entry the sweep stopped dead at its period and the
                               # clause after it carried no finding, which is the
                               # unredactable-by-construction failure the whole exception
                               # list exists to prevent.
                               #
                               # This entry is NOT free, and an earlier version of this
                               # comment claimed it was. "STI." ends English sentences --
                               # sexually transmitted infection -- and it does so in
                               # exactly the documents health_data runs on, whose triggers
                               # include the English "medical" and "patient". Measured:
                               # "The medical record notes a prior STI. Kadikoy 2.
                               # Noterligi onayli ornegi" widens the health_data span from
                               # 'medical record notes a prior STI' to '... STI. Kadikoy
                               # 2', pulling an authority name into a CRITICAL sample --
                               # court_or_authority is not a DIRECT_IDENTIFIER_CATEGORY,
                               # so the cut does not take it back out.
                               #
                               # Kept anyway, and this is the criterion at the head of this
                               # block applied rather than dodged. "No" and "age" were
                               # dropped because their buy was thin AND their sentence-final
                               # use is ordinary prose. Here only the second half holds: the
                               # buy is a Turkish company form written the way Turkish is
                               # actually typed, and losing it costs a whole clause its only
                               # CRITICAL finding. The cost runs the safe way -- a health
                               # span reaching too far is over-redaction, not a leak -- and
                               # its precondition is the literal token "STI." at an English
                               # sentence end, far narrower than the ordinal case rejected
                               # above, which fired on every Turkish filing. Pinned by
                               # test_english_sti_sentence_end_is_crossed_as_an_accepted_cost
                               # so the trade is observed rather than asserted.
    "vb", "vs",                # "ve benzeri" / "vesaire"; "vs." is also English "versus"
    "Av", "Dr", "Prof", "Doç",  # professional titles, always followed by a name
    "Sok", "Cad", "Mah", "Apt",  # street-address structure words
    "Bkz",                     # "bakınız"; always followed by the reference
)

def _i_forms(abbreviation: str) -> str:
    """Spell an abbreviation as a class-per-character, expanding the i-family.

    Every character becomes a class holding both its cases, and any of i/I/ı/İ/î/Î
    becomes a class holding all of them -- so "Şti" matches "ŞTİ", "ŞTI", "şti"
    and "ştı" without asking re.IGNORECASE to relate the dotted and dotless
    letters. Fixed width per character, which the lookbehind requires.

    CONSTRAINT ON CALLERS: pass only characters whose case mapping stays a
    single character. str.upper()/str.lower() can WIDEN one -- 'ß'.upper() is
    'SS' and 'İ'.lower() is 'i' plus a combining dot, two characters -- and a
    multi-character form dropped into a class below silently changes what that
    class matches, and breaks the fixed width the sweep's lookbehind needs.
    case_variants() in docx_redactor.py filters on len(form) == 1 for exactly
    this reason; this helper does not, because it is built for the abbreviation
    and legal-suffix vocabularies below, where nothing widens (verified over
    _CONTEXT_SWEEP_ABBREVIATIONS and every company suffix word: zero widening
    characters, and 'İ' is taken by the i-family branch before .lower() is ever
    called on it).

    The note is here rather than in a commit message because this helper has
    already grown one caller beyond the fixed abbreviation tuple it was written
    for -- the company_name suffixes -- and the next caller will read this
    docstring, not the history.
    """
    parts = []
    for char in abbreviation:
        if char in TURKISH_I_FORMS:
            parts.append("[" + "".join(sorted(TURKISH_I_FORMS)) + "]")
        else:
            forms = {char, char.upper(), char.lower()}
            parts.append("[" + "".join(sorted(forms)) + "]")
    return "".join(parts)


_CONTEXT_SWEEP_CHAR = "(?:" + "|".join(
    [
        r"[^.\n]",
        r"(?<=\b(?-i:[A-ZÇĞİÖŞÜ]))\.",
        r"(?<=\d)\.(?=\d)",
    ]
    + [rf"(?<=\b{_i_forms(abbreviation)})\." for abbreviation in _CONTEXT_SWEEP_ABBREVIATIONS]
) + ")"


# --- company_name legal-form suffixes -------------------------------------
#
# The company_name rule is the ONE rule that runs without re.IGNORECASE, and
# that is deliberate. Do not "fix" it by adding the flag back: its leading
# [A-ZÇĞİÖŞÜ] class is what keeps a match from starting on a lowercase letter
# in the middle of a word, and IGNORECASE folds that class too, so
# "davali yildiz ltd. sti. adresinde" would start matching. The suffixes below
# therefore carry their own case classes instead of inheriting the flag, which
# leaves the leading class case-sensitive by construction -- no (?-i:) scope to
# get lost in a later edit.
#
# Every suffix is built through _i_forms(), for the reason docx_redactor.py
# gives at length: CPython's re does relate 'I' to 'ı' and 'İ' to 'i' under
# IGNORECASE, but that is an undocumented property of sre's internal
# equivalence table, not something the re documentation promises. Inheriting it
# here is worse than inheriting it in the context sweep, not better. company_name
# is in DIRECT_IDENTIFIER_CATEGORIES, so if that folding ever narrows, a company
# written "Ltd. Şti." stops matching, has_direct_identifiers() goes quiet, and
# the external-LLM gate silently loses one of its six arms -- which is precisely
# the bug this construction was written to close.
#
# _i_forms() spells both cases of every character and the whole i-family for
# i/I/ı/İ, so "ANONİM" also covers the diacritic-free "ANONIM" for free. It does
# NOT relate 'Ş' to 'S', so the s-forms are spelled out here: Turkish is
# routinely typed without diacritics ("LIMITED SIRKETI"), and matching only the
# cedilla ships the other spelling.
_S_FORMS = "[SsŞş]"
_SIRKETI = _S_FORMS + _i_forms("İRKETİ")
_STI = _S_FORMS + _i_forms("Tİ")

# The uppercase members of the i-family, for a suffix whose INITIAL is an i
# ("Inc." in English, "İnc" if it is ever typed with the Turkish dotted capital).
_UPPER_I_FORMS = "[IİÎ]"

# ONE criterion decides how wide each alternative below is folded, and it is
# applied uniformly:
#
#   a suffix whose all-lowercase spelling OCCURS AS A TOKEN IN ORDINARY PROSE
#   keeps an uppercase initial; a suffix that collides with nothing folds
#   completely.
#
# "occurs as a token", not "is a word", and the difference is load-bearing.
# Neither "ltd" nor "plc" is a dictionary word, so the word phrasing prescribes
# folding both -- and measured, folding them is wrong: "The device uses a plc
# module" and "Belge ltd olarak kaydedildi" become company findings. ("plc" is
# a programmable logic controller, ordinary vocabulary in the technical annexes
# attached to commercial filings.) Both are pinned in PROSE_PROBES, because
# review measured that folding either initial otherwise survives the whole
# suite.
#
# This is not fussiness. Fully folded, "limited" matches ordinary English legal
# prose -- "Damages are limited by the terms herein", "Liability is limited to
# the fees paid" -- and this engine runs on English documents by design. Each
# such match is a HIGH finding in a category that IS a direct identifier, so it
# asserts an identifier is present where there is none and offers "Damages are
# limited" to the exporter as a redaction target. It fails safe rather than
# leaking, but a review queue full of spurious HIGH direct-identifier findings
# is exactly the fatigue the false-positive work exists to prevent. Measured:
# eleven English/Turkish prose probes went from 0 matches to 11.
#
# The same criterion, same measurement, catches the generic Turkish
# company-FORM phrases: fully folded, "Taraflar bir anonim şirketi kurmuştur"
# ("the parties founded a joint-stock company") is flagged as a named company.
# An uppercase initial on the two-word forms removes those too.
#
# What this gives up is the all-lowercase spelling of the six word-shaped
# suffixes: "Yıldız limited", "Yildiz anonim sirketi", "Acme plc". Those are
# precisely the spellings that collide with prose, so the two cannot both be
# had. The compound and dotted forms below -- "ltd. şti.", "llc", "a.ş." --
# collide with no word in either language and therefore stay fully folded, so
# the sloppily-typed company spellings that DO occur are still caught.
#
# Order is load-bearing. The body of the rule is lazy, so at a given position
# the FIRST alternative that matches wins and the rest of the suffix is left
# outside the finding. Two-word forms must therefore precede the bare ones, or
# "LOJİSTİK LİMİTED ŞİRKETİ" ends its span at "LİMİTED" and the reviewer
# approves a span that stops short of the identifier.
_COMPANY_SUFFIXES = (
    "A" + _i_forms("NONİM") + " " + _SIRKETI,
    "L" + _i_forms("İMİTED") + " " + _SIRKETI,
    # Fully folded: neither "ltd" nor "şti"/"sti" is a word.
    _i_forms("LTD") + r"\.?\s*" + _STI + r"\.?",
    "L" + _i_forms("İMİTED"),
    "L" + _i_forms("TD") + r"\.?",
    "P" + _i_forms("LC"),
    _UPPER_I_FORMS + _i_forms("NC") + r"\.?",
    # "A.Ş." folds for case ("a.ş.") but keeps the cedilla REQUIRED. The
    # diacritic-free twin "A.S." is left out on measured evidence, not on
    # taste: Turkish courts anonymise parties to their initials, so "A.S." is
    # far more often a redacted person than a company. Adding it flagged
    # "Müşteki A.S. beyanında bulunmuştur" and "tanık A.S." as company names.
    _i_forms("A") + r"\.[Şş]\.",
    # Bare "AŞ" stays UPPERCASE-ONLY, the same criterion again and also
    # measured: folded to [Aa][Şş] it matches the ordinary Turkish word "aş",
    # and flagged "Belediye aş", "Kurum aş" and "sıcak aş" as companies. The
    # dotted form above covers the running-text spelling.
    r"AŞ",
    # Fully folded: "llc" is not a word.
    _i_forms("LLC"),
)

# Share the trigger vocabulary with address-boundary detection. Match the
# triggers alone there: a full context sweep can hide a later trigger beside
# an address ("hasta olan hasta Gül Sok"). Keep the existing word boundaries.
_CONTEXT_TRIGGERS = {
    "health_data": r"\b(?:sağlık|saglik|hasta|hastane|cerrahi|tedavi|teşhis|teshis|reçete|recete|medical|health|patient)\b",
    "criminal_allegation": r"\b(?:suç|suc|şüpheli|supheli|sanık|sanik|cezai|kamu davası|arama|el koyma|soruşturma|sorusturma)\b",
    "privileged_or_confidential": r"\b(?:müvekkil|muvekkil|vekil|av\.|avukat|attorney-client|privileged|gizli|confidential|ticari sır|trade secret)\b",
}
_CONTEXT_TRIGGER_RE = re.compile("|".join(_CONTEXT_TRIGGERS.values()), re.IGNORECASE | re.UNICODE)

DETECTION_RULES = [
    DetectionRule("email_address", r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "HIGH", "Replace with consistent pseudonym", "EMAIL"),
    DetectionRule("phone_number", r"(?<!\d)(?:\+90|0)?\s?(?:5\d{2}|2\d{2}|3\d{2}|4\d{2})[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}(?!\d)", "HIGH", "Replace with consistent pseudonym", "PHONE"),
    DetectionRule("turkish_national_id", r"\b(?:T\.?\s*C\.?\s*(?:Kimlik|No|Numara|Kimlik No)?[:\s]*)?([1-9]\d{10})\b", "CRITICAL", "Remove completely or replace with neutral placeholder", "NATIONAL_ID"),
    DetectionRule("iban", r"\bTR\d{2}\s?(?:\d{4}\s?){5}\d{2}\b", "CRITICAL", "Remove completely or mask partially", "IBAN"),
    DetectionRule("tax_number", r"\b(?:VKN|vergi\s*(?:kimlik\s*)?(?:no|numarasi|numarası)|tax\s*(?:id|number))[:\s]*(\d{10})\b", "HIGH", "Mask partially", "TAX_NUMBER"),
    DetectionRule("mersis_number", r"\b(?:MERS[İI]S|mersis)\s*(?:no|numarası|numarasi)?[:\s]*\d{16}\b", "HIGH", "Replace with consistent pseudonym", "MERSIS"),
    DetectionRule("mersis_number", r"\b0\d{15}\b", "HIGH", "Replace with consistent pseudonym", "MERSIS"),
    # Second alternative widened from bare "sicil\s*no": a labelled personnel
    # registry number ("sicil numarası 884411") did not match at all, because
    # "no" consumed only the literal word "no" and left "numarası" unmatched.
    DetectionRule("bar_registration_number", r"\b(?:baro\s*(?:sicil|no|numarası|numarasi)|sicil\s*(?:no|numarası|numarasi))[:\s]*\d{3,8}\b", "HIGH", "Replace with consistent pseudonym", "BAR_REGISTRATION"),
    # Passport number: same government-issued, uniquely-identifying shape as
    # turkish_national_id/iban, so it carries the same CRITICAL risk.
    DetectionRule("passport_number", r"\b(?:pasaport|passport)\s*(?:no|numarası|numarasi|number)?[:\s]*[A-Z]{1,2}\d{6,9}\b", "CRITICAL", "Remove completely or replace with neutral placeholder", "PASSPORT"),
    # Labelled bank account number outside the IBAN format ("hesap no 1234-5678901").
    # Risk matched to tax_number/mersis/bar_registration_number rather than IBAN's
    # CRITICAL: it lacks IBAN's fixed, check-digited, country-coded structure.
    DetectionRule("account_number", r"\bhesap\s*(?:no|numarası|numarasi)[:\s]*\d[\d\-]{4,19}\d\b", "HIGH", "Mask partially", "ACCOUNT_NUMBER"),
    # Social media handle. Risk matched to email_address (HIGH): both are direct,
    # public-facing contact identifiers for a specific person. The negative
    # lookbehind keeps this from matching the "@domain" tail of an email address
    # already covered by email_address ("test@example.com" -- "t" before "@" is
    # a word char, so this rule does not also fire on it).
    DetectionRule("social_media_handle", r"(?<![\w.])@[A-Za-z0-9_]{2,30}\b", "HIGH", "Replace with consistent pseudonym", "SOCIAL_HANDLE"),
    # Vehicle plate. Deliberately anchored on a "plaka" context word on one side
    # or the other -- an unanchored "\d{2}\s?[A-Z]{1,3}\s?\d{2,4}" shape also
    # matches fragments of case numbers, dates, and reference codes. See the
    # accuracy-audit note above `DETECTION_RULES` before loosening this.
    DetectionRule("vehicle_plate", r"\b(?:plaka(?:sı|si)?\s*(?:no(?:su)?)?[:\s]*\d{2}\s?[A-ZÇĞİÖŞÜ]{1,3}\s?\d{2,4}|\d{2}\s?[A-ZÇĞİÖŞÜ]{1,3}\s?\d{2,4}\s+plaka(?:lı|li|sı|si)?)\b", "HIGH", "Replace with consistent pseudonym", "VEHICLE_PLATE"),
    DetectionRule("case_or_investigation_number", r"\b(?:soruşturma|sorusturma|kovuşturma|kovusturma|esas|karar|dosya|takip|yevmiye|talimat|değişik iş|degisik is|UYAP)\s*(?:no|numarası|numarasi)?[:\s]*[0-9]{4}\s*/\s*[0-9A-Za-z.-]+\b", "HIGH", "Replace with consistent pseudonym", "CASE_NUMBER"),
    # Triggered on address *structure* words (street/neighbourhood/building/
    # district), never on a bare place name. The trigger list used to carry
    # "İstanbul", "Beşiktaş" and "Ümraniye"; those fired on a city or district
    # mentioned in running text and then swallowed 140 characters of whatever
    # followed, so "İstanbul 7. İş Mahkemesi kararının temyiz incelemesinde,
    # davacı işçi Hasan Demirci'nin" was reported as an address. A place name on
    # its own is not an address -- it does not narrow anyone down -- and every
    # address in the gold set is anchored on a structure word whose trailing
    # span already sweeps up the district and city that follow it ("Bağdat
    # Caddesi No: 41 Daire: 7 Maltepe"). Dropping the three place names removed
    # 8 false positives with gold-set recall held at 1.0. Accepted cost: an
    # address written as a bare "Beşiktaş / İstanbul", with no street or
    # neighbourhood, is no longer flagged as an address.
    DetectionRule("address", r"(?P<address_prefix>(?:[A-ZÇĞİÖŞÜ][a-zA-Z0-9çğıöşüÇĞİÖŞÜ]*\s+){0,2})\b(?:mah\.?|mahallesi|cad\.?|caddesi|sok\.?|sokak|sokağı|sokagi|bulvarı|bulvari|apartmanı|apartmani|apt\.?|[İi]lçesi|ilcesi|köyü|koyu)\b(?:[^.\n]|(?<=\d)\.){0,140}", "HIGH", "Generalize or replace with consistent pseudonym", "ADDRESS"),
    DetectionRule("date", r"\b(?:\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}[./-]\d{1,2}[./-]\d{1,2})\b", "MEDIUM", "Generalize unless legally necessary", "DATE"),
    DetectionRule("money_amount", r"\b(?:USD|EUR|TRY|TL|₺|\$|€)\s?\d[\d.,]*|\b\d[\d.,]*\s?(?:USD|EUR|TRY|TL|₺|dolar|euro)\b", "MEDIUM", "Generalize or keep if legally necessary", "AMOUNT"),
    DetectionRule("health_data", _CONTEXT_TRIGGERS["health_data"] + _CONTEXT_SWEEP_CHAR + r"{0,120}", "CRITICAL", "Flag for human legal review", "SENSITIVE_HEALTH_DATA"),
    DetectionRule("criminal_allegation", _CONTEXT_TRIGGERS["criminal_allegation"] + _CONTEXT_SWEEP_CHAR + r"{0,160}", "CRITICAL", "Flag for human legal review", "CRIMINAL_ALLEGATION"),
    DetectionRule("privileged_or_confidential", _CONTEXT_TRIGGERS["privileged_or_confidential"] + _CONTEXT_SWEEP_CHAR + r"{0,160}", "CRITICAL", "Flag for human legal review", "PRIVILEGED_CONTENT"),
    # The role word alone, deliberately NOT the surrounding clause. A party role
    # is a re-identification *signal* for a reviewer to weigh, not an identifier.
    # Trailing context ([^.\n]{0,120}) made this span the longest at its start,
    # so build_redacted_preview preferred it over the findings nested inside it:
    # a CRITICAL national id was emitted as a MEDIUM [PARTY_ROLE_n], spans cut
    # mid-date ("[PARTY_ROLE_1].03.2026"), and whole clauses of legal substance
    # were destroyed. The identifiers in that clause -- name, TCKN, address,
    # phone, email -- each have their own precise rule and are still redacted at
    # their own risk level. Measured over the gold set, dropping the context
    # exposes 142 characters, all scaffolding ("vekili Av", "ile", "(TCKN:"),
    # and no identifier. It also stops party_role samples from storing a party's
    # name and national id in cleartext.
    DetectionRule("party_role", r"\b(?:davacı|davaci|davalı|davali|müşteki|musteki|şikayetçi|sikayetci|şüpheli|supheli|sanık|sanik|katılan|katilan|borçlu|borclu|alacaklı|alacakli|mağdur|magdur|tanık|tanik|müdahil|mudahil)\b", "MEDIUM", "Review party-role context for re-identification risk", "PARTY_ROLE"),
    GENERIC_COURT_SUFFIX_RULE,
    DetectionRule("court_or_authority", r"\b\d{1,2}\.\s*(?:Asliye|Ağır\s+Ceza|Agir\s+Ceza|Sulh|İdare|Idare|Ticaret|İş|Is|Aile|İcra|Icra|Hukuk|Ceza|Vergi)(?:\s+(?:Hukuk|Ceza|Ticaret|İş|Is|Aile|Mahkemesi|Dairesi|Müdürlüğü|Mudurlugu|Hakimliği|Hakimligi)){1,3}\b", "HIGH", "Replace with consistent pseudonym or generalize", "COURT_AUTHORITY"),
    DetectionRule("court_or_authority", r"\b\d{1,2}\.\s*Noterli[ğg]i\b", "HIGH", "Replace with consistent pseudonym or generalize", "COURT_AUTHORITY"),
    DetectionRule("court_or_authority", r"\b(?:Yargıtay|Yargitay|Danıştay|Danistay|Anayasa\s+Mahkemesi|Bölge\s+Adliye\s+Mahkemesi|Bolge\s+Adliye\s+Mahkemesi|Bölge\s+İdare\s+Mahkemesi|Bolge\s+Idare\s+Mahkemesi)\b[^.\n]{0,60}", "HIGH", "Replace with consistent pseudonym or generalize", "COURT_AUTHORITY"),
    # flags=re.UNICODE, i.e. no IGNORECASE, on purpose -- see the
    # _COMPANY_SUFFIXES block above before changing it.
    DetectionRule("company_name", r"\b[A-ZÇĞİÖŞÜ][A-Za-zÇĞİÖŞÜçğıöşü0-9&.,'\- ]{2,90}?\s(?:" + "|".join(_COMPANY_SUFFIXES) + r")(?!\w)", "HIGH", "Replace with consistent pseudonym", "COMPANY", flags=re.UNICODE),
]

# Separator WITHIN a captured name: spaces and tabs only, never a line break --
# the same rule, for the same reason, as turkish_names._SEP. A person name does
# not wrap across lines, and "\s+" here let the capture swallow the next line's
# words: "Av. Şeyma Karaduman\nBaro Sicil No: ..." was captured whole, as
# 'Şeyma Karaduman\nBaro Sicil'. That sample is then unusable twice over. It
# hashes to a different pseudonym key than the clean 'Şeyma Karaduman' the
# gazetteer path finds at the same offset, so one lawyer became [PERSON_1] and
# [PERSON_2] in one document; and it can never be redacted from the exported
# DOCX, because a DOCX part's text is the concatenation of its w:t runs and
# contains no newline at the paragraph boundary. The gap BEFORE the capture
# keeps "\s+": a label may legitimately sit on its own line ("VEKİLİ:\nAv. X"),
# and that gap is not part of the span.
_NAME_SEP = r"[ \t]+"

PERSON_CONTEXT_RE = re.compile(
    r"\b(?:Av\s?\.|Av\b|Avukat|Dr\s?\.|Dr\b|Sayın|Sn\.?|Mr\.?|Ms\.?)\s+"
    r"([A-ZÇĞİÖŞÜ][A-Za-zÇĞİÖŞÜçğıöşü'\-]+(?:" + _NAME_SEP + r"[A-ZÇĞİÖŞÜ][A-Za-zÇĞİÖŞÜçğıöşü'\-]+){1,3})"
)

ROLE_PERSON_RE = re.compile(
    r"\b(?i:davacı|davaci|davalı|davali|müşteki|musteki|şüpheli|supheli|sanık|sanik|müvekkil|muvekkil"
    r"|borçlu|borclu|alacaklı|alacakli|kiracı|kiraci|kiraya\s+veren|tanık|tanik|mağdur|magdur"
    r"|katılan|katilan|müdahil|mudahil|[İi]şçi|isci|[İi]şveren|isveren|hasta|mirasçı|mirasci|vasi)"
    r"\s+(?:[a-zçğıöşü]+\s+)?"
    r"([A-ZÇĞİÖŞÜ][a-zçğıöşü'\-]+(?:" + _NAME_SEP + r"[A-ZÇĞİÖŞÜ][a-zA-ZçğıöşüÇĞİÖŞÜ'\-]+){1,2})"
)


def _named_court_spans(text: str) -> list[tuple[int, int]]:
    """Spans matched by the court rules that begin at the institution's name.

    Every court_or_authority rule except GENERIC_COURT_SUFFIX_RULE *starts* on
    the institution name ("11. Aile Mahkemesi", "24. Noterliği", "Yargıtay"),
    which is what makes it safe for the generic suffix rule to yield to them.
    They do not all END there: the Yargıtay/Danıştay rule carries a
    `[^.\\n]{0,60}` sweep, so its span can run 60 characters past the name and
    over a following institution. That only widens the window the generic rule
    skips -- it never suppresses another name-anchored rule -- and the skipped
    text stays covered by the Yargıtay finding itself.
    """
    spans = []
    for rule in DETECTION_RULES:
        if rule.category != "court_or_authority" or rule is GENERIC_COURT_SUFFIX_RULE:
            continue
        for match in re.finditer(rule.pattern, text, rule.flags):
            spans.append((match.start(), match.end()))
    return spans


def _enclosing_span_end(start: int, spans: list[tuple[int, int]]) -> int | None:
    """End of the narrowest span in `spans` that strictly contains `start`.

    Strictly: a match starting at exactly the same offset as a span is a
    competing reading of the same text, not a fragment of it, and is kept so
    _dedupe_findings and build_redacted_preview can rank the two on risk.

    Narrowest or widest is inconsequential: if two spans both strictly contain
    `start`, every offset between their ends is still strictly inside the wider
    one and is skipped again on the next iteration, so both choices reach the
    same resume point. min() is used for determinism; a min->max mutation is an
    equivalent mutant (verified: identical findings on a 15,000-sentence fuzz).
    """
    ends = [span_end for span_start, span_end in spans if span_start < start < span_end]
    return min(ends) if ends else None


def _generic_court_matches(text: str, named_spans: list[tuple[int, int]]):
    """Yield GENERIC_COURT_SUFFIX_RULE matches that are not a named court's tail.

    Resumes at the end of the enclosing named span instead of the end of the
    skipped match, so an authority mentioned inside the skipped 120-character
    span is still offered its own finding. See the note on
    GENERIC_COURT_SUFFIX_RULE for why dropping the match outright is not
    equivalent. Terminates because every resume offset is strictly greater than
    the start of the match that produced it, which is itself at or after the
    previous offset.
    """
    pattern = re.compile(GENERIC_COURT_SUFFIX_RULE.pattern, GENERIC_COURT_SUFFIX_RULE.flags)
    position = 0
    while True:
        match = pattern.search(text, position)
        if match is None:
            return
        enclosing_end = _enclosing_span_end(match.start(), named_spans)
        if enclosing_end is None:
            yield match
            position = match.end()
        else:
            position = enclosing_end


def classify_document_context(filename: str, text: str) -> dict:
    sample = f"{filename}\n{text[:5000]}".lower()
    return {
        "appears_to_contain_personal_data": any(token in sample for token in ["av.", "şüpheli", "supheli", "t.c", "adres", "email", "telefon", "müvekkil"]),
        "appears_to_contain_sensitive_data": any(token in sample for token in ["sağlık", "saglik", "cezai", "suç", "suc", "şüpheli", "supheli", "soruşturma"]),
        "appears_privileged_or_confidential": any(token in sample for token in ["müvekkil", "muvekkil", "vekil", "av.", "gizli", "confidential", "ticari sır"]),
        "contains_contextual_reidentification_risk": any(token in sample for token in ["soruşturma no", "esas no", "mahkemesi", "savcılığı", "adres", "marka", "ek-"]),
    }


# The three rules that match a sensitive *clause* rather than an identifier:
# a trigger keyword plus a trailing sweep of up to 120-160 characters. The sweep
# is what makes them useful -- an allegation, a diagnosis or a privileged
# instruction is a clause, not a token -- and it is also how an unrelated
# person's name and national id ended up stored a second time, in a finding
# whose category has nothing to do with them ("hasta Leyla Kaya (TCKN:
# 66666666660), Özel Marmara Hastanesi'nde 22"). This is the same trailing-span
# over-reach that party_role was fixed for, except party_role could drop its
# context outright and these cannot: the clause IS the finding.
CONTEXT_SWEEP_CATEGORIES = {"health_data", "criminal_allegation", "privileged_or_confidential"}

# Placeholder prefix per context category, read off the rules themselves so a
# segment cut out of a context span keeps its rule's prefix rather than a
# hardcoded copy of it.
_CONTEXT_PLACEHOLDER_PREFIXES = {
    rule.category: rule.placeholder_prefix
    for rule in DETECTION_RULES
    if rule.category in CONTEXT_SWEEP_CATEGORIES
}

# A word, for the purpose of deciding whether a leftover segment says anything:
# a run of two or more letters. Digits and punctuation do not count, so "22",
# "),", and "(" are wordless.
_SEGMENT_WORD_RE = re.compile(r"[^\W\d_]{2,}", re.UNICODE)

# Clause punctuation a cut can orphan at the FRONT of a leftover segment.
#
# The address rule deliberately stops before an abbreviation's period: its tail
# is (?:[^.\n]|(?<=\d)\.){0,140}, and "sok\.?" backtracks off the dot so the
# trailing \b can hold. So in "hasta Gul Sok. 5 adresinde ikamet etmektedir"
# the address span is "Gul Sok" [6,13) and the period at 13 -- which belongs to
# "Sok." -- lands outside it. The health span covers the whole clause and is cut
# around the address, so that orphaned period became the FIRST character of the
# trailing health finding: '. 5 adresinde ikamet etmektedir'. A finding's sample
# is what a reviewer reads and what the exporter searches for, and a CRITICAL
# health finding that opens on another rule's abbreviation dot reads as a bug in
# the reviewer UI.
#
# Only whitespace and clause separators are consumed, never a letter, digit,
# currency symbol or bracket: dropping ".5 mg" to "5 mg" is right, dropping
# "(HIV" to "HIV" or "TL500" is not this function's call to make. A punctuation
# character carries no identifier, so no coverage that matters is lost -- and a
# segment that is ONLY punctuation was already dropped by
# _segment_is_reportable(), which counts words, not characters.
#
# No "^" anchor: this is used as .match(text, start, end), which already
# anchors at start, while "^" would additionally demand the real start of a
# line and so silently never fire at any offset past the first character.
_SEGMENT_LEADING_NOISE_RE = re.compile(r"[\s.,;:]+")

# All-capital abbreviations that LABEL a direct identifier rather than say
# anything themselves. They are the only reason a leftover segment can consist
# of a single all-caps token that is not content -- "(TCKN:" is the punctuation
# between a name and the national id that was just cut out of the span, and it
# must not become a CRITICAL finding, while "HIV" in the same position must.
# Form alone cannot separate those two, so this list is required.
#
# It is written out rather than derived from the identifier rules' own patterns.
# That derivation was tried and does not work, for three reasons:
#   * "TCKN" -- the token this exists for -- appears in no pattern at all. The
#     national-id rule spells its prefix "T\.?\s*C\.?", two single letters that
#     no word extractor keeps, and documents write "TCKN".
#   * Character classes mangle the words: "MERS[Ii]S" extracts as "MERSS".
#   * The case-number rule's pattern carries "sorusturma", "karar", "esas" and
#     "dosya", which are content words in criminal_allegation's own domain, so
#     deriving would trade this over-drop for a worse one.
# Only all-capital forms are listed. A capitalised label ("Kimlik", "No") on its
# own after a cut is rare, and reporting it is the safe direction. Keep this list
# to identifier labels -- it is the one thing allowed to suppress a segment.
IDENTIFIER_LABEL_ABBREVIATIONS = frozenset({"TCKN", "TC", "VKN", "MERSIS", "MERSİS", "IBAN", "UYAP"})


def _segment_is_reportable(segment: str, is_leading: bool) -> bool:
    """Whether a segment left over after the identifier cut earns its finding.

    The leading segment always starts on the rule's trigger keyword -- all three
    patterns are anchored on one -- so a single word there is the keyword itself
    and is kept. That is exactly what party_role keeps: the signal word without
    the clause, and it is what holds gold-set recall on labels like "Şüpheli
    Kemal Arslan hakkında nitelikli dolandırıcılık", whose leading "Şüpheli"
    segment is the part that still matches.

    Any other segment has lost the keyword, and is kept if it carries any word at
    all. The one exception is a segment whose ONLY word is an all-capital
    identifier label ("(TCKN:"): that is the punctuation between a name and the
    national id that was cut out around it, it says nothing on its own, and the
    identifier's own finding already covers it.

    Everything else is reported, including a single word. That word is often the
    whole sensitive point -- "kanser", "HIV", "Alzheimer" -- and an earlier
    version of this rule that asked non-leading segments for two words, and a
    later one that also dropped a lone Capitalised word as a proper noun, both
    silently lost it: the diagnosis stayed in the document with no CRITICAL
    finding, so no reviewer could approve it for redaction. Over-detection is
    the direction this system is built to fail in.

    Accepted cost, stated because the rule has it: a lone place-name tail such
    as "), Kadıköy 2" is now reported as a CRITICAL segment. It is a real but
    rare noise finding, and a reviewer dismisses it in one click. That is the
    cheap side of this trade -- a missing finding cannot be dismissed, because
    nobody is shown it.
    """
    words = _SEGMENT_WORD_RE.findall(segment)
    if is_leading:
        return len(words) >= 1
    if not words:
        return False
    return not (len(words) == 1 and words[0].upper() in IDENTIFIER_LABEL_ABBREVIATIONS)


def _context_segment_findings(
    finding: dict,
    text: str,
    cuts: list[tuple[int, int]],
    counters: Counter[str],
    placeholder_state: dict[tuple[str, str], str],
) -> list[dict]:
    """Split one context finding around the identifier spans cut out of it.

    Bounds are tightened onto the stripped text, so the relation _finding()
    guarantees -- sample == text[start:end].strip()[:180] -- holds with no
    slack. Every consumer treats the sample as the literal, contiguous
    document text the span points at -- it is the redaction target
    (redaction_targets_for_document in app.py), the key the PDF exporter maps to
    coordinate boxes, and the string export QA searches the produced file for --
    so a segment must never claim a span wider than the text it reports.
    """
    merged: list[list[int]] = []
    for cut_start, cut_end in sorted(cuts):
        if merged and cut_start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], cut_end)
        else:
            merged.append([cut_start, cut_end])

    spans: list[tuple[int, int]] = []
    cursor = finding["start"]
    for cut_start, cut_end in merged:
        spans.append((cursor, cut_start))
        cursor = cut_end
    spans.append((cursor, finding["end"]))

    prefix = _CONTEXT_PLACEHOLDER_PREFIXES[finding["category"]]
    segments = []
    for index, (start, end) in enumerate(spans):
        noise = _SEGMENT_LEADING_NOISE_RE.match(text, start, end)
        offset = noise.end() if noise else start
        value = text[offset:end].strip()
        if not value or not _segment_is_reportable(value, is_leading=index == 0):
            continue
        # The context finding being replaced already consumed a placeholder
        # number, so the segments start one above it and the preview shows a gap
        # ("[SENSITIVE_HEALTH_DATA_2]" with no _1). Nothing parses placeholder
        # numbers or assumes they are contiguous -- they only have to be stable
        # within one analysis, which _placeholder_for guarantees by keying on the
        # text. Renumbering would mean allocating placeholders after the cut for
        # every rule, which is a larger change for a cosmetic gain.
        placeholder = _placeholder_for(prefix, value, counters, placeholder_state)
        segments.append(
            _finding(
                finding["category"],
                value,
                finding["risk"],
                finding["recommended_action"],
                placeholder,
                offset,
                offset + len(value),
            )
        )
    return segments


def _cut_identifiers_from_context_findings(
    findings: list[dict],
    text: str,
    counters: Counter[str],
    placeholder_state: dict[tuple[str, str], str],
) -> list[dict]:
    """Keep another person's direct identifiers out of the context rules' samples.

    A finding's sample is stored, shown to reviewers and shipped to the exporter
    as a redaction target, so a health_data or privileged_or_confidential
    finding that sweeps up a name and a TCKN stores those identifiers a second
    time under a category that has nothing to do with them. The sample cannot be
    masked or elided -- it has to stay literal document text consistent with
    start/end -- so the span is cut instead: wherever a direct identifier sits
    inside a context span, the segments before and after it become the findings
    and the identifier's text belongs to the identifier's own finding only.

    The trailing segments are kept rather than dropped (subject to
    _segment_is_reportable) because they carry the sensitive clause. Dropping
    "hakkında nitelikli dolandırıcılık iddiası ile soruşturma yürütülmektedir"
    would leave the allegation with no CRITICAL finding covering it and
    therefore nothing a reviewer could approve for redaction -- the identifier
    finding beside it redacts only the identifier.

    An identifier span co-extensive with the context span is left alone: that is
    a competing reading of the same text rather than an identifier nested in a
    clause, and _dedupe_findings/build_redacted_preview already rank the two on
    risk. Same "strictly inside" rule as _enclosing_span_end.
    """
    identifier_spans = sorted(
        (item["start"], item["end"])
        for item in findings
        if item["category"] in DIRECT_IDENTIFIER_CATEGORIES
    )
    if not identifier_spans:
        return findings

    result: list[dict] = []
    for finding in findings:
        if finding["category"] not in CONTEXT_SWEEP_CATEGORIES:
            result.append(finding)
            continue
        cuts = []
        for id_start, id_end in identifier_spans:
            overlap_start = max(id_start, finding["start"])
            overlap_end = min(id_end, finding["end"])
            if overlap_start >= overlap_end:
                continue
            if overlap_start == finding["start"] and overlap_end == finding["end"]:
                continue
            cuts.append((overlap_start, overlap_end))
        if not cuts:
            result.append(finding)
            continue
        result.extend(_context_segment_findings(finding, text, cuts, counters, placeholder_state))
    return result


def _address_start(match: re.Match, text: str, triggers: list[tuple[int, int]]) -> int:
    """Exclude a preceding context trigger without case-narrowing street names.

    IGNORECASE is needed for "gül sok" as well as "GÜL SOK". It also lets
    the two-word prefix absorb "hasta" in "hasta Gül Sok". Cut that prefix
    after a context trigger only if another street-name word remains before
    the structure word. "Sağlık Caddesi" must keep Sağlık as its name.

    A multiword trigger can begin before the regex match ("ticari sır Gül
    Sok" matches from "sır"); use its complete span, not a prefix-token list.
    Ambiguous compound names containing a trigger can be split this way too,
    but the excluded trigger stays covered by its CRITICAL context finding.
    No address tail or context sweep is shortened here.

    The loop scans every trigger because the earliest one in the document is
    often NOT the applicable one -- in "hasta olan hasta<tab>Gul Sok" the address
    match starts at the SECOND "hasta", so the first ends before the span and
    must be skipped, not taken. At most one cut can actually apply, though:
    the prefix is two words at most, so once start has moved past a trigger the
    only remaining candidate is the second prefix word, whose remainder is
    whitespace and fails the guard above. Measured over 66,528 synthetic
    trigger/filler/structure-word analyses: 46,620 matches took one cut, 19,908
    took none, none took two. So the loop is a scan for the right trigger, not
    an accumulator -- do not "simplify" it to triggers[0].
    """
    start = match.start()
    prefix_end = match.end("address_prefix")
    for trigger_start, trigger_end in triggers:
        if trigger_start >= prefix_end:
            break
        if start < trigger_end < prefix_end:
            remainder = text[trigger_end:prefix_end]
            if remainder.strip():
                start = trigger_end + len(remainder) - len(remainder.lstrip())
    return start


def analyze_privacy(
    filename: str,
    text: str,
    extraction_warning: str | None = None,
    redaction_completed: bool = False,
    human_review_approved: bool = False,
    ocr_status: str = "not_required",
) -> dict:
    """Create a structured risk map and an anonymization-assisted preview."""
    findings = []
    placeholder_state: dict[tuple[str, str], str] = {}
    counters: Counter[str] = Counter()
    named_court_spans = _named_court_spans(text)
    context_triggers = [match.span() for match in _CONTEXT_TRIGGER_RE.finditer(text)]

    for rule in DETECTION_RULES:
        if rule is GENERIC_COURT_SUFFIX_RULE:
            matches = _generic_court_matches(text, named_court_spans)
        else:
            matches = re.finditer(rule.pattern, text, rule.flags)
        for match in matches:
            # The national-id rule matches an optional label ("T.C. Kimlik No:")
            # in front of the digits and reports only the digits as its sample,
            # so its SPAN has to be the digits as well. The sample is the
            # redaction target (redaction_targets_for_document in app.py), the
            # key the PDF exporter maps to coordinate boxes, and the needle
            # export QA searches the produced file for; build_redacted_preview
            # replaces the SPAN. A span wider than the sample therefore makes the
            # preview blank the whole labelled phrase while the export removes
            # only the digits, so the two disagree about what was removed. The
            # label "T.C. Kimlik No:" is not sensitive and the exporter already
            # leaves it, so narrowing the span is the side that makes them agree.
            if rule.category == "turkish_national_id" and match.lastindex:
                value, start, end = match.group(1).strip(), match.start(1), match.end(1)
            elif rule.category == "address":
                start, end = _address_start(match, text, context_triggers), match.end()
                value = text[start:end].strip()
            else:
                value, start, end = match.group(0).strip(), match.start(), match.end()
            if not value:
                continue
            if rule.category == "address" and len(value) < 6:
                continue
            if rule.category == "turkish_national_id" and not valid_turkish_national_id(value):
                continue
            if rule.category == "tax_number" and match.lastindex and not valid_turkish_tax_number(match.group(1)):
                continue
            placeholder = _placeholder_for(rule.placeholder_prefix, value, counters, placeholder_state)
            findings.append(_finding(rule.category, value, rule.risk, rule.action, placeholder, start, end))

    person_spans: list[tuple[str, int, int]] = []
    for person_re in (PERSON_CONTEXT_RE, ROLE_PERSON_RE):
        for match in person_re.finditer(text):
            person_spans.append((match.group(1).strip(), match.start(1), match.end(1)))

    # Bare names (no honorific or party-role prefix): parties in running text,
    # attendee/witness lists, signature blocks, labelled lines. The title/role
    # regexes above cannot see these, and they are the highest-value PII in a
    # legal document -- see legal_analyzer/turkish_names.py.
    person_spans.extend(detect_person_names(text))

    for value, start, end in person_spans:
        if not value:
            continue
        if re.search(r"\b(?:cad\.?|caddesi|sok\.?|sokak|mah\.?|mahallesi|bulvarı|bulvari|no|daire|kat)\b", value, re.IGNORECASE):
            continue
        # "Alacaklı Verdi Faktoring A.Ş." is a company, not a person. The role
        # rules above capture the words after the role word without looking at
        # what follows, so apply the legal-form guard to every person span.
        if COMPANY_SUFFIX_RE.match(text, end):
            continue
        placeholder = _placeholder_for("PERSON", value, counters, placeholder_state)
        findings.append(_finding("natural_person_name", value, "HIGH", "Replace with consistent pseudonym", placeholder, start, end))

    findings = _cut_identifiers_from_context_findings(findings, text, counters, placeholder_state)
    findings = _dedupe_findings(findings)
    redacted_preview = build_redacted_preview(text, findings)
    extraction_status = extraction_status_for(text, extraction_warning)
    residual_risk = residual_risk_assessment(findings, text, extraction_status)
    context = classify_document_context(filename, text)
    gate = external_llm_gate_policy(
        residual_risk,
        findings,
        extraction_status,
        redaction_completed=redaction_completed,
        human_review_approved=human_review_approved,
        ocr_status=ocr_status,
    )
    review_required = human_review_required(gate, residual_risk, findings, extraction_status, context)

    return {
        "terminology": TERMINOLOGY,
        "positioning": OUTPUT_POSITIONING,
        "extraction_status": extraction_status,
        "document_context": context,
        "risk_map": findings,
        "recommended_strategy": recommended_strategy(findings, context),
        "redacted_preview": redacted_preview,
        "residual_risk": residual_risk,
        "external_llm_gate": gate,
        "external_llm_readiness": gate["decision"],
        "redaction_status": redaction_status(findings, extraction_status, redaction_completed, ocr_status),
        "human_review_required": review_required,
        "release_controls": {
            "redaction_completed": redaction_completed,
            "human_review_approved": human_review_approved,
        },
        "llm_ingestion": llm_ingestion_recommendation(gate, residual_risk, findings, extraction_status, ocr_status),
        "human_review_checklist": human_review_checklist(context, findings, extraction_status, gate, ocr_status),
    }


def _finding(category: str, value: str, risk: str, action: str, placeholder: str, start: int, end: int) -> dict:
    return {
        "category": category,
        "sample": value[:180],
        "risk": risk,
        "recommended_action": action,
        "placeholder": placeholder,
        "start": start,
        "end": end,
        "fingerprint": hashlib.sha256(value.lower().encode("utf-8")).hexdigest()[:12],
    }


def _pseudonym_key(value: str) -> str:
    """Fold a matched value to the key its pseudonym is remembered under.

    str.lower() is not Turkish-aware, and the screen promises "consistent
    pseudonymization". Python lowercases the ASCII "I" of "DAVALI" to a dotted
    "i", while the same role spelled "Davalı" already carries the dotless "ı" --
    two different strings, so one party role was issued [PARTY_ROLE_2] in the
    heading and [PARTY_ROLE_3] four lines later. tr_fold is the repo's existing
    folding helper (legal_analyzer/turkish_names.py); it maps the dotted/dotless
    pairs explicitly before casefolding, and it is already what the given-name
    gazetteer matches on, so this reuses that scheme rather than adding another.

    Whitespace runs collapse too, so a name split by a DOCX run boundary or a
    wrapped line ("Şeyma  Karaduman") keeps the pseudonym it was first given.

    This is the KEY only. The finding's value, its span and the placeholder's
    visible text are untouched -- the folded form is never written anywhere.
    """
    return tr_fold(re.sub(r"\s+", " ", value)).strip()


def _placeholder_for(prefix: str, value: str, counters: Counter[str], state: dict[tuple[str, str], str]) -> str:
    key = (prefix, _pseudonym_key(value))
    if key not in state:
        counters[prefix] += 1
        state[key] = f"[{prefix}_{counters[prefix]}]"
    return state[key]


def valid_turkish_national_id(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11 or digits[0] == "0":
        return False
    nums = [int(char) for char in digits]
    tenth = ((sum(nums[0:9:2]) * 7) - sum(nums[1:8:2])) % 10
    eleventh = sum(nums[:10]) % 10
    return nums[9] == tenth and nums[10] == eleventh


def valid_turkish_tax_number(value: str) -> bool:
    """Validate a 10-digit VKN using the published check-digit algorithm."""
    digits = re.sub(r"\D", "", value)
    if len(digits) != 10:
        return False
    nums = [int(char) for char in digits]
    total = 0
    for index in range(9):
        tmp = (nums[index] + 9 - index) % 10
        if tmp == 0:
            continue
        part = (tmp * (2 ** (9 - index))) % 9
        if part == 0:
            part = 9
        total += part
    return (10 - (total % 10)) % 10 == nums[9]


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for item in sorted(findings, key=lambda f: (f["start"], -(f["end"] - f["start"]))):
        key = (item["category"], item["start"], item["end"], item["fingerprint"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


_MAX_RISK_ORDER = max(RISK_ORDER.values()) + 1


def build_redacted_preview(text: str, findings: list[dict], max_chars: int = 12_000) -> str:
    """Build a pseudonymized/redacted preview from disjoint finding regions.

    At a given start offset, prefer the highest-risk finding, then the widest
    span. Preferring width first let a wide low-risk span (e.g. the old,
    now-removed wide party_role span) outrank a CRITICAL identifier nested
    inside it, so the CRITICAL finding never reached the preview. An
    unrecognised risk value sorts as more severe than CRITICAL, consistent
    with the fail-closed handling of unresolved review statuses elsewhere.

    A finding that PARTIALLY overlaps one already chosen is CLIPPED, not
    dropped -- the same rule, for the same reason, as collect_replacements in
    legal_analyzer/docx_redactor.py. Real findings cross: an over-matched name
    span running into a label ("Leyla Kaya Vergi") and the tax_number that
    starts inside it ("Vergi Kimlik No: 0983930103") share four characters and
    neither contains the other. Dropping the loser wholesale rendered the part
    the winner does not cover as RAW document text, so the national/tax id was
    printed in full in a preview that is persisted in documents.privacy_profile
    and served as "PRIVACY-REVIEWED REDACTED EXPORT". The wide context spans
    used to hide this by covering the remainder; cutting identifiers out of
    those spans removed that accidental cover.

    The one deliberate difference from collect_replacements is the risk term in
    the sort key, which the DOCX path does not have: sorting on width alone, it
    always picks the widest finding at a tied start, while here the narrower,
    higher-risk one can win. That decides only WHICH finding is chosen. The
    loser is then clipped to its residual exactly like any other partial
    overlap -- a tied start is not a special case.

    Skipping the tied-start loser instead looked safe and was not. A CRITICAL
    context finding and a WIDER address can begin at the same offset, because
    a capitalised trigger word doubles as the start of a street name: in
    "Sağlık Caddesi No: 5 Daire: 12. Kat Kadıköy İstanbul adresinde oturuyor"
    health_data wins the tie at offset 0 and its sweep stops at the first
    period, so skipping the address printed ". Kat Kadıköy İstanbul adresinde
    oturuyor" -- house number, apartment and district -- in full. address is a
    direct identifier and this text is served as the redacted export.

    A finding that ends inside the chosen region contributes nothing, which is
    correct: every character of it is already being replaced.

    The max() that clips the start is deliberately kept although it cannot
    change this function's output: the emitted `cursor` is always the previous
    chosen finding's end, i.e. exactly the `last_end` that clipped the current
    one, so text[cursor:start] is already empty when start < cursor. A
    max->plain-start mutation is therefore an equivalent mutant (verified:
    identical previews on 10,018 texts, all fixtures included), the same status
    as the min->max choice in _enclosing_span_end. It stays because it makes
    `chosen` a correct list of disjoint regions for any future reader, instead
    of leaning on an inverted slice silently returning "".
    """
    chosen: list[tuple[int, dict]] = []
    last_end = 0
    for item in sorted(
        findings,
        key=lambda f: (f["start"], -RISK_ORDER.get(f["risk"], _MAX_RISK_ORDER), -(f["end"] - f["start"])),
    ):
        if item["end"] <= last_end:
            continue
        chosen.append((max(item["start"], last_end), item))
        last_end = item["end"]

    parts = []
    cursor = 0
    for start, item in chosen:
        parts.append(text[cursor:start])
        if item["risk"] == "CRITICAL" and "review" in item["recommended_action"].lower():
            parts.append(f"[{item['placeholder'].strip('[]')}_REDACTED]")
        else:
            parts.append(item["placeholder"])
        cursor = item["end"]
    parts.append(text[cursor:])
    return "".join(parts)[:max_chars]


def recommended_strategy(findings: list[dict], context: dict) -> str:
    if any(f["risk"] == "CRITICAL" for f in findings) or context["appears_privileged_or_confidential"]:
        return "Privacy-reviewed de-identification with targeted redaction, consistent pseudonymization, and mandatory human legal review."
    if any(f["risk"] == "HIGH" for f in findings):
        return "De-identification with consistent pseudonymization of direct identifiers and review of contextual identifiers."
    return "Light de-identification review; keep legal meaning while checking contextual re-identification risk."


def extraction_status_for(text: str, warning: str | None) -> dict:
    if warning and text:
        return {
            "status": "Partial",
            "warning": warning,
            "blocks_external_llm": True,
            "summary": "Text extraction produced a warning. Treat this document as not safe until OCR or manual review confirms coverage.",
        }
    if warning or not text.strip():
        return {
            "status": "Failed",
            "warning": warning or "No extracted text was available.",
            "blocks_external_llm": True,
            "summary": "No reliable text was extracted. Not extracted does not mean no sensitive data.",
        }
    return {
        "status": "Complete",
        "warning": None,
        "blocks_external_llm": False,
        "summary": "Text extraction completed for the automated pass.",
    }


def residual_risk_assessment(findings: list[dict], text: str, extraction_status: dict) -> dict:
    if extraction_status["status"] in {"Partial", "Failed"}:
        return {
            "level": "Unknown",
            "summary": f"{extraction_status['summary']} Legal anonymization remains context-dependent and requires review before LLM use.",
            "not_fully_anonymous": True,
            "extraction_gated": True,
        }

    max_risk = max((RISK_ORDER.get(f["risk"], 1) for f in findings), default=1)
    contextual_signals = sum(token in text.lower() for token in ["adres", "mahkemesi", "savcılığı", "soruşturma", "marka", "ek-", "tarih"])
    if max_risk >= 4 or contextual_signals >= 3:
        level = "High"
    elif max_risk == 3 or contextual_signals:
        level = "Medium"
    else:
        level = "Low"
    return {
        "level": level,
        "summary": "Legal anonymization is context-dependent; factual patterns, dates, authorities, case numbers, party roles, locations, and transaction context may still permit re-identification.",
        "not_fully_anonymous": True,
        "extraction_gated": False,
    }


def remaining_findings_residual_risk(remaining_findings: list[dict], extraction_status: dict) -> dict:
    """Residual risk over only the sensitive text that still remains in the output.

    `remaining_findings` is every finding whose review_status is NOT in
    RELEASE_CLEARED_REVIEW_STATUSES, i.e. (unresolved findings) ∪ (retained
    findings). A retained CRITICAL national id is resolved for review purposes
    but is still in the document, so it must keep the residual level above Low.
    A dismissed finding is excluded: the reviewer judged it a false positive, so
    its text remaining in the output is not residual risk at all — including it
    would put the release gate back out of reach for every document with a
    CRITICAL-risk false positive, which is the dead end this split exists to
    remove.

    The contextual-signal half of residual_risk_assessment() is measured over
    the remaining findings' samples rather than the full source text. At
    detection time those tokens ("adres", "mahkemesi", "tarih", …) are a proxy
    for "this document contains quasi-identifiers we may not have caught"; once
    every finding has been adjudicated, the finding set is the direct evidence
    and the bare label words that survive redaction are not identifiers. Scoring
    the source text here would also leave the gate permanently closed on any
    document containing the word "tarih", with no action a reviewer could take
    to satisfy it.
    """
    remaining_text = "\n".join(finding.get("sample") or "" for finding in remaining_findings)
    return residual_risk_assessment(remaining_findings, remaining_text, extraction_status)


def has_direct_identifiers(findings: list[dict]) -> bool:
    return any(f["category"] in DIRECT_IDENTIFIER_CATEGORIES for f in findings)


def external_llm_gate_policy(
    residual_risk: dict,
    findings: list[dict],
    extraction_status: dict,
    redaction_completed: bool = False,
    human_review_approved: bool = False,
    unresolved_critical_count: int | None = None,
    direct_identifiers_remaining: bool | None = None,
    ocr_status: str = "not_required",
) -> dict:
    critical_count = unresolved_critical_count
    if critical_count is None:
        critical_count = sum(1 for f in findings if f["risk"] == "CRITICAL")
    direct_identifiers_detected = direct_identifiers_remaining
    if direct_identifiers_detected is None:
        direct_identifiers_detected = has_direct_identifiers(findings)
    ocr_state = ocr_status or "not_required"
    # The one place the seven conditions are stated. `failed_conditions` and
    # `policy` are both derived from it, and the studio renders the whole list
    # from `conditions` rather than rebuilding a shorter approximation of it in
    # the browser -- which is what put five browser-computed green ticks
    # directly above this gate's red "Blocked". Order is load-bearing:
    # `failed_conditions` preserves the sequence callers and tests already read.
    conditions = [
        {
            "id": "extraction_complete",
            "label": "Extraction complete",
            "policy": "Extraction status = Complete",
            "message": "Extraction status must be Complete.",
            "passed": extraction_status["status"] == "Complete",
            "detail": str(extraction_status.get("status") or "Unknown"),
        },
        {
            "id": "ocr_resolved",
            "label": "OCR accepted or not required",
            "policy": "OCR accepted or not required",
            "message": "OCR output must be accepted or not required.",
            "passed": not ocr_blocks_release(ocr_status),
            "detail": ocr_state,
        },
        {
            "id": "residual_risk_low",
            "label": "Residual risk after review is Low",
            "policy": "Residual risk = Low",
            "message": "Residual risk must be Low.",
            "passed": residual_risk["level"] == "Low",
            "detail": f"currently {residual_risk.get('level') or 'Unknown'}",
        },
        {
            "id": "no_critical_findings",
            "label": "No undecided critical findings",
            "policy": "Critical findings = 0",
            "message": "Critical findings must be zero.",
            "passed": not critical_count,
            "detail": "clear" if not critical_count else f"{critical_count} outstanding",
        },
        {
            "id": "no_direct_identifiers",
            "label": "No direct identifiers remain",
            "policy": "No direct identifiers remain",
            "message": "No direct identifiers may remain in detected findings.",
            "passed": not direct_identifiers_detected,
            "detail": "none remain" if not direct_identifiers_detected else "at least one remains",
        },
        {
            "id": "redaction_completed",
            "label": "Redaction pass completed",
            "policy": "Redaction pass completed",
            "message": "Redaction pass must be completed.",
            "passed": bool(redaction_completed),
            "detail": "done" if redaction_completed else "not marked complete",
        },
        # Deliberately unconditional. There was an `or auto_mode_enabled` arm here
        # that substituted a stored flag for a person's approval; it had no UI, no
        # indicator and no audit surface, and it could only ever let a document out
        # that nobody had approved. It was removed rather than made visible. An
        # automated or batch mode, if it is ever wanted, is a feature to design with
        # its own visible switch and audit trail -- not an arm on this condition.
        {
            "id": "human_review_approved",
            "label": "Human review approved",
            "policy": "Human review approved",
            "message": "Human review approval is required.",
            "passed": bool(human_review_approved),
            "detail": "approved" if human_review_approved else "not approved",
        },
    ]
    failed_conditions = [condition["message"] for condition in conditions if not condition["passed"]]

    allowed = not failed_conditions
    if allowed:
        decision = EXTERNAL_LLM_ALLOWED
    elif extraction_status["blocks_external_llm"] or ocr_blocks_release(ocr_status):
        decision = "Blocked until OCR/manual review"
    else:
        decision = "Blocked until redaction is completed and reviewed"

    return {
        "allowed": allowed,
        "decision": decision,
        "failed_conditions": failed_conditions,
        "critical_count": critical_count,
        "direct_identifiers_detected": direct_identifiers_detected,
        "conditions": conditions,
        "policy": [condition["policy"] for condition in conditions],
    }


def ocr_blocks_release(ocr_status: str | None) -> bool:
    return (ocr_status or "not_required") not in {"not_required", "accepted"}


def redaction_status(
    findings: list[dict],
    extraction_status: dict,
    redaction_completed: bool = False,
    ocr_status: str = "not_required",
) -> str:
    if extraction_status["blocks_external_llm"] or ocr_blocks_release(ocr_status):
        return "Not started - extraction review required"
    if redaction_completed:
        return "Redaction pass completed - approval still required before release"
    if findings:
        return "Detected findings only - not redacted successfully"
    return "No automated findings - not a guarantee of de-identification"


def human_review_required(gate: dict, residual_risk: dict, findings: list[dict], extraction_status: dict, context: dict) -> bool:
    return bool(
        not gate["allowed"]
        or extraction_status["blocks_external_llm"]
        or residual_risk["level"] in {"Unknown", "High", "Medium"}
        or any(f["risk"] in {"HIGH", "CRITICAL"} for f in findings)
        or context["appears_privileged_or_confidential"]
    )


def llm_ingestion_recommendation(
    gate: dict,
    residual_risk: dict,
    findings: list[dict],
    extraction_status: dict,
    ocr_status: str = "not_required",
) -> dict:
    level = residual_risk["level"]
    has_critical = any(f["risk"] == "CRITICAL" for f in findings)
    external = EXTERNAL_LLM_ALLOWED if gate["allowed"] else EXTERNAL_LLM_BLOCKED
    internal = "High - human review required" if level in {"Unknown", "High"} or has_critical else "Medium - review recommended"
    return {
        "external_hosted_llm_api": external,
        "internal_private_llm": internal,
        "embedding_model": external,
        "vector_database": external,
        "evaluation_dataset": EXTERNAL_LLM_BLOCKED
        if has_critical or extraction_status["blocks_external_llm"] or ocr_blocks_release(ocr_status)
        else "Needs review before use",
        "fine_tuning_dataset": EXTERNAL_LLM_BLOCKED,
    }


def refresh_release_state(
    privacy_profile: dict,
    redaction_completed: bool = False,
    human_review_approved: bool = False,
    unresolved_critical_count: int | None = None,
    direct_identifiers_remaining: bool | None = None,
    remaining_findings: list[dict] | None = None,
    ocr_status: str = "not_required",
) -> dict:
    """Re-evaluate release controls without rerunning detection.

    `remaining_findings` carries the review outcome the stored profile cannot
    know: the findings whose sensitive text is still in the document (see
    remaining_findings_residual_risk). When it is supplied, residual risk is
    recomputed from it — reusing the stored, detection-time value instead froze
    residual risk at its pre-review level and made the gate's "Residual risk
    must be Low" condition unsatisfiable for every document that had any
    CRITICAL finding. An empty list is a valid answer ("nothing remains"); only
    None means the caller could not supply the data, and then the stored value
    is kept rather than assumed Low.
    """
    findings = privacy_profile.get("risk_map", [])
    extraction_status = privacy_profile.get("extraction_status", extraction_status_for("", "Missing extraction status."))
    residual_risk = privacy_profile.get(
        "residual_risk",
        {
            "level": "Unknown",
            "summary": "Residual risk was not available.",
            "not_fully_anonymous": True,
            "extraction_gated": True,
        },
    )
    if remaining_findings is not None:
        residual_risk = remaining_findings_residual_risk(remaining_findings, extraction_status)
    context = privacy_profile.get("document_context", {})
    gate = external_llm_gate_policy(
        residual_risk,
        findings,
        extraction_status,
        redaction_completed=redaction_completed,
        human_review_approved=human_review_approved,
        unresolved_critical_count=unresolved_critical_count,
        direct_identifiers_remaining=direct_identifiers_remaining,
        ocr_status=ocr_status,
    )

    privacy_profile["external_llm_gate"] = gate
    privacy_profile["external_llm_readiness"] = gate["decision"]
    # The level the gate was actually decided against, recorded separately so
    # that "residual_risk" stays the detection-time measurement the accuracy
    # audit and the risk badges are calibrated on.
    privacy_profile["post_review_residual_risk"] = residual_risk
    privacy_profile["redaction_status"] = redaction_status(findings, extraction_status, redaction_completed, ocr_status)
    privacy_profile["human_review_required"] = human_review_required(gate, residual_risk, findings, extraction_status, context)
    privacy_profile["release_controls"] = {
        "redaction_completed": redaction_completed,
        "human_review_approved": human_review_approved,
    }
    privacy_profile["llm_ingestion"] = llm_ingestion_recommendation(gate, residual_risk, findings, extraction_status, ocr_status)
    privacy_profile["human_review_checklist"] = human_review_checklist(context, findings, extraction_status, gate, ocr_status)
    return privacy_profile


def human_review_checklist(
    context: dict,
    findings: list[dict],
    extraction_status: dict,
    gate: dict,
    ocr_status: str = "not_required",
) -> list[str]:
    checklist = [
        "Confirm that the output is described as de-identified, redacted, pseudonymized, privacy-reviewed, or anonymization-assisted rather than fully anonymous.",
        "Confirm extraction status before relying on the scanner: extraction warning or failure means the document is blocked for external LLM use.",
        "Separate detected findings from redaction success; this automated pass does not prove the document has been safely redacted.",
        "Do not allow external LLM use until every external LLM gate condition is satisfied.",
        "Review whether dates, authorities, case numbers, party roles, locations, and factual patterns still identify a person, client, transaction, or matter.",
        "Confirm whether a mapping table exists and restrict access to authorized reviewers only.",
    ]
    for condition in gate["failed_conditions"]:
        checklist.append(f"Resolve gate condition: {condition}")
    if extraction_status["blocks_external_llm"]:
        checklist.append("Run OCR or manual review for unextracted/partially extracted content, including scanned pages, signatures, stamps, ID cards, barcodes, handwritten notes, and exhibits.")
    if ocr_blocks_release(ocr_status):
        checklist.append("Review and accept OCR output before it can affect findings, redaction completion, or external LLM readiness.")
    if context["appears_privileged_or_confidential"]:
        checklist.append("Review attorney-client privilege, professional secrecy, and client confidentiality separately from personal data risk.")
    if any(f["risk"] == "CRITICAL" for f in findings):
        checklist.append("Manually approve all critical-risk transformations before external LLM use.")
    return checklist
