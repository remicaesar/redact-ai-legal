"""Cautious privacy and confidentiality risk mapping for legal documents."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass

from .taxonomy import OUTPUT_POSITIONING, TERMINOLOGY

from legal_analyzer.turkish_names import COMPANY_SUFFIX_RE, detect_person_names

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
FINDING_REVIEW_STATUSES = {"pending", "approved", "rejected", "added_by_reviewer"}


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
    DetectionRule("address", r"(?:[A-ZÇĞİÖŞÜ][a-zA-Z0-9çğıöşüÇĞİÖŞÜ]*\s+){0,2}\b(?:mah\.?|mahallesi|cad\.?|caddesi|sok\.?|sokak|sokağı|sokagi|bulvarı|bulvari|apartmanı|apartmani|apt\.?|[İi]lçesi|ilcesi|köyü|koyu|beşiktaş|besiktas|ümraniye|umraniye|[İi]stanbul)\b(?:[^.\n]|(?<=\d)\.){0,140}", "HIGH", "Generalize or replace with consistent pseudonym", "ADDRESS"),
    DetectionRule("date", r"\b(?:\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}[./-]\d{1,2}[./-]\d{1,2})\b", "MEDIUM", "Generalize unless legally necessary", "DATE"),
    DetectionRule("money_amount", r"\b(?:USD|EUR|TRY|TL|₺|\$|€)\s?\d[\d.,]*|\b\d[\d.,]*\s?(?:USD|EUR|TRY|TL|₺|dolar|euro)\b", "MEDIUM", "Generalize or keep if legally necessary", "AMOUNT"),
    DetectionRule("health_data", r"\b(?:sağlık|saglik|hasta|hastane|cerrahi|tedavi|teşhis|teshis|reçete|recete|medical|health|patient)\b[^.\n]{0,120}", "CRITICAL", "Flag for human legal review", "SENSITIVE_HEALTH_DATA"),
    DetectionRule("criminal_allegation", r"\b(?:suç|suc|şüpheli|supheli|sanık|sanik|cezai|kamu davası|arama|el koyma|soruşturma|sorusturma)\b[^.\n]{0,160}", "CRITICAL", "Flag for human legal review", "CRIMINAL_ALLEGATION"),
    DetectionRule("privileged_or_confidential", r"\b(?:müvekkil|muvekkil|vekil|av\.|avukat|attorney-client|privileged|gizli|confidential|ticari sır|trade secret)\b[^.\n]{0,160}", "CRITICAL", "Flag for human legal review", "PRIVILEGED_CONTENT"),
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
    DetectionRule("court_or_authority", r"\b(?:UYAP|cumhuriyet başsavcılığı|cumhuriyet bassavciligi|mahkemesi|savcılığı|savciligi|hakimliği|hakimligi|hâkimliği|noterliği|noterligi|valiliği|valiligi|kaymakamlığı|kaymakamligi|[İi]cra müdürlüğü|icra mudurlugu|ticaret sicili? müdürlüğü|ticaret sicili? mudurlugu|bölge adliye|bolge adliye|türk patent|turkpatent|kurumu)\b[^.\n]{0,120}", "HIGH", "Replace with consistent pseudonym or generalize", "COURT_AUTHORITY"),
    DetectionRule("court_or_authority", r"\b\d{1,2}\.\s*(?:Asliye|Ağır\s+Ceza|Agir\s+Ceza|Sulh|İdare|Idare|Ticaret|İş|Is|Aile|İcra|Icra|Hukuk|Ceza|Vergi)(?:\s+(?:Hukuk|Ceza|Ticaret|İş|Is|Aile|Mahkemesi|Dairesi|Müdürlüğü|Mudurlugu|Hakimliği|Hakimligi)){1,3}\b", "HIGH", "Replace with consistent pseudonym or generalize", "COURT_AUTHORITY"),
    DetectionRule("court_or_authority", r"\b\d{1,2}\.\s*Noterli[ğg]i\b", "HIGH", "Replace with consistent pseudonym or generalize", "COURT_AUTHORITY"),
    DetectionRule("court_or_authority", r"\b(?:Yargıtay|Yargitay|Danıştay|Danistay|Anayasa\s+Mahkemesi|Bölge\s+Adliye\s+Mahkemesi|Bolge\s+Adliye\s+Mahkemesi|Bölge\s+İdare\s+Mahkemesi|Bolge\s+Idare\s+Mahkemesi)\b[^.\n]{0,60}", "HIGH", "Replace with consistent pseudonym or generalize", "COURT_AUTHORITY"),
    DetectionRule("company_name", r"\b[A-ZÇĞİÖŞÜ][A-Za-zÇĞİÖŞÜçğıöşü0-9&.,'\- ]{2,90}?\s(?:ANONİM ŞİRKETİ|ANONIM SIRKETI|LİMİTED ŞİRKETİ|LIMITED SIRKETI|LTD\.?\s*ŞT[İI]\.?|LIMITED|LTD\.?|PLC|INC\.?|A\.Ş\.|AŞ|LLC)(?!\w)", "HIGH", "Replace with consistent pseudonym", "COMPANY", flags=re.UNICODE),
]

PERSON_CONTEXT_RE = re.compile(
    r"\b(?:Av\s?\.|Av\b|Avukat|Dr\s?\.|Dr\b|Sayın|Sn\.?|Mr\.?|Ms\.?)\s+([A-ZÇĞİÖŞÜ][A-Za-zÇĞİÖŞÜçğıöşü'\-]+(?:\s+[A-ZÇĞİÖŞÜ][A-Za-zÇĞİÖŞÜçğıöşü'\-]+){1,3})"
)

ROLE_PERSON_RE = re.compile(
    r"\b(?i:davacı|davaci|davalı|davali|müşteki|musteki|şüpheli|supheli|sanık|sanik|müvekkil|muvekkil"
    r"|borçlu|borclu|alacaklı|alacakli|kiracı|kiraci|kiraya\s+veren|tanık|tanik|mağdur|magdur"
    r"|katılan|katilan|müdahil|mudahil|[İi]şçi|isci|[İi]şveren|isveren|hasta|mirasçı|mirasci|vasi)"
    r"\s+(?:[a-zçğıöşü]+\s+)?"
    r"([A-ZÇĞİÖŞÜ][a-zçğıöşü'\-]+(?:\s+[A-ZÇĞİÖŞÜ][a-zA-ZçğıöşüÇĞİÖŞÜ'\-]+){1,2})"
)


def classify_document_context(filename: str, text: str) -> dict:
    sample = f"{filename}\n{text[:5000]}".lower()
    return {
        "appears_to_contain_personal_data": any(token in sample for token in ["av.", "şüpheli", "supheli", "t.c", "adres", "email", "telefon", "müvekkil"]),
        "appears_to_contain_sensitive_data": any(token in sample for token in ["sağlık", "saglik", "cezai", "suç", "suc", "şüpheli", "supheli", "soruşturma"]),
        "appears_privileged_or_confidential": any(token in sample for token in ["müvekkil", "muvekkil", "vekil", "av.", "gizli", "confidential", "ticari sır"]),
        "contains_contextual_reidentification_risk": any(token in sample for token in ["soruşturma no", "esas no", "mahkemesi", "savcılığı", "adres", "marka", "ek-"]),
    }


def analyze_privacy(
    filename: str,
    text: str,
    extraction_warning: str | None = None,
    redaction_completed: bool = False,
    human_review_approved: bool = False,
    auto_mode_enabled: bool = False,
    ocr_status: str = "not_required",
) -> dict:
    """Create a structured risk map and an anonymization-assisted preview."""
    findings = []
    placeholder_state: dict[tuple[str, str], str] = {}
    counters: Counter[str] = Counter()

    for rule in DETECTION_RULES:
        for match in re.finditer(rule.pattern, text, rule.flags):
            value = match.group(1).strip() if rule.category == "turkish_national_id" and match.lastindex else match.group(0).strip()
            if not value:
                continue
            if rule.category == "address" and len(value) < 6:
                continue
            if rule.category == "turkish_national_id" and not valid_turkish_national_id(value):
                continue
            if rule.category == "tax_number" and match.lastindex and not valid_turkish_tax_number(match.group(1)):
                continue
            placeholder = _placeholder_for(rule.placeholder_prefix, value, counters, placeholder_state)
            findings.append(_finding(rule.category, value, rule.risk, rule.action, placeholder, match.start(), match.end()))

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
        auto_mode_enabled=auto_mode_enabled,
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
            "auto_mode_enabled": auto_mode_enabled,
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


def _placeholder_for(prefix: str, value: str, counters: Counter[str], state: dict[tuple[str, str], str]) -> str:
    key = (prefix, value.lower())
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
    """Build a pseudonymized/redacted preview from non-overlapping findings.

    At a given start offset, prefer the highest-risk finding, then the widest
    span. Preferring width first let a wide low-risk span (e.g. the old,
    now-removed wide party_role span) outrank a CRITICAL identifier nested
    inside it, so the CRITICAL finding never reached the preview. An
    unrecognised risk value sorts as more severe than CRITICAL, consistent
    with the fail-closed handling of unresolved review statuses elsewhere.
    """
    chosen = []
    last_end = -1
    for item in sorted(
        findings,
        key=lambda f: (f["start"], -RISK_ORDER.get(f["risk"], _MAX_RISK_ORDER), -(f["end"] - f["start"])),
    ):
        if item["start"] < last_end:
            continue
        chosen.append(item)
        last_end = item["end"]

    parts = []
    cursor = 0
    for item in chosen:
        parts.append(text[cursor:item["start"]])
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


def has_direct_identifiers(findings: list[dict]) -> bool:
    return any(f["category"] in DIRECT_IDENTIFIER_CATEGORIES for f in findings)


def external_llm_gate_policy(
    residual_risk: dict,
    findings: list[dict],
    extraction_status: dict,
    redaction_completed: bool = False,
    human_review_approved: bool = False,
    auto_mode_enabled: bool = False,
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
    failed_conditions = []

    if extraction_status["status"] != "Complete":
        failed_conditions.append("Extraction status must be Complete.")
    if ocr_blocks_release(ocr_status):
        failed_conditions.append("OCR output must be accepted or not required.")
    if residual_risk["level"] != "Low":
        failed_conditions.append("Residual risk must be Low.")
    if critical_count:
        failed_conditions.append("Critical findings must be zero.")
    if direct_identifiers_detected:
        failed_conditions.append("No direct identifiers may remain in detected findings.")
    if not redaction_completed:
        failed_conditions.append("Redaction pass must be completed.")
    if not (human_review_approved or auto_mode_enabled):
        failed_conditions.append("Human review approval is required unless explicit auto-mode is enabled.")

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
        "policy": [
            "Extraction status = Complete",
            "Residual risk = Low",
            "Critical findings = 0",
            "No direct identifiers remain",
            "Redaction pass completed",
            "Human review approved unless explicit auto-mode is enabled",
        ],
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
    auto_mode_enabled: bool = False,
    unresolved_critical_count: int | None = None,
    direct_identifiers_remaining: bool | None = None,
    ocr_status: str = "not_required",
) -> dict:
    """Re-evaluate release controls without rerunning detection."""
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
    context = privacy_profile.get("document_context", {})
    gate = external_llm_gate_policy(
        residual_risk,
        findings,
        extraction_status,
        redaction_completed=redaction_completed,
        human_review_approved=human_review_approved,
        auto_mode_enabled=auto_mode_enabled,
        unresolved_critical_count=unresolved_critical_count,
        direct_identifiers_remaining=direct_identifiers_remaining,
        ocr_status=ocr_status,
    )

    privacy_profile["external_llm_gate"] = gate
    privacy_profile["external_llm_readiness"] = gate["decision"]
    privacy_profile["redaction_status"] = redaction_status(findings, extraction_status, redaction_completed, ocr_status)
    privacy_profile["human_review_required"] = human_review_required(gate, residual_risk, findings, extraction_status, context)
    privacy_profile["release_controls"] = {
        "redaction_completed": redaction_completed,
        "human_review_approved": human_review_approved,
        "auto_mode_enabled": auto_mode_enabled,
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
