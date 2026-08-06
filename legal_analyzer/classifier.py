"""Document classification helpers."""

from __future__ import annotations

import re
from pathlib import Path

from .taxonomy import CLASSIFICATION_RULES, IGNORE_PATTERNS, SUPPORTED_EXTENSIONS


def should_skip(filename: str) -> bool:
    return any(pattern in filename for pattern in IGNORE_PATTERNS)


def supported_file(path: str | Path) -> bool:
    return Path(path).suffix.lower() in SUPPORTED_EXTENSIONS


def detect_language(filename: str) -> str:
    eng_keywords = ["Agreement", "Policy", "Terms", "Notice", "Certificate", "Consent", "Resolution", "Opinion", "Report", "Inc.", "Co.", "ENG"]
    tr_keywords = ["Sozlesme", "Sözleşme", "Yonetmelik", "Yönetmelik", "Aydinlatma", "Aydınlatma", "Tutanak", "Karar", "Rapor", "Devir", "Dilekce", "Dilekçe"]
    has_eng = any(kw.lower() in filename.lower() for kw in eng_keywords)
    has_tr = any(kw.lower() in filename.lower() for kw in tr_keywords)
    if has_eng and has_tr:
        return "TR/EN"
    if has_eng:
        return "EN"
    return "TR"


def detect_version(filename: str) -> str | None:
    patterns = [r"[vV]\.?\s*(\d+\.?\d*)", r"VL\s*(\d+\.?\d*)", r"_v(\d+)", r"version\s*(\d+\.?\d*)"]
    for pattern in patterns:
        match = re.search(pattern, filename, re.IGNORECASE)
        if match:
            return f"v{match.group(1)}"
    return None


def detect_date(filename: str) -> str | None:
    patterns = [
        r"(\d{4})(\d{2})(\d{2})",
        r"(\d{4})[._-](\d{2})[._-](\d{2})",
        r"(\d{2})[._-](\d{2})[._-](\d{4})",
        r"(\d{2})(\d{2})(\d{4})",
    ]
    for index, pattern in enumerate(patterns):
        match = re.search(pattern, filename)
        if not match:
            continue
        groups = match.groups()
        if index <= 1:
            year, month, day = groups
        else:
            day, month, year = groups
        try:
            y, m, d = int(year), int(month), int(day)
        except ValueError:
            continue
        if 2020 <= y <= 2035 and 1 <= m <= 12 and 1 <= d <= 31:
            return f"{y:04d}-{m:02d}-{d:02d}"
    return None


def generate_title(filename: str) -> str:
    title = Path(filename).stem
    title = title.replace("_", " ")
    return re.sub(r"\s+", " ", title).strip()


def classify_document(filename: str, text: str = "") -> dict:
    haystack = f"{filename}\n{text[:4000]}".lower()
    for keywords, category, subcategory, tags in CLASSIFICATION_RULES:
        if any(keyword.lower() in haystack for keyword in keywords):
            return {"category": category, "subcategory": subcategory, "tags": tags}
    return {"category": "other", "subcategory": "miscellaneous", "tags": ["sınıflandırılmamış"]}

