"""Standalone Turkish person-name detection.

The title/role rules in `privacy.py` (`PERSON_CONTEXT_RE`, `ROLE_PERSON_RE`) only
fire when a name is introduced by an honorific ("Av. X") or a party role
("davacı X"). Real legal documents are full of bare names: parties in running
text ("A ile B arasında"), attendee and witness lists, signature blocks, and
labelled lines ("Hakim: X"). Those names are the highest-value PII in the
document and were previously invisible to the scanner.

Detection here is deliberately gazetteer-anchored rather than "any two
capitalised words". Turkish given names are a small, distinctive vocabulary, so
requiring a known given name as the first token keeps precision high without an
ML dependency. Structural cues (labelled lines, list headers, signature blocks,
"X ile Y arasında") add a second path so that names *outside* the gazetteer are
still caught when the surrounding document structure makes them unambiguous.

Recall bias is intentional: a missed name leaks a real person into an LLM
prompt, while an over-flagged one costs a reviewer one click.
"""

from __future__ import annotations

import re

# --- Turkish case folding -------------------------------------------------
# str.casefold() maps "I" -> "i", but Turkish "I" lowercases to "ı" and "İ"
# lowercases to "i". Fold the dotted/dotless pairs explicitly first, otherwise
# an all-caps "IŞIL" never matches the gazetteer entry "ışıl".


def tr_fold(value: str) -> str:
    return value.replace("İ", "i").replace("I", "ı").casefold()


# --- Given-name gazetteer -------------------------------------------------
# Common Turkish given names. This is the precision anchor: a candidate is only
# accepted on the gazetteer path when its FIRST token appears here.
GIVEN_NAMES: frozenset[str] = frozenset(
    tr_fold(name)
    for name in """
    Ahmet Mehmet Mustafa Ali Hüseyin Hasan İbrahim İsmail Osman Yusuf Murat Ömer
    Ramazan Halil Süleyman Abdullah Fatih Mahmut Kemal Recep Bekir Cemal Şaban
    Erhan Ercan Serkan Selçuk Sinan Levent Tolga Volkan Burak Emre Onur Kaan
    Kerem Berk Barış Umut Uğur Tuncay Bülent Cengiz Ferhat Gökhan Hakan Kadir
    İlker İlhan Orhan Oktay Okan Özkan Erdem Erdal Ergün Ersin Engin Enis Cem
    Can Deniz Ege Efe Arda Baran Bora Çağrı Doruk Eren Furkan Görkem Kağan
    Mert Metin Necati Nihat Nuri Oğuz Polat Sercan Serhat Tarık Taner Tayfun
    Turgut Vedat Yavuz Yalçın Zafer Ziya Adem Ayhan Aykut Bahadır Baki Celal
    Davut Dursun Emrah Faruk Ferit Galip Hamza Haydar Hikmet İhsan İlyas Kenan
    Muhammed Muharrem Naci Nazım Nejat Nurettin Rasim Rıza Sabri Sadık Salih
    Sami Selim Semih Şükrü Talat Tamer Tevfik Ufuk Vahit Yakup Yaşar Yener
    Fatma Ayşe Emine Hatice Zeynep Elif Meryem Şerife Zehra Sultan Hanife
    Merve Havva Aslı Aslıhan Ayla Aynur Ayten Aysel Aysun Bahar Banu Başak
    Belgin Berna Betül Bilge Burcu Buse Canan Ceren Ceyda Çiğdem Damla Derya
    Dilek Dilan Duygu Ebru Eda Ela Emel Esra Esin Eylül Feride Figen Filiz
    Funda Gamze Gizem Gonca Gül Gülay Gülcan Gülsüm Gülşen Günay Handan Hande
    Hülya İnci İpek İrem Jale Kader Kevser Kübra Lale Leyla Melek Melis Melike
    Meltem Mine Müge Nalan Naz Nazlı Neslihan Nesrin Nihal Nilay Nilgün Nilüfer
    Nur Nurcan Nuray Özge Özlem Pelin Pınar Rabia Rana Reyhan Saliha Seda Sedef
    Selin Selma Sema Semra Sena Serap Serpil Sevgi Sevda Sevil Sevim Sibel
    Simge Songül Şule Şeyma Tuba Tuğba Tülay Türkan Ülkü Yasemin Yeliz Yeşim
    Yıldız Zeliha Zerrin Zübeyde Aleyna İlayda Ecrin Azra Eslem Beren Defne
    Duru Zümra Öykü Asya Alara Bade Berrak Cansu Çisem Damlanur Ezgi Gökçe
    """.split()
)

# --- Non-person guards ----------------------------------------------------
# Tokens that mark a capitalised sequence as an institution, place, document
# type, or date rather than a person. If any token in a candidate folds to one
# of these, the candidate is rejected.
NON_PERSON_TOKENS: frozenset[str] = frozenset(
    tr_fold(token)
    for token in """
    Mahkemesi Mahkeme Mahkemeleri Dairesi Daire Müdürlüğü Mudurlugu Müdürlüğüne
    Savcılığı Savciligi Başsavcılığı Bassavcligi Hakimliği Hakimligi Noterliği
    Noterligi Valiliği Valiligi Kaymakamlığı Kaymakamligi Başkanlığı Baskanligi
    Bakanlığı Bakanligi Kurumu Kurulu Komisyonu Müdürü Mudur Genel Şube Şubesi
    Bölge Bolge Adliye Adalet İcra Icra Ticaret Sicili Sicil Odası Odasi Birliği
    Birligi Barosu Baro Üniversitesi Universitesi Fakültesi Fakultesi Hastanesi
    Hastane Belediyesi Belediye Muhtarlığı Muhtarligi Kaymakamlık Defterdarlığı
    Anonim Limited Şirketi Sirketi Şirket Sirket Holding Ltd Şti Sti Inc Plc LLC
    Sözleşmesi Sozlesmesi Sözleşme Anlaşması Anlasmasi Anlaşma Protokolü
    Protokolu Kanunu Kanun Yönetmeliği Yonetmeligi Tebliği Tebligi Kararı
    Karari Karar Tutanağı Tutanagi Tutanak Raporu Raporlari Rapor Dilekçesi
    Dilekcesi Dilekçe Vekaletnamesi Vekaletname Beyannamesi Beyanname Layihası
    Cadde Caddesi Sokak Sokağı Sokagi Mahalle Mahallesi Bulvarı Bulvari
    Apartmanı Apartmani Sitesi Site Blok Daire Kat No Numara İlçesi Ilcesi
    Köyü Koyu Meydanı Meydani Plaza İş Is Merkezi Merkez
    Ocak Şubat Subat Mart Nisan Mayıs Mayis Haziran Temmuz Ağustos Agustos
    Eylül Eylul Ekim Kasım Kasim Aralık Aralik
    Pazartesi Salı Sali Çarşamba Carsamba Perşembe Persembe Cuma Cumartesi Pazar
    Türkiye Turkiye Cumhuriyeti Cumhuriyet Devleti Bakanlik Müdürlük
    Esas Dosya Soruşturma Sorusturma Kovuşturma Kovusturma Talimat Yevmiye
    Madde Fıkra Fikra Bent Ek Sayfa Toplam Tarih Konu Adres Telefon
    Davacı Davaci Davalı Davali Müşteki Musteki Şüpheli Supheli Sanık Sanik
    Müvekkil Muvekkil Borçlu Borclu Alacaklı Alacakli Kiracı Kiraci Tanık Tanik
    Mağdur Magdur Katılan Katilan Müdahil Mudahil İşçi Isci İşveren Isveren
    Hasta Mirasçı Mirasci Vasi Vekil Taraf Taraflar Sayın Sayin Avukat
    Bugün Bugun Dün Dun Yarın Yarin Ayrıca Ayrica Ancak Nitekim Böylece Boylece
    """.split()
)

# Legal-form suffixes; a candidate immediately followed by one of these is a
# company name and belongs to the `company_name` rule instead.
COMPANY_SUFFIX_RE = re.compile(
    r"\s*(?:ANON[İI]M\s+Ş[İI]RKET[İI]|L[İI]M[İI]TED\s+Ş[İI]RKET[İI]|LTD\.?\s*ŞT[İI]\.?"
    r"|A\.\s*Ş\.?|AŞ\b|LTD\b|LIMITED\b|INC\b|PLC\b|LLC\b|HOLD[İI]NG\b)",
    re.IGNORECASE,
)

# A single name token: capitalised or all-caps, Turkish letters, 2+ chars.
_TOKEN = r"[A-ZÇĞİÖŞÜ][A-Za-zÇĞİÖŞÜçğıöşü'’\-]+"

# Separator *within* a candidate: spaces/tabs only, never a line break. A person
# name does not wrap across lines, and allowing \s+ here let a candidate swallow
# the next line's label ("Selçuk Aydın\nKatip"), which then failed to align back
# onto the source text and silently dropped the name.
_SEP = r"[ \t]+"

# 2-4 token candidate sequence.
CANDIDATE_RE = re.compile(rf"{_TOKEN}(?:{_SEP}{_TOKEN}){{1,3}}")

# Single token, used to walk a name forward from a known anchor.
_TOKEN_RE = re.compile(_TOKEN)
_SEP_RE = re.compile(_SEP)

# Inside a list/signature window a name starts on its own line or after a list
# separator, optionally behind a bullet or "1)" style marker. Anchoring on that
# structure -- rather than on every capitalised token in the window -- keeps
# running prose out: "Tanık Mehmet Ali Yılmaz dinlendi" must not yield the
# person "Tanık Mehmet Ali".
_LIST_SEPARATOR_RE = re.compile(r"[\n,;]")
_LIST_MARKER_RE = re.compile(r"[ \t]*(?:[-*•]|\(?\d{1,2}[).\-])?[ \t]*")

# Longest name we will treat as one person.
_MAX_NAME_TOKENS = 3

# Roles that introduce a name on a labelled line ("Hakim: X Y").
PERSON_LABEL_RE = re.compile(
    r"(?:^|\n)\s*(?:Hakim|Hâkim|Katip|Kâtip|Zabıt\s+Katibi|Bilirkişi|Bilirkisi"
    r"|Devreden|Devralan|Satıcı|Satici|Alıcı|Alici|Kiralayan|Kiraya\s+Veren"
    r"|Vekil|Savcı|Savci|Cumhuriyet\s+Savcısı|Arabulucu|Uzman|Danışman|Danisman"
    r"|Temsilci|Yetkili|Başkan|Baskan|Üye|Uye|Raportör|Raportor|Muhbir"
    r"|Düzenleyen|Duzenleyen|Hazırlayan|Hazirlayan|Onaylayan|Teslim\s+Eden"
    r"|Teslim\s+Alan|Genel\s+Müdür|Genel\s+Mudur|İmzalayan|Imzalayan)"
    r"[ \t]*[:\-][ \t]*(" + _TOKEN + r"(?:" + _SEP + _TOKEN + r"){1,3})",
    re.IGNORECASE,
)

# Headers that introduce a list of people.
PERSON_LIST_HEADER_RE = re.compile(
    r"(?:Tanıklar|Taniklar|Hazır\s+bulunanlar|Hazir\s+bulunanlar|Katılanlar|Katilanlar"
    r"|Duruşmaya\s+[Kk]atılanlar|Durusmaya\s+[Kk]atilanlar|İmzalayanlar|Imzalayanlar"
    r"|Toplantıda\s+hazır\s+bulunanlar|Toplantida\s+hazir\s+bulunanlar"
    r"|Hazır\s+Bulunanlar|Şahitler|Sahitler)\s*[:\-]",
    re.IGNORECASE,
)

# Signature-block cues; names tend to sit on the following lines.
SIGNATURE_CUE_RE = re.compile(
    r"(?:^|\n)\s*(?:İMZA(?:LAR)?|IMZA(?:LAR)?|İmza(?:lar)?|Imza(?:lar)?"
    r"|Saygılarımla|Saygilarimla|Arz\s+ederim|Arz\s+olunur)\b[^\n]*",
    re.IGNORECASE,
)

# "X ile Y arasında" — a very high-precision party construction.
BETWEEN_PARTIES_RE = re.compile(
    rf"({_TOKEN}(?:{_SEP}{_TOKEN}){{1,2}})\s+ile\s+({_TOKEN}(?:{_SEP}{_TOKEN}){{1,2}})\s+arasında",
    re.IGNORECASE,
)


def _is_rejected(candidate: str) -> bool:
    """True when a capitalised sequence is an institution/date/document, not a person."""
    tokens = candidate.split()
    if len(tokens) < 2:
        return True
    return any(tr_fold(token) in NON_PERSON_TOKENS for token in tokens)


def _walk_tokens(text: str, pos: int, limit: int) -> list[tuple[str, int, int]]:
    """Collect up to `limit` name tokens from `pos`, keeping real offsets.

    Offsets are carried through rather than recovered later with str.find:
    tokens may be separated by tabs or runs of spaces (signature blocks and
    table-extracted DOCX text routinely are), and a normalised "A B" string
    does not occur verbatim in "A\\tB", which silently dropped the name.
    """
    tokens: list[tuple[str, int, int]] = []
    cursor = pos
    while len(tokens) < limit:
        token = _TOKEN_RE.match(text, cursor)
        if not token:
            break
        tokens.append((token.group(0), token.start(), token.end()))
        separator = _SEP_RE.match(text, token.end())
        if not separator:
            break
        cursor = separator.end()
    return tokens


def _best_name_run(tokens: list[tuple[str, int, int]]) -> tuple[str, int, int] | None:
    """Pick the first run of >=2 consecutive tokens that are all person-like.

    Guard tokens ("Mahkemesi", "Sözleşmesi", month names) split the sequence
    instead of ending it, so a name that follows one is still found.
    """
    run: list[tuple[str, int, int]] = []
    for token in tokens:
        if tr_fold(token[0]) in NON_PERSON_TOKENS:
            if len(run) >= 2:
                break
            run = []
            continue
        run.append(token)
        if len(run) == _MAX_NAME_TOKENS:
            break
    if len(run) < 2:
        return None
    # Span covers the original text exactly; the value is whitespace-normalised
    # so one person maps to one pseudonym regardless of spacing.
    return " ".join(token[0] for token in run), run[0][1], run[-1][2]


def _accept(value: str, start: int, end: int, text: str, out: dict[tuple[int, int], str]) -> None:
    if _is_rejected(value):
        return
    if COMPANY_SUFFIX_RE.match(text, end):
        return
    out[(start, end)] = value


def detect_person_names(text: str) -> list[tuple[str, int, int]]:
    """Return (value, start, end) for bare person names in `text`.

    Two independent paths: a given-name gazetteer, and structural cues that
    identify a name by its position even when the given name is unknown.
    """
    if not text:
        return []

    hits: dict[tuple[int, int], str] = {}

    # Path 1 - gazetteer: anchor on the given name itself and read forward.
    # Scanning whole candidates instead and testing their first token made any
    # name preceded by a capitalised word invisible ("Tanık Mehmet Yılmaz",
    # "Duruşmada Fatma Demir", or simply a name at the start of a sentence):
    # the greedy leftmost candidate began at the preceding word, which is not
    # in the gazetteer, so the whole span was skipped.
    for token in _TOKEN_RE.finditer(text):
        if tr_fold(token.group(0)) not in GIVEN_NAMES:
            continue
        run = _best_name_run(_walk_tokens(text, token.start(), _MAX_NAME_TOKENS))
        if run:
            _accept(*run, text, hits)

    # Path 2a - labelled lines: "Hakim: X Y".
    for match in PERSON_LABEL_RE.finditer(text):
        run = _best_name_run(_walk_tokens(text, match.start(1), _MAX_NAME_TOKENS))
        if run:
            _accept(*run, text, hits)

    # Path 2b - "X ile Y arasında".
    for match in BETWEEN_PARTIES_RE.finditer(text):
        for group in (1, 2):
            run = _best_name_run(_walk_tokens(text, match.start(group), _MAX_NAME_TOKENS))
            if run:
                _accept(*run, text, hits)

    # Path 2c - people listed after a list header, and names in signature
    # blocks. Both are scoped to a short window so the scan cannot run away
    # into unrelated prose.
    windows: list[tuple[int, int]] = []
    for match in PERSON_LIST_HEADER_RE.finditer(text):
        windows.append((match.end(), match.end() + 240))
    for match in SIGNATURE_CUE_RE.finditer(text):
        windows.append((match.end(), match.end() + 160))

    for window_start, window_end in windows:
        anchors = [window_start]
        for separator in _LIST_SEPARATOR_RE.finditer(text, window_start, window_end):
            anchors.append(separator.end())
        for anchor in anchors:
            marker = _LIST_MARKER_RE.match(text, anchor)
            run = _best_name_run(_walk_tokens(text, marker.end(), _MAX_NAME_TOKENS))
            if run:
                _accept(*run, text, hits)

    return _resolve_overlaps(hits)


def _resolve_overlaps(hits: dict[tuple[int, int], str]) -> list[tuple[str, int, int]]:
    """Keep the longest span where several cover the same name.

    Anchoring on every given name means "Mehmet Ali Yılmaz" is found twice
    (once from "Mehmet", once from "Ali"). Emitting both would assign one
    person two pseudonyms and double-count them in the findings list.
    """
    ordered = sorted(hits.items(), key=lambda item: (item[0][0], -(item[0][1] - item[0][0])))
    resolved: list[tuple[str, int, int]] = []
    last_end = -1
    for (start, end), value in ordered:
        if start < last_end:
            continue
        resolved.append((value, start, end))
        last_end = end
    return resolved
