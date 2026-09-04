import unittest
from pathlib import Path

from legal_analyzer.privacy import analyze_privacy
from legal_analyzer.turkish_names import detect_person_names, tr_fold


def names(text: str) -> set[str]:
    return {value for value, _start, _end in detect_person_names(text)}


def person_findings(text: str) -> set[str]:
    result = analyze_privacy("doc.txt", text)
    return {f["sample"] for f in result["risk_map"] if f["category"] == "natural_person_name"}


class BareNameDetectionTests(unittest.TestCase):
    """Names with no honorific or party-role prefix -- the gap the title/role regexes miss."""

    def test_detects_parties_in_running_text(self):
        text = "İşbu sözleşme, Mehmet Yılmaz ile Ayşe Kaya arasında akdedilmiştir."
        self.assertEqual(names(text), {"Mehmet Yılmaz", "Ayşe Kaya"})

    def test_detects_inline_attendee_list(self):
        text = "Toplantıda hazır bulunanlar: Ahmet Demir, Fatma Şahin, Mustafa Çelik."
        self.assertEqual(names(text), {"Ahmet Demir", "Fatma Şahin", "Mustafa Çelik"})

    def test_detects_numbered_witness_list(self):
        text = "TANIKLAR\n\n1) Zeynep Arslan\n2) Hüseyin Doğan\n"
        self.assertEqual(names(text), {"Zeynep Arslan", "Hüseyin Doğan"})

    def test_detects_signature_block(self):
        text = "Saygılarımla arz ederim.\n\nKemal Öztürk\n"
        self.assertIn("Kemal Öztürk", names(text))

    def test_detects_labelled_role_line(self):
        text = "Hakim: Selçuk Aydın\nKatip: Elif Korkmaz\n"
        self.assertEqual(names(text), {"Selçuk Aydın", "Elif Korkmaz"})

    def test_detects_all_caps_name(self):
        text = "İşbu sözleşme, MEHMET YILMAZ ile AYŞE KAYA arasında imzalanmıştır."
        self.assertEqual(names(text), {"MEHMET YILMAZ", "AYŞE KAYA"})

    def test_name_does_not_span_line_break(self):
        """A candidate must not swallow the next line's label.

        Regression: allowing \\s+ inside a candidate produced 'Selçuk Aydın\\nKatip',
        which no longer aligned back onto the source text and dropped the name.
        """
        text = "Hakim: Selçuk Aydın\nKatip: Elif Korkmaz\n"
        for value in names(text):
            self.assertNotIn("\n", value)
            self.assertNotIn("Katip", value)

    def test_bare_names_reach_the_risk_map_as_high(self):
        text = "İşbu sözleşme, Mehmet Yılmaz ile Ayşe Kaya arasında akdedilmiştir."
        result = analyze_privacy("sozlesme.txt", text)
        found = [f for f in result["risk_map"] if f["category"] == "natural_person_name"]

        self.assertEqual({f["sample"] for f in found}, {"Mehmet Yılmaz", "Ayşe Kaya"})
        self.assertTrue(all(f["risk"] == "HIGH" for f in found))
        self.assertTrue(all(f["placeholder"].startswith("[PERSON") for f in found))

    def test_repeated_name_reuses_one_placeholder(self):
        text = (
            "İşbu sözleşme, Mehmet Yılmaz ile Ayşe Kaya arasında akdedilmiştir.\n"
            "Devreden: Mehmet Yılmaz\n"
        )
        result = analyze_privacy("sozlesme.txt", text)
        placeholders = {
            f["placeholder"]
            for f in result["risk_map"]
            if f["category"] == "natural_person_name" and f["sample"] == "Mehmet Yılmaz"
        }
        self.assertEqual(len(placeholders), 1)


class NameAnchoringTests(unittest.TestCase):
    """Regression: a name preceded by a capitalised word was invisible.

    Candidates were matched greedily left-to-right and only the FIRST token was
    checked against the gazetteer, so "Tanık Mehmet Yılmaz" produced the single
    candidate "Tanık Mehmet Yılmaz" -- rejected, because "Tanık" is not a given
    name. Detection now anchors on the given name and reads forward.
    """

    def test_detects_name_after_capitalised_prefix(self):
        for prefix in ("Tanık", "Sayın", "Duruşmada", "Bugün", "Müvekkil"):
            with self.subTest(prefix=prefix):
                self.assertIn("Mehmet Yılmaz", names(f"{prefix} Mehmet Yılmaz dinlendi."))

    def test_detects_name_at_sentence_start(self):
        self.assertIn("Ahmet Yılmaz", names("Ahmet Yılmaz dün geldi."))

    def test_detects_three_token_name_after_prefix(self):
        self.assertIn("Mehmet Ali Yılmaz", names("Tanık Mehmet Ali Yılmaz dinlendi."))

    def test_name_is_reported_once_when_multiple_tokens_are_given_names(self):
        """"Mehmet Ali Yılmaz" anchors on both "Mehmet" and "Ali"; one person, one span."""
        found = detect_person_names("Tanık Mehmet Ali Yılmaz dinlendi.")
        self.assertEqual(len(found), 1)


class NameWhitespaceTests(unittest.TestCase):
    """Regression: names separated by tabs or repeated spaces were dropped.

    Spans used to be recovered by searching the source for a whitespace-
    normalised "A B", which does not occur in "A\\tB" -- so signature blocks and
    table-extracted DOCX text, where tabs are the norm, silently lost names.
    """

    def test_detects_name_separated_by_tab(self):
        self.assertIn("Ahmet Yılmaz", names("Taraflar: Ahmet\tYılmaz beyan etti."))

    def test_detects_name_separated_by_repeated_spaces(self):
        self.assertIn("Ahmet Yılmaz", names("Taraflar: Ahmet  Yılmaz beyan etti."))

    def test_detects_tab_separated_names_in_signature_block(self):
        self.assertEqual(
            names("İmzalar\nMehmet\tDemir\nAyşe\tKaya"),
            {"Mehmet Demir", "Ayşe Kaya"},
        )

    def test_detects_tab_after_role_label(self):
        self.assertIn("Selçuk Aydın", names("Hakim: Selçuk\tAydın"))

    def test_reported_span_covers_the_original_text(self):
        """The span must address the source exactly -- redaction replaces by offset."""
        text = "Taraflar: Ahmet\tYılmaz ve Mehmet  Demir."
        for _value, start, end in detect_person_names(text):
            self.assertRegex(text[start:end], r"^\S+\s+\S+$")

    def test_spacing_variants_share_one_placeholder(self):
        text = "Ahmet Yılmaz geldi. Sonra Ahmet\tYılmaz ayrıldı."
        result = analyze_privacy("dosya.txt", text)
        placeholders = {
            f["placeholder"]
            for f in result["risk_map"]
            if f["category"] == "natural_person_name"
        }
        self.assertEqual(len(placeholders), 1)


class SignatureBlockColumnTests(unittest.TestCase):
    """Regression: a wide gap (tab, or 2+ spaces) is a column boundary, not an
    intra-name gap.

    _SEP treats a tab or a run of spaces as an ordinary gap so a name run
    could walk straight across a column boundary in a two-column signature
    block. _MAX_NAME_TOKENS then truncated the merged four-token run at
    three, dropping the trailing surname entirely -- it survived, unredacted,
    in the exported document.
    """

    def test_two_names_side_by_side_resolve_separately(self):
        """Real shape from the hearing-minutes fixture's signature block."""
        text = "Hakim                          Katip\nSelçuk Aydın                   Elif Korkmaz\n"
        self.assertEqual(names(text), {"Selçuk Aydın", "Elif Korkmaz"})

    def test_tab_separated_names_under_signature_header_are_not_merged(self):
        text = "İMZALAR\nMehmet\tYılmaz\tAyşe\tKaya\n"
        self.assertEqual(names(text), {"Mehmet Yılmaz", "Ayşe Kaya"})

    def test_single_name_padded_with_tab_is_still_detected(self):
        """A wide gap may still be crossed while the run has fewer than 2 tokens,
        so one name filling a padded cell keeps working."""
        self.assertIn("Ahmet Yılmaz", names("Ahmet\tYılmaz"))

    def test_single_name_padded_with_wide_spaces_is_still_detected(self):
        self.assertIn("Ahmet Yılmaz", names("Ahmet                    Yılmaz"))

    def test_signature_block_leaves_no_surname_unredacted(self):
        """End-to-end: this is the test that would have caught the bug.

        Two correct findings from the earlier attendee list must not stop the
        engine from also separating the two names in the signature block --
        if it merges them, the fourth name's surname is dropped entirely and
        reaches the redacted export verbatim.
        """
        text = (Path(__file__).parent / "fixtures" / "bare_names_hearing_minutes.txt").read_text(
            encoding="utf-8"
        )
        result = analyze_privacy("bare_names_hearing_minutes.txt", text)
        self.assertNotIn("Korkmaz", result["redacted_preview"])


class NamePrecisionGuardTests(unittest.TestCase):
    """Capitalised sequences that must NOT be flagged as people."""

    def test_company_is_not_a_person(self):
        text = "Alacaklı Verdi Faktoring A.Ş. vekili başvurdu."
        self.assertNotIn("Verdi Faktoring", person_findings(text))

    def test_company_with_given_name_prefix_is_not_a_person(self):
        text = "Taraf, Mehmet Yılmaz İnşaat Limited Şirketi olarak kayıtlıdır."
        self.assertEqual(names(text), set())

    def test_court_is_not_a_person(self):
        text = "Ankara 7. Asliye Hukuk Mahkemesi kararı ile dosya kapatıldı."
        self.assertEqual(names(text), set())

    def test_institution_headers_are_not_people(self):
        text = "DURUŞMA TUTANAĞI\n\nHİSSE DEVİR SÖZLEŞMESİ\n\nBİLİRKİŞİ RAPORU\n"
        self.assertEqual(names(text), set())

    def test_month_and_place_words_are_not_people(self):
        text = "Rapor Mart 2025 tarihinde İstanbul Ticaret Sicili Müdürlüğüne sunuldu."
        self.assertEqual(names(text), set())

    def test_single_token_is_not_a_person(self):
        self.assertEqual(names("Mehmet geldi."), set())

    def test_role_word_is_not_part_of_the_name(self):
        for role in ("Tanık", "Müvekkil", "Davacı", "Şüpheli", "Sayın"):
            with self.subTest(role=role):
                found = names(f"{role} Mehmet Ali Yılmaz dinlendi.")
                self.assertEqual(found, {"Mehmet Ali Yılmaz"})

    def test_prose_inside_a_list_window_is_not_harvested(self):
        """Regression: the attendee/signature window scanned every capitalised token.

        Anchoring on any token meant sentences following a list absorbed their
        leading word -- "Tanık Mehmet Ali", "Bugün Ahmet Yılmaz". Names in a
        window are now anchored to line or list-separator structure.
        """
        text = (
            "Duruşmaya katılanlar:\n"
            "1) Zeynep Arslan\n"
            "2) Hüseyin Doğan\n\n"
            "Tanık Mehmet Ali Yılmaz dinlendi. Bugün Ahmet Yılmaz da hazır bulundu.\n"
        )
        found = names(text)
        self.assertEqual(found, {"Zeynep Arslan", "Hüseyin Doğan", "Mehmet Ali Yılmaz", "Ahmet Yılmaz"})
        for value in found:
            self.assertNotIn("Tanık", value)
            self.assertNotIn("Bugün", value)

    def test_each_person_gets_exactly_one_pseudonym(self):
        text = (
            "Duruşmaya katılanlar:\n1) Zeynep Arslan\n\n"
            "Tanık Mehmet Ali Yılmaz dinlendi. Bugün Ahmet Yılmaz da hazır bulundu.\n"
        )
        result = analyze_privacy("tutanak.txt", text)
        people = [f for f in result["risk_map"] if f["category"] == "natural_person_name"]
        self.assertEqual(len(people), len({f["placeholder"] for f in people}))


class MonthNameGuardTests(unittest.TestCase):
    """A month name only guards a candidate when it is functioning as a date.

    Regression: all twelve month names were unconditional NON_PERSON_TOKENS,
    so a real person whose given name happens to be a month word ("Eylül
    Kaya", "Nisan Yıldırım") could never be detected -- the run was split on
    the guard token before it could combine with the surname.
    """

    def test_month_as_given_name_is_detected(self):
        self.assertIn("Eylül Kaya", names("Sözleşme Eylül Kaya tarafından imzalanmıştır."))
        self.assertIn("Nisan Yıldırım", names("Nisan Yıldırım beyanda bulundu."))

    def test_month_next_to_year_is_still_a_date_not_a_person(self):
        self.assertEqual(names("Mart 2025"), set())
        self.assertEqual(names("Toplantı Mart 2025 tarihinde yapıldı."), set())

    def test_month_next_to_day_number_is_still_a_date_not_a_person(self):
        self.assertEqual(names("15 Mart 2025"), set())
        self.assertEqual(names("15 Mart tarihinde toplantı yapıldı."), set())
        # "Nisan" is now gazetteer-anchored; without the day-before check this
        # would misread the holiday-linked place name as a person "Nisan İlkokulu".
        self.assertEqual(names("23 Nisan İlkokulu açılışı yapıldı."), set())


class TurkishCaseFoldingTests(unittest.TestCase):
    def test_dotted_and_dotless_i_fold_correctly(self):
        # str.casefold() alone maps "I" -> "i", which breaks Turkish matching.
        self.assertEqual(tr_fold("İLKER"), "ilker")
        self.assertEqual(tr_fold("IŞIL"), "ışıl")
        self.assertEqual(tr_fold("İlker"), "ilker")


if __name__ == "__main__":
    unittest.main()
