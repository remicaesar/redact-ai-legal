import re
import unittest
from pathlib import Path

from legal_analyzer.privacy import analyze_privacy, build_redacted_preview, valid_turkish_tax_number


class TurkishLegalDetectionTests(unittest.TestCase):
    def categories_for(self, text: str) -> set[str]:
        return {finding["category"] for finding in analyze_privacy("uyap_dilekce.udf", text)["risk_map"]}

    def test_validates_turkish_national_id_checksum(self):
        categories = self.categories_for("Davacı T.C. Kimlik No: 10000000146 olarak bildirilmiştir.")
        self.assertIn("turkish_national_id", categories)

        invalid_categories = self.categories_for("Referans numarası 12345678901 olup kimlik değildir.")
        self.assertNotIn("turkish_national_id", invalid_categories)

    def test_detects_turkish_business_and_lawyer_identifiers(self):
        text = (
            "Davalı şirket VKN: 1234567890 ve MERSİS No: 0123456789012345 ile kayıtlıdır. "
            "Vekil Baro Sicil No: 45678."
        )
        categories = self.categories_for(text)

        self.assertIn("tax_number", categories)
        self.assertIn("mersis_number", categories)
        self.assertIn("bar_registration_number", categories)

    def test_detects_uyap_case_court_and_party_context(self):
        text = (
            "UYAP No: 2026/778 dosyasında İstanbul Anadolu 4. Asliye Hukuk Mahkemesi nezdinde "
            "davacı ve davalı taraflara ilişkin dilekçe sunulmuştur."
        )
        categories = self.categories_for(text)

        self.assertIn("case_or_investigation_number", categories)
        self.assertIn("court_or_authority", categories)
        self.assertIn("party_role", categories)

    def test_validates_turkish_tax_number_checksum(self):
        self.assertTrue(valid_turkish_tax_number("1234567890"))
        self.assertFalse(valid_turkish_tax_number("1234567891"))
        self.assertFalse(valid_turkish_tax_number("123456789"))

        valid = self.categories_for("Şirket VKN: 1234567890 ile kayıtlıdır.")
        self.assertIn("tax_number", valid)
        invalid = self.categories_for("Şirket VKN: 1234567891 ile kayıtlıdır.")
        self.assertNotIn("tax_number", invalid)

    def test_detects_bare_mersis_number(self):
        categories = self.categories_for("Şirket 0123456789012345 numarası ile ticaret siciline kayıtlıdır.")
        self.assertIn("mersis_number", categories)

    def test_detects_numbered_court_chambers_and_high_courts(self):
        samples = analyze_privacy(
            "karar.udf",
            "İstanbul Anadolu 4. Asliye Ticaret Mahkemesi kararı, Yargıtay 11. Hukuk Dairesi tarafından incelendi. "
            "3. Ağır Ceza Mahkemesi dosyayı devraldı.",
        )["risk_map"]
        court_samples = {finding["sample"] for finding in samples if finding["category"] == "court_or_authority"}

        self.assertTrue(any("4. Asliye Ticaret Mahkemesi" in sample for sample in court_samples))
        self.assertTrue(any("11. Hukuk Dairesi" in sample for sample in court_samples))
        self.assertTrue(any("Yargıtay" in sample for sample in court_samples))
        self.assertTrue(any("3. Ağır Ceza Mahkemesi" in sample for sample in court_samples))

    def test_detects_witness_and_victim_party_roles(self):
        categories = self.categories_for("Tanık beyanı alınmış, mağdur ifadesi dosyaya eklenmiştir.")
        self.assertIn("party_role", categories)

    def test_detects_apartment_style_address_fragments(self):
        categories = self.categories_for("Adres: Merkez Apartmanı Kat 3 Daire 5 olarak bildirilmiştir.")
        self.assertIn("address", categories)

    def test_commercial_case_fixture_has_no_false_low_risk(self):
        text = (Path(__file__).parent / "fixtures" / "sample_commercial_case.txt").read_text(encoding="utf-8")
        result = analyze_privacy("sample_commercial_case.txt", text)
        categories = {finding["category"] for finding in result["risk_map"]}

        for expected in (
            "tax_number",
            "mersis_number",
            "bar_registration_number",
            "court_or_authority",
            "case_or_investigation_number",
            "natural_person_name",
            "company_name",
            "address",
        ):
            self.assertIn(expected, categories)
        self.assertNotEqual(result["residual_risk"]["level"], "Low")

    def test_turkish_legal_identifiers_do_not_create_false_low_risk(self):
        result = analyze_privacy(
            "uyap_dilekce.udf",
            "T.C. Kimlik No: 10000000146, UYAP No: 2026/778 ve Baro Sicil No: 45678.",
        )

        self.assertNotEqual(result["residual_risk"]["level"], "Low")

    def samples_for(self, text: str, category: str) -> list[str]:
        return [f["sample"] for f in analyze_privacy("uyap_dilekce.udf", text)["risk_map"] if f["category"] == category]

    def test_detects_role_context_person_names(self):
        text = (
            "Davacı Elif Şahin ve davalı Murat Şahin arasındaki davada, "
            "şüpheli Kemal Arslan ile kiracı Barış Tunç dinlenmiştir. "
            "Davacı işçi Deniz Aksoy da beyanda bulunmuştur."
        )
        names = self.samples_for(text, "natural_person_name")

        for expected in ("Elif Şahin", "Murat Şahin", "Kemal Arslan", "Barış Tunç", "Deniz Aksoy"):
            self.assertTrue(any(expected in name for name in names), expected)

    def test_role_context_does_not_capture_uppercase_companies_or_places(self):
        names = self.samples_for(
            "Davacı YILMAZ İNŞAAT ANONİM ŞİRKETİ vekili sunulmuştur. Davacı, Çankaya İlçesi Birlik Mahallesi adresindedir.",
            "natural_person_name",
        )
        self.assertFalse(any("YILMAZ" in name for name in names), names)
        self.assertFalse(any("Mahallesi" in name or "İlçesi" in name for name in names), names)

    def test_dotted_capital_i_keywords_are_detected(self):
        samples = self.samples_for("Taraf, Çankaya İlçesi Birlik Mahallesi 45. Sokak No: 8 adresinde oturmaktadır.", "address")
        self.assertTrue(any("45. Sokak No: 8" in sample for sample in samples), samples)

    def test_address_includes_leading_street_name(self):
        samples = self.samples_for("Müşteki Bağdat Caddesi No: 41 Daire: 7 Maltepe adresinde oturmaktadır.", "address")
        self.assertTrue(any("Bağdat Caddesi No: 41" in sample for sample in samples), samples)

    def test_detects_takip_and_yevmiye_numbers(self):
        samples = self.samples_for("Takip No: 2026/45678 ve Yevmiye No: 2026/18821 kayıtlıdır.", "case_or_investigation_number")
        self.assertTrue(any("2026/45678" in sample for sample in samples), samples)
        self.assertTrue(any("2026/18821" in sample for sample in samples), samples)

    def test_detects_notary_and_judgeship_authorities(self):
        samples = self.samples_for(
            "Beyoğlu 24. Noterliği'nde düzenlenen belge İstanbul 3. Sulh Ceza Hakimliği'ne sunulmuştur.",
            "court_or_authority",
        )
        self.assertTrue(any("24. Noterliği" in sample for sample in samples), samples)
        self.assertTrue(any("3. Sulh Ceza Hakimliği" in sample for sample in samples), samples)

    def test_detects_titlecase_and_limited_sirketi_companies(self):
        text = "Alacaklı Verdi Faktoring A.Ş. ile KARTAL LOJİSTİK LİMİTED ŞİRKETİ anlaşmıştır."
        samples = self.samples_for(text, "company_name")
        self.assertTrue(any("Verdi Faktoring A.Ş." in sample for sample in samples), samples)
        self.assertTrue(any("KARTAL LOJİSTİK LİMİTED ŞİRKETİ" in sample for sample in samples), samples)

    def test_detects_company_suffix_at_line_end(self):
        samples = self.samples_for("Davalı işveren EGE TEKSTİL SANAYİ A.Ş.\nnezdinde çalışmıştır.", "company_name")
        self.assertTrue(any("EGE TEKSTİL SANAYİ A.Ş." in sample for sample in samples), samples)

    def test_detects_ocr_degraded_lawyer_title(self):
        names = self.samples_for("Muvekkil sirketi temsilen Av . Burak Sen basvuruda bulunmustur .", "natural_person_name")
        self.assertTrue(any("Burak Sen" in name for name in names), names)

    def test_detects_labelled_passport_number(self):
        text = "Davacı Ivan Petrov, pasaport no U12345678, olarak kayıtlıdır."
        findings = analyze_privacy("doc.txt", text)["risk_map"]
        passports = [f for f in findings if f["category"] == "passport_number"]
        self.assertEqual(len(passports), 1)
        self.assertIn("U12345678", passports[0]["sample"])
        self.assertEqual(passports[0]["risk"], "CRITICAL")

    def test_detects_widened_sicil_numarasi_variant(self):
        """The bare 'sicil numarası' alternative, which previously did not match
        at all because 'no' in the old pattern only consumed the word "no"."""
        text = "Davalı şirkette personel sicil numarası 884411 olarak kayıtlıdır."
        findings = analyze_privacy("doc.txt", text)["risk_map"]
        registrations = [f for f in findings if f["category"] == "bar_registration_number"]
        self.assertEqual(len(registrations), 1)
        self.assertIn("884411", registrations[0]["sample"])

    def test_detects_labelled_account_number(self):
        text = "Borçlu hesap no 1234-5678901 üzerinden ödeme yapmıştır."
        findings = analyze_privacy("doc.txt", text)["risk_map"]
        accounts = [f for f in findings if f["category"] == "account_number"]
        self.assertEqual(len(accounts), 1)
        self.assertIn("1234-5678901", accounts[0]["sample"])

    def test_detects_social_media_handle(self):
        text = "Müşteki @zbozkurt hesabından şikayet etti."
        findings = analyze_privacy("doc.txt", text)["risk_map"]
        handles = [f for f in findings if f["category"] == "social_media_handle"]
        self.assertEqual(len(handles), 1)
        self.assertEqual(handles[0]["sample"], "@zbozkurt")

    def test_social_media_handle_does_not_match_inside_an_email_address(self):
        text = "İletişim: test@example.com adresinden ulaşılabilir."
        findings = analyze_privacy("doc.txt", text)["risk_map"]
        handles = [f for f in findings if f["category"] == "social_media_handle"]
        self.assertEqual(handles, [])
        emails = [f for f in findings if f["category"] == "email_address"]
        self.assertEqual(len(emails), 1)

    def test_detects_vehicle_plate_with_context_keyword(self):
        text = "Mağdur aracı 34 ABC 123 plakalı otomobildir."
        findings = analyze_privacy("doc.txt", text)["risk_map"]
        plates = [f for f in findings if f["category"] == "vehicle_plate"]
        self.assertEqual(len(plates), 1)
        self.assertIn("34 ABC 123", plates[0]["sample"])

    def test_vehicle_plate_does_not_fire_without_context_keyword(self):
        """The bare digit-letter-digit shape alone must not fire -- it also
        matches fragments of case numbers, dates, and reference codes."""
        text = "34 ABC 123 numaralı referans kaydı incelenmiştir."
        findings = analyze_privacy("doc.txt", text)["risk_map"]
        plates = [f for f in findings if f["category"] == "vehicle_plate"]
        self.assertEqual(plates, [])


class AddressPlaceNameTriggerTests(unittest.TestCase):
    """The address rule triggers on address structure, never on a place name.

    "İstanbul", "Beşiktaş" and "Ümraniye" used to be triggers in their own
    right, so a city named in running text pulled in 140 characters of whatever
    followed and reported a court, a bar association or a contract clause as an
    address. Eight of the nine address false positives in the gold-set audit
    came from that one alternative.
    """

    def addresses_for(self, text: str) -> list[str]:
        return [f["sample"] for f in analyze_privacy("dilekce.txt", text)["risk_map"] if f["category"] == "address"]

    def test_bare_city_name_in_running_text_is_not_an_address(self):
        for text in (
            "İstanbul 7. İş Mahkemesi kararının temyiz incelemesinde karar verilmiştir.",
            "Sözleşme 04.11.2025 tarihinde İstanbul'da akdedilmiştir.",
            "Vekil İstanbul Barosu'na kayıtlı Av. Selin Aydın tarafından temsil edilmektedir.",
        ):
            with self.subTest(text=text):
                self.assertEqual(self.addresses_for(text), [])

    def test_street_address_is_still_detected_and_still_sweeps_up_the_city(self):
        """The gold-set shape the place-name trigger was never needed for.

        The structure word ("Caddesi") triggers, and its trailing span carries
        the district and city that follow, so removing the place-name trigger
        costs nothing here.
        """
        samples = self.addresses_for(
            "Müvekkil Moda Caddesi Deniz Apartmanı No: 15 Daire: 4 Kadıköy İstanbul adresinde ikamet etmektedir."
        )
        self.assertEqual(len(samples), 1)
        self.assertIn("Moda Caddesi Deniz Apartmanı No: 15", samples[0])
        self.assertIn("Kadıköy İstanbul", samples[0])

    def test_neighbourhood_and_street_address_is_still_detected(self):
        samples = self.addresses_for("Borçlu Etlik Mahallesi Güven Sokak No: 3 Keçiören adresinde bulunmaktadır.")
        self.assertEqual(len(samples), 1)
        self.assertIn("Etlik Mahallesi Güven Sokak No: 3", samples[0])


class CourtAuthoritySuffixSuppressionTests(unittest.TestCase):
    """The generic court-suffix rule yields to a rule that matched the name.

    GENERIC_COURT_SUFFIX_RULE fires on a bare suffix ("Mahkemesi",
    "Noterliği") and sweeps the clause after it. Where a specific rule already
    matched the whole institution, that produced a second, nameless copy of the
    same court -- seven of the eleven gold-set court false positives.
    """

    def court_samples(self, text: str) -> list[str]:
        return [f["sample"] for f in analyze_privacy("karar.txt", text)["risk_map"] if f["category"] == "court_or_authority"]

    def test_generic_suffix_does_not_re_report_a_named_court(self):
        samples = self.court_samples("İstanbul 11. Aile Mahkemesi Sayın Hakimliğine sunulmuştur.")
        self.assertEqual(samples, ["11. Aile Mahkemesi"])

    def test_generic_suffix_does_not_re_report_a_named_notary(self):
        samples = self.court_samples("Beyoğlu 24. Noterliği'nde düzenlenmiştir.")
        self.assertEqual(samples, ["24. Noterliği"])

    def test_authority_with_no_specific_rule_is_still_reported(self):
        samples = self.court_samples("Dosya Ümraniye Kaymakamlığı tarafından gönderilmiştir.")
        self.assertEqual(len(samples), 1)
        self.assertIn("Kaymakamlığı", samples[0])

    def test_named_court_inside_a_generic_trailing_clause_is_still_reported(self):
        """The suppression is one-directional, and this is why it has to be.

        The generic match starts first here and its trailing span runs over the
        start of "3. Sulh Ceza Hakimliği". Suppressing in that direction too
        would silently drop a second, genuinely distinct authority.
        """
        samples = self.court_samples("Kadıköy Kaymakamlığı yazısı 3. Sulh Ceza Hakimliği dosyasına eklenmiştir")
        self.assertIn("3. Sulh Ceza Hakimliği", samples)
        self.assertTrue(any("Kaymakamlığı" in sample for sample in samples), samples)

    def court_findings(self, text: str) -> list[dict]:
        return [f for f in analyze_privacy("karar.txt", text)["risk_map"] if f["category"] == "court_or_authority"]

    def assert_covered_by_a_finding(self, text: str, needle: str):
        """Every occurrence of `needle` lies inside some court finding's span.

        Coverage, not mere detection, is the property that matters downstream: a
        span carrying no finding cannot be approved by a reviewer, so export can
        never redact it. Asserting on spans rather than on `sample` substrings
        also keeps this from passing on a truncated fragment that happens to
        contain the word.
        """
        findings = self.court_findings(text)
        occurrences = [m.span() for m in re.finditer(re.escape(needle), text)]
        self.assertTrue(occurrences, f"{needle!r} does not occur in the text")
        for start, end in occurrences:
            self.assertTrue(
                any(f["start"] <= start and end <= f["end"] for f in findings),
                f"{needle!r} at [{start}:{end}] is covered by no finding: "
                f"{[(f['start'], f['end'], f['sample']) for f in findings]}",
            )

    def test_authority_after_a_named_court_is_still_reported(self):
        """The ordering that actually broke: named court FIRST, authority after.

        Skipping the generic match here also skips the 120 characters it spans,
        because re.finditer is non-overlapping -- so the prosecutor's office got
        no finding at all and survived verbatim into the preview. The scan has
        to resume at the end of the enclosing named span, not after the skipped
        match.
        """
        text = "İstanbul Anadolu 4. Asliye Ceza Mahkemesi kararı Kadıköy Cumhuriyet Başsavcılığı'na gönderilmiştir"
        samples = self.court_samples(text)

        self.assertIn("4. Asliye Ceza Mahkemesi", samples)
        self.assert_covered_by_a_finding(text, "Cumhuriyet Başsavcılığı")
        self.assertNotIn("Cumhuriyet Başsavcılığı", analyze_privacy("karar.txt", text)["redacted_preview"])

    def test_authority_after_a_named_notary_is_still_reported(self):
        text = "Şişli 15. Noterliği senedi Şişli Tapu Müdürlüğü ve İstanbul Valiliği kayıtlarına işlendi"
        samples = self.court_samples(text)

        self.assertIn("15. Noterliği", samples)
        self.assert_covered_by_a_finding(text, "Valiliği")

    def test_authority_after_a_high_court_sixty_char_sweep_is_still_reported(self):
        """The Yargıtay/Danıştay rule sweeps 60 characters past the name.

        So its span is the widest window the generic rule skips, and the
        authority that follows it is the one most likely to be lost.
        """
        text = (
            "Danıştay içtihadına göre Ümraniye Kaymakamlığı işlemi iptal edilmiş "
            "ve Kadıköy Valiliği yeni bir karar almıştır"
        )
        self.assert_covered_by_a_finding(text, "Danıştay")
        self.assert_covered_by_a_finding(text, "Ümraniye Kaymakamlığı")
        self.assert_covered_by_a_finding(text, "Valiliği")


class PartyRoleScopeTests(unittest.TestCase):
    """party_role flags the role word only -- never the clause after it.

    It used to capture up to 120 trailing characters. That span was the longest
    one starting at its offset, so build_redacted_preview chose it over every
    finding nested inside it: a CRITICAL national id surfaced as a MEDIUM
    [PARTY_ROLE_n], spans were cut mid-date, and legal substance was destroyed.
    """

    TEXT = "Müşteki Fatma Yıldız (TCKN: 22222222220) 05.03.2026 tarihinde hazır bulundu."

    def analyze(self) -> dict:
        return analyze_privacy("tutanak.txt", self.TEXT)

    def party_role_findings(self) -> list[dict]:
        return [f for f in self.analyze()["risk_map"] if f["category"] == "party_role"]

    def test_party_role_span_is_only_the_role_word(self):
        # Asserting on the filtered list itself (not a bare "for ... if" loop)
        # so this fails, rather than passing vacuously, if the rule stops firing.
        roles = self.party_role_findings()
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0]["sample"], "Müşteki")

    def test_party_role_sample_never_stores_name_or_national_id(self):
        roles = self.party_role_findings()
        self.assertEqual(len(roles), 1)
        self.assertNotIn("Fatma", roles[0]["sample"])
        self.assertNotIn("22222222220", roles[0]["sample"])

    def test_nested_identifiers_keep_their_own_category_and_risk(self):
        by_category = {f["category"]: f for f in self.analyze()["risk_map"]}
        self.assertIn("party_role", by_category)
        self.assertIn("turkish_national_id", by_category)
        self.assertEqual(by_category["turkish_national_id"]["risk"], "CRITICAL")
        self.assertIn("natural_person_name", by_category)

    def test_preview_keeps_sentence_structure_and_leaks_nothing(self):
        result = self.analyze()
        self.assertTrue(any(f["category"] == "party_role" for f in result["risk_map"]))
        preview = result["redacted_preview"]
        self.assertIn("tarihinde hazır bulundu", preview)
        for secret in ("Fatma Yıldız", "22222222220"):
            self.assertNotIn(secret, preview)


class RedactedPreviewSpanOrderingTests(unittest.TestCase):
    """At a given start offset, the higher-risk finding must win the preview.

    Regression: build_redacted_preview preferred the LONGEST span at a tied
    start offset regardless of risk. A wide low-risk finding (the old,
    now-removed wide party_role span is the historical example) could then
    outrank a CRITICAL identifier nested inside it, so the CRITICAL finding
    never reached the preview at all.

    The guarded property is that the CRITICAL reaches the preview and none of
    its text survives -- NOT that the wider finding is absent. The wider one now
    contributes a placeholder for the part of its span the CRITICAL does not
    cover, which is what clipping does for every other overlap. Forbidding that
    residual was stricter than this regression, and it was load-bearing in the
    wrong direction: it kept a tied-start address from being redacted at all.
    """

    def test_nested_critical_beats_wider_lower_risk_span_at_same_start(self):
        findings = [
            {
                "category": "party_role",
                "sample": "Müşteki ifadesinde TCKN belirtilmiştir",
                "risk": "MEDIUM",
                "recommended_action": "Review",
                "placeholder": "[PARTY_ROLE_1]",
                "start": 0,
                "end": 40,
                "fingerprint": "wide",
            },
            {
                "category": "turkish_national_id",
                "sample": "22222222220",
                "risk": "CRITICAL",
                "recommended_action": "Remove completely or replace with neutral placeholder",
                "placeholder": "[NATIONAL_ID_1]",
                "start": 0,
                "end": 11,
                "fingerprint": "narrow",
            },
        ]
        text = "22222222220 numaralı kişi hakkında işlem yapılmıştır."
        preview = build_redacted_preview(text, findings)

        # The CRITICAL wins the tied start: it reaches the preview, and it
        # reaches it first.
        self.assertIn("[NATIONAL_ID_1]", preview)
        self.assertTrue(preview.startswith("[NATIONAL_ID_1]"), preview)
        # No character of the CRITICAL's span survives.
        self.assertNotIn("22222222220", preview)
        for offset in range(0, 11 - 3):
            self.assertNotIn(text[offset:11], preview)


class ContextSweepAbbreviationTests(unittest.TestCase):
    """The three context sweeps must run through "T.C." and still stop at a period.

    health_data, criminal_allegation and privileged_or_confidential match a
    trigger keyword plus a trailing sweep. The sweep used to be [^.\n]{0,N},
    which stopped at the FIRST period of "T.C.", so in "hasta Leyla Kaya T.C.
    Kimlik No: 10000000146 kanser" the match ended at "Kaya T" and the diagnosis
    after the identifier had no finding of any kind -- and a span with no
    finding cannot be approved by a reviewer, so it is unredactable on export by
    construction. The sweep now allows a period that follows a single capital
    letter, and nothing else, so a real sentence boundary still ends it.
    """

    ABBREVIATION_CASES = (
        ("health_data", "hasta Leyla Kaya T.C. Kimlik No: 10000000146 kanser", "kanser"),
        ("criminal_allegation", "şüpheli Kemal Arslan T.C. Kimlik No: 10000000146 dolandırıcılık", "dolandırıcılık"),
        ("privileged_or_confidential", "müvekkil Cemile Doğan T.C. Kimlik No: 10000000146 stratejisi", "stratejisi"),
    )

    BOUNDARY_CASES = (
        ("health_data", "hasta iyileşti. Yeni cümle Ahmet Yılmaz"),
        ("criminal_allegation", "şüpheli yakalandı. Yeni cümle Ahmet Yılmaz"),
        ("privileged_or_confidential", "müvekkil ile görüşüldü. Yeni cümle Ahmet Yılmaz"),
    )

    def covering(self, findings: list[dict], category: str, text: str, word: str) -> list[dict]:
        start = text.index(word)
        end = start + len(word)
        return [
            finding
            for finding in findings
            if finding["category"] == category and finding["start"] <= start and finding["end"] >= end
        ]

    def test_sweep_reaches_the_clause_after_an_abbreviation(self):
        for category, text, word in self.ABBREVIATION_CASES:
            with self.subTest(category=category):
                findings = analyze_privacy("dilekce.txt", text)["risk_map"]

                covering = self.covering(findings, category, text, word)
                self.assertEqual(len(covering), 1, findings)
                self.assertEqual(covering[0]["risk"], "CRITICAL")

    def test_a_lowercase_single_letter_is_not_an_abbreviation(self):
        """The abbreviation exception is capitals only, under a rule that ignores case.

        These rules carry re.IGNORECASE, so an unscoped [A-ZÇĞİÖŞÜ] in the
        lookbehind would match any letter and let a period after a one-letter
        lowercase word through the stop. The exception is scoped with (?-i:...)
        to keep that from happening.

        The assertion is on "Yeni cümle", not on the name: a person name is a
        direct identifier, so _cut_identifiers_from_context_findings removes it
        from the context span however far the sweep ran. Asserting only that no
        context finding covers the NAME therefore passes even when the sweep has
        crossed the boundary -- measured, that is exactly what the unscoped
        variant does here.
        """
        text = "hasta b. Yeni cümle Ahmet Yılmaz"
        findings = analyze_privacy("dilekce.txt", text)["risk_map"]

        self.assertTrue([f for f in findings if f["category"] == "health_data"], findings)
        self.assertEqual(self.covering(findings, "health_data", text, "Yeni cümle"), [])
        self.assertEqual(self.covering(findings, "health_data", text, "Ahmet"), [])

    def test_sweep_still_stops_at_a_sentence_boundary(self):
        for category, text in self.BOUNDARY_CASES:
            with self.subTest(category=category):
                findings = analyze_privacy("dilekce.txt", text)["risk_map"]

                # The rule must still fire on the first sentence, or this would
                # pass simply because the category stopped being detected.
                self.assertTrue([f for f in findings if f["category"] == category], findings)
                # "Yeni cümle" is the load-bearing half: the name is a direct
                # identifier and _cut_identifiers_from_context_findings takes it
                # out of the context span however far the sweep ran, so the name
                # assertion alone can pass over a sweep that did cross.
                self.assertEqual(self.covering(findings, category, text, "Yeni cümle"), [])
                self.assertEqual(self.covering(findings, category, text, "Ahmet"), [])


if __name__ == "__main__":
    unittest.main()
