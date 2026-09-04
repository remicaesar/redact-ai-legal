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


class PartyRoleScopeTests(unittest.TestCase):
    """party_role flags the role word only -- never the clause after it.

    It used to capture up to 120 trailing characters. That span was the longest
    one starting at its offset, so build_redacted_preview chose it over every
    finding nested inside it: a CRITICAL national id surfaced as a MEDIUM
    [PARTY_ROLE_n], spans were cut mid-date, and legal substance was destroyed.
    """

    TEXT = "Müşteki Fatma Yıldız (TCKN: 20433218148) 05.03.2026 tarihinde hazır bulundu."

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
        self.assertNotIn("20433218148", roles[0]["sample"])

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
        for secret in ("Fatma Yıldız", "20433218148"):
            self.assertNotIn(secret, preview)


class RedactedPreviewSpanOrderingTests(unittest.TestCase):
    """At a given start offset, the higher-risk finding must win the preview.

    Regression: build_redacted_preview preferred the LONGEST span at a tied
    start offset regardless of risk. A wide low-risk finding (the old,
    now-removed wide party_role span is the historical example) could then
    outrank a CRITICAL identifier nested inside it, so the CRITICAL finding
    never reached the preview at all.
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
                "sample": "20433218148",
                "risk": "CRITICAL",
                "recommended_action": "Remove completely or replace with neutral placeholder",
                "placeholder": "[NATIONAL_ID_1]",
                "start": 0,
                "end": 11,
                "fingerprint": "narrow",
            },
        ]
        text = "20433218148 numaralı kişi hakkında işlem yapılmıştır."
        preview = build_redacted_preview(text, findings)
        self.assertIn("[NATIONAL_ID_1]", preview)
        self.assertNotIn("[PARTY_ROLE_1]", preview)


if __name__ == "__main__":
    unittest.main()
