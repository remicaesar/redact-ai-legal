"""Synthetic regressions for address/context boundaries and redaction coverage."""

import unittest

from legal_analyzer.privacy import analyze_privacy, build_redacted_preview


class AddressBoundaryTests(unittest.TestCase):
    def assert_boundary(self, trigger, category, address, separator=" "):
        text = trigger + separator + address + ". 5 adresinde ikamet etmektedir"
        profile = analyze_privacy("synthetic_boundary.txt", text)
        findings = profile["risk_map"]
        start = len(trigger + separator)
        addresses = [f for f in findings if f["category"] == "address"]
        self.assertEqual([(f["start"], f["end"], f["sample"]) for f in addresses],
                         [(start, start + len(address), address)])
        contexts = [f for f in findings if f["category"] == category]
        self.assertTrue(any(f["start"] == 0 and f["end"] >= len(trigger)
                            and f["risk"] == "CRITICAL" for f in contexts), contexts)
        # The trailing clause is still reviewable, including the number after
        # the abbreviation -- and it now STARTS on that number. The "." at
        # text.index(". 5") is the "Sok."/"Cad." abbreviation's own period: the
        # address rule's (?:[^.\n]|(?<=\d)\.){0,140} tail cannot cross it, so it
        # sits outside the address span, and the cut around the address used to
        # hand it to this segment. A CRITICAL health finding must not open on
        # another rule's punctuation.
        tail_start = text.index(". 5") + len(". ")
        self.assertIn((tail_start, len(text)),
                      [(f["start"], f["end"]) for f in contexts], contexts)
        # No finding of any category may open on whitespace or a clause
        # separator. _finding() already strips whitespace; the cut is the only
        # producer that could leave a leading separator behind.
        for finding in findings:
            self.assertNotRegex(finding["sample"], r"^[\s.,;:]")
            self.assertEqual(finding["sample"], text[finding["start"]:finding["end"]].strip())
        self.assertFalse(profile["external_llm_gate"]["allowed"])
        self.assertTrue(profile["human_review_required"])
        self.assertEqual(profile["residual_risk"]["level"], "High")

        # Give every source position a distinct character. No address or
        # trigger position may survive as literal text in a redacted preview.
        probe = "".join(chr(0xE000 + i) for i in range(len(text)))
        preview = build_redacted_preview(probe, findings)
        for offset in list(range(len(trigger))) + list(range(start, start + len(address))):
            self.assertNotIn(probe[offset], preview)

    def test_context_trigger_stays_out_of_address_in_each_case(self):
        for trigger, category in (
            ("hasta", "health_data"),
            ("şüpheli", "criminal_allegation"),
            ("müvekkil", "privileged_or_confidential"),
        ):
            for case in (str.lower, str.title, str.upper, lambda value: value.replace("i", "İ").upper()):
                for address in ("Gül Sok", "GÜL SOK", "gül sok", "Işık Sok", "ışık sok", "İNCİ SOK"):
                    with self.subTest(trigger=case(trigger), address=address):
                        self.assert_boundary(case(trigger), category, address)

    def test_multiword_triggers_are_not_cut_in_half(self):
        for trigger, category in (
            ("ticari sır", "privileged_or_confidential"),
            ("trade secret", "privileged_or_confidential"),
            ("kamu davası", "criminal_allegation"),
            ("el koyma", "criminal_allegation"),
        ):
            with self.subTest(trigger=trigger):
                self.assert_boundary(trigger, category, "Gül Sok")

    def test_repeated_trigger_and_whitespace_keep_the_nearest_boundary(self):
        self.assert_boundary("hasta olan hasta", "health_data", "Gül Sok", "\t  ")

    def test_multiword_addresses_keep_both_name_words(self):
        for address in ("Gül Bahçesi Sok", "GÜL BAHÇESİ SOK", "gül bahçesi sok"):
            with self.subTest(address=address):
                self.assert_boundary("hasta", "health_data", address)

    def test_a_context_word_that_is_the_only_street_name_is_not_removed(self):
        for address in ("Sağlık Caddesi", "SAĞLIK CADDESİ", "sağlık caddesi",
                        "Arama Sokağı", "arama sokağı"):
            with self.subTest(address=address):
                text = address + " No: 5 Daire: 12"
                findings = analyze_privacy("synthetic_street.txt", text)["risk_map"]
                self.assertEqual([(f["start"], f["end"], f["sample"]) for f in findings
                                  if f["category"] == "address"], [(0, len(text), text)])

    def test_punctuation_is_a_proven_boundary(self):
        self.assert_boundary("hasta,", "health_data", "Gül Sok")

    def test_hub_example_spans_are_exact(self):
        """The hub's recorded failing example, span for span, both symptoms.

        Before the fix the address was [0,13) "hasta Gul Sok" -- it absorbed the
        trigger -- and the clause carried exactly ONE health finding, [13,44)
        ". 5 adresinde ikamet etmektedir", which opened on the "Sok." period and
        left the trigger word covered only by an ADDRESS placeholder.
        """
        text = "hasta Gül Sok. 5 adresinde ikamet etmektedir"
        findings = analyze_privacy("synthetic_hub_example.txt", text)["risk_map"]
        spans = {(f["category"], f["start"], f["end"], f["sample"]) for f in findings}
        self.assertIn(("address", 6, 13, "Gül Sok"), spans)
        self.assertIn(("health_data", 0, 5, "hasta"), spans)
        self.assertIn(("health_data", 15, 44, "5 adresinde ikamet etmektedir"), spans)
        self.assertEqual([], [f["sample"] for f in findings if f["sample"][:1] in ".,;: "])

    def test_city_and_numbered_court_do_not_become_addresses(self):
        for text in ("İstanbul 7. İş Mahkemesi kararının incelenmesi",
                     "Beşiktaş ilçesel plan çalışması", "İstanbul ve Beşiktaş toplantısı"):
            with self.subTest(text=text):
                findings = analyze_privacy("synthetic_court.txt", text)["risk_map"]
                self.assertFalse([f for f in findings if f["category"] == "address"])
                if "Mahkemesi" in text:
                    self.assertTrue(any(f["category"] == "court_or_authority"
                                        and "7. İş Mahkemesi" in f["sample"] for f in findings))


if __name__ == "__main__":
    unittest.main()
