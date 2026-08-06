import unittest

from legal_analyzer.ocr import OCRToken, parse_tesseract_tsv, token_regions_for_sample


SAMPLE_TSV = "\n".join(
    [
        "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext",
        "1\t1\t0\t0\t0\t0\t0\t0\t1000\t500\t-1\t",
        "5\t1\t1\t1\t1\t1\t100\t50\t60\t20\t96.5\tAv.",
        "5\t1\t1\t1\t1\t2\t170\t50\t80\t20\t95.0\tAyse",
        "5\t1\t1\t1\t1\t3\t260\t50\t90\t20\t94.2\tDemir",
        "5\t1\t1\t1\t2\t1\t100\t80\t200\t20\t91.0\t10000000146",
        "5\t1\t1\t1\t2\t2\t320\t80\t50\t20\t-1\t",
    ]
)


class OcrTokenTests(unittest.TestCase):
    def test_parse_tesseract_tsv_builds_text_and_normalized_tokens(self):
        text, tokens = parse_tesseract_tsv(SAMPLE_TSV, image_width=1000, image_height=500)

        self.assertEqual(text, "Av. Ayse Demir\n10000000146")
        self.assertEqual(len(tokens), 4)
        ayse = tokens[1]
        self.assertEqual(ayse.text, "Ayse")
        self.assertAlmostEqual(ayse.x0, 0.17)
        self.assertAlmostEqual(ayse.x1, 0.25)
        self.assertAlmostEqual(ayse.y0, 0.1)
        self.assertAlmostEqual(ayse.y1, 0.14)
        self.assertAlmostEqual(ayse.confidence, 0.95)

    def test_multi_word_sample_maps_to_union_box(self):
        _, tokens = parse_tesseract_tsv(SAMPLE_TSV, image_width=1000, image_height=500)

        matches = token_regions_for_sample(tokens, "Ayse Demir")

        self.assertEqual(len(matches), 1)
        match = matches[0]
        self.assertAlmostEqual(match["x0"], 0.17)
        self.assertAlmostEqual(match["x1"], 0.35)
        self.assertAlmostEqual(match["y0"], 0.1)
        self.assertAlmostEqual(match["y1"], 0.14)

    def test_matching_tolerates_edge_punctuation(self):
        tokens = (
            OCRToken(text="Av.", x0=0.1, y0=0.1, x1=0.15, y1=0.12),
            OCRToken(text="Ayse", x0=0.16, y0=0.1, x1=0.2, y1=0.12),
            OCRToken(text="Demir,", x0=0.21, y0=0.1, x1=0.27, y1=0.12),
        )

        matches = token_regions_for_sample(tokens, "Av. Ayse Demir")

        self.assertEqual(len(matches), 1)
        self.assertAlmostEqual(matches[0]["x0"], 0.1)
        self.assertAlmostEqual(matches[0]["x1"], 0.27)

    def test_missing_sample_returns_no_regions(self):
        _, tokens = parse_tesseract_tsv(SAMPLE_TSV, image_width=1000, image_height=500)

        self.assertEqual(token_regions_for_sample(tokens, "Mehmet Yilmaz"), [])
        self.assertEqual(token_regions_for_sample(tokens, ""), [])
        self.assertEqual(token_regions_for_sample((), "Ayse"), [])


if __name__ == "__main__":
    unittest.main()
