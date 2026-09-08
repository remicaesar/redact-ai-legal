"""The document a lawyer reviews must be the document they receive.

Three surfaces used to render "what the redacted file will look like": the
browser review canvas, the "Preview TXT / Preview DOCX" server preview, and the
exported reviewed DOCX. They were three separate implementations and they
disagreed on the same document under the same review decisions -- 5 differing
hunks over 27 lines between the preview and the export alone, all three pairwise
combinations differing within the first 12 lines.

Two remain, and they are the two that matter: the canvas the lawyer decides
against, and the file they receive. The lower-assurance preview export is
deleted -- not because it disagreed (once it shared the resolver it agreed) but
because a rebuilt, non-layout-preserving `<name>_redacted.txt` headed
"PRIVACY-REVIEWED REDACTED EXPORT" is a file that reads as the deliverable and
is not one; before any review decision its body was the unredacted source.
Deleting a surface does not relax this contract, it shrinks what has to satisfy
it -- so every assertion below that named the preview now names the canvas, and
none was dropped.

These tests run one synthetic Turkish petition through both real paths and
assert they agree, plus the two properties that made "just make them share code"
insufficient on its own: no under-redaction relative to the old export, and no
placeholder welded onto an orphaned fragment of the word it replaced.

Every identifier here is invented. The TCKN and VKN are check-digit-valid
synthetic values so the detector's validators accept them; they belong to
nobody.
"""

import json
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile

import tests.env_setup  # noqa: F401  -- sets LEGAL_ANALYZER_SECRET_KEY before app is imported
import app as app_module
from legal_analyzer.extraction import extract_docx_text, normalize_layout
from legal_analyzer.privacy import analyze_privacy
from legal_analyzer.taxonomy import CATEGORIES, SUBCATEGORIES
from werkzeug.security import generate_password_hash

# A synthetic commercial-court petition. Invented court, parties, address, bar
# number, IBAN, phone and email. It carries, deliberately:
#   * a company name that the person detector also matches (overlapping spans),
#   * a VKN that the phone rule also matches,
#   * a lawyer's name that appears twice, once immediately before a line break,
#   * a defendant's name that appears twice but is only detected at one of them,
#   * the party role in three cases: DAVALI, davalı, Davalı,
#   * "davalıya" / "davalıdan" -- the role word carrying a Turkish suffix.
PETITION = """\
İSTANBUL 3. ASLİYE TİCARET MAHKEMESİ SAYIN HAKİMLİĞİNE

Dosya No: 2024/1187 E.
DAVACI: Yıldız Mermer Sanayi ve Ticaret A.Ş.
Vergi Kimlik No: 4561237896
Adres: Bağlarbaşı Mahallesi Kervan Sokak No: 14 Kadıköy İstanbul
VEKİLİ: Av. Şeyma Karaduman
Baro Sicil No: 34/28714, İstanbul Barosu
E-posta: seyma.karaduman@ornekhukuk.example
Telefon: 0532 118 44 27

DAVALI: Bircan Özdemir
T.C. Kimlik No: 14729368594

KONU: Ödenmeyen fatura bedelinin tahsili talebimizdir.

AÇIKLAMALAR:
1. Müvekkil şirket ile davalı arasında 12.03.2024 tarihli mal alım sözleşmesi imzalanmıştır.
2. İhtarname 05.06.2024 tarihinde davalıya tebliğ edilmiştir.
3. Alacağın 148.500,00 TL tutarındaki kısmı davalıdan tahsil edilememiştir.
4. Ödeme TR330006100519786457841326 numaralı hesaba yapılacaktır.
5. Davalı Bircan Özdemir savunmasında sözleşmenin geçersiz olduğunu ileri sürmüştür.

SONUÇ VE İSTEM: Yukarıda açıklanan nedenlerle davanın kabulüne karar verilmesini talep ederiz.

Davacı Vekili
Av. Şeyma Karaduman
"""

CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""

RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""

def write_petition_docx(path: Path, text: str) -> None:
    """One paragraph per line, one text node per paragraph.

    `app.build_docx` produces the same shape; this is spelled out here so the
    fixture cannot drift with an unrelated change to the export helper.
    """
    from xml.sax.saxutils import escape

    body = "".join(
        f'<w:p><w:r><w:t xml:space="preserve">{escape(line)}</w:t></w:r></w:p>'
        for line in text.splitlines()
    )
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body}</w:body></w:document>"
    )
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", CONTENT_TYPES)
        archive.writestr("_rels/.rels", RELS)
        archive.writestr("word/document.xml", document)


class RedactionParityTests(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.db_path = self.tmp_path / "parity.db"
        self.original_db_path = app_module.DB_PATH
        self.original_export_dir = app_module.EXPORT_DIR
        app_module.DB_PATH = self.db_path
        app_module.EXPORT_DIR = self.tmp_path / "exports"
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())
        self.addCleanup(self.restore)
        self.addCleanup(self.tmp.cleanup)

        self.docx_path = self.tmp_path / "synthetic-dilekce.docx"
        write_petition_docx(self.docx_path, PETITION)
        # The text the app itself reads back out of that DOCX. Detection offsets
        # and every rendering are relative to this, not to PETITION.
        self.source_text, _ = extract_docx_text(self.docx_path, 200_000)

        conn = sqlite3.connect(self.db_path)
        conn.executescript(Path("db/schema.sql").read_text(encoding="utf-8"))
        for name, name_tr, icon in CATEGORIES:
            conn.execute("INSERT OR IGNORE INTO categories (name, name_tr, icon) VALUES (?, ?, ?)", (name, name_tr, icon))
            category_id = conn.execute("SELECT id FROM categories WHERE name = ?", (name,)).fetchone()[0]
            for sub_name, sub_name_tr in SUBCATEGORIES[name]:
                conn.execute(
                    "INSERT OR IGNORE INTO subcategories (category_id, name, name_tr) VALUES (?, ?, ?)",
                    (category_id, sub_name, sub_name_tr),
                )
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("reviewer", generate_password_hash("secret"), "reviewer"),
        )

        self.profile = analyze_privacy("synthetic-dilekce.docx", self.source_text)
        conn.execute(
            """
            INSERT INTO documents (
                id, filename, filepath, file_extension, file_size, title, extraction_status,
                privacy_profile, residual_risk, risk_summary, recommended_strategy,
                external_llm_readiness, human_review_required, redaction_status,
                review_status, ocr_status
            ) VALUES (1, ?, ?, '.docx', ?, 'dilekce', 'Complete', ?, ?, ?, ?, ?, 1, ?, 'pending_review', 'not_required')
            """,
            (
                "synthetic-dilekce.docx",
                str(self.docx_path),
                self.docx_path.stat().st_size,
                json.dumps(self.profile),
                self.profile["residual_risk"]["level"],
                self.profile["residual_risk"]["summary"],
                self.profile["recommended_strategy"],
                self.profile["external_llm_readiness"],
                self.profile["redaction_status"],
            ),
        )
        for index, finding in enumerate(self.profile["risk_map"]):
            conn.execute(
                """
                INSERT INTO privacy_findings (
                    document_id, category, sample, risk, recommended_action, placeholder,
                    replacement_text, review_status, source, fingerprint, start_offset, end_offset
                ) VALUES (1, ?, ?, ?, ?, ?, ?, 'pending', 'detector', ?, ?, ?)
                """,
                (
                    finding["category"],
                    finding["sample"],
                    finding["risk"],
                    finding["recommended_action"],
                    finding["placeholder"],
                    finding["placeholder"],
                    f"fp{index}",
                    finding["start"],
                    finding["end"],
                ),
            )
        conn.execute("INSERT OR IGNORE INTO matters (id, name, status) VALUES (1, 'Unassigned', 'active')")
        conn.execute("INSERT OR IGNORE INTO document_matters (document_id, matter_id) VALUES (1, 1)")
        conn.commit()
        conn.close()

        self.client = app_module.app.test_client()
        self.client.post("/login", json={"username": "reviewer", "password": "secret"})

    def restore(self):
        app_module.DB_PATH = self.original_db_path
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())
        app_module.EXPORT_DIR = self.original_export_dir

    # --- the three real renderings ---------------------------------------

    def canvas_text(self) -> str:
        """What the review canvas draws, joined back into text.

        `buildDocHtml` in studio.html renders exactly `segment.text` for every
        segment (escaped, and wrapped in a span for the non-plain kinds), so
        joining them is the canvas's visible text.
        """
        response = self.client.get("/api/document/1/redaction-plan")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["has_text"])
        return "".join(segment["text"] for segment in response.json["segments"])

    def export_text(self) -> str:
        response = self.client.get("/api/document/1/redacted-export?format=docx")
        # The body is a DOCX, so it is only decodable as text when the request
        # failed and Flask returned a JSON error instead.
        self.assertEqual(response.status_code, 200, response.get_data()[:400])
        exported = self.tmp_path / "exported.docx"
        exported.write_bytes(response.get_data())
        response.close()
        text, _ = extract_docx_text(exported, 200_000)
        return text

    def approve_everything_and_release(self):
        approved = self.client.post(
            "/api/document/1/findings/review-batch",
            json={"action": "approve", "only_pending": True},
        )
        self.assertEqual(approved.status_code, 200, approved.get_data(as_text=True))
        self.assertEqual(self.client.post("/api/document/1/review", json={"action": "mark_redacted"}).status_code, 200)
        self.assertEqual(self.client.post("/api/document/1/review", json={"action": "approve"}).status_code, 200)

    # --- Defect A ---------------------------------------------------------

    def test_the_reviewed_rendering_and_the_deliverable_agree(self):
        """The equality this whole change exists to establish.

        (Was `test_all_three_renderings_agree_on_the_same_document`; the third
        rendering, the lower-assurance preview export, has been deleted.)

        Before the shared resolver this failed on every pair: the canvas
        rendered "[PARTY_ROLE_1]: [PERSON_5] ve Ticaret A.Ş." where the export
        wrote "[PARTY_ROLE_1]: [COMPANY_1]", and the canvas left the defendant's
        name in cleartext where the export removed it.
        """
        self.approve_everything_and_release()
        canvas = self.canvas_text()
        export = self.export_text()

        # The export is compared after the app's own extractor reads the produced
        # DOCX back, because that is the text a reader of the deliverable sees.
        # normalize_layout is what the extractor applies on the way in, so the
        # canvas goes through it too rather than the comparison rewarding a
        # difference in trailing whitespace.
        self.assertEqual(normalize_layout(canvas), export, "review canvas and exported DOCX disagree")

    def test_renderings_agree_when_only_some_findings_are_approved(self):
        """Agreement must not depend on every finding being approved.

        A mixed review is the normal case, and it is where the old detection-time
        rendering was furthest wrong: it redacted findings the reviewer had
        dismissed.
        """
        findings = self.client.get("/api/document/1").json["findings"]
        for index, finding in enumerate(findings):
            action = ["approve", "dismiss", "retain"][index % 3]
            response = self.client.post(f"/api/finding/{finding['id']}/review", json={"action": action})
            self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(self.client.post("/api/document/1/review", json={"action": "mark_redacted"}).status_code, 200)
        self.assertEqual(self.client.post("/api/document/1/review", json={"action": "approve"}).status_code, 200)

        canvas = self.canvas_text()
        export = self.export_text()
        self.assertEqual(normalize_layout(canvas), export)

    def test_the_rendering_reflects_a_decision_change(self):
        """A dismissed finding comes back in every rendering, together.

        (Was `test_preview_reflects_a_decision_change`, named for the deleted
        preview export; the property is the canvas's and the export's.)
        """
        self.approve_everything_and_release()
        target = next(
            finding
            for finding in self.client.get("/api/document/1").json["findings"]
            if finding["sample"] == "0532 118 44 27"
        )
        self.assertNotIn("0532 118 44 27", self.canvas_text())

        self.assertEqual(
            self.client.post(f"/api/finding/{target['id']}/review", json={"action": "dismiss"}).status_code, 200
        )
        self.assertEqual(self.client.post("/api/document/1/review", json={"action": "mark_redacted"}).status_code, 200)
        self.assertEqual(self.client.post("/api/document/1/review", json={"action": "approve"}).status_code, 200)

        canvas, export = self.canvas_text(), self.export_text()
        self.assertIn("0532 118 44 27", canvas)
        self.assertEqual(normalize_layout(canvas), export)

    def test_no_placeholder_is_welded_to_an_orphaned_word_fragment(self):
        """`[PARTY_ROLE_2]ya tebliğ edilmiştir` must not be producible.

        The source reads "davalıya". The role target is "DAVALI", a literal
        prefix of it once Turkish case folds, so a bare substring replacement
        cut into the inflectional suffix and shipped text that would not survive
        a filing. The rule now widens a match to the whole word it lands in.
        """
        self.approve_everything_and_release()
        for name, rendering in (
            ("canvas", self.canvas_text()),
            ("export", self.export_text()),
        ):
            for match in __import__("re").finditer(r"\[[A-Z0-9_]+\](\w+)", rendering):
                self.fail(f"{name} welded {match.group(1)!r} onto {match.group(0)[:match.start(1) - match.start()]!r}")
            self.assertNotIn("davalıya", rendering)
            self.assertNotIn("davalıdan", rendering)

    def test_export_still_redacts_everything_it_redacted_before(self):
        """No under-redaction. The one outcome that must not happen.

        The old export's coverage came from replacing every string match of each
        approved sample, including occurrences detection never recorded -- the
        defendant's name is detected once and appears twice. That coverage is
        kept, and now the canvas shows it too instead of under-reporting what
        will be removed.
        """
        self.approve_everything_and_release()
        renderings = {
            "canvas": self.canvas_text(),
            "export": self.export_text(),
        }
        secrets = [
            "Bircan Özdemir",
            "Şeyma Karaduman",
            "4561237896",
            "14729368594",
            "TR330006100519786457841326",
            "seyma.karaduman@ornekhukuk.example",
            "0532 118 44 27",
            "Yıldız Mermer Sanayi ve Ticaret A.Ş.",
        ]
        for name, rendering in renderings.items():
            for secret in secrets:
                self.assertNotIn(secret, rendering, f"{secret!r} survived in the {name} rendering")

    def test_repeat_occurrence_missed_by_detection_is_redacted_everywhere(self):
        """The defendant's name is detected once and written twice.

        The old canvas replaced recorded offsets, so it showed the first
        occurrence in cleartext while the export removed both. That is the
        review surface UNDER-reporting redaction, and it is the coverage the
        shared resolver had to keep.
        """
        detected = [
            finding
            for finding in self.profile["risk_map"]
            if finding["sample"] == "Bircan Özdemir"
        ]
        self.assertEqual(len(detected), 1, "fixture no longer exercises a repeat occurrence")
        self.assertEqual(self.source_text.count("Bircan Özdemir"), 2)

        self.approve_everything_and_release()
        self.assertEqual(self.canvas_text().count(detected[0]["placeholder"]), 2)


class PseudonymConsistencyTests(unittest.TestCase):
    """Defect B: one identifier, one pseudonym."""

    def test_one_lawyer_gets_one_pseudonym_across_both_mentions(self):
        """The over-greedy span that crossed a line is what split this name.

        "Av. Şeyma Karaduman\\nBaro Sicil No: ..." was captured whole, as
        'Şeyma Karaduman\\nBaro Sicil', because the intra-name separator was
        `\\s+`. It hashed to a different pseudonym key than the clean
        'Şeyma Karaduman' found at the same offset, so one lawyer became
        [PERSON_1] and [PERSON_3] in one document.
        """
        findings = analyze_privacy("dilekce.docx", normalize_layout(PETITION))["risk_map"]
        karaduman = {
            finding["placeholder"]
            for finding in findings
            if "Karaduman" in finding["sample"] and finding["category"] == "natural_person_name"
        }
        self.assertEqual(len(karaduman), 1, f"one lawyer, {len(karaduman)} pseudonyms: {sorted(karaduman)}")

    def test_no_finding_sample_crosses_a_line_boundary(self):
        """The invariant behind that fix, stated directly.

        Every detection rule bounds its trailing context with `[^\\n]` for this
        reason: a sample that spans a line break can never be matched in a DOCX
        part, whose text is the concatenation of its `w:t` runs with no newline
        at the paragraph boundary. So it can never be redacted from the
        deliverable, however it was reviewed.
        """
        for name in sorted(Path("tests/fixtures").glob("*.txt")):
            findings = analyze_privacy(name.name, normalize_layout(name.read_text(encoding="utf-8")))["risk_map"]
            for finding in findings:
                self.assertNotIn("\n", finding["sample"], f"{name.name}: {finding['category']} {finding['sample']!r}")

    def test_one_party_role_gets_one_pseudonym_in_every_case(self):
        """`str.lower()` is not Turkish-aware, and that split a role in two.

        'DAVALI'.lower() is 'davali' with a DOTTED i; 'Davalı' already carries
        the dotless one. Two strings, two keys, two pseudonyms for one role.
        """
        findings = analyze_privacy("dilekce.docx", normalize_layout(PETITION))["risk_map"]
        by_role = {}
        for finding in findings:
            if finding["category"] != "party_role":
                continue
            by_role.setdefault(finding["sample"].casefold().replace("i", "ı").replace("İ", "ı"), set()).add(
                finding["placeholder"]
            )
        for role, placeholders in by_role.items():
            self.assertEqual(len(placeholders), 1, f"role {role!r} got {sorted(placeholders)}")

    def test_case_and_spacing_variants_share_one_pseudonym(self):
        """Repeated, differently-cased and differently-spanned occurrences.

        Stated as a single direct assertion rather than left implicit in the
        petition fixture, so a change to that fixture cannot quietly retire it.
        """
        text = normalize_layout(
            "DAVALI: Işıl Karadeniz\n"
            "Davalı Işıl Karadeniz beyanda bulundu.\n"
            "davalı vekili dinlendi.\n"
            "Tanık IŞIL KARADENİZ ifade verdi.\n"
        )
        findings = analyze_privacy("varyant.docx", text)["risk_map"]
        roles = {
            finding["placeholder"]
            for finding in findings
            if finding["category"] == "party_role" and finding["sample"].lower().startswith(("davali", "davalı"))
        }
        self.assertEqual(len(roles), 1, f"party role got {sorted(roles)}")
        names = {
            finding["placeholder"]
            for finding in findings
            if finding["category"] == "natural_person_name" and "aradeni" in finding["sample"].lower()
        }
        self.assertEqual(len(names), 1, f"one person got {sorted(names)}")


if __name__ == "__main__":
    unittest.main()
