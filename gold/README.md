# Mini-Gold Accuracy Dataset

Use this folder for manually labeled accuracy audits. Speed benchmarks only show that the scanner is fast; this dataset is for recall, precision, false negatives, and false-Low checks.

Recommended production audit set:

- 5 pleadings or petitions, including UYAP/UDF where available
- 5 contracts
- 5 scanned/image PDFs or exhibits
- 5 public/template documents

For each document, label direct identifiers, indirect identifiers, sensitive attributes, contextual identifiers, and confidential legal/business information.

For Turkish legal practice, explicitly label:

- TCKN, VKN, MERSIS, IBAN, phone, email, and address data
- Bar registration numbers and lawyer/person names
- Court, enforcement office, prosecutor, UYAP, investigation, case, decision, and file numbers
- Party roles such as davacı, davalı, müşteki, şüpheli, sanık, borçlu, and alacaklı
- Privileged/confidential legal-business context

Use optional `ocr_text` fields for scanned exhibits where reviewer-accepted OCR should be compared against pre-OCR extraction.

Run:

```bash
python3 accuracy_audit.py --labels gold/gold_labels.example.json
```

The key goals are `false_low_count = 0` (no document reported Low when it has undetected
gold labels or an expected risk above Low) and `risk_shortfall_count = 0` (no document's
computed risk level is ranked below its gold-expected level, e.g. expected High computing
Medium — a case `false_low_count` alone cannot see, since it only fires when the computed
level is exactly Low).

## False-positive triage (2026-09-05)

Triage of the 58 false positives the gold-set audit reported at `8017ec2`, so that
reviewers are not trained to click Approve through a queue of noise.

The tracker for this work said 65 false positives. That figure does not reproduce: the
audit at `8017ec2` reports 58, against 117 gold labels and 194 findings. Everything below
uses the measured 58.

Reproduce any of the numbers below with:

```bash
python3 accuracy_audit.py --labels gold/gold_labels.example.json
```

### Before / after

| Rule | FPs before | FPs after | Outcome |
|---|---|---|---|
| `party_role` | 20 | 20 | accepted, see below |
| `court_or_authority` | 11 | 4 | tightened |
| `address` | 9 | 1 | tightened |
| `date` | 7 | 7 | out of scope |
| `criminal_allegation` | 4 | 4 | out of scope |
| `privileged_or_confidential` | 3 | 3 | out of scope |
| `health_data` | 3 | 3 | out of scope |
| `bar_registration_number` | 1 | 1 | out of scope |
| **total** | **58** | **43** | |

| Metric | Before | After |
|---|---|---|
| recall | 1.0 | 1.0 |
| precision | 0.701 | 0.7557 |
| gold labels | 117 | 117 |
| findings | 194 | 176 |
| `false_negative_count` | 0 | 0 |
| `false_low_count` | 0 | 0 |
| `risk_shortfall_count` | 0 | 0 |
| post-OCR precision | 0.6429 | 0.6923 |

Recall, `false_low_count` and `risk_shortfall_count` were re-checked after each
individual change, not only at the end. Full suite: 318 tests, OK.

### Tightened: `address` — dropped the bare place-name triggers

`beşiktaş|besiktas|ümraniye|umraniye|[İi]stanbul` were triggers in their own right, so a
city or district named anywhere in running text matched and then swallowed the following
140 characters. Every one of the eight false positives it produced was a court, an
institution or a contract clause reported as an address:

- `İstanbul Anadolu 4. Asliye Ticaret Mahkemesi`
- `İstanbul 7. İş Mahkemesi kararının temyiz incelemesinde, davacı işçi Hasan Demirci'nin`
- `İstanbul Cumhuriyet Başsavcılığı Dolandırıcılık Suçları Soruşturma Bürosu`
- `İstanbul Barosu'na kayıtlı Av`
- `İstanbul Ticaret Sicili Müdürlüğü kaydı güncellenecektir`
- `tarihinde\nİstanbul'da akdedilmiştir`

**Why it is safe.** A place name on its own is not an address — it does not narrow anyone
down. All seven `address` gold labels are anchored on a structure word instead (`Caddesi
Merkez Apartmanı`, `Bağdat Caddesi No: 41`, `Birlik Mahallesi 45. Sokak No: 8`, `Etlik
Mahallesi Güven Sokak No: 3`, `Alsancak Mahallesi 1475 Sokak`, `Moda Caddesi Deniz
Apartmanı No: 15`, `Fenerbahçe Mahallesi`), and the structure word's 140-character
trailing span already sweeps up the district and city that follow it. The place-name
alternative matched no gold label before the change and none after: recall stayed 1.0 and
`false_negative_count` stayed 0.

**Accepted cost, and its gate consequence.** An address written as a bare district and
city (`Adres: Kadıköy İstanbul`), with no street or neighbourhood, is no longer flagged as
an address. That is under-detection, which is the unsafe direction in this codebase, so
the consequence is recorded here in full. `address` is in `DIRECT_IDENTIFIER_CATEGORIES`,
so such a document now produces **zero** findings and no longer trips the *"No direct
identifiers may remain in detected findings"* arm of the external-LLM gate —
`external_llm_gate.direct_identifiers_detected` goes `True` -> `False` and that entry
disappears from `failed_conditions` (verified before and after on that exact string). For
this particular document the gate still blocks, on the separate *"Residual risk must be
Low"* arm; but a document that is otherwise Low would lose a blocking condition it
previously had. Extend the gold set with a bare district-and-city document before relying
on the rule for that shape.

### Tightened: `court_or_authority` — the generic suffix rule yields to a named court

`GENERIC_COURT_SUFFIX_RULE` fires on a bare institution *suffix* (`Mahkemesi`,
`Hakimliği`, `Noterliği`, `Savcılığı`) and sweeps up to 120 characters, because the
institution's own name is not part of its trigger. Where one of the specific
numbered-court rules had already matched the full name, the generic rule reported a
second, nameless copy of the same institution starting mid-name:

| Already reported by a name-anchored rule | Reported again by the generic rule |
|---|---|
| `11. Aile Mahkemesi` | `Mahkemesi Sayın Hakimliğine` |
| `7. İş Mahkemesi` | `Mahkemesi kararının temyiz incelemesinde, davacı işçi Hasan Demirci'nin` |
| `3. İş Mahkemesi` | `Mahkemesi'ne` |
| `5. Asliye Hukuk Mahkemesi` | `Mahkemesi - Malpraktis Dosyası` |
| `3. Sulh Ceza Hakimliği` | `Hakimliği kararı ile dosyaya eklenmiştir` |
| `24. Noterliği` | `Noterliği'nde düzenlenmiştir` |
| `2. Noterliği` | `Noterliği onaylı örneği ile,` |

`_generic_court_matches()` now skips a match of the generic rule that *begins strictly
inside* a span one of the name-anchored rules already matched, **and resumes the scan at
the end of that enclosing span** rather than after the skipped match. There was no
existing overlap-suppression mechanism to reuse: `_dedupe_findings()` only drops exact
`(category, start, end, fingerprint)` repeats, and `build_redacted_preview()` resolves
overlap for the preview only, not for the finding list a reviewer works through.

**The resume is the load-bearing half.** Simply dropping the match and letting
`re.finditer()` continue is *not* equivalent, and the first version of this change made
exactly that mistake: `finditer` is non-overlapping, so the scan restarted after the
discarded 120-character match and any second authority inside it was never offered again.
In `"İstanbul Anadolu 4. Asliye Ceza Mahkemesi kararı Kadıköy Cumhuriyet Başsavcılığı'na
gönderilmiştir"` the prosecutor's office got no finding of any kind and survived verbatim
into `redacted_preview` — and a span with no finding cannot be approved by a reviewer, so
it is unredactable on export by construction. The gold set contains no document of that
shape, which is why the audit could not see it; the metrics are identical either way.

**What is guaranteed.** Precisely two things, no more:

1. A name-anchored court is never suppressed.
2. The **start** of every authority mention lies inside at least one finding span — its
   own, or the name-anchored finding that encloses it — so the place name and the
   institution stem can always be approved and redacted. Not the whole mention: the
   Yargıtay/Danıştay rule's fixed 60-character sweep can end mid-word, the resume then
   lands where `\b` cannot match, and the tail of that word falls outside every finding.
   `"Yargıtay bozma ilamı doğrultusunda dosya Kadıköy Cumhuriyet Başsavcılığına
   gönderilmiştir"` previews as `[COURT_AUTHORITY_1]lığına gönderilmiştir`. Measured on
   15,000 adversarial sentences during review: 0 whole misses, 664 such tail fragments,
   none carrying an identifier. Two candidate code fixes were tried and neither closed it
   cleanly, so this is recorded rather than patched.

Point 2 is weaker than "every authority gets its own finding", and deliberately so: the
Yargıtay/Danıştay rule sweeps up to 60 characters past the institution name, so an
authority named inside that sweep (`Ümraniye Kaymakamlığı` in `"Danıştay içtihadına göre
Ümraniye Kaymakamlığı işlemi iptal edilmiş ve Kadıköy Valiliği yeni bir karar almıştır"`)
is covered by the Danıştay finding rather than by one of its own. It is still redacted.
`CourtAuthoritySuffixSuppressionTests` asserts coverage by finding *span*, not by `sample`
substring, so it cannot pass on a truncated fragment that merely contains the word.

Three *true* positives were also removed (`Mahkemesi`, `İcra Müdürlüğü`, `MAHKEMESİ` —
bare-suffix fragments of `4. Asliye Ticaret Mahkemesi`, `12. İcra Müdürlüğü` and
`ANKARA 7. ASLİYE HUKUK MAHKEMESİ`); each of those gold labels is still matched by the
enclosing name-anchored finding, which is why recall stayed 1.0.

Known cosmetic gap, unchanged by this work: the generic rule triggers on the institution
*suffix*, so a leading place word is left outside the finding — `Kadıköy` in `Kadıköy
Cumhuriyet Başsavcılığı` stays in the preview while the office itself is replaced. That is
pre-existing behaviour of the rule, not a consequence of the suppression.

**The 4 remaining `court_or_authority` false positives are gold-set gaps, not rule
defects** — three of them are real authorities the gold set simply does not label in that
document:

- `Cumhuriyet Başsavcılığı'na sunulmak üzere hazırlanmıştır` (`synthetic_pleading`, which has no `court_or_authority` label at all)
- `11. Hukuk Dairesi` (`synthetic_commercial_case` labels only `Yargıtay`)
- `2. Noterliği` (`power_of_attorney` labels only `24. Noterliği`)
- `UYAP No: 2026/9981 kaydı ile dosyalanmıştır` — the one genuine over-reach left. `UYAP` is a trigger in the generic rule, so a docket reference is reported as an authority. Not fixed here: removing `UYAP` from the trigger list is a recall change on documents outside the gold set, and the docket number itself is already caught at HIGH by `case_or_investigation_number`.

### Accepted with reason: `party_role` (20 FPs, unchanged)

`party_role` was **not** tightened. Three reasons, in order of weight:

1. **The gold set contains zero `party_role` labels.** Every `party_role` finding is
   therefore a false positive *by construction of the scoring* — `label_matches_finding()`
   requires the categories to be equal, so no `party_role` finding can ever match
   anything. No amount of regex tightening moves this rule's FP count to zero; only
   deleting the category would, and that is a safety change, not a precision change. The
   absence also contradicts this README's own labelling instructions above, which ask for
   "Party roles such as davacı, davalı, müşteki, şüpheli, sanık, borçlu, and alacaklı" to
   be labelled. **The fix belongs in the gold set, not in `privacy.py`.**
2. **The obvious tightening is blocked by an existing test.** Requiring an identifying
   continuation after the role word (at most one intervening lowercase word, then a
   capitalised token or a digit — note this must be written case-sensitively with
   `(?-i:...)`, since the rule runs under `re.IGNORECASE`, where `[A-ZÇĞİÖŞÜ]` also
   matches lowercase and the whole check is vacuous) yields **zero** matches on
   `"Tanık beyanı alınmış, mağdur ifadesi dosyaya eklenmiştir."`, which
   `tests/test_turkish_legal_detection.py::TurkishLegalDetectionTests::test_detects_witness_and_victim_party_roles`
   asserts *does* produce `party_role`. That test encodes the documented intent of the
   rule: a party role is a re-identification *signal* for a reviewer to weigh, not an
   identifier.
3. **The measured gain is small and the span is already minimal.** That tightening drops
   4 of the 20 gold-set matches (`Şüpheli hakkında suç duyurusu…`, `Davalı tanık
   beyanlarına göre…`, `tanık beyanlarına göre…`, `Tanık listesi ekte sunulmuştur.`) and
   keeps 16, all still scored as false positives — precision 0.7557 → 0.7733. The rule
   already matches the role word *only*, so its samples carry no name and no national id.

Reviewer noise is still the real concern here: 20 MEDIUM `party_role` flags is the single
largest group in the queue. Address it by labelling party roles in the gold set and by
grouping same-category findings in the review UI, not by weakening detection.

### Out-of-scope observations (not changed)

- **`criminal_allegation` fires on a case number, not an allegation.**
  `Soruşturma No: 2026/123` (`synthetic_pleading`), `Soruşturma No: 2026/815`
  (`criminal_investigation`) and `Sorusturma No : 2026 / 3377` (`ocr_scan_noisy`) are
  docket references already reported at HIGH by `case_or_investigation_number`. The
  `soruşturma|sorusturma` trigger cannot tell "an investigation exists with this number"
  from "this person is accused", and it escalates to CRITICAL. `Soruşturma Bürosu` (part
  of a prosecutor's office name) is the same defect. Worth a rule that requires the
  trigger *not* to be followed by a `no/numarası` + `YYYY/NNN` shape.
- **A real address the gold set does not label.**
  `Yoğurtçu Parkı Caddesi No: 27 Daire: 6 Kadıköy` in `lease_agreement` is a genuine
  street address, and is scored as a false positive only because `lease_agreement`'s
  single `address` label is `Fenerbahçe Mahallesi`. This is the last remaining `address`
  FP and it is **not** something to tighten — the gold set should gain a second `address`
  label for that document.
- **`date` (7).** Bare `dd.mm.yyyy` dates in documents whose gold labels include no `date`
  entry. Two documents do label dates, so the category is live; the other five simply do
  not label theirs.
- **`health_data` (3) and `privileged_or_confidential` (3).** Both rules sweep up to
  120/160 characters of trailing clause, so their samples store an unrelated person's name
  and TCKN in cleartext (`hasta Leyla Kaya (TCKN: 66666666660), Özel Marmara
  Hastanesi'nde 22`, `Müvekkil Cemile Doğan (TCKN: 11111111110), Kadıköy 2`). This is the
  same span over-reach that was already fixed for `party_role` and it should be fixed the
  same way, but changing a CRITICAL rule's span is out of scope for a precision pass.
- **`bar_registration_number` (1).** `Sicil No: 123456` in `corporate_resolution` is a
  *company* registry number matched by the widened `sicil no` alternative, not a bar
  registration.
