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

The key goal is `false_low_count = 0`.
