# Try a fictional matter

These are invented practice documents, written for this repository. Every file
visibly says it is synthetic. No client document or real person's data was used.
They are neither legal advice nor forms to use in a real matter.

Docker loads all three into **Synthetic practice** on first start. You can also
use **Upload document** to upload the files from `samples/documents/` yourself.

| File | Try this |
| --- | --- |
| [Turkish petition](documents/turkish_petition.docx) | Review TCKN/VKN numbers, party names, a fictional court/case reference, address and email. Decide each finding, add anything missed, then inspect the reviewed DOCX export when its gates permit it. |
| [English agreement](documents/english_agreement.docx) | Find emails and demonstration Turkish identifiers, then read the English names and addresses carefully. Coverage is materially lower than Turkish; use manual findings for omissions. |
| [Scanned receipt](documents/scanned_receipt.pdf) | This is an image-only PDF with **no text layer**. Open it, run local OCR, inspect the recovered text, and accept or reject it. OCR completion does not approve findings or export. |

Start with the Turkish petition. All findings begin pending and all samples
require review. A label saying "synthetic" does not bypass any safety gate.

## About the demonstration identifiers

Every national/tax identifier was **randomly generated for demonstration**, verified
against this repository's TCKN/VKN check-digit validators, and paired only with
invented parties. We have not associated these demonstration identifiers with any
real person or company; no real identity record was used or verified.

Passing a check-digit algorithm proves format validity, **not that a number is
unassigned**. Coincidence with an assigned number cannot be excluded. These are not
reserved test numbers and must never be used to look up, contact or represent a
real person or company. They exist only to exercise local detection and review.
Invalid numbers would not demonstrate this feature: the engine rejects them.

The names, organisations, addresses, court and events are fictional. Contact
emails use documentation domains (`example.com` / `example.org`). Do not send
email, money or a filing based on a sample. Any resemblance is coincidental.

The examples are simple one-page documents, useful for learning the workflow;
they are not an accuracy benchmark or evidence of real-world detection coverage.
