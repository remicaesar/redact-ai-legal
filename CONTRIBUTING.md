# Contributing

This is a local-first, single-user Flask prototype written by a practising
Turkish lawyer. It classifies Turkish legal documents, detects privacy
findings with regular expressions plus check-digit validation and a Turkish
name gazetteer, and gates every export on human review. There is no AI or
network egress in it; keep it that way unless a change is discussed first.

## Setup

For a populated local evaluation with bundled OCR, use `./start.sh` after starting
Docker. See the [README](README.md#try-it-locally) for persistence and reset behavior.
For development without Docker, install the OCR system packages listed in the
[manual setup](README.md#run-without-docker), then:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export LEGAL_ANALYZER_ADMIN_PASSWORD="change-this-local-password"
export LEGAL_ANALYZER_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 db/init_db.py
python3 db/migrate.py
python3 classify.py
python3 app.py
```

Open `http://127.0.0.1:5000`.

## Tests

Tests use `unittest`, not `pytest` (there is no `pytest` in `requirements.txt`).
Run the full suite with:

```bash
python -W error::ResourceWarning -m unittest discover -s tests -t .
```

Running a single test file directly does **not** work:

```bash
python tests/test_privacy.py   # fails: ModuleNotFoundError
```

Use the module path instead:

```bash
python -m unittest tests.test_privacy
python -m unittest tests.test_privacy.PrivacyTests.test_some_method   # single test
```

Run `python3 accuracy_audit.py --labels gold/gold_labels.example.json` after
touching `legal_analyzer/privacy.py` detection rules or extraction/OCR logic —
it is not a unit test, but it is the only thing that checks recall/precision
against the gold set, and a regression there is a privacy regression.

## Migrations

Migrations are forward-only. Add a new numbered `.sql` file under
`db/migrations/`; never edit an already-applied migration or retroactively
change `db/schema.sql` to fix an existing database — `db/schema.sql` is only
used by `db/init_db.py` for a fresh database. Run `python3 db/migrate.py
--status` to check applied state and `python3 db/migrate.py` to apply pending
migrations.

## Terminology

`redaction`, `pseudonymization`, `de-identification`, and `anonymization` are
defined once, in `legal_analyzer/taxonomy.py` (`TERMINOLOGY`,
`OUTPUT_POSITIONING`). Use those definitions consistently in code, UI copy, and
API responses rather than introducing new synonyms or loosening the
distinction — the project exists specifically to avoid claiming a document is
"anonymous" when it has only been redacted or pseudonymized.

## The red-proof rule

Every new guard or invariant needs a test that has been **observed to fail**
when the code it guards is broken — not just a test that is green today. When
you add a check (a safety gate condition, a validation rule, a detection
pattern), before you consider it done:

1. Write the test.
2. Break the production code the test is supposed to guard (invert the
   comparison, remove the guard, return the wrong value).
3. Re-run that specific test and confirm it fails.
4. Restore the code and confirm the test passes again.

A test that stays green through step 2 does not test what its name claims.
This matters most around the safety gates in `legal_analyzer/privacy.py`
(external-LLM release gate, residual-risk computation) — see `CLAUDE.md` for
which invariants must not be weakened without explicit discussion.

## Pull requests

- Keep changes focused on one concern; do not mix a detection-rule change with
  an unrelated refactor.
- Use only synthetic documents and synthetic personal data in tests and
  fixtures — never real client or case files.
- Describe what you verified (tests run, red-proof pairs) in the PR
  description; a green suite alone is not evidence for a new invariant.
