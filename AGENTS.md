# AGENTS.md

This file provides guidance to Codex when working with code in this repository.

## What this is

A cautious legal-tech prototype (Flask + SQLite) for classifying Turkish/English legal documents and preparing privacy-reviewed, risk-reduced outputs for LLM workflows. It deliberately avoids claiming outputs are "anonymous" unless re-identification risk has been assessed as genuinely low — see `legal_analyzer/taxonomy.py` (`TERMINOLOGY`, `OUTPUT_POSITIONING`) for the redaction/pseudonymization/de-identification/anonymization distinctions used throughout the UI, API, and code comments.

## Non-negotiable engineering constraints

- Do not weaken privacy, redaction, OCR, or export safety gates.
- Do not bypass human review or approval requirements.
- Detection is not equivalent to completed redaction.
- Do not expose pseudonym mappings in exports, logs, or frontend responses.
- Do not place raw sensitive document text in audit metadata.
- Preserve role-based permissions and authentication.
- Preserve fail-closed behavior.
- Preserve existing backend route contracts unless the user explicitly approves changes.
- Do not send document contents to external services.
- Use only synthetic documents and synthetic personal data in tests.
- Do not delete functionality merely because it is difficult to redesign.
- Avoid introducing a new frontend framework unless the existing architecture clearly cannot support the required interface.

## Frontend direction

- Create a premium, restrained legal-tech interface.
- Organize the experience around matters rather than database records.
- Make the document the center of the review workspace, with contextual AI assistance beside it.
- Use progressive disclosure for technical information.
- Support accessible, keyboard-driven review.
- Present one obvious primary action per screen.
- Use a warm off-white background, white surfaces, near-black text, and a restrained indigo accent.
- Avoid generic SaaS dashboard patterns, glassmorphism, excessive gradients, giant KPI cards, robot imagery, magic-wand icons, and decorative AI effects.

## Required working method

Before changing code, inspect the relevant routes, templates, styles, JavaScript, tests, and data flow. Keep changes focused, preserve existing behavior unless a change is explicitly approved, run tests appropriate to the modified surface, and report exactly what changed.

## Setup and running

For the Docker onboarding path, use `./start.sh`; see `README.md` for prerequisites,
persistent volumes, credentials, and the destructive `--reset` option. Setup lives
in `docker/bootstrap.py`; `samples/README.md` explains the fictional practice files.
Run `python -m unittest tests.test_onboarding` when changing that surface.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export LEGAL_ANALYZER_ADMIN_PASSWORD="change-this-local-password"
python3 db/init_db.py       # safe: keeps an existing db/legal_documents.db and tops it up
python3 db/init_db.py --reset  # DESTRUCTIVE: prints row counts, then wipes and reseeds
python3 db/migrate.py       # apply pending migrations to an existing db
python3 classify.py         # scans DEFAULT_STOCK_DIR + extra files, populates the db
python3 app.py
```

App runs at `http://127.0.0.1:5000`. Set `LEGAL_ANALYZER_ADMIN_PASSWORD` and `LEGAL_ANALYZER_SECRET_KEY` in your environment; neither has a default and the app refuses to start without the secret key. The first local admin user is created from `LEGAL_ANALYZER_ADMIN_USERNAME` (default `admin`) / `LEGAL_ANALYZER_ADMIN_PASSWORD` env vars on first DB connection (`bootstrap_admin_from_env` in `app.py`).


### Database migrations

Migrations are plain `.sql` files in `db/migrations/`, applied in filename-sort order and tracked in a `schema_migrations` table (`db/migrate.py`). `ensure_db_ready()` in `app.py` calls `apply_migrations` automatically on first DB connection per process, so the app self-migrates — but run `python3 db/migrate.py --status` to check state, and `python3 db/migrate.py` to apply manually (e.g. after pulling new migrations before running tests). To add a migration, add a new numbered `.sql` file to `db/migrations/`; don't edit `db/schema.sql` retroactively for existing databases (it's only used by `db/init_db.py` for fresh DBs).

Two constraints make column *removal* impractical here, so prefer retiring a column in place (annotate it in `db/schema.sql`, delete every read, pin that with a test):

- **A migration may not reference any `documents` column beyond `id`/`filename`/`filepath`.** `tests/test_migrations.py::test_existing_database_upgrades_without_data_loss` applies the whole chain to a three-column legacy table, so anything else — even in a `WHERE` clause or an index — fails the suite.
- **`db/schema.sql` must stay the state a database actually ends up in.** `tests/test_csrf.py`, `test_app_workflow.py`, `test_gate_reachability.py` and `test_landing.py` build their database from it *without* running migrations, so a column dropped by a migration but still listed there (or vice versa) makes every test database disagree with every real one.

SQLite has no `DROP COLUMN IF EXISTS`, and the only idempotent alternative is a twelve-step rebuild of `documents` — the table the FTS5 content-table, its three triggers, nine indexes and every foreign key hang off.

## Tests

Tests use `unittest`, not pytest (no pytest in `requirements.txt`). Run files as modules:

```bash
python3 -m unittest tests.test_app_workflow
python3 -m unittest tests.test_app_workflow.AppWorkflowTests.test_some_method   # single test
python3 -m unittest discover -s tests -t .
```

Tests generally build fixtures in-memory or under a `TemporaryDirectory` and construct a fresh SQLite DB per test (see `tests/test_app_workflow.py`) rather than touching `db/legal_documents.db`.

The `-t .` on the discover command is load-bearing. It makes `tests` import as a package, which runs `tests/__init__.py` — that file points `app.test_client_class` at a client which carries the session CSRF token. Without it the package is skipped, every state-changing request in the suite arrives with no token, and ~58 tests fail with 403. CSRF protection is deliberately *not* disabled under test: `tests/test_csrf.py` uses a raw `FlaskClient` to prove the check still rejects. Anything that calls `reload(app_module)` must re-run `install_csrf_client()` afterwards, since the reload builds a new Flask object with the default client (see `reload_app()` in `tests/test_app_hardening.py`).

## Accuracy and benchmark tooling

These are not unit tests but repo-specific validation scripts — run them after touching `legal_analyzer/privacy.py` detection rules or extraction/OCR logic:

```bash
python3 accuracy_audit.py --labels gold/gold_labels.example.json   # recall/precision against a hand-labeled gold set; watch false_low_count == 0 and risk_shortfall_count == 0
python3 benchmark.py                                               # full benchmark -> benchmark_report.json
python3 benchmark.py --limit 25 --api-iterations 5                 # fast smoke benchmark
python3 benchmark.py --stock-dir tests/fixtures --api-iterations 5  # measures the detection pipeline on synthetic data only
python3 benchmark.py --api-iterations 1000 --api-concurrency 50    # local concurrency check (still not real load testing)
```

`benchmark.py` imports `app`, so it exits immediately unless `LEGAL_ANALYZER_SECRET_KEY`
is set — it refuses to invent a session-signing key. Its `pipeline` arm also measures
whatever `--stock-dir` points at, defaulting to `DEFAULT_STOCK_DIR` (`documents/`); when
that directory is absent the run still succeeds and reports `documents: 0`, so a green
benchmark proves nothing about extraction/classification/privacy timing. Point it at
`tests/fixtures` for a run that exercises the pipeline without touching real documents.

`gold/` holds the synthetic gold-label set (17 documents, 117 required labels) used to validate the Turkish/English PII detection rules — extend it with real labeled documents before trusting it for production accuracy claims.

## Architecture

**`app.py`** (~950 lines) is the shared core: the Flask app object and its config, DB access, session-based auth/RBAC (`admin`/`reviewer`/`viewer`), audit logging, document persistence helpers, and the release-gate refresh. HTTP routes live in `blueprints/` and import these helpers. It does not contain detection/extraction/redaction logic itself — it calls into `legal_analyzer/*` and `classify.py`.

**`legal_analyzer/`** — the core domain logic, split by concern:
- `taxonomy.py` — category/subcategory vocabulary, supported file extensions, terminology definitions (redaction vs. pseudonymization vs. de-identification vs. anonymization). Other modules import from here rather than hardcoding categories.
- `classifier.py` — document classification (category/subcategory), title/date/language/version detection.
- `extraction.py` — text extraction across DOCX, PDF, UDF, TXT/MD, PPTX, XLSX, legacy DOC (via macOS `textutil`), and ZIP containers (nested ZIPs skipped). Marks extraction `Complete`/`Partial`/`Failed`, degrading status when the size cap truncates output.
- `privacy.py` — the PII/privacy-risk detection engine: `DETECTION_RULES` (regex-based, Turkish-aware — e.g. TCKN/VKN check-digit validation, court/notary/case-number patterns, dotted-İ handling), `analyze_privacy()`, `refresh_release_state()`, and the external-LLM release gate logic (`DIRECT_IDENTIFIER_CATEGORIES`, `EXTERNAL_LLM_BLOCKED`/`EXTERNAL_LLM_ALLOWED`). This is the most safety-critical module — see "Safety gates" below before changing it.
- `ocr.py` — local-first OCR (`tesseract` + `pdftoppm` via `brew install tesseract tesseract-lang poppler`). OCR text is stored separately from extracted text and never affects findings/redaction/release-readiness until a reviewer explicitly accepts it (`ocr/accept` endpoint). Tesseract TSV output captures word bounding boxes (`ocr_tokens`) used to map accepted OCR findings to PDF coordinate boxes.
- `docx_redactor.py` / `docx_quality.py` — actual reviewed DOCX redaction (in-place text redaction across body/tables/headers/footers/footnotes/endnotes/comments, preserving package structure) and its QA checks (package parts, XML node/paragraph/table counts, approved-target leakage).
- `redaction_plan.py` — the ONE post-decision rendering. The browser review canvas and the reviewed DOCX export must both resolve through it (it calls `docx_redactor.resolve_redaction_regions`), or they drift apart and a lawyer approves a rendering that is not the deliverable. Do not add a third. (There were three: the "Preview TXT / Preview DOCX (lower assurance)" export was deleted — a rebuilt `<name>_redacted.txt` headed `PRIVACY-REVIEWED REDACTED EXPORT` whose pre-decision body was the unredacted source.) `privacy.build_redacted_preview` is NOT a rendering — it is the detection-time measurement stored on the profile, like `residual_risk`.
- `pdf_redactor.py` — actual reviewed PDF redaction via PyMuPDF, driven by reviewer-approved coordinate regions (not the browser preview overlay, which is UI-only). Includes PDF export QA (extractable-text leak checks attributed to specific `region_id`s, metadata scrubbing, annotation removal).

**`classify.py`** — the standalone indexing script: scans a document root (`DEFAULT_STOCK_DIR`) plus extra files, extracts/classifies/privacy-analyzes each, and populates the `documents` table. `detect_client()` matches filenames/text against known client aliases in the `clients` table.

**`db/`** — SQLite schema (`schema.sql`, used only for fresh init) + forward-only migrations (`migrations/*.sql`, tracked via `schema_migrations`). Key tables: `documents`, `clients`, `matters`, plus findings, audit_log, OCR pages/tokens, and PDF redaction regions (see schema for exact columns). `data/exports/document_<id>/` stores saved reviewed export artifacts, referenced by the artifact timeline.

**`templates/`** + **`static/`** — server-rendered Jinja UI. `studio.html` is the large Redaction Studio workspace (PDF viewer + region drawing, finding review, OCR review). The in-browser PDF viewer is a vendored PDF.js build under `static/vendor/pdfjs/` — no CDN dependency.

### Safety gates (do not weaken without explicit instruction)

External hosted LLM use is gated on ALL of: extraction complete, residual risk Low, zero critical findings, no direct identifiers remaining, redaction completed, and human review approved. Human approval has no substitute: the `auto_mode_enabled` arm that once stood in for it was removed, `documents.auto_mode_enabled` is a retired column no code reads, and `tests/test_auto_mode_removed.py` fails if any read comes back. Any extraction warning (`Partial`/`Failed`) blocks external LLM use until OCR/manual review resolves it. Detected findings are not the same as successfully redacted findings — only findings with `approved` or `added_by_reviewer` status get redacted on export. If OCR text is accepted without coordinate tokens, native PDF export fails closed until manual boxes are drawn and approved. Raw sensitive text, original-to-placeholder mappings, OCR text, passwords, and replacement text must never be written to `audit_log` metadata or artifact-timeline metadata.

A finding's `sample` must never contain a newline. Redaction is a string match against a DOCX part, whose text is the concatenation of its `w:t` runs, and `build_part_spans` inserts the paragraph breaks that `extraction` also sees — but a span the detector let run across a line break still matches nothing there, so it can never be removed from the deliverable however it was reviewed. Every detection rule bounds its trailing context with `[^\n]` for this reason; the person-name regexes use `[ \t]+` between name tokens (`privacy._NAME_SEP`, `turkish_names._SEP`). `tests/test_redaction_parity.py` asserts the invariant across the fixture corpus.


### Matter/document API surface (for orientation, not exhaustive)

Matters group documents; review/export flows operate per-document. See `README.md` for the full endpoint list (matters, OCR queue/run/accept/reject, PDF region CRUD/approve/reject/generate, redacted-export + QA for DOCX/PDF). When adding endpoints that touch findings, redaction, or export, follow the existing gate-checking pattern in `app.py` rather than introducing a new path around `refresh_release_state()`.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
