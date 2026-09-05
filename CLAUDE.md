# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A cautious legal-tech prototype (Flask + SQLite) for classifying Turkish/English legal documents and preparing privacy-reviewed, risk-reduced outputs for LLM workflows. It deliberately avoids claiming outputs are "anonymous" unless re-identification risk has been assessed as genuinely low — see `legal_analyzer/taxonomy.py` (`TERMINOLOGY`, `OUTPUT_POSITIONING`) for the redaction/pseudonymization/de-identification/anonymization distinctions used throughout the UI, API, and code comments.

## Setup and running

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

App runs at `http://127.0.0.1:5000` (the `.claude/launch.json` config runs it on port 5001 instead, with `LEGAL_ANALYZER_ADMIN_PASSWORD=<a strong local password>`). The first local admin user is created from `LEGAL_ANALYZER_ADMIN_USERNAME` (default `admin`) / `LEGAL_ANALYZER_ADMIN_PASSWORD` env vars on first DB connection (`bootstrap_admin_from_env` in `app.py`).

### Database migrations

Migrations are plain `.sql` files in `db/migrations/`, applied in filename-sort order and tracked in a `schema_migrations` table (`db/migrate.py`). `ensure_db_ready()` in `app.py` calls `apply_migrations` automatically on first DB connection per process, so the app self-migrates — but run `python3 db/migrate.py --status` to check state, and `python3 db/migrate.py` to apply manually (e.g. after pulling new migrations before running tests). To add a migration, add a new numbered `.sql` file to `db/migrations/`; don't edit `db/schema.sql` retroactively for existing databases (it's only used by `db/init_db.py` for fresh DBs).

## Tests

Tests use `unittest`, not pytest (no pytest in `requirements.txt`). Each test file is run via `python -m unittest tests.<module>` (direct `python tests/x.py` fails with ModuleNotFoundError):

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
python3 benchmark.py --api-iterations 1000 --api-concurrency 50    # local concurrency check (still not real load testing)
```

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
- `pdf_redactor.py` — actual reviewed PDF redaction via PyMuPDF, driven by reviewer-approved coordinate regions (not the browser preview overlay, which is UI-only). Includes PDF export QA (extractable-text leak checks attributed to specific `region_id`s, metadata scrubbing, annotation removal).

**`classify.py`** — the standalone indexing script: scans a document root (`DEFAULT_STOCK_DIR`) plus extra files, extracts/classifies/privacy-analyzes each, and populates the `documents` table. `detect_client()` matches filenames/text against known client aliases in the `clients` table.

**`db/`** — SQLite schema (`schema.sql`, used only for fresh init) + forward-only migrations (`migrations/*.sql`, tracked via `schema_migrations`). Key tables: `documents`, `clients`, `matters`, plus findings, audit_log, OCR pages/tokens, and PDF redaction regions (see schema for exact columns). `data/exports/document_<id>/` stores saved reviewed export artifacts, referenced by the artifact timeline.

**`templates/`** + **`static/`** — server-rendered Jinja UI. `studio.html` is the large Redaction Studio workspace (PDF viewer + region drawing, finding review, OCR review). The in-browser PDF viewer is a vendored PDF.js build under `static/vendor/pdfjs/` — no CDN dependency.

### Safety gates (do not weaken without explicit instruction)

External hosted LLM use is gated on ALL of: extraction complete, residual risk Low, zero critical findings, no direct identifiers remaining, redaction completed, and human review approved (unless explicit auto-mode). Any extraction warning (`Partial`/`Failed`) blocks external LLM use until OCR/manual review resolves it. Detected findings are not the same as successfully redacted findings — only findings with `approved` or `added_by_reviewer` status get redacted on export. If OCR text is accepted without coordinate tokens, native PDF export fails closed until manual boxes are drawn and approved. Raw sensitive text, original-to-placeholder mappings, OCR text, passwords, and replacement text must never be written to `audit_log` metadata or artifact-timeline metadata.

### Matter/document API surface (for orientation, not exhaustive)

Matters group documents; review/export flows operate per-document. See `README.md` for the full endpoint list (matters, OCR queue/run/accept/reject, PDF region CRUD/approve/reject/generate, redacted-export + QA for DOCX/PDF). When adding endpoints that touch findings, redaction, or export, follow the existing gate-checking pattern in `app.py` rather than introducing a new path around `refresh_release_state()`.
