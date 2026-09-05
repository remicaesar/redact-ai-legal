-- Split the single privacy_findings.review_status value 'rejected' into the two
-- decisions it was being used for:
--
--   'dismissed' — "this is a false positive, it is not sensitive." Resolved for
--                 workflow purposes, excluded from the post-review residual-risk
--                 recompute, and release may proceed. This is the reviewer's most
--                 common action: 58 of 194 findings on the gold set are false
--                 positives and 10 of those are CRITICAL-risk, so dismissing them
--                 must not be able to block release.
--   'retained'  — "this is a real identifier and I am choosing to leave it
--                 unredacted." Resolved for workflow purposes, but the identifier
--                 genuinely remains in the exported document, so it stays in the
--                 residual-risk recompute and keeps the release gate shut.
--
-- Every existing 'rejected' row becomes 'dismissed'. That is the reading which
-- preserves today's observable behaviour for data already in the database: the
-- old single status resolved the finding for review purposes, and 'dismissed' is
-- the one of the two that keeps a document releasable.
--
-- Forward-only, per the project's migration ADR — there is no down migration.
-- After this runs nothing writes 'rejected' to privacy_findings, and a stale row
-- carrying it is deliberately treated as an unrecognised status, which the
-- fail-closed logic in review_gate_counts() turns into "unresolved" and blocks.
--
-- pdf_redaction_regions.review_status keeps its own 'rejected' value: a rejected
-- redaction box is a different workflow (a box that will not be blacked out) and
-- is untouched here.

-- privacy_findings is declared in db/schema.sql and by no earlier migration, so
-- a database predating that schema (see tests/test_migrations.py's legacy
-- upgrade fixture) reaches this point without the table and the UPDATE below
-- would fail at prepare time. Re-declared here with IF NOT EXISTS, the way
-- migrations 001-004 re-declare the tables they touch; identical to schema.sql.
CREATE TABLE IF NOT EXISTS privacy_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    sample TEXT,
    risk TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    placeholder TEXT,
    replacement_text TEXT,
    review_status TEXT DEFAULT 'pending',
    reviewer_note TEXT,
    source TEXT DEFAULT 'detector',
    part_name TEXT,
    start_offset INTEGER,
    end_offset INTEGER,
    fingerprint TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_privacy_findings_review_status ON privacy_findings(review_status);

UPDATE privacy_findings SET review_status = 'dismissed' WHERE review_status = 'rejected';
