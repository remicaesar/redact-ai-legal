PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    name_tr TEXT NOT NULL,
    icon TEXT DEFAULT 'DOC',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS subcategories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    name_tr TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(id),
    UNIQUE(category_id, name)
);

CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    aliases TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS matters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    client_id INTEGER,
    status TEXT DEFAULT 'active',
    description TEXT,
    created_by INTEGER,
    reviewed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL UNIQUE,
    file_extension TEXT,
    file_size INTEGER,
    client_id INTEGER,
    category_id INTEGER,
    subcategory_id INTEGER,
    title TEXT,
    language TEXT DEFAULT 'TR',
    version TEXT,
    date_detected TEXT,
    extraction_warning TEXT,
    extraction_status TEXT DEFAULT 'Unknown',
    privacy_profile TEXT,
    residual_risk TEXT DEFAULT 'Unknown',
    risk_summary TEXT,
    recommended_strategy TEXT,
    external_llm_readiness TEXT DEFAULT 'Unknown',
    human_review_required INTEGER DEFAULT 1,
    redaction_status TEXT DEFAULT 'Detected findings only - not redacted successfully',
    redaction_completed INTEGER DEFAULT 0,
    human_review_approved INTEGER DEFAULT 0,
    -- RETIRED, read by nothing. This was the auto-mode release bypass: the release
    -- gate and the reviewed DOCX/PDF exports accepted it in place of
    -- human_review_approved, and it could only ever let a document out that no
    -- person had approved. Every read is gone; tests/test_auto_mode_removed.py
    -- fails if one comes back. The column itself is kept because SQLite has no
    -- DROP COLUMN IF EXISTS and no migration here may touch a documents column
    -- (see "Migrations" in AGENTS.md), so dropping it would split this file from
    -- every already-migrated database. Do not read it, and do not write it.
    auto_mode_enabled INTEGER DEFAULT 0,
    review_status TEXT DEFAULT 'pending_review',
    ocr_status TEXT DEFAULT 'not_required',
    reviewed_at TIMESTAMP,
    is_archive INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(id),
    FOREIGN KEY (category_id) REFERENCES categories(id),
    FOREIGN KEY (subcategory_id) REFERENCES subcategories(id)
);

CREATE TABLE IF NOT EXISTS document_matters (
    document_id INTEGER PRIMARY KEY,
    matter_id INTEGER NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (matter_id) REFERENCES matters(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS document_tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    UNIQUE(document_id, tag)
);

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

CREATE TABLE IF NOT EXISTS pseudonym_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    finding_id INTEGER,
    original_text TEXT NOT NULL,
    replacement_text TEXT NOT NULL,
    category TEXT NOT NULL,
    restricted INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (finding_id) REFERENCES privacy_findings(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS document_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    matter_id INTEGER,
    artifact_type TEXT NOT NULL,
    label TEXT NOT NULL,
    file_path TEXT,
    metadata TEXT,
    export_style TEXT,
    qa_status TEXT,
    actor_id INTEGER,
    actor_username TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (matter_id) REFERENCES matters(id) ON DELETE SET NULL,
    FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS finding_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    document_id INTEGER NOT NULL,
    source_part TEXT,
    page_number INTEGER,
    start_offset INTEGER,
    end_offset INTEGER,
    context TEXT,
    verification_status TEXT DEFAULT 'pending_export',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES privacy_findings(id) ON DELETE CASCADE,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pdf_redaction_regions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    finding_id INTEGER,
    page_number INTEGER NOT NULL,
    x0 REAL NOT NULL,
    y0 REAL NOT NULL,
    x1 REAL NOT NULL,
    y1 REAL NOT NULL,
    category TEXT NOT NULL,
    source TEXT DEFAULT 'manual',
    review_status TEXT DEFAULT 'pending',
    reviewer_note TEXT,
    confidence REAL,
    fingerprint TEXT,
    created_by INTEGER,
    reviewed_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (finding_id) REFERENCES privacy_findings(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE(document_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS ocr_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    ocr_page_id INTEGER,
    page_number INTEGER NOT NULL,
    text TEXT NOT NULL,
    confidence REAL,
    x0 REAL NOT NULL,
    y0 REAL NOT NULL,
    x1 REAL NOT NULL,
    y1 REAL NOT NULL,
    source TEXT DEFAULT 'tesseract_tsv',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (ocr_page_id) REFERENCES ocr_pages(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ocr_pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    page_number INTEGER NOT NULL,
    text TEXT DEFAULT '',
    confidence REAL,
    status TEXT DEFAULT 'completed',
    source TEXT DEFAULT 'local',
    reviewer_note TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    UNIQUE(document_id, page_number)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'reviewer', 'viewer')),
    active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP
);

-- Failed-login records backing the /login throttle. Mirrors
-- db/migrations/005_login_throttle.sql, which brings existing databases
-- forward; this copy is what a fresh database is built from.
--
-- Operational state, not evidence: rows are deleted once they age out of the
-- window or the user signs in. audit_log keeps the permanent record.
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    remote_addr TEXT NOT NULL DEFAULT '',
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_pair ON login_attempts(username, remote_addr, attempted_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_addr ON login_attempts(remote_addr, attempted_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    actor_username TEXT,
    actor_role TEXT,
    action TEXT NOT NULL,
    document_id INTEGER,
    result TEXT NOT NULL DEFAULT 'success',
    metadata TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE SET NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
    filename,
    title,
    risk_summary,
    content='documents',
    content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
    INSERT INTO documents_fts(rowid, filename, title, risk_summary)
    VALUES (new.id, new.filename, new.title, new.risk_summary);
END;

CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
    INSERT INTO documents_fts(documents_fts, rowid, filename, title, risk_summary)
    VALUES ('delete', old.id, old.filename, old.title, old.risk_summary);
END;

CREATE TRIGGER IF NOT EXISTS documents_au AFTER UPDATE ON documents BEGIN
    INSERT INTO documents_fts(documents_fts, rowid, filename, title, risk_summary)
    VALUES ('delete', old.id, old.filename, old.title, old.risk_summary);
    INSERT INTO documents_fts(rowid, filename, title, risk_summary)
    VALUES (new.id, new.filename, new.title, new.risk_summary);
END;

CREATE INDEX IF NOT EXISTS idx_documents_client ON documents(client_id);
CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category_id);
CREATE INDEX IF NOT EXISTS idx_documents_subcategory ON documents(subcategory_id);
CREATE INDEX IF NOT EXISTS idx_documents_extension ON documents(file_extension);
CREATE INDEX IF NOT EXISTS idx_documents_residual_risk ON documents(residual_risk);
CREATE INDEX IF NOT EXISTS idx_documents_extraction_status ON documents(extraction_status);
CREATE INDEX IF NOT EXISTS idx_documents_external_llm_readiness ON documents(external_llm_readiness);
CREATE INDEX IF NOT EXISTS idx_documents_human_review_required ON documents(human_review_required);
-- Databases created before the auto-mode bypass was removed keep a third,
-- retired column in this index. It is a dead byte per row, not a behaviour.
CREATE INDEX IF NOT EXISTS idx_documents_release_controls ON documents(redaction_completed, human_review_approved);
CREATE INDEX IF NOT EXISTS idx_documents_review_status ON documents(review_status);
CREATE INDEX IF NOT EXISTS idx_documents_ocr_status ON documents(ocr_status);
CREATE INDEX IF NOT EXISTS idx_matters_client ON matters(client_id);
CREATE INDEX IF NOT EXISTS idx_matters_status ON matters(status);
CREATE INDEX IF NOT EXISTS idx_document_matters_matter ON document_matters(matter_id);
CREATE INDEX IF NOT EXISTS idx_privacy_findings_document ON privacy_findings(document_id);
CREATE INDEX IF NOT EXISTS idx_privacy_findings_risk ON privacy_findings(risk);
CREATE INDEX IF NOT EXISTS idx_privacy_findings_review_status ON privacy_findings(review_status);
CREATE INDEX IF NOT EXISTS idx_pseudonym_mappings_document ON pseudonym_mappings(document_id);
CREATE INDEX IF NOT EXISTS idx_document_artifacts_document ON document_artifacts(document_id);
CREATE INDEX IF NOT EXISTS idx_document_artifacts_matter ON document_artifacts(matter_id);
CREATE INDEX IF NOT EXISTS idx_document_artifacts_type ON document_artifacts(artifact_type);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding ON finding_evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_document ON finding_evidence(document_id);
CREATE INDEX IF NOT EXISTS idx_pdf_regions_document ON pdf_redaction_regions(document_id);
CREATE INDEX IF NOT EXISTS idx_pdf_regions_finding ON pdf_redaction_regions(finding_id);
CREATE INDEX IF NOT EXISTS idx_pdf_regions_review_status ON pdf_redaction_regions(review_status);
CREATE INDEX IF NOT EXISTS idx_pdf_regions_source ON pdf_redaction_regions(source);
CREATE INDEX IF NOT EXISTS idx_ocr_tokens_document ON ocr_tokens(document_id);
CREATE INDEX IF NOT EXISTS idx_ocr_tokens_page ON ocr_tokens(document_id, page_number);
CREATE INDEX IF NOT EXISTS idx_ocr_pages_document ON ocr_pages(document_id);
CREATE INDEX IF NOT EXISTS idx_ocr_pages_status ON ocr_pages(status);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_audit_log_document ON audit_log(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_username);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);

CREATE VIEW IF NOT EXISTS v_category_stats AS
SELECT
    cat.id,
    cat.name_tr AS category,
    cat.icon,
    COUNT(d.id) AS document_count,
    COUNT(DISTINCT d.client_id) AS client_count
FROM categories cat
LEFT JOIN documents d ON cat.id = d.category_id
GROUP BY cat.id
ORDER BY document_count DESC;

CREATE VIEW IF NOT EXISTS v_client_stats AS
SELECT
    c.id,
    c.name AS client,
    COUNT(d.id) AS document_count,
    GROUP_CONCAT(DISTINCT cat.name_tr) AS categories
FROM clients c
LEFT JOIN documents d ON c.id = d.client_id
LEFT JOIN categories cat ON d.category_id = cat.id
GROUP BY c.id
ORDER BY document_count DESC;
