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

CREATE INDEX IF NOT EXISTS idx_pdf_regions_document ON pdf_redaction_regions(document_id);
CREATE INDEX IF NOT EXISTS idx_pdf_regions_finding ON pdf_redaction_regions(finding_id);
CREATE INDEX IF NOT EXISTS idx_pdf_regions_review_status ON pdf_redaction_regions(review_status);
CREATE INDEX IF NOT EXISTS idx_pdf_regions_source ON pdf_redaction_regions(source);
