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
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS document_matters (
    document_id INTEGER PRIMARY KEY,
    matter_id INTEGER NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (matter_id) REFERENCES matters(id) ON DELETE CASCADE
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

CREATE INDEX IF NOT EXISTS idx_matters_client ON matters(client_id);
CREATE INDEX IF NOT EXISTS idx_matters_status ON matters(status);
CREATE INDEX IF NOT EXISTS idx_document_matters_matter ON document_matters(matter_id);
CREATE INDEX IF NOT EXISTS idx_document_artifacts_document ON document_artifacts(document_id);
CREATE INDEX IF NOT EXISTS idx_document_artifacts_matter ON document_artifacts(matter_id);
CREATE INDEX IF NOT EXISTS idx_document_artifacts_type ON document_artifacts(artifact_type);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding ON finding_evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_document ON finding_evidence(document_id);

INSERT OR IGNORE INTO matters (name, status, description)
VALUES ('Unassigned', 'active', 'Default local matter for documents without an explicit matter selection.');

INSERT OR IGNORE INTO document_matters (document_id, matter_id)
SELECT d.id, m.id
FROM documents d
JOIN matters m ON m.name = 'Unassigned';
