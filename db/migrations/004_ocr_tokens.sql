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

CREATE INDEX IF NOT EXISTS idx_ocr_tokens_document ON ocr_tokens(document_id);
CREATE INDEX IF NOT EXISTS idx_ocr_tokens_page ON ocr_tokens(document_id, page_number);
