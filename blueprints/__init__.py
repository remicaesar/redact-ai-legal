"""Route blueprints for the legal document analyzer Flask app.

Each module holds the HTTP routes for one functional area. Shared
infrastructure (DB access, auth decorators, audit logging, release-gate
refresh) lives in ``app.py`` — blueprints import helper functions from
there and must route every finding/OCR/region mutation through
``refresh_document_state`` so the external-LLM release gate stays accurate.
"""
