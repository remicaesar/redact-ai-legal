FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    LEGAL_ANALYZER_STOCK_DIR=/app/samples/documents
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr tesseract-ocr-tur tesseract-ocr-eng poppler-utils \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /tmp/requirements.txt
COPY docker/requirements.txt /tmp/docker-requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt -r /tmp/docker-requirements.txt
COPY . /app
RUN useradd --uid 10001 --create-home workstation \
    && mkdir -p /state /app/data \
    && ln -s /state/legal_documents.db /app/db/legal_documents.db \
    && chown -R workstation:workstation /state /app/data
USER workstation
ENTRYPOINT ["python", "docker/bootstrap.py"]
