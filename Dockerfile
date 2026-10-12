FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-deu tesseract-ocr-eng poppler-utils libmagic1 tini cifs-utils nfs-common && rm -rf /var/lib/apt/lists/*
LABEL org.opencontainers.image.source="https://github.com/phillipunzen/DMS-System"
WORKDIR /app
COPY requirements.lock .
RUN pip install -r requirements.lock
RUN groupadd -g 10001 dms && useradd -u 10001 -g dms -m dms && mkdir -p /data/documents /data/consume /data/scanner /data/storage-state /data/nas && chown -R dms:dms /data
COPY --chown=dms:dms app ./app
COPY --chown=dms:dms storage_service ./storage_service
COPY --chown=dms:dms dms_contracts ./dms_contracts
COPY --chown=dms:dms migrations ./migrations
COPY --chown=dms:dms alembic.ini ./
COPY --chown=dms:dms scripts ./scripts
COPY --chown=dms:dms scripts/entrypoint.sh /entrypoint.sh
USER dms
EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
