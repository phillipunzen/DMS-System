FROM node:22-bookworm-slim AS codex
RUN npm install --global --no-audit --no-fund @openai/codex@0.162.1 && find /usr/local/lib/node_modules/@openai -type f -name codex -exec cp {} /codex \;
FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
LABEL org.opencontainers.image.source="https://github.com/phillipunzen/DMS-System"
WORKDIR /service
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock
COPY --from=codex /codex /usr/local/bin/codex
RUN chmod 755 /usr/local/bin/codex && groupadd -g 10002 codex && useradd -u 10002 -g codex -m codex && mkdir -p /data/codex && chown -R codex:codex /data/codex
COPY --chown=codex:codex codex_service ./codex_service
COPY --chown=codex:codex dms_contracts ./dms_contracts
USER codex
EXPOSE 8001
CMD ["python", "-m", "uvicorn", "codex_service.server:app", "--host", "0.0.0.0", "--port", "8001", "--no-access-log"]
