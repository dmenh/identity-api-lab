FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="Identity API Lab" \
      org.opencontainers.image.authors="Dinesh" \
      org.opencontainers.image.url="https://www.linkedin.com/in/dineshwarmanukonda/" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary" \
      org.opencontainers.image.version="1.5.0"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 FRONTEND_DIST=/app/frontend/dist
WORKDIR /app
COPY backend/requirements.txt ./backend/requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip==26.2.2 \
    && pip install --no-cache-dir -r backend/requirements.txt \
    && useradd --create-home --uid 10001 lab
COPY backend/ ./backend/
COPY scripts/ ./scripts/
COPY --from=frontend /build/dist ./frontend/dist
RUN mkdir -p /app/data && chown -R lab:lab /app
USER lab
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
