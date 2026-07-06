# syntax=docker/dockerfile:1

# Pinned slim base (supply-chain: A06:2021). Pin the digest too in a real
# pipeline; the tag is the minimum. slim = smaller attack surface than full.
FROM python:3.12-slim-bookworm

# Don't buffer stdout (so logs flush immediately) and don't write .pyc.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install deps first (layer caching): copy only requirements, then install.
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt gunicorn==23.*

# Copy application code. .dockerignore keeps secrets/tests/caches OUT.
COPY . .

# Run as a non-root user (privilege reduction: if the app is compromised, the
# attacker does not get root inside the container).
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

# Render provides $PORT. Bind to it. Gunicorn manages uvicorn workers:
#  - workers 2: modest concurrency for a small instance. NOTE: each worker has
#    its OWN in-memory rate-limiter/spend-cap state, so >1 worker multiplies the
#    effective caps. For correct global caps with multiple workers, move those
#    stores to Redis first (tracked limitation). Until then, consider workers=1.
#  - timeout 30: bound a stuck request (e.g. a hung provider call) so a worker
#    can't be tied up indefinitely (resource-exhaustion mitigation).
ENV PORT=8000
CMD gunicorn main:app \
    --worker-class uvicorn.workers.UvicornWorker \
    --workers 1 \
    --timeout 30 \
    --bind 0.0.0.0:${PORT} \
    --access-logfile - \
    --error-logfile -
