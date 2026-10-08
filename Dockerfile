# CIMS application image.
# Build:  docker build -t cims:1.0 .
# Run:    docker run --rm -p 8000:8000 -e CIMS_SECRET_KEY=<32+ chars> cims:1.0

FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Non-root user with a fixed UID, so Kubernetes can enforce runAsNonRoot.
RUN groupadd --system --gid 10001 cims \
 && useradd --system --uid 10001 --gid cims --no-create-home --shell /usr/sbin/nologin cims

WORKDIR /app

# Install pinned dependencies first, so this layer is cached between code changes.
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

# Application code only. Tests, git history and local data are excluded by .dockerignore.
COPY app ./app

# Writable folder for the SQLite database and evidence files. Nothing else is writable.
RUN mkdir -p /app/data/evidence && chown -R 10001:10001 /app/data

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"]

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--access-logfile", "-", "app:create_app()"]
