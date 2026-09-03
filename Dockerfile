# Multi-stage build for the zuumb app service.
#   docker build -t zuumb .
#   docker run --rm -p 8000:8000 --env-file .env zuumb
# Published multi-arch (amd64+arm64) to ghcr.io/<owner>/zuumb by
# .github/workflows/publish.yml on a v*.*.* tag.

# ---- build: install deps into an isolated venv --------------------------------
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt .
RUN python -m venv /venv && /venv/bin/pip install -r requirements.txt

# ---- runtime: slim image, non-root, just the venv + app ----------------------
FROM python:3.12-slim AS runtime
ENV PATH=/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATABASE_URL=sqlite:////data/zuumb.db
WORKDIR /app

COPY --from=build /venv /venv
COPY app/ app/
COPY prompts/ prompts/
COPY scripts/ scripts/
COPY eval/ eval/
COPY data/synthetic_alerts/ data/synthetic_alerts/

# non-root, plus a writable /data for the SQLite file (mount a volume here)
RUN useradd -u 10001 -M -s /usr/sbin/nologin zuumb \
 && mkdir -p /data && chown zuumb:zuumb /data
USER zuumb

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/',timeout=3).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
