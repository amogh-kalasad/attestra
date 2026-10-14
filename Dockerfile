# Attestra image (Phase 6.5): one image, two roles.
#   API:    docker run attestra:dev                      (default CMD = serve)
#   Worker: docker run attestra:dev attestra worker
# Build:   docker build -t attestra:dev .
# Scanners are NOT bundled; they run as separate digest-pinned Kubernetes Jobs.

FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY attestra ./attestra
COPY migrations ./migrations
COPY alembic.ini ./
RUN pip wheel --wheel-dir /wheels ".[postgres]"

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    ATTESTRA_DATA_DIR=/data
RUN groupadd --system --gid 10001 attestra \
 && useradd --system --uid 10001 --gid attestra --home-dir /app --shell /usr/sbin/nologin attestra
WORKDIR /app
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
# Alembic config + migrations are needed by `attestra init` (db.init(use_migrations=True)).
COPY --chown=attestra:attestra alembic.ini ./
COPY --chown=attestra:attestra migrations ./migrations
RUN mkdir -p /data && chown attestra:attestra /data
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/', timeout=4); sys.exit(0)" || exit 1
CMD ["attestra", "serve", "--host", "0.0.0.0", "--port", "8000"]
