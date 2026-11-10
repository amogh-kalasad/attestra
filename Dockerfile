# Attestra image: one image, two roles.
#   API:    docker run attestra:dev                      (default CMD = serve)
#   Worker: docker run attestra:dev attestra worker
# Build:   docker build -t attestra:dev .
# Scanners are NOT bundled; they run as separate digest-pinned Kubernetes Jobs
# (or host `docker run` from the worker). MongoDB (replica set) is required;
# Mongo schema init lives in the attestra package (no Alembic/SQL migrations).

FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY attestra ./attestra
RUN pip wheel --wheel-dir /wheels "."

FROM python:3.12-slim
ARG TARGETARCH
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    ATTESTRA_DATA_DIR=/data \
    ATTESTRA_PERSISTENCE=mongo \
    ATTESTRA_STORAGE=mongo \
    ATTESTRA_MONGODB_URI=mongodb://mongo:27017/?replicaSet=rs0 \
    ATTESTRA_MONGODB_DB=attestra
# ATTESTRA_MONGODB_URI above is compose-friendly (hostname `mongo`, no auth).
# Production MUST override with credentials (and usually TLS), e.g. via Secret —
# do not bake passwords into the image.
# Docker CLI (client only) for compose/dev worker docker-out-of-Docker against a
# mounted host socket. Scanners are still separate digest-pinned images, not baked in.
RUN groupadd --system --gid 10001 attestra \
 && useradd --system --uid 10001 --gid attestra --home-dir /app --shell /usr/sbin/nologin attestra \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && arch="$(case "${TARGETARCH:-amd64}" in amd64) echo x86_64;; arm64) echo aarch64;; *) echo x86_64;; esac)" \
 && curl -fsSL "https://download.docker.com/linux/static/stable/${arch}/docker-27.5.1.tgz" -o /tmp/docker.tgz \
 && tar -xzf /tmp/docker.tgz -C /tmp \
 && mv /tmp/docker/docker /usr/local/bin/docker \
 && chmod 755 /usr/local/bin/docker \
 && rm -rf /tmp/docker /tmp/docker.tgz \
 && apt-get purge -y curl \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
RUN mkdir -p /data && chown attestra:attestra /data
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4); sys.exit(0)" || exit 1
CMD ["attestra", "serve", "--host", "0.0.0.0", "--port", "8000"]
