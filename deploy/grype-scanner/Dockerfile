# Fleet Terminal grype-scanner sidecar: wraps Anchore Grype so the vulnerability
# database and scanner run in their own container, isolated from the Go backend.
# The vulnerability DB is NOT baked into the image — it is fetched at runtime via
# /db/update (online) or /db/import (offline) and persisted in a volume.
FROM python:3.12-slim

# Empty = install the latest release (its DB schema is the one Anchore actively
# publishes). Pin a specific vX.Y.Z here for reproducible builds if desired.
ARG GRYPE_VERSION=

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
        | sh -s -- -b /usr/local/bin ${GRYPE_VERSION} \
    && apt-get purge -y curl && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py /app/app.py

# Unprivileged; the scanner never needs root. The DB cache lives under its home so
# a mounted volume persists the (large) vulnerability database across restarts.
#
# Create the DB cache directory owned by the scanner user BEFORE it becomes a
# volume mount point. Docker seeds a fresh named volume from the image's content
# and ownership at the mount path, so pre-creating it here makes new volumes
# writable by uid 10001. Without this, Docker creates the empty volume as root and
# grype (running as scanner) cannot mkdir its download dir — "permission denied".
RUN useradd --create-home --uid 10001 scanner \
    && mkdir -p /home/scanner/.cache/grype/db \
    && chown -R scanner:scanner /home/scanner/.cache
USER scanner
# Don't auto-update mid-scan (updates are explicit, for air-gap support), and
# don't reject a self-managed DB on age — operators control DB freshness and the
# UI surfaces the DB's build date.
ENV GRYPE_DB_AUTO_UPDATE=false \
    GRYPE_DB_VALIDATE_AGE=false \
    GRYPE_DB_CACHE_DIR=/home/scanner/.cache/grype/db

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
