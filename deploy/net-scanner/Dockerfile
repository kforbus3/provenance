# Provenance net-scanner sidecar: network-side vulnerability scanning (naabu port
# discovery, fingerprintx service identification, nuclei checks). Nuclei templates are
# NOT baked into the image -- like grype's database they are fetched at runtime
# (/templates/update) or imported offline (/templates/import), and persisted in a volume.
#
# The tools are built from source at pinned versions so the image is the same on
# amd64 and arm64 and nothing is fetched from a moving "latest".
FROM golang:1.26-bookworm AS tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
ARG NUCLEI_VERSION=v3.11.1
ARG NAABU_VERSION=v2.6.1
ARG FINGERPRINTX_VERSION=v1.1.19
ENV GOBIN=/out
RUN CGO_ENABLED=0 go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} \
    && CGO_ENABLED=1 go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION} \
    && CGO_ENABLED=0 go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@${FINGERPRINTX_VERSION}

FROM python:3.12-slim-bookworm
# libpcap: naabu links it even in connect-scan mode. iproute2: the entrypoint picks
# the bind address, and /healthz checks the overlay route.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=tools /out/ /usr/local/bin/

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py probes.py entrypoint.sh /app/

# Unprivileged, with no added capabilities: every scan is a TCP connect scan, which
# needs neither root nor NET_RAW. The templates directory is created and owned here,
# before it becomes a volume, so Docker seeds a new volume writable by the scanner.
RUN useradd --create-home --uid 10001 scanner \
    && mkdir -p /home/scanner/nuclei-templates /home/scanner/.config/nuclei \
    && chown -R scanner:scanner /home/scanner
USER scanner
ENV NETSCAN_TEMPLATES_DIR=/home/scanner/nuclei-templates \
    NETSCAN_PORT=8001
EXPOSE 8001
ENTRYPOINT ["/app/entrypoint.sh"]
