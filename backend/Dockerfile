# syntax=docker/dockerfile:1
# Multi-stage production build for the Provenance backend.

# Go 1.24+ so the native FIPS 140-3 cryptographic module is compiled in (it ships
# in every Go 1.24 binary; FIPS mode is a RUNTIME toggle via GODEBUG=fips140=on,
# set by the entrypoint when PROV_FIPS_MODE=true — one image serves both modes).
FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates openssh-client
# Resolve dependencies first for better layer caching. go.sum is generated here
# when absent (no local Go toolchain is required on the developer machine).
COPY go.mod ./
COPY go.sum* ./
ENV GOFLAGS=-mod=mod
RUN go mod download || true
COPY . .
RUN go mod tidy
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/provd ./cmd/provd
# Offline admin/recovery CLI shipped alongside the server.
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/provctl ./cmd/provctl

FROM alpine:3.24 AS runtime
RUN apk add --no-cache ca-certificates openssh-client tzdata postgresql16-client openssl su-exec && \
    addgroup -S prov && adduser -S -G prov prov && \
    mkdir -p /var/lib/prov/recordings /var/lib/prov/scans /var/lib/prov/scap-content /var/lib/prov/backups /var/lib/prov/rdp-drive /var/lib/prov/updates && chown -R fleet:fleet /var/lib/prov
COPY --from=build /out/provd /usr/local/bin/provd
COPY --from=build /out/provctl /usr/local/bin/provctl
# Entrypoint: when started as root (Docker Compose with root-owned named volumes),
# make the data dirs writable and drop to the unprivileged prov user via su-exec.
# When already started as a non-root user (Kubernetes runAsNonRoot, where su-exec's
# setuid/setgid would fail with all capabilities dropped), just exec provd directly.
RUN printf '#!/bin/sh\nmkdir -p /var/lib/prov/recordings /var/lib/prov/scans /var/lib/prov/scap-content /var/lib/prov/backups /var/lib/prov/rdp-drive /var/lib/prov/updates 2>/dev/null || true\nif [ "$PROV_FIPS_MODE" = "true" ]; then export GODEBUG="fips140=on${GODEBUG:+,$GODEBUG}"; fi\nif [ "$(id -u)" = "0" ]; then chown fleet:fleet /var/lib/prov/recordings /var/lib/prov/scans /var/lib/prov/scap-content /var/lib/prov/backups /var/lib/prov/rdp-drive /var/lib/prov/updates 2>/dev/null || true; exec su-exec fleet:fleet env GODEBUG="$GODEBUG" /usr/local/bin/provd "$@"; fi\nexec env GODEBUG="$GODEBUG" /usr/local/bin/provd "$@"\n' > /usr/local/bin/entrypoint.sh \
    && chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
