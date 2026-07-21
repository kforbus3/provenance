# syntax=docker/dockerfile:1
# Multi-stage production build for the Fleet Terminal backend.

# Go 1.24+ so the native FIPS 140-3 cryptographic module is compiled in (it ships
# in every Go 1.24 binary; FIPS mode is a RUNTIME toggle via GODEBUG=fips140=on,
# set by the entrypoint when FLEET_FIPS_MODE=true — one image serves both modes).
FROM golang:1.24-alpine AS build
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
      -o /out/fleetd ./cmd/fleetd
# Offline admin/recovery CLI shipped alongside the server.
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/fleetctl ./cmd/fleetctl

FROM alpine:3.20 AS runtime
RUN apk add --no-cache ca-certificates openssh-client tzdata postgresql16-client openssl su-exec && \
    addgroup -S fleet && adduser -S -G fleet fleet && \
    mkdir -p /var/lib/fleet/recordings /var/lib/fleet/scans /var/lib/fleet/scap-content /var/lib/fleet/backups /var/lib/fleet/rdp-drive && chown -R fleet:fleet /var/lib/fleet
COPY --from=build /out/fleetd /usr/local/bin/fleetd
COPY --from=build /out/fleetctl /usr/local/bin/fleetctl
# Entrypoint runs as root only to make the data dirs writable (named volumes can
# mount root-owned), then drops to the unprivileged fleet user.
RUN printf '#!/bin/sh\nmkdir -p /var/lib/fleet/recordings /var/lib/fleet/scans /var/lib/fleet/scap-content /var/lib/fleet/backups /var/lib/fleet/rdp-drive\nchown fleet:fleet /var/lib/fleet/recordings /var/lib/fleet/scans /var/lib/fleet/scap-content /var/lib/fleet/backups /var/lib/fleet/rdp-drive 2>/dev/null || true\n# FIPS mode: activate the Go FIPS 140-3 module for the runtime. The backend also\n# fails closed at boot if this is not active while FLEET_FIPS_MODE=true.\nif [ "$FLEET_FIPS_MODE" = "true" ]; then export GODEBUG="fips140=on${GODEBUG:+,$GODEBUG}"; fi\nexec su-exec fleet:fleet env GODEBUG="$GODEBUG" /usr/local/bin/fleetd "$@"\n' > /usr/local/bin/entrypoint.sh \
    && chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
