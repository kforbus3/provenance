# Provenance — systemd install (`provd.service`)

Runs the Provenance backend (`provd`) as a hardened systemd service on a
bare-metal or VM host. Postgres and Redis can run on the same host or remotely;
point the backend at them via the env file.

## 1. Build / install the binary

```sh
# From the repo (requires Go 1.23+):
cd backend
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o provd ./cmd/provd
sudo install -m 0755 provd /usr/local/bin/provd
```

## 2. Create the service user and state directory

The unit ships with `User=fleet`/`Group=fleet` and `StateDirectory=fleet`
(systemd creates `/var/lib/prov` automatically on start). Create the account:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin fleet
```

> Prefer zero standing accounts? Switch the unit to `DynamicUser=yes` and remove
> the `User=`/`Group=` lines. `StateDirectory=fleet` still gives you a stable,
> per-service `/var/lib/prov`. Only do this if no other process needs a fixed
> uid on the recordings directory.

## 3. Configuration (`/etc/prov/prov.env`)

```sh
sudo install -d -m 0750 -o root -g fleet /etc/prov
sudo tee /etc/prov/prov.env >/dev/null <<'EOF'
PROV_ENV=production
PROV_HTTP_ADDR=:8080
PROV_PUBLIC_URL=https://provenance.example.com
PROV_COOKIE_SECURE=true

# Database / cache
PROV_DATABASE_URL=postgres://prov:CHANGE_ME@127.0.0.1:5432/prov?sslmode=disable
PROV_REDIS_URL=redis://127.0.0.1:6379/0

# Secrets — generate with: openssl rand -hex 32
PROV_JWT_SECRET=
PROV_CSRF_SECRET=
PROV_CA_PASSPHRASE=

# SSH gateway
PROV_JUMP_HOST=jumphost:22
PROV_JUMP_USER=fleet

# Recordings live under the systemd StateDirectory.
PROV_RECORDING_DIR=/var/lib/prov/recordings
EOF
sudo chmod 0640 /etc/prov/prov.env
sudo chown root:fleet /etc/prov/prov.env
```

The file is `0640 root:fleet` so only root and the service can read the secrets.

## 4. Install and start the unit

```sh
sudo install -m 0644 deploy/systemd/provd.service /etc/systemd/system/provd.service
sudo systemctl daemon-reload
sudo systemctl enable --now provd.service
```

## 5. Verify

```sh
systemctl status provd.service
journalctl -u provd.service -f
curl -fsS http://127.0.0.1:8080/health   # liveness
curl -fsS http://127.0.0.1:8080/ready    # readiness (checks DB/Redis)
curl -fsS http://127.0.0.1:8080/metrics  # Prometheus metrics
```

## Hardening summary

The unit applies a defense-in-depth sandbox:

- `NoNewPrivileges=yes`, empty `CapabilityBoundingSet`/`AmbientCapabilities`
  (binds the non-privileged port 8080).
- `ProtectSystem=strict` + `ProtectHome=yes` — the entire filesystem is
  read-only except `StateDirectory`/`RuntimeDirectory` and `PrivateTmp`.
- `MemoryDenyWriteExecute`, `LockPersonality`, `RestrictRealtime`,
  `RestrictSUIDSGID`, `RestrictNamespaces`.
- Kernel/host isolation: `ProtectKernelTunables/Modules/Logs`,
  `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`,
  `ProtectProc=invisible`, `ProcSubset=pid`.
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` and a
  `@system-service` syscall allow-list (minus `@privileged`/`@resources`).

Audit the sandbox at any time with:

```sh
systemd-analyze security provd.service
```

## Run behind TLS

`provd` serves plain HTTP on `:8080`; terminate TLS in front of it (nginx,
Caddy, HAProxy, or a cloud load balancer) and forward to `127.0.0.1:8080`.
Keep `PROV_COOKIE_SECURE=true` and set `PROV_PUBLIC_URL` to the HTTPS origin.

## Upgrades

```sh
sudo install -m 0755 provd /usr/local/bin/provd
sudo systemctl restart provd.service
```
