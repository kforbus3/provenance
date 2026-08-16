# Moorgate — systemd install (`fleetd.service`)

Runs the Moorgate backend (`fleetd`) as a hardened systemd service on a
bare-metal or VM host. Postgres and Redis can run on the same host or remotely;
point the backend at them via the env file.

## 1. Build / install the binary

```sh
# From the repo (requires Go 1.23+):
cd backend
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o fleetd ./cmd/fleetd
sudo install -m 0755 fleetd /usr/local/bin/fleetd
```

## 2. Create the service user and state directory

The unit ships with `User=fleet`/`Group=fleet` and `StateDirectory=fleet`
(systemd creates `/var/lib/fleet` automatically on start). Create the account:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin fleet
```

> Prefer zero standing accounts? Switch the unit to `DynamicUser=yes` and remove
> the `User=`/`Group=` lines. `StateDirectory=fleet` still gives you a stable,
> per-service `/var/lib/fleet`. Only do this if no other process needs a fixed
> uid on the recordings directory.

## 3. Configuration (`/etc/fleet/fleet.env`)

```sh
sudo install -d -m 0750 -o root -g fleet /etc/fleet
sudo tee /etc/fleet/fleet.env >/dev/null <<'EOF'
FLEET_ENV=production
FLEET_HTTP_ADDR=:8080
FLEET_PUBLIC_URL=https://fleet.example.com
FLEET_COOKIE_SECURE=true

# Database / cache
FLEET_DATABASE_URL=postgres://fleet:CHANGE_ME@127.0.0.1:5432/fleet?sslmode=disable
FLEET_REDIS_URL=redis://127.0.0.1:6379/0

# Secrets — generate with: openssl rand -hex 32
FLEET_JWT_SECRET=
FLEET_CSRF_SECRET=
FLEET_CA_PASSPHRASE=

# SSH gateway
FLEET_JUMP_HOST=jumphost:22
FLEET_JUMP_USER=fleet

# Recordings live under the systemd StateDirectory.
FLEET_RECORDING_DIR=/var/lib/fleet/recordings
EOF
sudo chmod 0640 /etc/fleet/fleet.env
sudo chown root:fleet /etc/fleet/fleet.env
```

The file is `0640 root:fleet` so only root and the service can read the secrets.

## 4. Install and start the unit

```sh
sudo install -m 0644 deploy/systemd/fleetd.service /etc/systemd/system/fleetd.service
sudo systemctl daemon-reload
sudo systemctl enable --now fleetd.service
```

## 5. Verify

```sh
systemctl status fleetd.service
journalctl -u fleetd.service -f
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
systemd-analyze security fleetd.service
```

## Run behind TLS

`fleetd` serves plain HTTP on `:8080`; terminate TLS in front of it (nginx,
Caddy, HAProxy, or a cloud load balancer) and forward to `127.0.0.1:8080`.
Keep `FLEET_COOKIE_SECURE=true` and set `FLEET_PUBLIC_URL` to the HTTPS origin.

## Upgrades

```sh
sudo install -m 0755 fleetd /usr/local/bin/fleetd
sudo systemctl restart fleetd.service
```
