# Fleet Terminal — Kubernetes manifests

Raw, ordered manifests for a from-scratch deploy. For a parameterized install
use the Helm chart in `../helm/fleet-terminal` instead.

## Apply order

Files are number-prefixed so `kubectl apply -f .` resolves dependencies:

```sh
kubectl apply -f deploy/k8s/
```

| File                      | Resource                                                     |
|---------------------------|-------------------------------------------------------------|
| `00-namespace.yaml`       | Namespace (Pod Security: restricted)                        |
| `10-configmap.yaml`       | Non-secret backend config                                   |
| `11-secret.yaml`          | **Templated** secrets — replace before applying             |
| `20-postgres.yaml`        | Postgres StatefulSet + headless Service + PVC               |
| `21-redis.yaml`           | Redis Deployment + Service                                  |
| `30-backend.yaml`         | Backend Deployment + Service + **shared RWX PVC** + HPA     |
| `31-frontend.yaml`        | Frontend Deployment + Service                               |
| `32-ansible-runner.yaml`  | Ansible-runner sidecar Deployment + Service                 |
| `33-grype-scanner.yaml`   | Grype-scanner sidecar Deployment + Service + DB PVC         |
| `40-ingress.yaml`         | TLS Ingress (host + cert-manager)                           |

### Shared storage (required for >1 replica)

`30-backend.yaml` mounts a single **ReadWriteMany** PVC (`fleet-shared-data`) for
recordings, scans, backups, and staged updates. With the HPA scaling the backend to
multiple replicas, these files **must** be on shared storage — otherwise recording
replay 404s on the wrong pod and retention prunes only one pod's files. Set
`storageClassName` on that PVC to an RWX-capable class (NFS, CephFS, EFS, Azure Files,
Filestore) before applying. A single-replica dev deploy can leave it unset only if the
default StorageClass happens to grant RWX.

### Redis

`21-redis.yaml` is retained for compatibility but the app does not use Redis
(`FLEET_REDIS_URL` is parsed and ignored); it can be removed without effect.

### Services not modeled here

- **guacd (RDP/VNC brokering)** — omitted. RDP desktops need guacd to mount the same
  shared recordings/rdp-drive volume as the backend and run as the backend's uid; add
  it as a Deployment + `guacd:4822` Service mounting `fleet-shared-data` if you use RDP.
- **fleet-updater** — intentionally **not** modeled for Kubernetes. It drives the host
  Docker socket to swap Compose images and is Compose-specific; on Kubernetes you
  upgrade by rolling the Deployment image (`kubectl set image` / Helm upgrade) instead.

## Before you apply

1. Edit `10-configmap.yaml` → set `FLEET_PUBLIC_URL` to your real host.
2. Replace `11-secret.yaml` placeholders, or create the secret out-of-band:

   ```sh
   kubectl -n fleet-terminal create secret generic fleet-secrets \
     --from-literal=FLEET_JWT_SECRET="$(openssl rand -hex 32)" \
     --from-literal=FLEET_CSRF_SECRET="$(openssl rand -hex 32)" \
     --from-literal=FLEET_CA_PASSPHRASE="$(openssl rand -hex 32)" \
     --from-literal=FLEET_VAULT_PASSPHRASE="$(openssl rand -hex 32)" \
     --from-literal=FLEET_BACKUP_PASSPHRASE="$(openssl rand -hex 32)" \
     --from-literal=FLEET_AUDIT_HMAC_KEY="$(openssl rand -hex 32)" \
     --from-literal=FLEET_ANSIBLE_RUNNER_TOKEN="$(openssl rand -hex 32)" \
     --from-literal=FLEET_RECORDING_KEY="$(openssl rand -hex 32)" \
     --from-literal=POSTGRES_PASSWORD="$(openssl rand -hex 24)" \
     --from-literal=FLEET_DATABASE_URL="postgres://fleet:THE_SAME_PASSWORD@fleet-postgres:5432/fleet?sslmode=disable"
   ```

   In `production` the backend **fails closed** at boot without real values for
   `FLEET_JWT_SECRET`, `FLEET_CSRF_SECRET`, `FLEET_CA_PASSPHRASE`,
   `FLEET_AUDIT_HMAC_KEY`, and `FLEET_ANSIBLE_RUNNER_TOKEN`. `FLEET_VAULT_PASSPHRASE`
   and `FLEET_BACKUP_PASSPHRASE` must each differ from `FLEET_CA_PASSPHRASE`.

3. Update the host in `40-ingress.yaml` (and the TLS `secretName`).
4. Push images to `ghcr.io/fleet-terminal/{backend,frontend}` or edit the
   `image:` fields to point at your registry.

## Probes & scaling

- Backend readiness: `GET /ready`, liveness: `GET /health`, metrics: `GET /metrics`.
- Prometheus scrape annotations are set on the backend Service and Pods.
- The backend HPA scales 2→10 on CPU (70%) / memory (80%).

## Security posture

All workloads run `runAsNonRoot`, drop all capabilities, disable privilege
escalation, and use `readOnlyRootFilesystem: true` where the image permits
(backend, redis, frontend). Postgres keeps a writable data volume.
