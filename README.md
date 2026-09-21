# Provenance

**Privileged access management and OS lifecycle for Linux fleets.**

Provenance gives operators secure, audited browser access to Linux hosts and
manages the operating systems those hosts run. Its core workflow is simple:
enroll a host, grant a person time-bounded access, and broker their session
without putting an SSH key, VPN, or certificate in their browser.

```
Browser ──HTTPS/WSS──> Provenance ──SSH──> Jump host ──Overlay──> Managed hosts
                               │
                  SSH CA · RBAC · JIT access · audit trail
```

The backend is the only SSH client. It creates a new Ed25519 keypair in memory
for each login, signs a short-lived SSH certificate, and discards the private
key when the session ends. Managed hosts trust the Provenance SSH CA; operators
never receive the underlying credential or network access.

## What it is for

Start with browser-based, controlled access to Linux fleets:

- Terminal and SFTP sessions, recording/replay, and read-only live shadowing.
- RBAC, host-scoped access, just-in-time approvals, MFA/passkeys, and SSO.
- A built-in SSH CA with certificate rotation, revocation, and an auditable,
  HMAC-keyed event trail.
- Host inventory, health checks, package-update visibility, vulnerability and
  compliance scans, and safely isolated Ansible automation.

The same control plane also supports the host lifecycle: A/B image builds,
PXE/iPXE provisioning, signed update bundles, and staged OS rollouts. These
features are optional; a deployment can use Provenance solely as a PAM gateway.
See [imaging.md](docs/imaging.md) for how the lifecycle and access paths fit
together.

## Trust boundaries

The default production path is browser → backend → jump host → WireGuard overlay
→ managed host. The browser only speaks HTTPS/WebSocket to Provenance.

Provenance also supports direct, no-install, and SSH-agent-assisted enrollment
for constrained environments. Those paths trade deployment convenience against
the default overlay boundary; choose them deliberately and document the policy
for the fleet. The [host enrollment guide](docs/host-enrollment-guide.md)
explains each option.

## Try it locally

Requires Docker and Docker Compose. No local Go, Node, or Postgres toolchain is
needed.

```bash
make up
```

Open <http://localhost:5173> and complete the one-time bootstrap wizard to
create the first Super Administrator. The default stack includes a small SSH test
fabric; use `make up-app` when you only want the application stack.

```bash
make test       # backend + frontend tests
make logs       # tail service logs
make down       # stop services; volumes remain
```

For a production deployment, begin with the
[installation guide](docs/installation.md), then follow its
[Make it useful](docs/installation.md#8-make-it-useful--the-order-to-do-things-in)
sequence: enroll hosts, add people, configure log collection, and harden the
deployment.

## Documentation

| If you want to… | Start here |
| --- | --- |
| Understand the data flows and security model | [Architecture](docs/architecture.md) and [Security guide](docs/security-guide.md) |
| Install, operate, or expose Provenance | [Installation](docs/installation.md), [Deployment](docs/deployment.md), and [Operations](docs/operations.md) |
| Enroll hosts and define access | [Host enrollment](docs/host-enrollment-guide.md), [Admin guide](docs/admin-guide.md), and [Access policies](docs/access-policies.md) |
| Integrate or automate it | [API reference](docs/api.md) and [Automation](docs/automation.md) |
| Plan recovery or manage the SSH CA | [Disaster recovery](docs/disaster-recovery.md), [Break-glass recovery](docs/break-glass.md), and [Certificate lifecycle](docs/certificate-lifecycle.md) |
| Build images and roll out OS updates | [Imaging and updates](docs/imaging.md) |
| Develop or contribute | [Developer guide](docs/developer-guide.md) and [Contributing](CONTRIBUTING.md) |

The [documentation index](docs/README.md) has the complete reference, including
database, Kubernetes, database-broker, federation, high-availability, and
integration guides.

## Repository layout

```
backend/    Go API server and SSH gateway
frontend/   React application
builder/    A/B image builder and signed update bundles
imager/     PXE/iPXE netboot imager
server/     provisioning services for the imaging segment
deploy/     Compose, Kubernetes, Helm, and systemd deployment artifacts
docs/       operator, security, API, and developer documentation
```

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
