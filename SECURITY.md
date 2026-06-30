# Security Policy

Fleet Terminal is a privileged access management (PAM) platform. It brokers SSH
access to production hosts, issues SSH certificates, and stores audit records, so
security issues are taken seriously. Thank you for helping keep it and its users safe.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately through **GitHub Security Advisories** — open a draft advisory
via the repository's **Security → Report a vulnerability** tab. This keeps the
report private and lets us collaborate on a fix and CVE.

Please include, as far as you can:

- a description of the issue and its impact,
- the component and version/commit affected,
- step-by-step reproduction (proof-of-concept welcome),
- any suggested remediation.

### What to expect

- **Acknowledgement** within 3 business days.
- An initial **assessment and severity** within 10 business days.
- We will keep you updated on remediation progress and coordinate a disclosure
  timeline with you. Please allow a reasonable period to ship a fix before any
  public disclosure.
- With your consent, we are happy to credit you in the release notes.

## Scope

In scope — anything affecting the confidentiality, integrity, or availability of:

- authentication, session/refresh handling, MFA, SSO (OIDC/LDAP), and RBAC,
- the SSH certificate authority, ephemeral identity issuance, and key handling,
- the SSH gateway / jump-host brokering and host enrollment,
- the tamper-evident audit log and audit forwarding,
- secret-at-rest sealing (`internal/secretbox`) and backup handling,
- privilege escalation, injection, SSRF, path traversal, or auth bypass anywhere
  in the backend API or frontend.

Out of scope:

- issues that require a pre-compromised host, server, or administrator account,
- vulnerabilities in third-party dependencies that are already public and have an
  available upstream fix (please still let us know so we can bump them),
- denial of service from unrealistic traffic volumes,
- best-practice or hardening suggestions with no concrete exploit (open a normal
  issue or PR for those).

## Operator security notes

Fleet Terminal is self-hosted; deployment security is partly your responsibility.
A few essentials, covered in more detail in [`docs/security.md`](docs/security.md):

- **`FLEET_CA_PASSPHRASE`** and **`FLEET_BACKUP_PASSPHRASE`** are the root of trust.
  Keep them off the server (e.g. in a password manager); they are deliberately
  excluded from backups. Losing them is unrecoverable; leaking them is fatal.
- Never commit a real `.env`. Only `*.example` files belong in version control.
- Terminate TLS in front of the app and restrict who can reach the jump host.

## Supported versions

This project is under active development. The current release is **v0.1.0**.
Security fixes are applied to `main` and roll into the next tagged release; until
the next tag, running a recent commit from `main` gets you the latest fixes.

| Version | Supported |
| ------- | --------- |
| v0.1.x  | ✅        |
| < v0.1  | ❌        |
