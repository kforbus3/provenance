# Database access brokering

Fleet brokers privileged access to **databases** the same way it brokers SSH, RDP, and Kubernetes:
operators never hold the database credential. Register a database target, and users run SQL from the
**Databases** page — Fleet reaches the database **through the jump host**, injects a **vaulted
credential**, executes the statement, and **audits it**. The password is never shown to the operator.

Manage targets under **Databases** (registering/editing/deleting needs `Database.Manage`; running
queries needs `Database.Connect`).

## Supported engines

| Engine | Notes |
|--------|-------|
| PostgreSQL | Default port 5432. |
| MySQL / MariaDB | MySQL wire protocol; default port 3306. |
| SQL Server | TDS protocol; default port 1433. |

Each engine runs its native driver over the single SSH-tunneled connection Fleet opens through the
jump host. The SQL console adapts per engine (default port and starter query).

## Register a database

1. **Store the credential in the vault.** Create a vault *password* secret whose username/password
   authenticate to the database.
2. **Register the target**: name, engine, address and port (reachable from the jump host), the
   database name, and the vault credential.

## Run SQL

Open the SQL console for a target and run a statement. Row-returning statements (`SELECT`, `SHOW`,
`WITH`, …) render as a grid; other statements report rows affected. Results are capped (1000 rows,
100 KB of SQL) and each query is recorded as a `db.query` audit event (who ran what against which
database, success, row count).

## Security model

- **Zero-knowledge credential.** The database password is decrypted only in memory at the point of
  use and never returned to the client. The connection authenticates as the credential's user.
- **Jump-host reachability.** Fleet dials the database through the jump host using the caller's
  session certificate for the hop; the database itself sees a connection from the jump host.
- **Least privilege.** Scope the vaulted database credential to what the brokered users should be
  able to do; Fleet's `Database.Connect` gate and any [access policies](./access-policies.md) apply on
  top.
