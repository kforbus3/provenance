export const meta = {
  name: 'provenance-breadth',
  description: 'Orchestrated parallel build of Provenance breadth (frontend, backend CRUD modules, test fabric, docs, deploy)',
  phases: [
    { title: 'Backend modules' },
    { title: 'Frontend' },
    { title: 'Infra & docs' },
  ],
}

const REPO = '/Users/keith/provenance'

const RULES = `
You are a worker in an orchestrated build of "Provenance", a Go + React PAM platform
for browser-based SSH. The repo is at ${REPO}. Work ONLY inside your assigned files.

HARD RULES:
- Do NOT edit: backend/internal/api/server.go, backend/cmd/**, backend/go.mod, backend/go.sum,
  or any file owned by another worker. Do NOT run git commit.
- Match the existing code style EXACTLY. Read these reference files first to learn conventions:
  backend/internal/hosts/handlers.go (the canonical backend HTTP module),
  backend/internal/store/hosts.go (canonical store file),
  backend/internal/store/rbac.go, backend/internal/auth/handlers.go,
  backend/internal/app/deps.go, backend/internal/models/models.go.
- Backend modules MUST expose: func Mount(r chi.Router, d *app.Deps) and gate every route with
  d.Auth.RequireAuth plus d.Auth.RequirePermission("<Perm>"). Audit state changes via
  d.Store.AppendAudit(...). Use ONLY parameterized SQL. Get the principal with auth.MustPrincipal(r).
- Verify your Go package compiles with this exact command before returning:
  docker run --rm -v ${REPO}/backend:/src -w /src golang:1.23-alpine sh -c "apk add --no-cache git >/dev/null 2>&1 && GOFLAGS=-mod=mod go build ./internal/<yourpkg>/..."
  (If it fails due to a method you expected on *Store that you did not add, add it to YOUR assigned store file.)
- Permission keys that exist: Host.View Host.Connect Host.Enroll Host.Edit Host.Delete
  Host.RotateCertificate Session.Start Session.Terminate Session.Replay File.Transfer
  Audit.View Audit.Export User.Create User.Edit User.Delete User.ResetPassword Group.Create
  Group.Edit Group.Delete Role.Create Role.Edit Role.Delete Approval.Request Approval.Decide
  Certificate.Manage System.Configure Admin.All
Return a short summary: files created, the exact "Mount" import path + call line, and any new store methods.
`

const MOUNT_SCHEMA = {
  type: 'object',
  required: ['ok', 'summary', 'mountImport', 'mountCall'],
  properties: {
    ok: { type: 'boolean', description: 'true if the package compiles' },
    summary: { type: 'string' },
    mountImport: { type: 'string', description: 'Go import path, e.g. github.com/provenance/backend/internal/admin' },
    mountCall: { type: 'string', description: 'e.g. admin.Mount(r, d)' },
    storeMethods: { type: 'array', items: { type: 'string' } },
  },
}

const FILE_SCHEMA = {
  type: 'object',
  required: ['ok', 'summary', 'files'],
  properties: {
    ok: { type: 'boolean' },
    summary: { type: 'string' },
    files: { type: 'array', items: { type: 'string' } },
  },
}

// ---------------------------------------------------------------------------
// Phase 1 — backend CRUD modules (parallel). Each owns disjoint files.
// ---------------------------------------------------------------------------
phase('Backend modules')

const backend = await parallel([
  () => agent(`${RULES}

TASK: Build the ADMIN module for user/role/group/settings management.
Create:
- backend/internal/store/settings.go : Store methods GetSetting(ctx,key)(json.RawMessage,error),
  SetSetting(ctx,key,value any) error, ListSettings(ctx)(map[string]json.RawMessage,error),
  and saved-filter CRUD (ListSavedFilters, CreateSavedFilter, DeleteSavedFilter) per the
  saved_filters/settings tables in backend/internal/db/migrations/0001_init.sql.
- backend/internal/admin/users.go, roles.go, groups.go, settings.go : HTTP handlers.
  Reuse existing *Store methods (ListUsers, CreateUser, UpdateUser, DeleteUser, SetDisabled,
  SetMustChangePassword, Unlock, SetPasswordHash, ListRoles, CreateRole, DeleteRole,
  SetRolePermissions, AssignRole, RemoveRole, ListPermissions, ListGroups, CreateGroup,
  DeleteGroup, AddUserToGroup, RemoveUserFromGroup). For password reset use
  auth.HashPassword + Store.SetPasswordHash. For user create, require a password and hash it.
- backend/internal/admin/admin.go : func Mount(r chi.Router, d *app.Deps) wiring:
  GET/POST/PUT/DELETE /users, /users/{id}, /users/{id}/disable, /users/{id}/unlock,
  /users/{id}/reset-password, /users/{id}/roles/{roleId}, /users/{id}/groups/{groupId};
  /roles, /roles/{id}, /roles/{id}/permissions; /permissions; /groups, /groups/{id};
  /settings, /settings/{key}. Gate with the matching User.*/Role.*/Group.*/System.Configure perms.
`, { label: 'be:admin', phase: 'Backend modules', schema: MOUNT_SCHEMA }),

  () => agent(`${RULES}

TASK: Build the AUDIT + SESSIONS read API.
Create:
- backend/internal/store/sshsessions.go : Store methods for ssh_sessions, session_recordings,
  sftp_transfers per 0001_init.sql: CreateSSHSession, EndSSHSession(id,exitCode,bytesIn,bytesOut),
  GetSSHSession, ListSSHSessions(filter by user/host, limit/offset), CreateRecording,
  GetRecordingBySession, RecordSFTPTransfer, ListSFTPTransfers. Scan into models.SSHSession,
  models.Recording (these structs already exist in models).
- backend/internal/auditapi/auditapi.go : Mount(r, d). Routes (perm Audit.View / Audit.Export):
  GET /audit (filters: action, actor, limit, offset via Store.ListAudit),
  GET /audit/verify (Store.VerifyAuditChain -> {intact, brokenAtSeq}),
  GET /audit/export (Audit.Export -> stream JSON of events).
- backend/internal/sessionsapi/sessionsapi.go : Mount(r, d). Routes:
  GET /sessions (Session.Replay -> Store.ListSSHSessions), GET /sessions/{id},
  GET /sessions/{id}/recording (Session.Replay -> recording metadata + the asciicast file
  contents from the recording path on disk if present, else 404).
`, { label: 'be:audit+sessions', phase: 'Backend modules', schema: MOUNT_SCHEMA }),

  () => agent(`${RULES}

TASK: Build the APPROVALS (just-in-time access) module.
Create:
- backend/internal/store/approvals.go : Store methods per approval_requests/temporary_permissions:
  CreateApprovalRequest(params), ListApprovalRequests(status filter), GetApprovalRequest,
  DecideApprovalRequest(id, decidedBy, status, note, grantedSecs) (in a tx: update request, and on
  'approved' insert a temporary_permissions row with expires_at=now()+grantedSecs),
  ListTemporaryPermissions(userID), ExpireTemporaryPermissions(ctx) (mark expired rows + update
  parent request to 'expired'; return count). Scan into models.ApprovalRequest / models.TemporaryPermission.
- backend/internal/approvals/approvals.go : Mount(r, d). Routes:
  POST /approvals (Approval.Request: requester=current user; body reason, targetKind, hostId|groupId,
  requestedSecs, ticketRef), GET /approvals (Approval.Decide sees all; requester sees own),
  GET /approvals/mine, POST /approvals/{id}/decide (Approval.Decide: approve/deny + note + grantedSecs),
  GET /approvals/grants/mine (current user's active temporary_permissions). Audit every action.
- Also add an exported func Reaper(ctx, d *app.Deps) that calls Store.ExpireTemporaryPermissions once
  (the main server will schedule it).
`, { label: 'be:approvals', phase: 'Backend modules', schema: MOUNT_SCHEMA }),
])

// ---------------------------------------------------------------------------
// Phase 2 — frontend (parallel). Disjoint page/component files.
// ---------------------------------------------------------------------------
phase('Frontend')

const FE_RULES = `
${RULES}
FRONTEND SPECIFICS: React 18 + TypeScript + Vite + MUI v6 + @tanstack/react-query + zustand + axios.
Read backend/.. no — read frontend/src/api/client.ts, frontend/src/App.tsx,
frontend/src/components/AppLayout.tsx, frontend/src/pages/DashboardPage.tsx, frontend/src/store/ui.ts
for conventions. Use the shared axios instance 'api' from src/api/client.ts (withCredentials).
Do NOT edit src/App.tsx or src/main.tsx (the orchestrator wires routes). Create page components that
default-export-free, named exports like existing pages. Verify the build compiles with:
docker run --rm -v ${REPO}/frontend:/app -w /app node:22-alpine sh -c "npm install >/dev/null 2>&1 && npx tsc -b --noEmit"
(it is OK if npm install is slow). Keep components typed (no 'any' unless unavoidable).
`

const frontend = await parallel([
  () => agent(`${FE_RULES}

TASK: Build AUTH (login + bootstrap wizard) and the auth store.
Create:
- frontend/src/store/auth.ts : zustand store holding {user, permissions, accessToken, isSuperAdmin},
  actions login(username,password) -> POST /api/v1/auth/login (store accessToken via setAccessToken from
  api/client.ts; keep token in memory only), logout() -> POST /api/v1/auth/logout, loadMe() -> GET
  /api/v1/auth/me, and a helper has(perm) using permissions/Admin.All wildcard.
- frontend/src/api/auth.ts : typed API functions (bootstrapStatus, bootstrapInit, login, me, logout,
  changePassword).
- frontend/src/pages/LoginPage.tsx : MUI login form; on submit calls store.login then navigates to "/".
- frontend/src/pages/BootstrapPage.tsx : first-run wizard; GET /api/v1/bootstrap/status; if available,
  form to create the first Super Admin (POST /api/v1/bootstrap/init) then redirect to /login.
- frontend/src/components/ProtectedRoute.tsx : wrapper that redirects to /login if not authenticated,
  and optionally checks a required permission (renders 403 if missing).
Return the list of route elements you expect the orchestrator to add (paths -> components).
`, { label: 'fe:auth', phase: 'Frontend', schema: FILE_SCHEMA }),

  () => agent(`${FE_RULES}

TASK: Build the HOST INVENTORY page using @mui/x-data-grid.
Create:
- frontend/src/api/hosts.ts : typed functions over GET /api/v1/hosts (returns {hosts,count}),
  GET /api/v1/hosts/{id}, POST/PUT/DELETE, GET /api/v1/hosts/stats/status. Define a Host type matching
  backend/internal/models/models.go Host (camelCase JSON).
- frontend/src/pages/HostsPage.tsx : DataGrid with columns hostname, description, environment, owner,
  address, wgAddress, sshVersion(from inventory), status(from status.status as colored chip), latency,
  tags(chips), groups, lastSeen(status.checkedAt), actions. Features: quick filter/search, column sort,
  pagination, multi-row selection with a bulk toolbar (delete), a "New Host" dialog (create), responsive.
  Use react-query (useQuery/useMutation) against api/hosts.ts. Light/dark already handled by theme.
Return route elements to add.
`, { label: 'fe:hosts', phase: 'Frontend', schema: FILE_SCHEMA }),

  () => agent(`${FE_RULES}

TASK: Build ADMIN + AUDIT + APPROVALS + SESSIONS pages (functional-but-shallow, real API calls).
Create typed api modules and pages:
- frontend/src/api/admin.ts, audit.ts, approvals.ts, sessions.ts (typed fns over the documented endpoints:
  /users /roles /groups /permissions /settings ; /audit /audit/verify ; /approvals /approvals/mine
  /approvals/{id}/decide ; /sessions /sessions/{id}/recording).
- frontend/src/pages/UsersPage.tsx, RolesPage.tsx, GroupsPage.tsx, SettingsPage.tsx : MUI tables + create/edit
  dialogs. RolesPage shows permission checkboxes.
- frontend/src/pages/AuditPage.tsx : filterable table of audit events + a "Verify integrity" button hitting
  /audit/verify and showing the result.
- frontend/src/pages/ApprovalsPage.tsx : two tabs — "My requests" (create request form + list) and "Queue"
  (pending requests with Approve/Deny actions + duration select: 30m,1h,4h,8h,24h,7d,custom).
- frontend/src/pages/SessionsPage.tsx : list recorded SSH sessions; clicking one opens a replay drawer that
  fetches the recording and plays it back in an xterm.js terminal (use @xterm/xterm) honoring asciicast v2
  timing. If no recording, show metadata only.
Return route elements to add.
`, { label: 'fe:admin', phase: 'Frontend', schema: FILE_SCHEMA }),
])

// ---------------------------------------------------------------------------
// Phase 3 — infra & docs (parallel, fully independent).
// ---------------------------------------------------------------------------
phase('Infra & docs')

const infra = await parallel([
  () => agent(`${RULES}

TASK: Build the LOCAL SSH TEST FABRIC so the SSH path is demonstrable on macOS Docker Desktop
(no WireGuard kernel module — use userspace wireguard-go).
Create:
- deploy/compose/docker-compose.testfabric.yml : an override (name: provenance) adding services:
  jumphost (builds deploy/testfabric/jumphost), host-ubuntu and host-rocky (build deploy/testfabric/managed
  with build args for base image ubuntu:22.04 and rockylinux:9). All on the existing 'fleet' network with
  static-ish addressing. The backend service reaches 'jumphost:22'.
- deploy/testfabric/jumphost/Dockerfile + entrypoint.sh : Debian/Ubuntu base, install openssh-server,
  wireguard-tools, wireguard-go, iproute2; create user 'fleet'; configure a wg0 interface via wireguard-go
  (userspace) with a generated keypair; sshd allows the fleet CA (TrustedUserCAKeys) — leave a placeholder
  /etc/ssh/prov_ca.pub that the enrollment flow can replace; enable AuthorizedPrincipalsFile. Start wg then sshd -D.
- deploy/testfabric/managed/Dockerfile + entrypoint.sh : parameterized base (ubuntu/rocky); install
  openssh-server + wireguard-go + sudo; create 'fleet' user with passwordless sudo; configure wg0 (userspace)
  peered with the jumphost; sshd configured to trust the fleet user CA via TrustedUserCAKeys
  (/etc/ssh/prov_ca.pub placeholder) and AuthorizedPrincipalsFile mapping principal 'fleet'. sshd -D.
- deploy/testfabric/README.md : explain the topology (backend -> jumphost -> wg -> managed hosts), how keys
  are generated, and that it uses userspace WireGuard. Document the wg peer config generation.
Keep it self-contained and runnable with: docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.testfabric.yml up -d.
You do NOT need Go; just write Docker/shell/config files. Return files created.
`, { label: 'infra:testfabric', phase: 'Infra & docs', schema: FILE_SCHEMA }),

  () => agent(`${RULES}

TASK: Build DEPLOYMENT artifacts (no Go needed).
Create:
- deploy/k8s/*.yaml : namespace, configmap, secret (templated), postgres statefulset+svc, redis deploy+svc,
  backend deployment+svc (uses the backend image, env from configmap/secret, readiness /ready, liveness /health,
  prometheus scrape annotations), frontend deployment+svc, ingress (TLS). Resource requests/limits, securityContext
  (non-root, readOnlyRootFilesystem where possible), HPA for backend.
- deploy/helm/provenance/ : Chart.yaml, values.yaml, and templates/ mirroring the k8s manifests with
  values for image tags, replicas, resources, ingress host, secrets. Include NOTES.txt and _helpers.tpl.
- deploy/systemd/provd.service + deploy/systemd/README.md : a hardened unit (DynamicUser or a fleet user,
  NoNewPrivileges, ProtectSystem=strict, env file /etc/prov/prov.env) plus install notes.
Return files created.
`, { label: 'infra:deploy', phase: 'Infra & docs', schema: FILE_SCHEMA }),

  () => agent(`${RULES}

TASK: Write DOCUMENTATION (Markdown only). Read the repo structure, migrations, and existing modules to be accurate.
Create under docs/:
- architecture.md (component diagram in ASCII: Browser -> HTTPS/WS -> React -> REST -> Backend -> SSH Gateway
  -> Jump Host -> WireGuard -> Managed Hosts; data flows; security model: ephemeral in-RAM keys, hash-chained audit).
- api.md (REST endpoint reference grouped by module: auth, bootstrap, hosts, users/roles/groups, audit, sessions,
  approvals, certificates, health/metrics — with methods, paths, required permission, sample req/resp).
- database.md (table-by-table schema reference derived from backend/internal/db/migrations/0001_init.sql).
- admin-guide.md, user-guide.md, developer-guide.md, host-enrollment-guide.md, disaster-recovery.md,
  security-guide.md, certificate-lifecycle.md.
- Update docs to reference make targets (make up / make test) and the bootstrap flow.
Be accurate to the actual code; do not invent endpoints that contradict the modules. Return files created.
`, { label: 'docs', phase: 'Infra & docs', schema: FILE_SCHEMA }),
])

return {
  backend: backend.filter(Boolean),
  frontend: frontend.filter(Boolean),
  infra: infra.filter(Boolean),
}
