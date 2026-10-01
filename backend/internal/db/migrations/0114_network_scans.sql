-- Network vulnerability scanning: the half grype cannot see.
--
-- vuln_scans (0026) record what a host has INSTALLED, matched against a CVE
-- database. Nothing recorded what a host EXPOSES: which ports answer, from where,
-- what is serving on them, and whether that service is vulnerable or misconfigured
-- -- deprecated TLS, weak SSH algorithms, an unauthenticated Redis, an admin panel on
-- the network. These tables hold that, as produced by the net-scanner sidecar.
--
-- One net_scans row per address scanned. A managed host is scanned on each PATH it
-- has -- its LAN address and its overlay address -- because they answer different
-- questions: what anything on that network can reach, and what the jump host (and
-- whoever controls it) can reach. A host firewall that trusts wg0 makes them differ.
-- Range scans (net_scan_ranges) produce rows with path 'range', attached to a host
-- when the address matches one.

CREATE TABLE IF NOT EXISTS net_scan_ranges (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    cidr        CIDR NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant_id   UUID NOT NULL DEFAULT prov_current_tenant() REFERENCES tenants(id),
    CONSTRAINT net_scan_ranges_name_nonempty CHECK (length(trim(name)) > 0)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_net_scan_ranges_tenant_cidr ON net_scan_ranges (tenant_id, cidr);

CREATE TABLE IF NOT EXISTS net_scans (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- One request scans a host on each of its paths; run_id groups those rows so the
    -- UI can show "this host, this scan" as one thing and the diff between paths.
    run_id            UUID NOT NULL,
    host_id           UUID REFERENCES hosts(id) ON DELETE CASCADE,
    range_id          UUID REFERENCES net_scan_ranges(id) ON DELETE SET NULL,
    target            TEXT NOT NULL,   -- the IP literal scanned
    path              TEXT NOT NULL,   -- lan | overlay | range
    requested_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    requester         TEXT NOT NULL DEFAULT '',
    scheduled         BOOLEAN NOT NULL DEFAULT false,
    -- pending | running | completed | unreachable | failed. 'unreachable' is its own
    -- state and never 'completed with zero findings': an address the scanner could
    -- not reach has not been assessed, and must not read as clean.
    status            TEXT NOT NULL DEFAULT 'pending',
    error             TEXT NOT NULL DEFAULT '',
    reason            TEXT NOT NULL DEFAULT '',
    templates_version TEXT NOT NULL DEFAULT '',
    open_ports        INT NOT NULL DEFAULT 0,
    total             INT NOT NULL DEFAULT 0,
    critical          INT NOT NULL DEFAULT 0,
    high              INT NOT NULL DEFAULT 0,
    medium            INT NOT NULL DEFAULT 0,
    low               INT NOT NULL DEFAULT 0,
    -- Reachable ports the host's own listener list does not account for: a port
    -- forward, a NAT rule, or a host that is not telling the truth.
    unexpected        INT NOT NULL DEFAULT 0,
    -- The host's own view of what it has bound, collected at scan time over SSH or
    -- WinRM, with the package that owns each listening process and the packages of
    -- the libraries it has loaded. NULL when it could not be collected (no shell
    -- access, a range target) -- never "nothing is listening".
    listeners         JSONB,
    warnings          JSONB NOT NULL DEFAULT '[]'::jsonb,
    duration_sec      DOUBLE PRECISION NOT NULL DEFAULT 0,
    instance_id       UUID,
    started_at        TIMESTAMPTZ,
    finished_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant_id         UUID NOT NULL DEFAULT prov_current_tenant() REFERENCES tenants(id),
    CONSTRAINT net_scans_path_known CHECK (path IN ('lan', 'overlay', 'range')),
    CONSTRAINT net_scans_status_known
        CHECK (status IN ('pending', 'running', 'completed', 'unreachable', 'failed'))
);
CREATE INDEX IF NOT EXISTS idx_net_scans_host ON net_scans (host_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_net_scans_run ON net_scans (run_id);
CREATE INDEX IF NOT EXISTS idx_net_scans_range ON net_scans (range_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_net_scans_target ON net_scans (target, created_at DESC);

-- What answered on the network, per port.
CREATE TABLE IF NOT EXISTS net_services (
    scan_id     UUID NOT NULL REFERENCES net_scans(id) ON DELETE CASCADE,
    port        INT NOT NULL,
    proto       TEXT NOT NULL DEFAULT 'tcp',
    service     TEXT NOT NULL DEFAULT '',
    product     TEXT NOT NULL DEFAULT '',
    version     TEXT NOT NULL DEFAULT '',
    tls         BOOLEAN NOT NULL DEFAULT false,
    cpes        TEXT[] NOT NULL DEFAULT '{}',
    -- Facts nuclei reported about the service that are not problems ("this is
    -- Grafana"), kept with the service rather than among the findings.
    detections  JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- The listening process the host itself reported for this port, if any.
    process     TEXT NOT NULL DEFAULT '',
    unexpected  BOOLEAN NOT NULL DEFAULT false,
    tenant_id   UUID NOT NULL DEFAULT prov_current_tenant() REFERENCES tenants(id),
    PRIMARY KEY (scan_id, proto, port)
);

CREATE TABLE IF NOT EXISTS net_findings (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id      UUID NOT NULL REFERENCES net_scans(id) ON DELETE CASCADE,
    template_id  TEXT NOT NULL,
    name         TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT 'unknown',
    port         INT NOT NULL DEFAULT 0,
    proto        TEXT NOT NULL DEFAULT 'tcp',
    matched_at   TEXT NOT NULL DEFAULT '',
    cves         TEXT[] NOT NULL DEFAULT '{}',
    cwes         TEXT[] NOT NULL DEFAULT '{}',
    cvss_score   DOUBLE PRECISION NOT NULL DEFAULT 0,
    cvss_vector  TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    remediation  TEXT NOT NULL DEFAULT '',
    refs         JSONB NOT NULL DEFAULT '[]'::jsonb,
    extracted    JSONB NOT NULL DEFAULT '[]'::jsonb,
    tags         TEXT[] NOT NULL DEFAULT '{}',
    tenant_id    UUID NOT NULL DEFAULT prov_current_tenant() REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_net_findings_scan ON net_findings (scan_id, severity);
-- "Which hosts expose CVE-X on the network" -- the correlation with grype's findings.
CREATE INDEX IF NOT EXISTS idx_net_findings_cves ON net_findings USING gin (cves);

CREATE INDEX IF NOT EXISTS idx_net_scan_ranges_tenant ON net_scan_ranges (tenant_id);
CREATE INDEX IF NOT EXISTS idx_net_scans_tenant ON net_scans (tenant_id);
CREATE INDEX IF NOT EXISTS idx_net_services_tenant ON net_services (tenant_id);
CREATE INDEX IF NOT EXISTS idx_net_findings_tenant ON net_findings (tenant_id);

DO $$
BEGIN
  EXECUTE 'ALTER TABLE net_scan_ranges ENABLE ROW LEVEL SECURITY';
  EXECUTE 'ALTER TABLE net_scan_ranges FORCE ROW LEVEL SECURITY';
  EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON net_scan_ranges';
  EXECUTE 'CREATE POLICY tenant_isolation ON net_scan_ranges USING (prov_rls_visible(tenant_id)) WITH CHECK (prov_rls_visible(tenant_id))';

  EXECUTE 'ALTER TABLE net_scans ENABLE ROW LEVEL SECURITY';
  EXECUTE 'ALTER TABLE net_scans FORCE ROW LEVEL SECURITY';
  EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON net_scans';
  EXECUTE 'CREATE POLICY tenant_isolation ON net_scans USING (prov_rls_visible(tenant_id)) WITH CHECK (prov_rls_visible(tenant_id))';

  EXECUTE 'ALTER TABLE net_services ENABLE ROW LEVEL SECURITY';
  EXECUTE 'ALTER TABLE net_services FORCE ROW LEVEL SECURITY';
  EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON net_services';
  EXECUTE 'CREATE POLICY tenant_isolation ON net_services USING (prov_rls_visible(tenant_id)) WITH CHECK (prov_rls_visible(tenant_id))';

  EXECUTE 'ALTER TABLE net_findings ENABLE ROW LEVEL SECURITY';
  EXECUTE 'ALTER TABLE net_findings FORCE ROW LEVEL SECURITY';
  EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON net_findings';
  EXECUTE 'CREATE POLICY tenant_isolation ON net_findings USING (prov_rls_visible(tenant_id)) WITH CHECK (prov_rls_visible(tenant_id))';
END $$;
