-- Installed third-party software inventory for Windows hosts, collected over WinRM
-- from the registry Uninstall keys. Powers a software-inventory view and the
-- third-party CVE matching (map each app -> CPE -> grype/NVD). Distinct from
-- host_inventory (OS facts) and msrc_updates (Microsoft patch CVEs).

CREATE TABLE IF NOT EXISTS windows_software (
    host_id      UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    version      TEXT NOT NULL DEFAULT '',
    publisher    TEXT NOT NULL DEFAULT '',
    collected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host_id, name, version)
);

CREATE INDEX IF NOT EXISTS idx_windows_software_host ON windows_software(host_id);
