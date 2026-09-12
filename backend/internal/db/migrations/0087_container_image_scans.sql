-- Vulnerability findings for container images, keyed by DIGEST.
--
-- Keyed by digest rather than by (host, container) because the same image runs
-- in many places: a fleet with a dozen hosts pulling the same base image should
-- scan it once, not a dozen times. grype fetches the image from its registry to
-- scan it, so the duplication would be bandwidth and disk as well as time -- on a
-- server that ran out of disk the same week this was written.
--
-- The digest is also what makes the result reusable. A tag moves; a digest does
-- not, so a finding recorded against one stays true until the image is rebuilt,
-- and the only reason to rescan an unchanged digest is that the vulnerability
-- database has moved on.
CREATE TABLE IF NOT EXISTS container_image_scans (
    digest      TEXT PRIMARY KEY,
    -- A representative reference, for display. Several repositories can carry
    -- the same digest; which one is shown does not change what was scanned.
    image       TEXT NOT NULL DEFAULT '',
    findings    JSONB,
    critical    INT NOT NULL DEFAULT 0,
    high        INT NOT NULL DEFAULT 0,
    medium      INT NOT NULL DEFAULT 0,
    low         INT NOT NULL DEFAULT 0,
    -- Which vulnerability database produced this, so a finding can be aged
    -- against the data rather than against the clock.
    db_built    TEXT NOT NULL DEFAULT '',
    -- Why a scan produced nothing, when it produced nothing. An image that could
    -- not be pulled -- no credentials, rate limited, gone from the registry --
    -- must not read as an image with no vulnerabilities.
    error       TEXT NOT NULL DEFAULT '',
    scanned_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_container_scans_scanned ON container_image_scans(scanned_at);
