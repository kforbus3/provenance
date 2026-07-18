-- Access certification (recertification campaigns). An access review snapshots the
-- current access grants in scope — user↔group memberships and direct user↔host
-- grants — into per-grant review items; a reviewer keeps or revokes each, and the
-- completed campaign is the evidence that access was reviewed. Revoking an item
-- removes the underlying grant.

CREATE TABLE IF NOT EXISTS access_reviews (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    scope        JSONB NOT NULL DEFAULT '{"type":"all"}',  -- {type: all|group|user, ...}
    status       TEXT NOT NULL DEFAULT 'open',              -- open | completed
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    due_at       TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    completed_by UUID REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_access_reviews_status ON access_reviews(status, created_at DESC);

CREATE TABLE IF NOT EXISTS access_review_items (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    review_id       UUID NOT NULL REFERENCES access_reviews(id) ON DELETE CASCADE,
    subject_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    grant_kind      TEXT NOT NULL,               -- group_membership | direct_host
    resource_kind   TEXT NOT NULL,               -- group | host
    resource_id     UUID NOT NULL,
    decision        TEXT NOT NULL DEFAULT 'pending', -- pending | keep | revoke
    note            TEXT NOT NULL DEFAULT '',
    decided_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    decided_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_access_review_items_review ON access_review_items(review_id);

INSERT INTO permissions(key, description) VALUES
    ('AccessReview.Manage', 'Create and conduct access-certification reviews')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'AccessReview.Manage' FROM roles r
WHERE r.name IN ('Super Administrator', 'Administrator', 'Auditor')
ON CONFLICT DO NOTHING;
