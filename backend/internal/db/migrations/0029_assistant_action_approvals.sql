-- Guarded/destructive assistant actions require a second person to approve before
-- they run. A proposal for such an action moves proposed → pending_approval (when
-- the requester asks for approval) → executed/failed (on approve) or denied. These
-- columns record the approval decision; separation of duties is enforced in code
-- (the approver may not be the requester).

ALTER TABLE assistant_actions
    ADD COLUMN IF NOT EXISTS decided_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS decided_at    TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS decision_note TEXT NOT NULL DEFAULT '';

-- A distinct approver permission: who may approve guarded actions the assistant
-- proposes. Kept separate from Approval.Decide (access requests) and withheld from
-- Operators — approving a destructive action should be an administrator decision.
INSERT INTO permissions(key, description) VALUES
    ('Assistant.Approve', 'Approve or deny guarded actions proposed via the assistant')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_key)
SELECT r.id, 'Assistant.Approve' FROM roles r
WHERE r.name IN ('Super Administrator', 'Administrator')
ON CONFLICT DO NOTHING;
