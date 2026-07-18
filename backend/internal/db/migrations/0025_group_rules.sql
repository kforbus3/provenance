-- Dynamic host groups: a group may carry a membership rule (JSONB) over stable
-- host attributes — environment, tags, OS, hostname. When set, the group's host
-- membership is computed from the rule and materialized into host_groups (so the
-- host-access check path is unchanged), and manual host add/remove is disabled.
-- A NULL rule keeps the group static/manual, exactly as before.

ALTER TABLE groups ADD COLUMN IF NOT EXISTS rule JSONB;
