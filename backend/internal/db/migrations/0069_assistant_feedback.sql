-- Operator feedback on Ask Fleet answers (thumbs up/down + optional comment).
-- Captures the question, the answer as shown, and which tool produced it, so
-- misrouted or unhelpful answers can be found and fixed without live debugging.
CREATE TABLE IF NOT EXISTS assistant_feedback (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    ask_id      TEXT NOT NULL DEFAULT '',
    question    TEXT NOT NULL,
    answer      TEXT NOT NULL,
    answered_by TEXT NOT NULL DEFAULT '',
    helpful     BOOLEAN NOT NULL,
    comment     TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_assistant_feedback_created ON assistant_feedback (created_at DESC);
