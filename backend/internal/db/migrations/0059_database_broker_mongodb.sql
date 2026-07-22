-- Extend the database broker to MongoDB (document-oriented; a JSON-command console
-- rather than SQL). Only the engine CHECK constraint changes; existing targets are
-- unaffected.
ALTER TABLE databases DROP CONSTRAINT IF EXISTS databases_engine_check;
ALTER TABLE databases ADD CONSTRAINT databases_engine_check
    CHECK (engine IN ('postgres', 'mysql', 'mariadb', 'sqlserver', 'mongodb'));
