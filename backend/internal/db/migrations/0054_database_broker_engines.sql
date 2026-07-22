-- Extend the database broker beyond PostgreSQL: allow MySQL/MariaDB and SQL Server
-- targets. Only the engine CHECK constraint changes; the connection path branches on
-- engine at query time (internal/dbbroker). Existing rows (engine='postgres') are
-- unaffected.
ALTER TABLE databases DROP CONSTRAINT IF EXISTS databases_engine_check;
ALTER TABLE databases ADD CONSTRAINT databases_engine_check
    CHECK (engine IN ('postgres', 'mysql', 'mariadb', 'sqlserver'));
