package dbbroker

import "testing"

func TestIsRowReturning(t *testing.T) {
	rowReturning := []string{
		"SELECT 1", "  select * from t", "\n\t(SELECT 1)", "WITH x AS (SELECT 1) SELECT * FROM x",
		"SHOW TABLES", "EXPLAIN SELECT 1", "DESCRIBE t", "desc t", "VALUES (1)", "TABLE t", "PRAGMA foo",
	}
	for _, s := range rowReturning {
		if !isRowReturning(s) {
			t.Errorf("isRowReturning(%q) = false, want true", s)
		}
	}
	notRowReturning := []string{
		"INSERT INTO t VALUES (1)", "UPDATE t SET x=1", "DELETE FROM t", "CREATE TABLE t (id int)",
		"DROP TABLE t", "  begin", "SET foo=1",
	}
	for _, s := range notRowReturning {
		if isRowReturning(s) {
			t.Errorf("isRowReturning(%q) = true, want false", s)
		}
	}
}

func TestNormalizeAndSupportEngine(t *testing.T) {
	if normalizeEngine("") != "postgres" {
		t.Error("empty engine should default to postgres")
	}
	if normalizeEngine("  MySQL ") != "mysql" {
		t.Error("engine should be lower-cased and trimmed")
	}
	for _, e := range []string{"postgres", "mysql", "mariadb", "sqlserver"} {
		if !engineSupported(e) {
			t.Errorf("engine %q should be supported", e)
		}
	}
	for _, e := range []string{"oracle", "mongodb", ""} {
		if engineSupported(e) {
			t.Errorf("engine %q should not be supported", e)
		}
	}
}
