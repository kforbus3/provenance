package dbbroker

import "strings"

// engineInfo holds per-engine defaults used when registering a target.
type engineInfo struct {
	defaultPort int
	defaultDB   string
}

// engines is the set of database engines the broker supports. Adding an engine here
// plus a branch in execute() (query.go) extends the broker.
var engines = map[string]engineInfo{
	"postgres":  {defaultPort: 5432, defaultDB: "postgres"},
	"mysql":     {defaultPort: 3306, defaultDB: ""},
	"mariadb":   {defaultPort: 3306, defaultDB: ""}, // MariaDB speaks the MySQL protocol
	"sqlserver": {defaultPort: 1433, defaultDB: "master"},
}

// normalizeEngine lower-cases/trims an engine string, defaulting to postgres for the
// empty value (backward compatible with pre-v0.41 targets).
func normalizeEngine(e string) string {
	e = strings.ToLower(strings.TrimSpace(e))
	if e == "" {
		return "postgres"
	}
	return e
}

func engineSupported(e string) bool {
	_, ok := engines[e]
	return ok
}
