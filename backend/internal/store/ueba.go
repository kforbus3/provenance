package store

import (
	"context"
	"time"

	"github.com/fleet-terminal/backend/internal/ueba"
)

// SessionsForUEBA returns recorded sessions started since `since`, newest first and
// bounded by `limit`, for behavioral analysis. Only the fields the analyzer needs are
// selected.
func (s *Store) SessionsForUEBA(ctx context.Context, since time.Time, limit int) ([]ueba.Session, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT user_id, COALESCE(username,''), host_id, COALESCE(hostname,''),
		       COALESCE(host(client_ip),''), started_at
		FROM ssh_sessions
		WHERE started_at >= $1 AND user_id IS NOT NULL
		ORDER BY started_at DESC
		LIMIT $2`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ueba.Session
	for rows.Next() {
		var s ueba.Session
		if err := rows.Scan(&s.UserID, &s.Username, &s.HostID, &s.Hostname, &s.IP, &s.StartedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
