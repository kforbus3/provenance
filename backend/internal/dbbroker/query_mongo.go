package dbbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/fleet-terminal/backend/internal/models"
)

const maxMongoDoc = 200_000 // cap the JSON result size

// mongoDialer adapts a dial function to the driver's ContextDialer interface.
type mongoDialer func(ctx context.Context, network, addr string) (net.Conn, error)

func (d mongoDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d(ctx, network, addr)
}

// executeMongo runs a MongoDB command (supplied as a JSON document) against the target
// through the jump host. Because the Mongo driver opens several connections (topology
// monitoring + the operation), each driver dial gets its OWN fresh jump tunnel; all are
// closed when the query finishes.
func (h *handler) executeMongo(cctx context.Context, sessionID uuid.UUID, db *models.Database, dbUser, dbPass, statement string) (*QueryResult, error) {
	var mu sync.Mutex
	var closers []io.Closer
	dial := mongoDialer(func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, jumpClient, err := h.gw.DialRawViaJump(ctx, sessionID.String(), db.Address, db.Port)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		closers = append(closers, jumpClient)
		mu.Unlock()
		return noDeadlineConn{conn}, nil
	})
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range closers {
			_ = c.Close()
		}
	}()

	dbName := db.DatabaseName
	if dbName == "" {
		dbName = "admin"
	}
	opts := options.Client().
		SetHosts([]string{fmt.Sprintf("%s:%d", db.Address, db.Port)}).
		SetDialer(dial).
		SetDirect(true).
		SetConnectTimeout(10 * time.Second).
		SetServerSelectionTimeout(12 * time.Second)
	if dbUser != "" {
		opts = opts.SetAuth(options.Credential{Username: dbUser, Password: dbPass, AuthSource: dbName})
	}

	client, err := mongo.Connect(cctx, opts)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	// The statement is a MongoDB command document, e.g. {"find":"users","limit":5} or
	// {"listCollections":1}. Parse order-preserving so the command name stays first.
	var cmd bson.D
	if err := bson.UnmarshalExtJSON([]byte(statement), false, &cmd); err != nil {
		return nil, fmt.Errorf("command must be a JSON document (e.g. {\"find\":\"coll\"}): %w", err)
	}

	var result bson.M
	if err := client.Database(dbName).RunCommand(cctx, cmd).Decode(&result); err != nil {
		return nil, err
	}

	// Render as MongoDB extended JSON (ObjectIds/dates preserved), then indent.
	raw, err := bson.MarshalExtJSON(result, false, false)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		buf.Write(raw)
	}
	doc, truncated := buf.String(), false
	if len(doc) > maxMongoDoc {
		doc, truncated = doc[:maxMongoDoc]+"\n… (truncated)", true
	}
	return &QueryResult{Columns: []string{}, Rows: [][]string{}, Command: "ok", Document: doc, Truncated: truncated}, nil
}
