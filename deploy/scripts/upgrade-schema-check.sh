#!/usr/bin/env bash
# Does an OLD database upgrade to the same schema as a fresh install?
#
# Every release bundle declares minFromVersion 0.0.0 — it claims it will upgrade any
# version. Nothing checked that, and it was not true: migrating a v0.55.5 database
# forward stopped at 0074 with
#
#   ERROR: function prov_current_tenant() does not exist
#
# because the fleet->prov rename edited 0051 in place, and the migration that converges
# the two populations runs at 0097 — twenty-three migrations too late. Six more
# migrations between them wrap their tenant work in "if the prov_ functions exist", so
# on that path they skipped it SILENTLY and produced tables with no row-level security
# at all.
#
# This builds both paths in throwaway databases and compares columns, RLS policies and
# indexes. Usage:  deploy/scripts/upgrade-schema-check.sh [old-tag]
set -e
cd /Users/keith/provenance
OLD_TAG="${1:-v0.55.5}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; docker rm -f prov-migtest >/dev/null 2>&1 || true' EXIT

echo "=== old migrations from $OLD_TAG"
mkdir -p "$WORK/old"
git archive "$OLD_TAG" backend/internal/db/migrations | tar -x -C "$WORK/old"
ls "$WORK/old/backend/internal/db/migrations"/*.sql | wc -l | sed 's/^/  files: /'

docker run -d --name prov-migtest -e POSTGRES_PASSWORD=test -e POSTGRES_USER=prov \
  -e POSTGRES_DB=postgres -p 0:5432 postgres:16-alpine -c max_connections=200 >/dev/null
PORT=$(docker port prov-migtest 5432/tcp | head -1 | sed 's/.*://')
for i in $(seq 1 60); do docker exec prov-migtest pg_isready -U prov >/dev/null 2>&1 && break; sleep 1; done
PSQL="docker exec -i -e PGPASSWORD=test prov-migtest psql -v ON_ERROR_STOP=1 -q -U prov"
$PSQL -d postgres -c "CREATE DATABASE fresh;" -c "CREATE DATABASE upgraded;"

echo "=== path A: fresh install — current migrations only"
cd backend && go run ./cmd/provctl migrate-db "postgres://prov:test@127.0.0.1:$PORT/fresh?sslmode=disable" | sed 's/^/  /'

echo "=== path B: an OLD database, then upgraded"
$PSQL -d upgraded -c "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now());"
n=0
for f in $(ls "$WORK/old/backend/internal/db/migrations"/*.sql | sort); do
  v=$(basename "$f" .sql)
  $PSQL -d upgraded < "$f" >/dev/null
  $PSQL -d upgraded -c "INSERT INTO schema_migrations(version) VALUES ('$v') ON CONFLICT DO NOTHING;" >/dev/null
  n=$((n+1))
done
echo "  applied $n old migrations (simulating a $OLD_TAG deployment)"
go run ./cmd/provctl migrate-db "postgres://prov:test@127.0.0.1:$PORT/upgraded?sslmode=disable" | sed 's/^/  /'

echo "=== comparing the two schemas"
Q="SELECT table_name||'.'||column_name||' '||data_type||' '||is_nullable FROM information_schema.columns WHERE table_schema='public' ORDER BY 1;"
$PSQL -tA -d fresh -c "$Q" > "$WORK/fresh.txt"
$PSQL -tA -d upgraded -c "$Q" > "$WORK/upgraded.txt"
echo "  fresh columns:    $(wc -l < "$WORK/fresh.txt" | tr -d ' ')"
echo "  upgraded columns: $(wc -l < "$WORK/upgraded.txt" | tr -d ' ')"
if diff -q "$WORK/fresh.txt" "$WORK/upgraded.txt" >/dev/null; then
  echo "  IDENTICAL — an upgraded $OLD_TAG database matches a fresh install"
else
  echo "  DIFFERENT:"
  diff "$WORK/fresh.txt" "$WORK/upgraded.txt" | head -40
fi
echo "=== row-level-security policy comparison (what actually isolates tenants)"
QP="SELECT tablename||' '||policyname||' '||coalesce(qual,'')||' '||coalesce(with_check,'') FROM pg_policies WHERE schemaname='public' ORDER BY 1;"
$PSQL -tA -d fresh -c "$QP" > "$WORK/fp.txt"; $PSQL -tA -d upgraded -c "$QP" > "$WORK/up.txt"
echo "  fresh policies:    $(wc -l < "$WORK/fp.txt" | tr -d ' ')"
echo "  upgraded policies: $(wc -l < "$WORK/up.txt" | tr -d ' ')"
diff "$WORK/fp.txt" "$WORK/up.txt" >/dev/null && echo "  policies identical" || { echo "  POLICY DIFFERENCES:"; diff "$WORK/fp.txt" "$WORK/up.txt" | head -20; }

echo "=== index + constraint comparison"
QI="SELECT tablename||' '||indexdef FROM pg_indexes WHERE schemaname='public' ORDER BY 1;"
$PSQL -tA -d fresh -c "$QI" > "$WORK/fi.txt"; $PSQL -tA -d upgraded -c "$QI" > "$WORK/ui.txt"
diff "$WORK/fi.txt" "$WORK/ui.txt" >/dev/null && echo "  indexes identical" || { echo "  index differences:"; diff "$WORK/fi.txt" "$WORK/ui.txt" | head -20; }
