#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="$(dirname "$0")/docker-compose.yml"
DB_USER="docdockgo_admin"
DB_NAME="docdockgo"
DB_CONTAINER="test-postgres-1"

echo "=== Reset BDD (sauf users) ==="
docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" <<'SQL'
DO $$
DECLARE
  r RECORD;
BEGIN
  FOR r IN
    SELECT tablename FROM pg_tables
    WHERE schemaname = 'public'
      AND tablename <> 'users'
  LOOP
    EXECUTE 'TRUNCATE TABLE ' || quote_ident(r.tablename) || ' CASCADE';
    RAISE NOTICE 'Truncated: %', r.tablename;
  END LOOP;
END $$;
SQL

echo ""
echo "=== Reset volume quarantaine ==="
docker run --rm \
  -v "$(docker volume inspect test_quarantaine --format '{{.Name}}'):/vol" \
  alpine sh -c 'find /vol -mindepth 1 -delete && echo "quarantaine: OK"'

echo ""
echo "=== Reset volume cache ==="
docker run --rm \
  -v "$(docker volume inspect test_cache --format '{{.Name}}'):/vol" \
  alpine sh -c 'find /vol -mindepth 1 -delete && echo "cache: OK"'

echo ""
echo "=== Vérification ==="
docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" <<'SQL'
SELECT
  schemaname,
  relname AS table,
  n_live_tup AS rows
FROM pg_stat_user_tables
ORDER BY relname;
SQL

echo ""
echo "Done."
