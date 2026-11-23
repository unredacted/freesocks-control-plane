#!/bin/sh
# One-shot (docker-compose.stack.yml `db-roles`): create or refresh the
# read-only role the backup sidecar dumps as. Runs as the superuser over the
# private `data` network; idempotent, so it runs on every `up`.
#
# pg_read_all_data (PostgreSQL 14+) grants SELECT on every table, view and
# sequence and USAGE on every schema, including tables Convex creates later, and
# nothing else: the role cannot write, create or administer anything.
#
# The password goes in as a psql variable (:'pw'), never into the SQL text.
set -eu
: "${BACKUP_DB_PASSWORD:?BACKUP_DB_PASSWORD is required}"

psql -v ON_ERROR_STOP=1 -v pw="$BACKUP_DB_PASSWORD" -q <<'SQL'
SET client_min_messages = warning;
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fcp_backup') THEN
    CREATE ROLE fcp_backup;
  END IF;
END
$$;
ALTER ROLE fcp_backup WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'pw';
GRANT pg_read_all_data TO fcp_backup;
SQL

echo "[db-roles] fcp_backup is ready (read-only)"
