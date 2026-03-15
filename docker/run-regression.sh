#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${REPO_DIR:-/workspace}"
PG_MAJOR="${PG_MAJOR:-18}"
PG_BINDIR="${PG_BINDIR:-/usr/lib/postgresql/${PG_MAJOR}/bin}"
export PATH="${PG_BINDIR}:$PATH"
export PG_CONFIG="${PG_BINDIR}/pg_config"
export PGDATA="${PGDATA:-/tmp/column-encrypt-pgdata}"
export PGPORT="${PGPORT:-55432}"
export PGHOST="${PGHOST:-/tmp}"
export PGDATABASE="${PGDATABASE:-test_column_encrypt}"
export PGUSER="${PGUSER:-postgres}"

pg_as_postgres() {
  runuser -u postgres -- env \
    PATH="${PATH}" \
    PG_CONFIG="${PG_CONFIG}" \
    PGDATA="${PGDATA}" \
    PGPORT="${PGPORT}" \
    PGHOST="${PGHOST}" \
    PGDATABASE="${PGDATABASE}" \
    PGUSER="${PGUSER}" \
    "$@"
}

cleanup() {
  if [[ -d "${PGDATA}" ]] && [[ -f "${PGDATA}/postmaster.pid" ]]; then
    pg_as_postgres pg_ctl -D "${PGDATA}" -m fast stop >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

cd "${REPO_DIR}"
rm -rf "${PGDATA}"
mkdir -p "${PGDATA}"
chown -R postgres:postgres "${PGDATA}"

make clean PG_CONFIG="${PG_CONFIG}"
make PG_CONFIG="${PG_CONFIG}"
make install PG_CONFIG="${PG_CONFIG}"

pg_as_postgres initdb --no-locale -E UTF8 "${PGDATA}" >/dev/null
{
  echo "shared_preload_libraries = 'column_encrypt'"
  echo "unix_socket_directories = '${PGHOST}'"
  echo "port = ${PGPORT}"
} >> "${PGDATA}/postgresql.conf"
chown postgres:postgres "${PGDATA}/postgresql.conf"

pg_as_postgres pg_ctl -D "${PGDATA}" -l "${PGDATA}/postgres.log" -w start >/dev/null || {
  cat "${PGDATA}/postgres.log"
  exit 1
}

pg_as_postgres createdb "${PGDATABASE}"
pg_as_postgres psql -d "${PGDATABASE}" -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;" >/dev/null

make installcheck PG_CONFIG="${PG_CONFIG}" PGDATABASE="${PGDATABASE}" || {
  cat "${PGDATA}/postgres.log"
  if [[ -f regression.diffs ]]; then
    cat regression.diffs
  fi
  exit 1
}

echo "Docker regression succeeded for PostgreSQL ${PG_MAJOR}"
