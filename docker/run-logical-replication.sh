#!/usr/bin/env bash
set -euo pipefail

PG_MAJOR="${PG_MAJOR:-18}"
PG_BINDIR="/usr/lib/postgresql/${PG_MAJOR}/bin"
COMPOSE_FILE="docker/docker-compose.replication.yml"
REPO_DIR="/workspace"

docker_compose() {
  docker compose -f "${COMPOSE_FILE}" "$@"
}

exec_service() {
  local service="$1"
  shift
  docker_compose exec -T "${service}" bash -lc "$*"
}

init_service() {
  local service="$1"
  local port="$2"
  local extra_conf="$3"

  exec_service "${service}" "
    set -euo pipefail
    export PATH='${PG_BINDIR}':\$PATH
    cd '${REPO_DIR}'
    make clean PG_CONFIG='${PG_BINDIR}/pg_config'
    make PG_CONFIG='${PG_BINDIR}/pg_config'
    make install PG_CONFIG='${PG_BINDIR}/pg_config'
    rm -rf /tmp/${service}-pgdata
    install -d -o postgres -g postgres /tmp/${service}-pgdata
    runuser -u postgres -- initdb --no-locale -E UTF8 /tmp/${service}-pgdata >/dev/null
    cat >> /tmp/${service}-pgdata/postgresql.conf <<'EOF'
listen_addresses = '*'
port = ${port}
wal_level = logical
max_wal_senders = 10
max_replication_slots = 10
shared_preload_libraries = 'column_encrypt'
unix_socket_directories = '/tmp'
${extra_conf}
EOF
    cat >> /tmp/${service}-pgdata/pg_hba.conf <<'EOF'
host all all all trust
host replication all all trust
EOF
    chown postgres:postgres /tmp/${service}-pgdata/postgresql.conf /tmp/${service}-pgdata/pg_hba.conf
    runuser -u postgres -- pg_ctl -D /tmp/${service}-pgdata -l /tmp/${service}-pg.log -w start >/dev/null
    runuser -u postgres -- pg_isready -h /tmp -p ${port} >/dev/null
  "
}

cleanup() {
  docker_compose down -v >/dev/null 2>&1 || true
}

trap cleanup EXIT

docker_compose up -d --build publisher subscriber >/dev/null

init_service publisher 55432 ""
init_service subscriber 55433 ""

exec_service publisher "
  export PATH='${PG_BINDIR}':\$PATH
  runuser -u postgres -- createdb -h /tmp -p 55432 repltest
  runuser -u postgres -- psql -h /tmp -p 55432 -d repltest -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'
  runuser -u postgres -- psql -h /tmp -p 55432 -d repltest -c 'CREATE EXTENSION IF NOT EXISTS column_encrypt;'
  runuser -u postgres -- psql -h /tmp -p 55432 -d repltest <<'SQL'
CREATE ROLE repluser WITH LOGIN REPLICATION;
ALTER ROLE repluser SET encrypt.enable = off;
SELECT cipher_key_disable_log();
SELECT register_cipher_key('publisher-key-v1', 'aes', 'publisher-passphrase');
SELECT cipher_key_enable_log();
SELECT load_key('publisher-passphrase');
CREATE TABLE secure_repl (id integer PRIMARY KEY, ssn encrypted_text);
INSERT INTO secure_repl VALUES (1, '111-11-1111');
GRANT SELECT ON TABLE secure_repl TO repluser;
CREATE PUBLICATION column_encrypt_pub FOR TABLE secure_repl;
SQL
"

exec_service subscriber "
  export PATH='${PG_BINDIR}':\$PATH
  runuser -u postgres -- createdb -h /tmp -p 55433 repltest
  runuser -u postgres -- psql -h /tmp -p 55433 -d repltest -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'
  runuser -u postgres -- psql -h /tmp -p 55433 -d repltest -c 'CREATE EXTENSION IF NOT EXISTS column_encrypt;'
  runuser -u postgres -- psql -h /tmp -p 55433 -d repltest <<'SQL'
CREATE ROLE subworker WITH LOGIN SUPERUSER;
ALTER ROLE subworker SET encrypt.enable = off;
SELECT cipher_key_disable_log();
SELECT register_cipher_key('publisher-key-v1', 'aes', 'publisher-passphrase');
SELECT cipher_key_enable_log();
SET ROLE subworker;
CREATE TABLE secure_repl (id integer PRIMARY KEY, ssn encrypted_text);
CREATE SUBSCRIPTION column_encrypt_sub
CONNECTION 'host=publisher port=55432 dbname=repltest user=repluser'
PUBLICATION column_encrypt_pub
WITH (copy_data = true);
RESET ROLE;
SQL
"

sleep 5

exec_service publisher "
  export PATH='${PG_BINDIR}':\$PATH
  runuser -u postgres -- psql -h /tmp -p 55432 -d repltest <<'SQL'
SELECT load_key('publisher-passphrase');
INSERT INTO secure_repl VALUES (2, '222-22-2222');
SQL
"

sleep 5

exec_service subscriber "
  export PATH='${PG_BINDIR}':\$PATH
  count=0
  for _ in \$(seq 1 30); do
    count=\$(runuser -u postgres -- psql -h /tmp -p 55433 -d repltest -At -c 'SELECT COUNT(*) FROM secure_repl;')
    if [ \"\${count}\" = '2' ]; then
      break
    fi
    sleep 1
  done
  if [ \"\${count}\" != '2' ]; then
    echo \"Expected 2 replicated rows, found \${count}\" >&2
    exit 1
  fi
"

exec_service subscriber "
  export PATH='${PG_BINDIR}':\$PATH
  runuser -u postgres -- psql -h /tmp -p 55433 -d repltest <<'SQL'
SELECT load_key('publisher-passphrase');
TABLE secure_repl ORDER BY id;
SQL
"

echo 'Logical replication integration succeeded'
