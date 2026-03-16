#!/usr/bin/env bash
set -euo pipefail

PG_MAJOR="${1:-18}"

case "${PG_MAJOR}" in
  18)
    ;;
  *)
    echo "Logical replication harness currently supports PostgreSQL 18 only." >&2
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "${SCRIPT_DIR}"
chmod +x docker/run-logical-replication.sh
PG_MAJOR="${PG_MAJOR}" docker/run-logical-replication.sh
