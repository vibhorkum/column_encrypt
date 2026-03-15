#!/usr/bin/env bash
set -euo pipefail

PG_MAJOR="${1:-18}"

case "${PG_MAJOR}" in
  14|15|16|17|18)
    ;;
  *)
    echo "Unsupported PostgreSQL version: ${PG_MAJOR}" >&2
    echo "Usage: $0 [14|15|16|17|18]" >&2
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "${SCRIPT_DIR}"
PG_MAJOR="${PG_MAJOR}" docker compose -f docker/docker-compose.test.yml run --rm regression
