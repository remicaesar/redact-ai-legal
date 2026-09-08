#!/bin/sh
# Run from any directory; only --reset can remove this Compose project's data.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
case "${1:-}" in
  "") [ "$#" -eq 0 ] || { echo 'Usage: ./start.sh [--reset]' >&2; exit 2; } ;;
  --reset) [ "$#" -eq 1 ] || { echo 'Usage: ./start.sh [--reset]' >&2; exit 2; } ;;
  *) echo 'Usage: ./start.sh [--reset]' >&2; exit 2 ;;
esac
if ! docker info >/dev/null 2>&1; then
  echo 'Start Docker Desktop (or your local Docker engine), then run ./start.sh again.' >&2
  exit 1
fi
docker compose version >/dev/null
if [ "${1:-}" = --reset ]; then
  echo 'RESET: deleting this install’s database, uploads, exports and credentials.'
  docker compose down --volumes
fi
docker compose up --build --wait --wait-timeout 120
printf '\nRedact AI is ready: http://127.0.0.1:%s/login\n' "${REDACT_PORT:-5055}"
docker compose exec -T workstation python docker/bootstrap.py --credentials
printf 'Three fictional practice documents are ready. Stop with: docker compose stop\n'
