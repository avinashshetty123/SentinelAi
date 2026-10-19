#!/bin/sh
# Container entrypoint: apply migrations (unless disabled), then serve with a single Uvicorn worker.
# A single worker is intentional: WebSocket broadcast, rate limiting and the demo runner are in-process.
set -e
if [ "${RUN_MIGRATIONS_ON_START:-true}" = "true" ]; then
  echo "Applying database migrations..."
  alembic upgrade head
fi
exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port "${PORT:-8000}" \
  --proxy-headers \
  --forwarded-allow-ips="${FORWARDED_ALLOW_IPS:-127.0.0.1}" \
  --workers 1 \
  --ws-max-size 65536
