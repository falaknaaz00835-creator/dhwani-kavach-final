#!/usr/bin/env bash
set -e
PORT="${PORT:-8000}"
echo "==> Starting Dhwani-Kavach Server on port $PORT..."
exec gunicorn --bind "0.0.0.0:${PORT}" --workers 1 --threads 4 --timeout 120 demo_server:app
