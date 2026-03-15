#!/bin/bash
# Usage: ./load-test.sh
# Requires: docker, k6 (brew install k6)
set -e

export WAITING_ROOM_MAX_USERS=10

echo "Starting load test stack (MAX_USERS=$WAITING_ROOM_MAX_USERS)..."
docker compose -f docker-compose.test.yml up --build -d

# Throttle nginx container to match prod (512MB RAM, 0.5 CPU)
NGINX_ID=$(docker compose -f docker-compose.test.yml ps -q nginx)
docker update --cpus="0.5" --memory="512m" --memory-swap="512m" "$NGINX_ID"

echo "Waiting for OpenResty to be ready..."
until curl -s http://localhost:8888/waiting-room > /dev/null 2>&1; do sleep 1; done

echo ""
echo "Monitor containers in another terminal:"
echo "  docker stats \$(docker compose -f docker-compose.test.yml ps -q)"
echo ""

echo "Running k6 — dashboard at http://localhost:5665"
k6 run \
  --out web-dashboard \
  -e BASE_URL=http://localhost:8888 \
  load-test.js

echo "Stopping stack..."
docker compose -f docker-compose.test.yml down
