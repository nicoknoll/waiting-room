# Waitingroom

A waiting room / queue system for any web application, built with OpenResty (nginx + Lua) and Redis.

When enabled, users accessing the protected path are placed in a queue and granted access in order, up to a configurable maximum number of concurrent users.

## Architecture

```
User -> OpenResty -> Redis (queue management via Lua)
                  -> upstream (if access granted)
                  -> queue page (if waiting)
```

All waiting room logic runs as Lua inside OpenResty, using Redis sorted sets for O(log N) queue operations. There is no external function or service — the nginx container handles everything.

Background timers on worker 0 handle promotion (every 2s) and stale session cleanup (every 30s), keeping the request path lightweight.

## How it works

1. User visits the protected path without an access token cookie -> redirected to `/waiting-room`
2. `/waiting-room` checks if the user has an existing session (via cookie)
3. If no session exists, the user is added to the queue
4. A promotion script (atomic Redis Lua) moves users from the queue to granted when slots open up — runs inline for new arrivals, and every 2s via background timer for everyone else
5. Granted users get a session cookie + access token cookie and are redirected to the protected path
6. Queued users see a waiting page with their position and estimated wait time, which auto-refreshes with adaptive intervals

## Configuration

Environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `REDIS_LOCATION` | Yes | Redis URL (e.g. `redis://host:6379` or `rediss://...` for TLS) |
| `WAITING_ROOM_SECRET` | Yes | Secret for admin endpoints (`/stats`, `/grant`) |
| `WAITING_ROOM_MAX_USERS` | No | Max concurrent granted users (default: 100) |
| `WAITING_ROOM_ENABLED` | No | Set to `1` to enable waiting room redirects (default: `0`) |
| `WAITING_ROOM_BLOCKED_UNTIL` | No | Unix timestamp or ISO datetime — blocks promotions until this time |
| `WAITING_ROOM_BLOCK_DURATION_MINUTES` | No | Minutes before `BLOCKED_UNTIL` to start blocking (default: 30) |
| `WAITING_ROOM_QUEUED_TTL` | No | Seconds a queued session stays alive without polling (default: 300) |
| `WAITING_ROOM_GRANTED_TTL` | No | Seconds a granted session lasts (default: 300) |
| `WAITING_ROOM_ACCESS_TOKEN_TTL` | No | Seconds the access token cookie is valid (default: 600) |
| `WAITING_ROOM_PROTECTED_PATH` | No | URL prefix to protect with the waiting room (default: `/`) |
| `WAITING_ROOM_UPSTREAM_URL` | No | Backend service to proxy to (default: `http://localhost:8000`) |

## Endpoints

| Path | Description |
|------|-------------|
| `/waiting-room` | Main entry — queues or grants the user |
| `/waiting-room/stats?secret=SECRET` | JSON stats (queued/granted counts, session list) |
| `/waiting-room/validate?token=TOKEN&session=SESSION_ID` | Validate an access token |
| `/waiting-room/grant?secret=SECRET&next=/path` | Admin: grant immediate access, bypassing the queue |

## Testing

Both the integration tests and load tests use the same `docker-compose.test.yml`. It spins up Valkey (Redis-compatible), OpenResty, and a stub upstream container.

### Integration tests

Runs 29 test groups (71 assertions) covering all endpoints, the queue/grant lifecycle, background promotion, protected path routing, Redis failure + recovery.

```bash
# Run the full test suite (starts/stops containers automatically)
bash test.sh
```

The tests use `MAX_USERS=3` (the default in the compose file) so slots fill up quickly.

### Load tests

Requires [k6](https://k6.io/): `brew install k6`

Two scenarios run back-to-back:
- **thundering_herd** — 5,000 VUs arrive at once (simulates pre-sale open)
- **steady_queue** — 1,000 VUs refreshing every ~10s (simulates waiting)

```bash
# Run (starts containers, throttles nginx to prod-like limits, runs k6)
bash load-test.sh
```

The k6 web dashboard is available at http://localhost:5665 during the run.

**Monitor container resources** in a second terminal while the load test runs:

```bash
docker stats $(docker compose -f docker-compose.test.yml ps -q)
```

**Inspect Redis** during or after a test:

```bash
# Live command stream
docker compose -f docker-compose.test.yml exec redis redis-cli monitor

# Queue/grant counts
docker compose -f docker-compose.test.yml exec redis redis-cli ZCARD wr:queue
docker compose -f docker-compose.test.yml exec redis redis-cli ZCARD wr:granted

# Flush everything (reset between runs)
docker compose -f docker-compose.test.yml exec redis redis-cli FLUSHALL
```

**Check nginx error logs:**

```bash
docker compose -f docker-compose.test.yml logs nginx
```

### Manual testing

```bash
# Start the stack
docker compose -f docker-compose.test.yml up --build -d

# Open in browser
open http://localhost:8888/waiting-room
open "http://localhost:8888/waiting-room/stats?secret=test-secret-123"

# Stop
docker compose -f docker-compose.test.yml down
```

To see the queue page: grant 3 users to fill all slots, then visit in an incognito window:

```bash
curl -s "http://localhost:8888/waiting-room/grant?secret=test-secret-123" > /dev/null
curl -s "http://localhost:8888/waiting-room/grant?secret=test-secret-123" > /dev/null
curl -s "http://localhost:8888/waiting-room/grant?secret=test-secret-123" > /dev/null
open http://localhost:8888/waiting-room
```

## Project structure

```
nginx/
  Dockerfile          # OpenResty (alpine) + Lua + envsubst
  nginx.conf          # OpenResty config with Lua integration + background timers
  run.sh              # Entrypoint: envsubst + start OpenResty
  lua/
    waiting_room.lua  # All waiting room logic
docker-compose.test.yml  # Shared test/load-test setup
test.sh                  # Integration test suite (71 assertions)
load-test.sh             # Load test runner (wraps k6)
load-test.js             # k6 scenarios
```

## Redis data model

Uses sorted sets for O(log N) operations (no `KEYS` scans):

| Key | Type | Score | Member |
|-----|------|-------|--------|
| `wr:queue` | Sorted Set | enqueue timestamp (ms) | session_id |
| `wr:granted` | Sorted Set | expiry timestamp (s) | session_id |
| `wr:heartbeat` | Hash | — | session_id -> last seen (s) |

Promotion runs as an atomic Redis Lua script. Background timer (worker 0) runs it every 2s; new arrivals also run it inline for instant promotion when slots are free.
