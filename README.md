# Waitingroom

A waiting room / queue system for pretix, built with OpenResty (nginx + Lua) and Redis.

When enabled, users accessing the ticket shop are placed in a queue and granted access in order, up to a configurable maximum number of concurrent users.

## Architecture

```
User -> OpenResty -> Redis (queue management via Lua)
                  -> pretix (if access granted)
                  -> queue page (if waiting)
```

All waiting room logic runs as Lua inside OpenResty, using Redis sorted sets for O(log N) queue operations. There is no external function or service — the nginx container handles everything.

## How it works

1. User visits `/kdp/` without an access token cookie -> redirected to `/waiting-room`
2. `/waiting-room` checks if the user has an existing session (via cookie)
3. If no session exists, the user is added to the queue
4. A promotion script (rate-limited, atomic) moves users from the queue to granted when slots open up
5. Granted users get a session cookie + access token cookie and are redirected to the shop
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

## Endpoints

| Path | Description |
|------|-------------|
| `/waiting-room` | Main entry — queues or grants the user |
| `/waiting-room/stats?secret=SECRET` | JSON stats (queued/granted counts, session list) |
| `/waiting-room/validate?token=TOKEN&session=SESSION_ID` | Validate an access token |
| `/waiting-room/grant?secret=SECRET&next=/path` | Admin: grant immediate access, bypassing the queue |

## Local testing

Requirements: Docker

```bash
# Start Redis + OpenResty locally (port 8888, logs in foreground)
./run_local.sh

# Or run in background
docker compose -f docker-compose.test.yml up --build -d

# Open in browser
open http://localhost:8888/waiting-room
open "http://localhost:8888/waiting-room/stats?secret=test-secret-123"

# Run automated tests (32 tests covering all endpoints)
./test.sh

# Stop
docker compose -f docker-compose.test.yml down
```

The test setup uses `MAX_USERS=3` so you can easily fill the slots and see the queue page. To test queuing:

1. Open `http://localhost:8888/waiting-room/grant?secret=test-secret-123` three times to fill slots
2. Open `http://localhost:8888/waiting-room` in an incognito window — you'll see the queue page

## Project structure

```
nginx/
  Dockerfile          # OpenResty (alpine) + Lua + envsubst
  nginx.conf          # OpenResty config with Lua integration
  run.sh              # Entrypoint: envsubst + start OpenResty
  lua/
    waiting_room.lua  # All waiting room logic
docker-compose.test.yml  # Local test setup
test.sh                  # Automated test suite
```

## Redis data model

Uses sorted sets for O(log N) operations (no `KEYS` scans):

| Key | Type | Score | Member |
|-----|------|-------|--------|
| `wr:queue` | Sorted Set | enqueue timestamp (ms) | session_id |
| `wr:granted` | Sorted Set | expiry timestamp (s) | session_id |
| `wr:heartbeat` | Hash | — | session_id -> last seen (s) |

Promotion runs as an atomic Redis Lua script, rate-limited to once per 2 seconds via OpenResty shared memory.
