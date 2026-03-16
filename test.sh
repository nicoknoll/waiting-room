#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

PASS=0
FAIL=0
BASE="http://localhost:8888"
SECRET="test-secret-123"
PROTECTED_PATH="/kdp/"

assert() {
    local name="$1"
    local expected="$2"
    local actual="$3"
    if echo "$actual" | grep -q "$expected"; then
        echo -e "  ${GREEN}✓${NC} $name"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} $name"
        echo "    expected: $expected"
        echo "    actual:   $actual"
        FAIL=$((FAIL + 1))
    fi
}

assert_not() {
    local name="$1"
    local unexpected="$2"
    local actual="$3"
    if echo "$actual" | grep -q "$unexpected"; then
        echo -e "  ${RED}✗${NC} $name"
        echo "    should not contain: $unexpected"
        FAIL=$((FAIL + 1))
    else
        echo -e "  ${GREEN}✓${NC} $name"
        PASS=$((PASS + 1))
    fi
}

assert_status() {
    local name="$1"
    local expected="$2"
    local actual="$3"
    local status
    status=$(echo "$actual" | head -1 | grep -o '[0-9]\{3\}')
    if [ "$status" = "$expected" ]; then
        echo -e "  ${GREEN}✓${NC} $name (HTTP $status)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} $name (expected HTTP $expected, got HTTP $status)"
        FAIL=$((FAIL + 1))
    fi
}

echo "Starting test containers..."
docker compose -f docker-compose.test.yml up --build -d 2>&1 | tail -2
sleep 2

# Flush Redis to start clean
docker compose -f docker-compose.test.yml exec -T redis redis-cli FLUSHALL > /dev/null 2>&1

echo ""
echo "=== 1. New user gets queued and immediately promoted (slots available) ==="
RESP=$(curl -s -D- "$BASE/waiting-room" 2>&1)
assert_status "Returns 302 redirect" "302" "$RESP"
assert "Sets session cookie" "waiting_room_session_id=" "$RESP"
assert "Sets access token cookie" "waiting_room_access_token=" "$RESP"
assert "Shows granted HTML" "Access Granted" "$RESP"

# Extract session ID and token from first response
SESSION1=$(echo "$RESP" | grep -o 'waiting_room_session_id=[^;]*' | head -1 | cut -d= -f2)
TOKEN1=$(echo "$RESP" | grep -o 'waiting_room_access_token=[^;]*' | head -1 | cut -d= -f2)

echo ""
echo "=== 2. New user with ?next= param gets redirected to that URL ==="
RESP=$(curl -s -D- "$BASE/waiting-room?next=${PROTECTED_PATH}my-event/" 2>&1)
assert_status "Returns 302" "302" "$RESP"
assert "Redirects to next URL" "Location: ${PROTECTED_PATH}my-event/" "$RESP"
assert "HTML contains next URL link" "${PROTECTED_PATH}my-event/" "$RESP"

echo ""
echo "=== 3. Returning granted user gets 302 again (not re-queued) ==="
RESP=$(curl -s -D- -b "waiting_room_session_id=$SESSION1" "$BASE/waiting-room?next=${PROTECTED_PATH}" 2>&1)
assert_status "Returns 302" "302" "$RESP"
assert "Sets access token cookie" "waiting_room_access_token=" "$RESP"
assert "Redirects to next" "Location: ${PROTECTED_PATH}" "$RESP"

echo ""
echo "=== 4. Bogus session cookie is treated as new arrival ==="
RESP=$(curl -s -D- -b "waiting_room_session_id=nonexistent-session-id" "$BASE/waiting-room" 2>&1)
assert_status "Returns 302 (new session granted)" "302" "$RESP"
assert "Gets new session cookie" "waiting_room_session_id=" "$RESP"
assert_not "Does not keep bogus session" "nonexistent-session-id" "$RESP"

echo ""
echo "=== 5. Stats endpoint with valid secret ==="
RESP=$(curl -s "$BASE/waiting-room/stats?secret=$SECRET" 2>&1)
assert "Returns active_users" "active_users" "$RESP"
assert "Returns max_users" "max_users" "$RESP"
assert "Shows granted session" "$SESSION1" "$RESP"

echo ""
echo "=== 6. Stats endpoint with invalid secret ==="
RESP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/waiting-room/stats?secret=wrong" 2>&1)
assert "Returns 403" "403" "$RESP"

echo ""
echo "=== 7. Stats endpoint without secret ==="
RESP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/waiting-room/stats" 2>&1)
assert "Returns 403" "403" "$RESP"

echo ""
echo "=== 8. Validate access token ==="
RESP=$(curl -s "$BASE/waiting-room/validate?token=$TOKEN1&session=$SESSION1" 2>&1)
assert "Token is valid" '"valid":true' "$RESP"
assert "Returns session_id" "$SESSION1" "$RESP"
assert "Returns expires_in" "expires_in" "$RESP"

echo ""
echo "=== 9. Validate with wrong token ==="
RESP=$(curl -s "$BASE/waiting-room/validate?token=wrongtoken&session=$SESSION1" 2>&1)
assert "Token is invalid" '"valid":false' "$RESP"
assert "Error says invalid token" "Invalid token" "$RESP"

echo ""
echo "=== 10. Validate with missing session param ==="
RESP=$(curl -s "$BASE/waiting-room/validate?token=abc" 2>&1)
assert "Missing session error" "Missing session parameter" "$RESP"

echo ""
echo "=== 11. Validate with missing token param ==="
RESP=$(curl -s "$BASE/waiting-room/validate?session=abc" 2>&1)
assert "Missing token error" "Missing token parameter" "$RESP"

echo ""
echo "=== 12. Validate with non-existent session ==="
RESP=$(curl -s "$BASE/waiting-room/validate?token=abc&session=does-not-exist" 2>&1)
assert "Returns valid=false" '"valid":false' "$RESP"
assert "Session not found" "not found or not granted" "$RESP"

echo ""
echo "=== 13. Grant with secret and next param ==="
RESP=$(curl -s -D- "$BASE/waiting-room/grant?secret=$SECRET&next=${PROTECTED_PATH}" 2>&1)
assert_status "Returns 302" "302" "$RESP"
assert "Redirects to protected path" "Location: ${PROTECTED_PATH}" "$RESP"
assert "Sets session cookie" "waiting_room_session_id=" "$RESP"
assert "Sets access token cookie" "waiting_room_access_token=" "$RESP"

echo ""
echo "=== 14. Grant without next param defaults to / ==="
RESP=$(curl -s -D- "$BASE/waiting-room/grant?secret=$SECRET" 2>&1)
assert_status "Returns 302" "302" "$RESP"
assert "Redirects to /" "Location: /" "$RESP"

echo ""
echo "=== 15. Grant with invalid secret ==="
RESP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/waiting-room/grant?secret=wrong" 2>&1)
assert "Returns 403" "403" "$RESP"

echo ""
echo "=== 16. Grant without secret ==="
RESP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/waiting-room/grant" 2>&1)
assert "Returns 403" "403" "$RESP"

echo ""
echo "=== 17. Fill slots and verify queuing ==="
# Flush and start fresh — MAX_USERS=3
docker compose -f docker-compose.test.yml exec -T redis redis-cli FLUSHALL > /dev/null 2>&1
sleep 1
# Grant 3 users to fill all slots
curl -s "$BASE/waiting-room/grant?secret=$SECRET" > /dev/null
curl -s "$BASE/waiting-room/grant?secret=$SECRET" > /dev/null
curl -s "$BASE/waiting-room/grant?secret=$SECRET" > /dev/null
# Wait for background promotion timer to run (ensures it sees slots are full)
sleep 3
# Now a new user should be queued
RESP=$(curl -s -D- "$BASE/waiting-room" 2>&1)
assert_status "Returns 200 (queued)" "200" "$RESP"
assert "Shows queue page" "You are in the queue" "$RESP"
assert "Shows position" "position in the queue is:" "$RESP"
assert "Shows estimated wait" "Estimated wait time" "$RESP"
assert "Has jitter script" "jitter" "$RESP"
assert "Sets session cookie" "waiting_room_session_id=" "$RESP"
assert_not "Does NOT set access token" "waiting_room_access_token=" "$RESP"

QUEUED_SESSION=$(echo "$RESP" | grep -o 'waiting_room_session_id=[^;]*' | head -1 | cut -d= -f2)

echo ""
echo "=== 18. Returning queued user keeps position ==="
RESP=$(curl -s -D- -b "waiting_room_session_id=$QUEUED_SESSION" "$BASE/waiting-room" 2>&1)
assert_status "Returns 200 (still queued)" "200" "$RESP"
assert "Same session ID in page" "$QUEUED_SESSION" "$RESP"
assert "Shows queue position" "position in the queue is:" "$RESP"

echo ""
echo "=== 19. Adaptive refresh interval ==="
# Position 1 with small queue should get 10s refresh
assert "Refresh interval 10s for front of queue" "var base = 10000" "$RESP"

echo ""
echo "=== 20. Multiple queued users get ordered positions ==="
sleep 3
RESP2=$(curl -s -D- "$BASE/waiting-room" 2>&1)
QUEUED2=$(echo "$RESP2" | grep -o 'waiting_room_session_id=[^;]*' | head -1 | cut -d= -f2)
assert "Second user is position 2" "position in the queue is: 2" "$RESP2"
# First user should still be position 1
RESP_CHECK=$(curl -s -b "waiting_room_session_id=$QUEUED_SESSION" "$BASE/waiting-room" 2>&1)
assert "First queued user still position 1" "position in the queue is: 1" "$RESP_CHECK"

echo ""
echo "=== 21. Stats shows accurate counts ==="
RESP=$(curl -s "$BASE/waiting-room/stats?secret=$SECRET" 2>&1)
assert "Has queued users" "queued_users" "$RESP"
assert "Has active users" "active_users" "$RESP"
assert "Has slots_available" "slots_available" "$RESP"
assert "Shows 3 active users" '"active_users":3' "$RESP"
assert "Shows 2 queued users" '"queued_users":2' "$RESP"
assert "Shows 0 slots available" '"slots_available":0' "$RESP"
assert "Shows max_users 3" '"max_users":3' "$RESP"

echo ""
echo "=== 22. Queued user gets promoted when slots free up (background timer) ==="
# Set all grant scores to epoch 1 (expired) — the promote script's ZREMRANGEBYSCORE
# will clean these up, then promote queued users into the freed slots
docker compose -f docker-compose.test.yml exec -T redis redis-cli EVAL \
    "local ms = redis.call('ZRANGE', KEYS[1], 0, -1); for _, m in ipairs(ms) do redis.call('ZADD', KEYS[1], 1, m) end; return #ms" \
    1 wr:granted > /dev/null 2>&1
# Wait for background promotion timer to run (every 2s)
sleep 4
# First queued user should now be granted
RESP=$(curl -s -D- -b "waiting_room_session_id=$QUEUED_SESSION" "$BASE/waiting-room" 2>&1)
assert_status "Queued user now gets 302 (promoted)" "302" "$RESP"
assert "Sets access token cookie" "waiting_room_access_token=" "$RESP"
assert "Shows granted page" "Access Granted" "$RESP"

echo ""
echo "=== 23. Protected path without access token redirects to waiting room ==="
RESP=$(curl -s -D- -o /dev/null -w "%{http_code}|%{redirect_url}" "$BASE${PROTECTED_PATH}my-event/" 2>&1)
# Should get 302 redirect
assert "Redirects from protected path" "302" "$RESP"

echo ""
echo "=== 24. Protected path with access token passes through ==="
# First get a valid grant to get cookies
GRANT_RESP=$(curl -s -D- "$BASE/waiting-room/grant?secret=$SECRET" 2>&1)
GRANT_TOKEN=$(echo "$GRANT_RESP" | grep -o 'waiting_room_access_token=[^;]*' | head -1 | cut -d= -f2)
GRANT_SESSION=$(echo "$GRANT_RESP" | grep -o 'waiting_room_session_id=[^;]*' | head -1 | cut -d= -f2)
# Now hit protected path with the token — should proxy to upstream, not redirect
RESP=$(curl -s -D- -b "waiting_room_access_token=$GRANT_TOKEN;waiting_room_session_id=$GRANT_SESSION" "$BASE${PROTECTED_PATH}" 2>&1)
# The upstream container is traefik/whoami, so it should return 200,
# but NOT a 302 redirect to /waiting-room
assert_not "Does not redirect to waiting room" "Location: /waiting-room" "$RESP"

echo ""
echo "=== 25. Redis failure: user-facing route returns 503 HTML ==="
docker compose -f docker-compose.test.yml stop redis 2>&1 | tail -1
sleep 1
RESP=$(curl -s -D- "$BASE/waiting-room" 2>&1)
assert_status "Returns 503" "503" "$RESP"
assert "Returns HTML content-type" "text/html" "$RESP"
assert "Shows unavailable page" "temporarily unavailable" "$RESP"

echo ""
echo "=== 26. Redis failure: stats route returns 503 JSON ==="
RESP=$(curl -s -D- "$BASE/waiting-room/stats?secret=$SECRET" 2>&1)
assert_status "Returns 503" "503" "$RESP"
assert "Returns JSON error" "Redis unavailable" "$RESP"

echo ""
echo "=== 27. Redis failure: validate route returns 503 JSON ==="
RESP=$(curl -s -D- "$BASE/waiting-room/validate?token=x&session=y" 2>&1)
assert_status "Returns 503" "503" "$RESP"
assert "Returns JSON error" "Redis unavailable" "$RESP"

echo ""
echo "=== 28. Redis failure: grant route returns 503 JSON ==="
RESP=$(curl -s -D- "$BASE/waiting-room/grant?secret=$SECRET" 2>&1)
assert_status "Returns 503" "503" "$RESP"
assert "Returns JSON error" "Redis unavailable" "$RESP"

echo ""
echo "Restarting Redis..."
docker compose -f docker-compose.test.yml start redis 2>&1 | tail -1
# Wait for stale keepalive connections to expire (10s TTL) + Redis startup
sleep 12

echo ""
echo "=== 29. Recovery after Redis restart ==="
# Redis is empty after restart, all slots are free. New arrival gets inline promotion.
# Flush Redis to ensure clean state (bg timer may have enqueued ghost entries during restart)
docker compose -f docker-compose.test.yml exec -T redis redis-cli FLUSHALL > /dev/null 2>&1
sleep 3
RESP=$(curl -s -D- "$BASE/waiting-room" 2>&1)
assert_status "Returns 302 after recovery" "302" "$RESP"
assert "Shows granted page" "Access Granted" "$RESP"

echo ""
echo "================================================"
echo -e "Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
echo "================================================"

echo ""
echo "Stopping test containers..."
docker compose -f docker-compose.test.yml down 2>&1 | tail -1

if [ $FAIL -gt 0 ]; then
    exit 1
fi
