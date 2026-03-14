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
echo "=== 2. Stats endpoint with valid secret ==="
RESP=$(curl -s "$BASE/waiting-room/stats?secret=$SECRET" 2>&1)
assert "Returns active_users" "active_users" "$RESP"
assert "Returns max_users" "max_users" "$RESP"
assert "Shows granted session" "$SESSION1" "$RESP"

echo ""
echo "=== 3. Stats endpoint with invalid secret ==="
RESP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/waiting-room/stats?secret=wrong" 2>&1)
assert "Returns 403" "403" "$RESP"

echo ""
echo "=== 4. Validate access token ==="
RESP=$(curl -s "$BASE/waiting-room/validate?token=$TOKEN1&session=$SESSION1" 2>&1)
assert "Token is valid" '"valid":true' "$RESP"
assert "Returns session_id" "$SESSION1" "$RESP"
assert "Returns expires_in" "expires_in" "$RESP"

echo ""
echo "=== 5. Validate with wrong token ==="
RESP=$(curl -s "$BASE/waiting-room/validate?token=wrongtoken&session=$SESSION1" 2>&1)
assert "Token is invalid" '"valid":false' "$RESP"

echo ""
echo "=== 6. Validate with missing params ==="
RESP=$(curl -s "$BASE/waiting-room/validate?token=abc" 2>&1)
assert "Missing session error" "Missing session parameter" "$RESP"

echo ""
echo "=== 7. Grant with secret ==="
RESP=$(curl -s -D- "$BASE/waiting-room/grant?secret=$SECRET&next=/kdp/" 2>&1)
assert_status "Returns 302" "302" "$RESP"
assert "Redirects to /kdp/" "Location: /kdp/" "$RESP"
assert "Sets session cookie" "waiting_room_session_id=" "$RESP"
assert "Sets access token cookie" "waiting_room_access_token=" "$RESP"

echo ""
echo "=== 8. Grant with invalid secret ==="
RESP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/waiting-room/grant?secret=wrong" 2>&1)
assert "Returns 403" "403" "$RESP"

echo ""
echo "=== 9. Fill slots and verify queuing ==="
# MAX_USERS=3, we already have 2 granted. Grant one more to fill up.
curl -s "$BASE/waiting-room/grant?secret=$SECRET" > /dev/null
# Wait for promotion rate limit to pass
sleep 3
# Now a new user should be queued
RESP=$(curl -s -D- "$BASE/waiting-room" 2>&1)
assert_status "Returns 200 (queued)" "200" "$RESP"
assert "Shows queue page" "You are in the queue" "$RESP"
assert "Shows position" "position in the queue is:" "$RESP"
assert "Shows estimated wait" "Estimated wait time" "$RESP"
assert "Has jitter script" "jitter" "$RESP"
assert "Sets session cookie" "waiting_room_session_id=" "$RESP"

QUEUED_SESSION=$(echo "$RESP" | grep -o 'waiting_room_session_id=[^;]*' | head -1 | cut -d= -f2)

echo ""
echo "=== 10. Returning queued user keeps position ==="
RESP=$(curl -s -D- -b "waiting_room_session_id=$QUEUED_SESSION" "$BASE/waiting-room" 2>&1)
assert_status "Returns 200 (still queued)" "200" "$RESP"
assert "Same session ID in page" "$QUEUED_SESSION" "$RESP"
assert "Shows queue position" "position in the queue is:" "$RESP"

echo ""
echo "=== 11. Adaptive refresh interval ==="
# Position 1 with small queue should get 10s refresh
assert "Refresh interval 10s for front of queue" "var base = 10000" "$RESP"

echo ""
echo "=== 12. Stats shows queued + granted ==="
RESP=$(curl -s "$BASE/waiting-room/stats?secret=$SECRET" 2>&1)
assert "Has queued users" "queued_users" "$RESP"
assert "Has active users" "active_users" "$RESP"
assert "Has slots_available" "slots_available" "$RESP"

echo ""
echo "=== 13. Multiple queued users get ordered positions ==="
sleep 3
RESP2=$(curl -s -D- "$BASE/waiting-room" 2>&1)
QUEUED2=$(echo "$RESP2" | grep -o 'waiting_room_session_id=[^;]*' | head -1 | cut -d= -f2)
# First user should still be position 1
RESP_CHECK=$(curl -s -b "waiting_room_session_id=$QUEUED_SESSION" "$BASE/waiting-room" 2>&1)
assert "First queued user still position 1" "position in the queue is: 1" "$RESP_CHECK"

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
