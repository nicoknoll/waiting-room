-- scripts.lua
-- Atomic Redis Lua scripts (run on the Redis server via EVAL/EVALSHA)

local _M = {}

-- Promotion script: expires grants, promotes queued users into freed slots.
-- check_session (ARGV[5]) is optional: pass "" to skip session check.
_M.PROMOTE = [[
local queue_key = KEYS[1]
local granted_key = KEYS[2]
local heartbeat_key = KEYS[3]
local now = tonumber(ARGV[1])
local max_users = tonumber(ARGV[2])
local granted_ttl = tonumber(ARGV[3])
local queued_ttl = tonumber(ARGV[4])
local check_session = ARGV[5]

-- Clean expired grants
redis.call('ZREMRANGEBYSCORE', granted_key, '-inf', now)

-- Count available slots
local granted_count = redis.call('ZCARD', granted_key)
local available = max_users - granted_count
if available <= 0 then
    -- Still check if session was already granted
    if check_session and check_session ~= "" then
        local gs = redis.call('ZSCORE', granted_key, check_session)
        if gs then return {0, tostring(gs)} end
    end
    return {0, ""}
end

-- Fetch more candidates than needed to skip stale ones
local fetch_count = math.max(10, available * 3)
local candidates = redis.call('ZRANGE', queue_key, 0, fetch_count - 1)
local stale_cutoff = now - queued_ttl
local promoted = 0
for _, sid in ipairs(candidates) do
    if promoted >= available then break end
    local hb = redis.call('HGET', heartbeat_key, sid)
    if hb and tonumber(hb) >= stale_cutoff then
        redis.call('ZREM', queue_key, sid)
        redis.call('HDEL', heartbeat_key, sid)
        redis.call('ZADD', granted_key, now + granted_ttl, sid)
        promoted = promoted + 1
    end
    -- stale users are skipped here, cleaned up by background timer
end

-- Return granted score for the checked session
local session_score = ""
if check_session and check_session ~= "" then
    local gs = redis.call('ZSCORE', granted_key, check_session)
    if gs then session_score = tostring(gs) end
end

return {promoted, session_score}
]]

-- Cleanup script: removes stale sessions from the queue in batches.
_M.CLEANUP = [[
local queue_key = KEYS[1]
local heartbeat_key = KEYS[2]
local stale_cutoff = tonumber(ARGV[1])
local offset = tonumber(ARGV[2])
local batch_size = tonumber(ARGV[3])
local members = redis.call('ZRANGE', queue_key, offset, offset + batch_size - 1)
local removed = 0
for _, sid in ipairs(members) do
    local hb = redis.call('HGET', heartbeat_key, sid)
    if not hb or tonumber(hb) < stale_cutoff then
        redis.call('ZREM', queue_key, sid)
        redis.call('HDEL', heartbeat_key, sid)
        removed = removed + 1
    end
end
return removed
]]

return _M