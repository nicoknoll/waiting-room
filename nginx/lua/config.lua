-- config.lua
-- Shared configuration for waiting room (loaded once per worker)

local _M = {}

-- Redis keys
_M.QUEUE_KEY = "wr:queue"
_M.GRANTED_KEY = "wr:granted"
_M.HEARTBEAT_KEY = "wr:heartbeat"

-- TTLs (seconds)
_M.QUEUED_TTL = tonumber(os.getenv("WAITING_ROOM_QUEUED_TTL") or "300")
_M.GRANTED_TTL = tonumber(os.getenv("WAITING_ROOM_GRANTED_TTL") or "300")
_M.ACCESS_TOKEN_TTL = tonumber(os.getenv("WAITING_ROOM_ACCESS_TOKEN_TTL") or "600")

-- Config from environment
_M.MAX_USERS = tonumber(os.getenv("WAITING_ROOM_MAX_USERS") or "100")
_M.SECRET = os.getenv("WAITING_ROOM_SECRET") or ""
_M.BLOCK_DURATION_MINUTES = tonumber(os.getenv("WAITING_ROOM_BLOCK_DURATION_MINUTES") or "30")

-- Cookie flag
_M.SECURE_FLAG = os.getenv("WAITING_ROOM_DEBUG") == "1" and "" or "; Secure"

-- Parse BLOCKED_UNTIL
local BLOCKED_UNTIL_RAW = os.getenv("WAITING_ROOM_BLOCKED_UNTIL") or ""
local function parse_blocked_until()
    if BLOCKED_UNTIL_RAW == "" then return nil end
    if BLOCKED_UNTIL_RAW:match("^%d+$") then return tonumber(BLOCKED_UNTIL_RAW) end
    local y, m, d, h, mn, s = BLOCKED_UNTIL_RAW:match("^(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if y then
        return os.time({ year = tonumber(y), month = tonumber(m), day = tonumber(d),
                         hour = tonumber(h), min = tonumber(mn), sec = tonumber(s) })
    end
    return nil
end
_M.BLOCKED_UNTIL = parse_blocked_until()

function _M.is_access_blocked()
    if not _M.BLOCKED_UNTIL then return false, 0 end
    local now = ngx.time()
    local block_start = _M.BLOCKED_UNTIL - (_M.BLOCK_DURATION_MINUTES * 60)
    if now >= block_start and now <= _M.BLOCKED_UNTIL then
        return true, _M.BLOCKED_UNTIL - now
    end
    return false, 0
end

return _M
