local _M = {}

-- Shared Redis connection helper for background timers
local bg_redis_host = nil  -- cached resolved host

local function bg_get_redis()
    local redis_mod = require "resty.redis"
    local red = redis_mod:new()
    red:set_timeouts(300, 2000, 2000)

    local redis_url = os.getenv("REDIS_LOCATION") or ""
    local rhost, rport, rpass, rdb, rssl = "127.0.0.1", 6379, nil, 0, false
    if redis_url ~= "" then
        local url = redis_url
        if url:sub(1, 9) == "rediss://" then rssl = true; url = "redis://" .. url:sub(10) end
        url = url:gsub("^redis://", "")
        local auth, rest = url:match("^(.-)@(.+)$")
        if auth then
            local _, pw = auth:match("^(.*):(.+)$")
            if pw then rpass = pw elseif auth ~= "" then rpass = auth end
            url = rest
        end
        local hp, db = url:match("^([^/]+)/(%d+)")
        if not hp then hp = url:gsub("/+$", "") end
        if db then rdb = tonumber(db) end
        local h, p = hp:match("^(.+):(%d+)$")
        if h then rhost = h; rport = tonumber(p) elseif hp ~= "" then rhost = hp end
    end

    if not bg_redis_host then
        if rhost:match("^%d+%.%d+%.%d+%.%d+$") then
            bg_redis_host = rhost
        else
            local resolver = require "resty.dns.resolver"
            local nameservers = {}
            local f = io.open("/etc/resolv.conf", "r")
            if f then
                for line in f:lines() do
                    local ns = line:match("^%s*nameserver%s+(%S+)")
                    if ns then table.insert(nameservers, ns) end
                end
                f:close()
            end
            if #nameservers == 0 then nameservers = { "8.8.8.8" } end
            local r, err = resolver:new({ nameservers = nameservers, retrans = 3, timeout = 2000 })
            if r then
                local answers = r:query(rhost, { qtype = r.TYPE_A })
                if answers and not answers.errcode then
                    for _, ans in ipairs(answers) do
                        if ans.address then bg_redis_host = ans.address; break end
                    end
                end
            end
            if not bg_redis_host then return nil, "cannot resolve " .. rhost end
        end
    end

    local ok, err
    if rssl then
        ok, err = red:connect(bg_redis_host, rport, { ssl = true, ssl_verify = false })
    else
        ok, err = red:connect(bg_redis_host, rport)
    end
    if not ok then return nil, err end
    if rpass then red:auth(rpass) end
    if rdb > 0 then red:select(rdb) end
    return red
end

-- Background promotion (every 2 seconds)
local promote_script = [[
    local queue_key = KEYS[1]
    local granted_key = KEYS[2]
    local heartbeat_key = KEYS[3]
    local now = tonumber(ARGV[1])
    local max_users = tonumber(ARGV[2])
    local granted_ttl = tonumber(ARGV[3])
    local queued_ttl = tonumber(ARGV[4])

    redis.call('ZREMRANGEBYSCORE', granted_key, '-inf', now)

    local granted_count = redis.call('ZCARD', granted_key)
    local available = max_users - granted_count
    if available <= 0 then return {0, ""} end

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
    end
    return {promoted, ""}
]]

local function bg_promote()
    -- Check if access is blocked
    local blocked_raw = os.getenv("WAITING_ROOM_BLOCKED_UNTIL") or ""
    if blocked_raw ~= "" then
        local blocked_until
        if blocked_raw:match("^%d+$") then
            blocked_until = tonumber(blocked_raw)
        else
            local y, m, d, h, mn, s = blocked_raw:match("^(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
            if y then
                blocked_until = os.time({ year = tonumber(y), month = tonumber(m), day = tonumber(d),
                    hour = tonumber(h), min = tonumber(mn), sec = tonumber(s) })
            end
        end
        if blocked_until then
            local block_dur = tonumber(os.getenv("WAITING_ROOM_BLOCK_DURATION_MINUTES") or "30")
            local now = ngx.time()
            if now >= blocked_until - (block_dur * 60) and now <= blocked_until then
                return  -- access blocked, skip promotion
            end
        end
    end

    local red, err = bg_get_redis()
    if not red then ngx.log(ngx.WARN, "bg_promote: redis: ", err); return end

    local now = ngx.time()
    local max_users = tonumber(os.getenv("WAITING_ROOM_MAX_USERS") or "100")
    local granted_ttl = tonumber(os.getenv("WAITING_ROOM_GRANTED_TTL") or "300")
    local queued_ttl = tonumber(os.getenv("WAITING_ROOM_QUEUED_TTL") or "300")

    local result, err = red:eval(promote_script, 3,
        "wr:queue", "wr:granted", "wr:heartbeat",
        tostring(now), tostring(max_users),
        tostring(granted_ttl), tostring(queued_ttl))
    if err then ngx.log(ngx.ERR, "bg_promote: eval: ", err) end

    red:set_keepalive(10000, 10)
end

-- Background stale cleanup (every 30 seconds)
local cleanup_script = [[
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

local function stale_cleanup()
    local red, err = bg_get_redis()
    if not red then ngx.log(ngx.WARN, "cleanup: redis: ", err); return end

    local queued_ttl = tonumber(os.getenv("WAITING_ROOM_QUEUED_TTL") or "300")
    local stale_cutoff = ngx.time() - queued_ttl
    local batch_size = 200
    local offset = 0
    local total_removed = 0

    while true do
        local removed, err = red:eval(cleanup_script, 2, "wr:queue", "wr:heartbeat",
            tostring(stale_cutoff), tostring(offset), tostring(batch_size))
        if err or type(removed) ~= "number" then break end
        total_removed = total_removed + removed
        offset = offset + batch_size - removed
        local queue_len = red:zcard("wr:queue")
        if type(queue_len) ~= "number" or offset >= queue_len then break end
    end

    if total_removed > 0 then
        ngx.log(ngx.INFO, "cleanup: removed ", total_removed, " stale queue entries")
    end

    red:set_keepalive(10000, 10)
end

function _M.start()
    -- Background promotion timer (every 2 seconds)
    local ok, err = ngx.timer.every(2, function(premature)
        if premature then return end
        local ok, err = pcall(bg_promote)
        if not ok then ngx.log(ngx.ERR, "promote timer error: ", err) end
    end)
    if not ok then ngx.log(ngx.ERR, "failed to create promote timer: ", err) end

    -- Background stale cleanup timer (every 30 seconds)
    ok, err = ngx.timer.every(30, function(premature)
        if premature then return end
        local ok, err = pcall(stale_cleanup)
        if not ok then ngx.log(ngx.ERR, "cleanup timer error: ", err) end
    end)
    if not ok then ngx.log(ngx.ERR, "failed to create cleanup timer: ", err) end
end

return _M