local config = require "config"
local redis_helper = require "redis_helper"
local scripts = require "scripts"

local _M = {}

local POOL_SIZE = 10

-- Background promotion (every 2 seconds)
local function bg_promote()
    if config.is_access_blocked() then return end

    local red, err = redis_helper.get_redis()
    if not red then ngx.log(ngx.WARN, "bg_promote: redis: ", err); return end

    local now = ngx.time()
    local result, err = red:eval(scripts.PROMOTE, 3,
        config.QUEUE_KEY, config.GRANTED_KEY, config.HEARTBEAT_KEY,
        tostring(now), tostring(config.MAX_USERS),
        tostring(config.GRANTED_TTL), tostring(config.QUEUED_TTL),
        "")
    if err then ngx.log(ngx.ERR, "bg_promote: eval: ", err) end

    redis_helper.release_redis(red, POOL_SIZE)
end

-- Background stale cleanup (every 30 seconds)
local function stale_cleanup()
    local red, err = redis_helper.get_redis()
    if not red then ngx.log(ngx.WARN, "cleanup: redis: ", err); return end

    local stale_cutoff = ngx.time() - config.QUEUED_TTL
    local batch_size = 200
    local offset = 0
    local total_removed = 0

    while true do
        local removed, err = red:eval(scripts.CLEANUP, 2,
            config.QUEUE_KEY, config.HEARTBEAT_KEY,
            tostring(stale_cutoff), tostring(offset), tostring(batch_size))
        if err or type(removed) ~= "number" then break end
        total_removed = total_removed + removed
        offset = offset + batch_size - removed
        local queue_len = red:zcard(config.QUEUE_KEY)
        if type(queue_len) ~= "number" or offset >= queue_len then break end
    end

    if total_removed > 0 then
        ngx.log(ngx.INFO, "cleanup: removed ", total_removed, " stale queue entries")
    end

    redis_helper.release_redis(red, POOL_SIZE)
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
