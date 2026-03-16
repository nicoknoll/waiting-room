-- redis_helper.lua
-- Shared Redis connection helpers (loaded once per worker)

local redis = require "resty.redis"

local _M = {}

function _M.parse_redis_url(url)
    local r = { host = "127.0.0.1", port = 6379, password = nil, username = nil, db = 0, ssl = false }
    if not url or url == "" then return r end

    if url:sub(1, 9) == "rediss://" then
        r.ssl = true
        url = "redis://" .. url:sub(10)
    end
    url = url:gsub("^redis://", "")

    -- auth@host (supports user:password and just password)
    local auth, rest = url:match("^(.-)@(.+)$")
    if auth then
        local user, pw = auth:match("^(.*):(.+)$")
        if user and pw then
            if user ~= "" then r.username = user end
            r.password = pw
        elseif auth ~= "" then
            r.password = auth
        end
        url = rest
    end

    -- host:port/db
    local hp, db = url:match("^([^/]+)/(%d+)")
    if not hp then hp = url:gsub("/+$", "") end
    if db then r.db = tonumber(db) end

    local h, p = hp:match("^(.+):(%d+)$")
    if h then r.host = h; r.port = tonumber(p)
    elseif hp ~= "" then r.host = hp end

    return r
end

local redis_config = _M.parse_redis_url(os.getenv("REDIS_LOCATION"))

local function get_nameservers()
    local nameservers = {}
    local f = io.open("/etc/resolv.conf", "r")
    if f then
        for line in f:lines() do
            local ns = line:match("^%s*nameserver%s+(%S+)")
            if ns then table.insert(nameservers, ns) end
        end
        f:close()
    end
    if #nameservers == 0 then
        nameservers = { "8.8.8.8" }
    end
    return nameservers
end

local function resolve_host(host)
    -- If it's already an IP, return as-is
    if host:match("^%d+%.%d+%.%d+%.%d+$") then
        return host
    end
    local resolver = require "resty.dns.resolver"
    local r, err = resolver:new({
        nameservers = get_nameservers(),
        retrans = 3,
        timeout = 2000,
    })
    if not r then return nil, "resolver: " .. (err or "unknown") end
    local answers, err = r:query(host, { qtype = r.TYPE_A })
    if not answers then return nil, "dns query: " .. (err or "unknown") end
    if answers.errcode then return nil, "dns error: " .. (answers.errstr or "unknown") end
    for _, ans in ipairs(answers) do
        if ans.address then return ans.address end
    end
    return nil, "no A record for " .. host
end

-- Cached resolved Redis host (per worker)
local resolved_redis_host = nil

function _M.get_redis()
    local red = redis:new()
    red:set_timeouts(300, 2000, 2000)

    -- Resolve hostname on first call, cache for this worker
    if not resolved_redis_host then
        local ip, err = resolve_host(redis_config.host)
        if not ip then return nil, "redis resolve: " .. (err or "unknown") end
        resolved_redis_host = ip
    end

    local ok, err
    if redis_config.ssl then
        ok, err = red:connect(resolved_redis_host, redis_config.port,
            { ssl = true, ssl_verify = false })
    else
        ok, err = red:connect(resolved_redis_host, redis_config.port)
    end
    if not ok then return nil, "redis connect: " .. (err or "unknown") end

    if redis_config.password then
        if redis_config.username then
            ok, err = red:auth(redis_config.username, redis_config.password)
        else
            ok, err = red:auth(redis_config.password)
        end
        if not ok then return nil, "redis auth: " .. (err or "unknown") end
    end

    if redis_config.db > 0 then
        ok, err = red:select(redis_config.db)
        if not ok then return nil, "redis select: " .. (err or "unknown") end
    end

    return red
end

function _M.release_redis(red, pool_size)
    pool_size = pool_size or 100
    if red then red:set_keepalive(10000, pool_size) end
end

return _M
