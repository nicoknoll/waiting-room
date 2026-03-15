-- waiting_room.lua
-- Waiting room implementation using OpenResty + Redis sorted sets
--
-- Redis data model:
--   wr:queue      - sorted set: member=session_id, score=enqueue_timestamp_ms
--   wr:granted    - sorted set: member=session_id, score=expiry_timestamp_seconds
--   wr:heartbeat  - hash: session_id -> last_seen_timestamp_seconds

local redis = require "resty.redis"
local resty_sha1 = require "resty.sha1"
local resty_str = require "resty.string"
local cjson = require "cjson"

-- Redis keys
local QUEUE_KEY = "wr:queue"
local GRANTED_KEY = "wr:granted"
local HEARTBEAT_KEY = "wr:heartbeat"

-- TTLs (seconds)
local QUEUED_TTL = tonumber(os.getenv("WAITING_ROOM_QUEUED_TTL") or "300")
local GRANTED_TTL = tonumber(os.getenv("WAITING_ROOM_GRANTED_TTL") or "300")
local ACCESS_TOKEN_TTL = tonumber(os.getenv("WAITING_ROOM_ACCESS_TOKEN_TTL") or "600")

-- Cookie names
local SESSION_COOKIE_NAME = "waiting_room_session_id"
local ACCESS_TOKEN_COOKIE_NAME = "waiting_room_access_token"

-- Config from environment
local MAX_USERS = tonumber(os.getenv("WAITING_ROOM_MAX_USERS") or "100")
local SECRET = os.getenv("WAITING_ROOM_SECRET") or ""
local BLOCKED_UNTIL_RAW = os.getenv("WAITING_ROOM_BLOCKED_UNTIL") or ""
local BLOCK_DURATION_MINUTES = tonumber(os.getenv("WAITING_ROOM_BLOCK_DURATION_MINUTES") or "30")

-- Atomic promotion script (runs on Redis server)
-- Only checks heartbeats for candidates being considered for promotion,
-- not the entire queue. Stale cleanup is handled by a background timer.
local PROMOTE_SCRIPT = [[
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



--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

local function parse_redis_url(url)
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

local redis_config = parse_redis_url(os.getenv("REDIS_LOCATION"))

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

-- Resolve Redis host once at first use (cached per worker)
local resolved_redis_host = nil

local function get_redis()
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

local function release_redis(red)
    if red then red:set_keepalive(10000, 100) end
end

local function generate_session_id()
    local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    return string.gsub(template, "[xy]", function(c)
        local v = (c == "x") and math.random(0, 15) or math.random(8, 11)
        return string.format("%x", v)
    end)
end

local function generate_access_token(session_id)
    local sha1 = resty_sha1:new()
    sha1:update(session_id .. SECRET)
    return resty_str.to_hex(sha1:final())
end

local function timestamp_to_iso(timestamp_ms)
    return os.date("!%Y-%m-%dT%H:%M:%S", math.floor(timestamp_ms / 1000))
end

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

local BLOCKED_UNTIL = parse_blocked_until()

local function is_access_blocked()
    if not BLOCKED_UNTIL then return false, 0 end
    local now = ngx.time()
    local block_start = BLOCKED_UNTIL - (BLOCK_DURATION_MINUTES * 60)
    if now >= block_start and now <= BLOCKED_UNTIL then
        return true, BLOCKED_UNTIL - now
    end
    return false, 0
end

local function is_null(v)
    return v == nil or v == ngx.null
end

local function parse_cookies()
    local header = ngx.var.http_cookie
    if not header then return {} end
    local cookies = {}
    for k, v in header:gmatch("([%w_]+)=([^;]+)") do
        cookies[k] = v:match("^%s*(.-)%s*$")
    end
    return cookies
end

local SECURE_FLAG = os.getenv("WAITING_ROOM_DEBUG") == "1" and "" or "; Secure"

local function set_cookies(session_id, access_token)
    local cookies = {}
    table.insert(cookies, SESSION_COOKIE_NAME .. "=" .. session_id ..
        "; Path=/; HttpOnly" .. SECURE_FLAG .. "; Max-Age=" .. (86400 * 30))
    if access_token then
        table.insert(cookies, ACCESS_TOKEN_COOKIE_NAME .. "=" .. access_token ..
            "; Path=/; HttpOnly" .. SECURE_FLAG .. "; Max-Age=" .. ACCESS_TOKEN_TTL)
    end
    ngx.header["Set-Cookie"] = cookies
end

local function compute_refresh_interval(position, queue_size)
    -- Users near the front always get a short interval regardless of queue size
    if position <= 10 then return 10 end
    if position <= 50 then return 20 end
    -- For users further back, throttle refreshes when queue is large,
    -- but cap at 90s so nobody waits forever for an update
    local min_for_capacity = math.min(90, math.max(1, math.floor(queue_size / MAX_USERS * 2)))
    if position <= 200 then return math.max(45, min_for_capacity) end
    return math.max(90, min_for_capacity)
end

local function calculate_wait_time(position, expiry_schedule)
    if position <= 0 then return 0 end
    if position <= #expiry_schedule then
        return math.floor(expiry_schedule[position])
    end
    local remaining = position - #expiry_schedule
    local cycles = math.floor((remaining - 1) / MAX_USERS)
    local slot = (remaining - 1) % MAX_USERS
    local base_wait = (slot < #expiry_schedule) and expiry_schedule[slot + 1] or 0
    return math.floor(base_wait + ((cycles + 1) * GRANTED_TTL))
end


--------------------------------------------------------------------------------
-- HTML renderers
--------------------------------------------------------------------------------

local function render_granted_html(session_id, next_url)
    next_url = next_url or "/"
    return string.format([[
    <html>
    <head><title>Access Granted</title></head>
    <body>
        <h1>Access Granted</h1>
        <p>Your access has been granted. You can now proceed to the application.</p>
        <p><a href="%s">Continue to the application</a></p>
        <p>This page will automatically redirect you in 5 seconds.</p>
        <p style="color: #999">Session ID: %s</p>
        <script>
            setTimeout(function() {
                window.location.href = "%s";
            }, 5000);
        </script>
    </body>
    </html>
    ]], next_url, session_id, next_url)
end

local function render_queued_html(data, refresh_interval)
    local wait_min = math.floor(data.estimated_wait_time / 60)
    local wait_text = wait_min == 0 and "Less than a minute"
        or string.format("%d minute(s)", wait_min)

    local blocked_message = ""
    local blocked, seconds_left = is_access_blocked()
    if blocked and seconds_left > 0 then
        local minutes_left = math.floor(seconds_left / 60)
        local time_desc = minutes_left >= 1
            and string.format("in %d minute(s)", minutes_left)
            or "in less than a minute"
        blocked_message = string.format(
            '<p><strong>Notice:</strong> Access is paused until the start of the pre-sale (%s).</p>',
            time_desc)
    end

    return string.format([[
    <html>
    <head><title>Waiting Room</title></head>
    <body>
        <h1>You are in the queue</h1>
        %s
        <p>Your current position in the queue is: %d</p>
        <p>Estimated wait time: %s</p>
        <p>This page will refresh automatically every %d seconds to update your position.</p>
        <p>Please do not close this page, otherwise you will lose your place in the queue.</p>
        <p style="color: #999">Session ID: %s</p>
        <script>
            var base = %d;
            var jitter = Math.floor(Math.random() * base * 0.3);
            setTimeout(function() {
                window.location.reload();
            }, base + jitter);
        </script>
    </body>
    </html>
    ]], blocked_message, data.position, wait_text, refresh_interval,
        data.session_id, refresh_interval * 1000)
end


local function render_unavailable_html()
    return [[
    <html>
    <head><title>Service Unavailable</title></head>
    <body>
        <h1>Service Temporarily Unavailable</h1>
        <p>The waiting room is temporarily unavailable. Please try again in a moment.</p>
    </body>
    </html>
    ]]
end


--------------------------------------------------------------------------------
-- PROMOTE_SCRIPT SHA cache (per-worker, avoids re-transmitting the script)
--------------------------------------------------------------------------------

local promote_sha = nil

local function promote(red, ...)
    if not promote_sha then
        local sha, err = red:script("LOAD", PROMOTE_SCRIPT)
        if not sha then
            return red:eval(PROMOTE_SCRIPT, ...)
        end
        promote_sha = sha
    end
    local res, err = red:evalsha(promote_sha, ...)
    if err and err:find("NOSCRIPT") then
        promote_sha = nil
        return red:eval(PROMOTE_SCRIPT, ...)
    end
    return res, err
end


--------------------------------------------------------------------------------
-- Route handlers
--------------------------------------------------------------------------------

local function handle_main(red)
    local cookies = parse_cookies()
    local session_id = cookies[SESSION_COOKIE_NAME]
    local args = ngx.req.get_uri_args()
    local now = ngx.time()
    local dict = ngx.shared.waiting_room

    -- Check session state with one pipeline
    local session_granted = false
    local session_queued = false
    local granted_score = nil

    if session_id then
        red:init_pipeline()
        red:zscore(GRANTED_KEY, session_id)
        red:zscore(QUEUE_KEY, session_id)
        local results, err = red:commit_pipeline()
        if results then
            granted_score = results[1]
            local queued_score = results[2]
            session_granted = not is_null(granted_score) and tonumber(granted_score) > now
            session_queued = not is_null(queued_score)
        end
    end

    local is_new_arrival = false
    if not (session_granted or session_queued) then
        is_new_arrival = true
        session_id = generate_session_id()
        local enqueue_time = math.floor(now * 1000)
        red:init_pipeline()
        red:zadd(QUEUE_KEY, enqueue_time, session_id)
        red:hset(HEARTBEAT_KEY, session_id, tostring(now))
        red:commit_pipeline()
        dict:set("hb:" .. session_id, now, 120)
        session_queued = true
    end

    -- Promotion runs in a background timer (every 2s on worker 0).
    -- Only run inline for new arrivals so they get instant promotion when slots are free.
    if not session_granted then
        local blocked = is_access_blocked()
        local ran_promotion = false
        if not blocked and is_new_arrival then
            local result, eval_err = promote(red, 3,
                QUEUE_KEY, GRANTED_KEY, HEARTBEAT_KEY,
                tostring(now), tostring(MAX_USERS),
                tostring(GRANTED_TTL), tostring(QUEUED_TTL),
                session_id)
            if eval_err then
                ngx.log(ngx.ERR, "PROMOTE_SCRIPT error: ", eval_err)
            elseif type(result) == "table" and result[2] and result[2] ~= "" then
                granted_score = result[2]
                session_granted = tonumber(granted_score) and tonumber(granted_score) > now
                ran_promotion = true
            end
        end

        -- Re-check if we got promoted (background timer may have promoted us)
        if not ran_promotion and session_queued then
            granted_score = red:zscore(GRANTED_KEY, session_id)
            session_granted = not is_null(granted_score) and tonumber(granted_score) > now
        end
    end

    -- Granted → redirect
    if session_granted then
        local next_url = args.next or "/"
        local access_token = generate_access_token(session_id)
        set_cookies(session_id, access_token)
        ngx.header["Location"] = next_url
        ngx.status = 302
        ngx.header["Content-Type"] = "text/html"
        ngx.say(render_granted_html(session_id, next_url))
        return
    end

    -- Queued → show queue page
    -- Cache position data in shared dict for 2s to reduce Redis load under burst.
    -- Heartbeat is throttled: only written to Redis if last update was >60s ago.
    -- QUEUED_TTL=300s gives 240s of safety margin.
    local cache_key = "pos:" .. session_id
    local position, queue_size, wait_time, refresh_interval

    -- Throttle heartbeat: only update Redis if last write was >60s ago
    local hb_key = "hb:" .. session_id
    local needs_heartbeat = true
    local last_hb = dict:get(hb_key)
    if last_hb and (now - last_hb) < 60 then
        needs_heartbeat = false
    end

    local cached = dict:get(cache_key)
    if cached then
        if needs_heartbeat then
            red:hset(HEARTBEAT_KEY, session_id, tostring(now))
            dict:set(hb_key, now, 120)
        end
        local p, q, w, r = cached:match("^(%d+):(%d+):(%d+):(%d+)$")
        position = tonumber(p); queue_size = tonumber(q)
        wait_time = tonumber(w); refresh_interval = tonumber(r)
    else
        -- Check if we have a cached expiry schedule (avoids ZRANGEBYSCORE)
        local cached_expiry = dict:get("expiry_schedule")
        local need_expiry_query = not cached_expiry

        -- Redis query: rank + queue size (+ expiry schedule if not cached) (+ heartbeat if needed)
        red:init_pipeline()
        red:zrank(QUEUE_KEY, session_id)       -- [1]
        red:zcard(QUEUE_KEY)                    -- [2]
        if need_expiry_query then
            red:zrangebyscore(GRANTED_KEY, tostring(now), "+inf", "WITHSCORES")  -- [3] (optional)
        end
        if needs_heartbeat then
            red:hset(HEARTBEAT_KEY, session_id, tostring(now))  -- [3 or 4] (optional)
        end
        local results, err = red:commit_pipeline()

        if not results then
            ngx.status = 500
            ngx.say("Redis error: " .. (err or "unknown"))
            return
        end

        local rank = results[1]
        queue_size = results[2]

        position = (not is_null(rank)) and (tonumber(rank) + 1) or -1
        queue_size = (not is_null(queue_size)) and tonumber(queue_size) or 0

        local expiry_schedule = {}
        if need_expiry_query then
            local granted_with_scores = results[3]
            if type(granted_with_scores) == "table" then
                for i = 2, #granted_with_scores, 2 do
                    local score = tonumber(granted_with_scores[i])
                    if score then table.insert(expiry_schedule, score - now) end
                end
                table.sort(expiry_schedule)
            end
            -- Cache serialized expiry schedule for 5s
            local parts = {}
            for _, v in ipairs(expiry_schedule) do parts[#parts + 1] = tostring(v) end
            dict:set("expiry_schedule", table.concat(parts, ","), 5)
        else
            -- Deserialize cached expiry schedule
            for v in cached_expiry:gmatch("[^,]+") do
                expiry_schedule[#expiry_schedule + 1] = tonumber(v)
            end
        end

        wait_time = calculate_wait_time(position, expiry_schedule)
        refresh_interval = compute_refresh_interval(position, queue_size)
        dict:set(cache_key, position .. ":" .. queue_size .. ":" .. wait_time .. ":" .. refresh_interval, 2)
        if needs_heartbeat then
            dict:set(hb_key, now, 120)
        end
    end
    set_cookies(session_id, nil)
    ngx.status = 200
    ngx.header["Content-Type"] = "text/html"
    ngx.say(render_queued_html({
        session_id = session_id,
        position = position,
        estimated_wait_time = wait_time,
    }, refresh_interval))
end


local function handle_stats(red)
    local args = ngx.req.get_uri_args()
    ngx.header["Content-Type"] = "application/json"

    if not args.secret or args.secret ~= SECRET then
        ngx.status = 403
        ngx.say(cjson.encode({ error = "Invalid or missing secret" }))
        return
    end

    local now = ngx.time()
    red:init_pipeline()
    red:zrangebyscore(QUEUE_KEY, "-inf", "+inf", "WITHSCORES")
    red:zrangebyscore(GRANTED_KEY, tostring(now), "+inf", "WITHSCORES")
    local results = red:commit_pipeline()

    local queued_raw = results[1] or {}
    local granted_raw = results[2] or {}

    local queued_sessions = {}
    if type(queued_raw) == "table" then
        for i = 1, #queued_raw, 2 do
            table.insert(queued_sessions, {
                session_id = queued_raw[i],
                queued_at = timestamp_to_iso(tonumber(queued_raw[i + 1])),
            })
        end
    end

    local granted_sessions = {}
    if type(granted_raw) == "table" then
        for i = 1, #granted_raw, 2 do
            local score = tonumber(granted_raw[i + 1])
            table.insert(granted_sessions, {
                session_id = granted_raw[i],
                granted_at = timestamp_to_iso(math.floor((score - GRANTED_TTL) * 1000)),
                ttl_seconds = math.floor(score - now),
            })
        end
    end

    local blocking_info = cjson.null
    if BLOCKED_UNTIL then
        local block_start = BLOCKED_UNTIL - (BLOCK_DURATION_MINUTES * 60)
        local blocked = is_access_blocked()
        blocking_info = {
            is_blocked = blocked,
            block_start_time = timestamp_to_iso(block_start * 1000),
            block_end_time = timestamp_to_iso(BLOCKED_UNTIL * 1000),
            block_duration_minutes = BLOCK_DURATION_MINUTES,
        }
    end

    ngx.status = 200
    ngx.say(cjson.encode({
        summary = {
            queued_users = #queued_sessions,
            active_users = #granted_sessions,
            max_users = MAX_USERS,
            slots_available = MAX_USERS - #granted_sessions,
        },
        blocking = blocking_info,
        queued_sessions = queued_sessions,
        granted_sessions = granted_sessions,
    }))
end


local function handle_validate(red)
    local args = ngx.req.get_uri_args()
    ngx.header["Content-Type"] = "application/json"

    if not args.token then
        ngx.status = 400
        ngx.say(cjson.encode({ valid = false, error = "Missing token parameter" }))
        return
    end
    if not args.session then
        ngx.status = 400
        ngx.say(cjson.encode({ valid = false, error = "Missing session parameter" }))
        return
    end

    local now = ngx.time()
    local expiry_ts = red:zscore(GRANTED_KEY, args.session)
    if is_null(expiry_ts) or tonumber(expiry_ts) <= now then
        ngx.status = 200
        ngx.say(cjson.encode({ valid = false, error = "Session not found or not granted" }))
        return
    end

    local expected = generate_access_token(args.session)
    if args.token ~= expected then
        ngx.status = 200
        ngx.say(cjson.encode({ valid = false, error = "Invalid token for session" }))
        return
    end

    expiry_ts = tonumber(expiry_ts)
    ngx.status = 200
    ngx.say(cjson.encode({
        valid = true,
        session_id = args.session,
        granted_at = timestamp_to_iso(math.floor((expiry_ts - GRANTED_TTL) * 1000)),
        expires_in = math.floor(expiry_ts - now),
    }))
end


local function handle_grant(red)
    local args = ngx.req.get_uri_args()

    if not args.secret or args.secret ~= SECRET then
        ngx.status = 403
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({ error = "Invalid or missing secret" }))
        return
    end

    local next_url = args.next or "/"
    local session_id = generate_session_id()
    local now = ngx.time()

    red:zadd(GRANTED_KEY, now + GRANTED_TTL, session_id)

    local access_token = generate_access_token(session_id)
    set_cookies(session_id, access_token)
    ngx.header["Location"] = next_url
    ngx.status = 302
    ngx.header["Content-Type"] = "text/html"
    ngx.say(render_granted_html(session_id, next_url))
end


--------------------------------------------------------------------------------
-- Router
--------------------------------------------------------------------------------

local uri = ngx.var.uri
local subpath = uri:match("^/waiting%-room(.*)$") or ""

local red, err = get_redis()
if not red then
    ngx.log(ngx.ERR, "Redis connection failed (", subpath, "): ", err)
    if subpath == "/stats" or subpath == "/validate" or subpath == "/grant" then
        ngx.status = 503
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({ error = "Redis unavailable: " .. (err or "unknown") }))
    else
        ngx.status = 503
        ngx.header["Content-Type"] = "text/html"
        ngx.say(render_unavailable_html())
    end
    return
end

local ok, handler_err = pcall(function()
    if subpath == "/stats" then
        handle_stats(red)
    elseif subpath == "/validate" then
        handle_validate(red)
    elseif subpath == "/grant" then
        handle_grant(red)
    else
        handle_main(red)
    end
end)

release_redis(red)

if not ok then
    ngx.status = 500
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({ error = tostring(handler_err) }))
end
