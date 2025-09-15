import json
from datetime import datetime
from urllib.parse import parse_qs

import redis
import time
import uuid
import os
import hashlib
import traceback
from http.cookies import SimpleCookie
from typing import Optional, Dict, Any


redis_client = redis.from_url(os.environ["REDIS_LOCATION"], decode_responses=True)

# 5 minutes in queue, gets renewed on each check
QUEUED_TTL = 300
# 5 minutes of access time is blocked
GRANTED_TTL = 300
# 10 minutes validity for access token -> sliding window
# (you can still access even though your granted session expired, until this token expires)
ACCESS_TOKEN_TTL = 600

MAX_USERS = int(os.environ.get("WAITING_ROOM_MAX_USERS", "100"))
SECRET = os.environ["WAITING_ROOM_SECRET"]
BLOCKED_UNTIL_TIMESTAMP = os.environ.get("WAITING_ROOM_BLOCKED_UNTIL")
BLOCK_DURATION_MINUTES = int(
    os.environ.get("WAITING_ROOM_BLOCK_DURATION_MINUTES", "30")
)

SESSION_COOKIE_NAME = "waiting_room_session_id"
ACCESS_TOKEN_COOKIE_NAME = "waiting_room_access_token"


def is_access_blocked_by_timestamp() -> bool:
    """
    Check if access should be blocked based on timestamp configuration.
    Access is blocked from BLOCK_DURATION_MINUTES before BLOCKED_UNTIL_TIMESTAMP until the timestamp.
    """
    if not BLOCKED_UNTIL_TIMESTAMP:
        return False

    try:
        # Parse the timestamp - assume ISO format or Unix timestamp
        if BLOCKED_UNTIL_TIMESTAMP.isdigit():
            blocked_until = int(BLOCKED_UNTIL_TIMESTAMP)
        else:
            # Try to parse as ISO format
            blocked_until = int(
                datetime.fromisoformat(
                    BLOCKED_UNTIL_TIMESTAMP.replace("Z", "+00:00")
                ).timestamp()
            )

        current_time = int(time.time())
        block_start_time = blocked_until - (
            BLOCK_DURATION_MINUTES * 60
        )  # Convert minutes to seconds

        return block_start_time <= current_time <= blocked_until
    except (ValueError, TypeError):
        # If parsing fails, don't block access
        return False


def main(event, context):
    try:
        path = event.get("http", {}).get("path", "/")
        query_string = event.get("http", {}).get("queryString", "")
        query_params = parse_qs(query_string)

        if path == "/stats":
            return get_queue_stats(query_params)

        if path == "/validate":
            return validate_access_token(query_params)

        if path == "/grant":
            return grant_session_with_secret(query_params)

        session_id = get_session_id_from_cookie(event)
        session_granted = session_id and is_session_granted(session_id)
        session_queued = session_id and is_session_queued(session_id)

        if not (session_granted or session_queued):
            # ensure a session is at least queued
            session_id = create_queued_session()

        promote_queued_users()

        if is_session_granted(session_id):
            next_url = query_params.get("next", ["/"])[0]
            return handle_granted_session(session_id, next_url=next_url)

        return handle_queued_session(session_id)

    except Exception as e:
        return {
            "statusCode": 500,
            "body": {"error": str(e), "trace": traceback.format_exc()},
        }


def parse_cookies(cookie_header: str) -> dict:
    cookie = SimpleCookie()
    cookie.load(cookie_header)
    return {key: morsel.value for key, morsel in cookie.items()}


def get_session_id_from_cookie(event) -> Optional[str]:
    headers = event.get("http", {}).get("headers", {})
    cookie_header = headers.get("cookie", "") or headers.get("Cookie", "")

    if not cookie_header:
        return None

    cookies = parse_cookies(cookie_header)
    return cookies.get(SESSION_COOKIE_NAME)


def is_session_granted(session_id: str) -> bool:
    return redis_client.exists(f"granted:{session_id}")


def is_session_queued(session_id: str) -> bool:
    return redis_client.exists(f"queued:{session_id}")


def timestamp_to_iso(timestamp_ms: int) -> str:
    return datetime.fromtimestamp(timestamp_ms / 1000).isoformat()


def generate_access_token(session_id: str) -> str:
    return hashlib.sha1((session_id + SECRET).encode()).hexdigest()


def create_session_cookie(session_id: str) -> str:
    cookie = SimpleCookie()
    cookie[SESSION_COOKIE_NAME] = session_id
    cookie[SESSION_COOKIE_NAME]["path"] = "/"
    cookie[SESSION_COOKIE_NAME]["httponly"] = True
    # cookie[SESSION_COOKIE_NAME]["samesite"] = "Strict"
    cookie[SESSION_COOKIE_NAME]["secure"] = True
    cookie[SESSION_COOKIE_NAME]["max-age"] = 86400 * 30
    return cookie.output(header="").strip()


def create_access_token_cookie(access_token: str) -> str:
    cookie = SimpleCookie()
    cookie[ACCESS_TOKEN_COOKIE_NAME] = access_token
    cookie[ACCESS_TOKEN_COOKIE_NAME]["path"] = "/"
    cookie[ACCESS_TOKEN_COOKIE_NAME]["httponly"] = True
    # cookie[ACCESS_TOKEN_COOKIE_NAME]["samesite"] = "Strict"
    cookie[ACCESS_TOKEN_COOKIE_NAME]["secure"] = True
    cookie[ACCESS_TOKEN_COOKIE_NAME]["max-age"] = ACCESS_TOKEN_TTL
    return cookie.output(header="").strip()


def create_queued_session() -> str:
    session_id = str(uuid.uuid4())
    current_time = int(time.time() * 1000)
    redis_client.set(f"queued:{session_id}", current_time, ex=QUEUED_TTL)
    return session_id


def handle_granted_session(session_id: str, next_url=None) -> Dict[str, Any]:
    granted_at = int(redis_client.get(f"granted:{session_id}"))
    ttl = redis_client.ttl(f"granted:{session_id}")
    access_token = generate_access_token(session_id)

    data = {
        "session_id": session_id,
        "status": "granted",
        "granted_at": timestamp_to_iso(granted_at),
        "expires_in": ttl,
        "access_token": access_token,
    }

    return {
        "statusCode": 302,
        "headers": {
            # both cookies need to exist for access
            "Location": next_url or "/",
            "Set-Cookie": [
                create_session_cookie(session_id),
                create_access_token_cookie(access_token),
            ],
        },
        "body": render_granted_html(data, next_url),
    }


def render_granted_html(data, next_url: str) -> str:
    return f"""
    <html>
    <head><title>Access Granted</title></head>
    <body>
        <h1>Access Granted</h1>
        <p>Your access has been granted. You can now proceed to the application.</p>
        <p><a href="{next_url or '/'}">Continue to the application</a></p>
        <p>This page will automatically redirect you in 5 seconds.</p>
        <p style="color: #999">Session ID: {data['session_id']}</p>
        <script>
            // Automatically redirect after 5 seconds
            setTimeout(() => {{
                window.location.href = "{next_url or '/'}";
            }}, 5000);
        </script>
    </body>
    </html>
    """


def handle_queued_session(session_id: str) -> Dict[str, Any]:
    redis_client.expire(f"queued:{session_id}", QUEUED_TTL)

    position = get_queue_position(session_id)
    queued_at = int(redis_client.get(f"queued:{session_id}"))

    data = {
        "session_id": session_id,
        "status": "queued",
        "queued_at": timestamp_to_iso(queued_at),
        "position": position,
        "estimated_wait_time": calculate_wait_time(position),
    }

    return {
        "statusCode": 200,
        "headers": {"Set-Cookie": create_session_cookie(session_id)},
        "body": render_queued_html(data),
    }


def render_queued_html(data) -> str:
    estimated_wait_min = data["estimated_wait_time"] // 60

    # Check if access is blocked and add appropriate message
    blocked_message = ""
    if is_access_blocked_by_timestamp():
        try:
            if BLOCKED_UNTIL_TIMESTAMP.isdigit():
                blocked_until = int(BLOCKED_UNTIL_TIMESTAMP)
            else:
                blocked_until = int(
                    datetime.fromisoformat(
                        BLOCKED_UNTIL_TIMESTAMP.replace("Z", "+00:00")
                    ).timestamp()
                )

            current_time = int(time.time())
            seconds_until_unblock = max(0, blocked_until - current_time)

            if seconds_until_unblock > 0:
                minutes_until_unblock = seconds_until_unblock // 60
                time_desc = (
                    f"in {minutes_until_unblock} minute(s)"
                    if minutes_until_unblock >= 1
                    else "in less than a minute"
                )
                blocked_message = f"""
                <p><strong>Notice:</strong> Access is paused until the start of the pre-sale ({time_desc}).</p>
                """
        except (ValueError, TypeError):
            blocked_message = """
            <p><strong>Notice:</strong> Access is paused until the start of the pre-sale.</p>
            """

    return f"""
    <html>
    <head><title>Waiting Room</title></head>
    <body>
        <h1>You are in the queue</h1>
        {blocked_message}
        <p>Your current position in the queue is: {data['position']}</p>
        <p>Estimated wait time: {estimated_wait_min == 0 and "Less than a minute" or f"{estimated_wait_min} minute(s)"}</p>
        <p>This page will refresh automatically every 15 seconds to update your position.</p>
        <p>Please do not close this page, otherwise you will lose your place in the queue.</p>
        <p style="color: #999">Session ID: {data['session_id']}</p>
        <script>
            setTimeout(() => {{
                window.location.reload();
            }}, 15000); // Refresh every 15 seconds
        </script>
    </body>
    </html>
    """


def promote_queued_users():
    # batch promotion in a transaction

    # Don't promote users if access is blocked by timestamp
    if is_access_blocked_by_timestamp():
        return

    with redis_client.pipeline() as pipe:
        pipe.multi()

        granted_count = len(redis_client.keys("granted:*"))
        available_slots = MAX_USERS - granted_count

        if available_slots <= 0:
            return

        queued_keys = redis_client.keys("queued:*")
        queue_data = [(key, int(redis_client.get(key))) for key in queued_keys]
        queue_data.sort(key=lambda x: x[1])  # Sort by timestamp

        for i in range(min(available_slots, len(queue_data))):
            key, timestamp = queue_data[i]
            session_id = key.split(":", 1)[1]

            pipe.delete(f"queued:{session_id}")
            pipe.set(f"granted:{session_id}", int(time.time() * 1000), ex=GRANTED_TTL)

        pipe.execute()


def get_queue_position(session_id: str) -> int:
    queued_keys = redis_client.keys("queued:*")
    queue_data = []

    for key in queued_keys:
        timestamp = int(redis_client.get(key))
        sid = key.split(":", 1)[1]
        queue_data.append((sid, timestamp))

    queue_data.sort(key=lambda x: x[1])

    for position, (sid, _) in enumerate(queue_data, 1):
        if sid == session_id:
            return position

    return -1


def get_granted_expiry_schedule():
    granted_keys = redis_client.keys("granted:*")
    expiry_times = []

    for key in granted_keys:
        ttl = redis_client.ttl(key)
        if ttl > 0:
            expiry_times.append(ttl)

    return sorted(expiry_times)


def calculate_wait_time(position):
    expiry_schedule = get_granted_expiry_schedule()

    # If we have over-granted users, just assign to expiring slots first
    if position <= len(expiry_schedule):
        return expiry_schedule[position - 1]

    # Only use MAX_USERS logic for positions beyond current granted users
    remaining_position = position - len(expiry_schedule)
    cycles_needed = (remaining_position - 1) // MAX_USERS
    slot_index = (remaining_position - 1) % MAX_USERS

    # Use 0 if slot_index doesn't exist in expiry_schedule
    base_wait = expiry_schedule[slot_index] if slot_index < len(expiry_schedule) else 0
    return base_wait + ((cycles_needed + 1) * GRANTED_TTL)


def get_queue_stats(query_params: dict) -> Dict[str, Any]:
    secret = query_params.get("secret", [None])[0]

    if not secret or secret != SECRET:
        return {
            "statusCode": 403,
            "body": {"error": "Invalid or missing secret"},
        }
    queued_keys = redis_client.keys("queued:*")
    granted_keys = redis_client.keys("granted:*")

    queued_sessions = []
    for key in queued_keys:
        session_id = key.split(":", 1)[1]
        timestamp = int(redis_client.get(key))
        ttl = redis_client.ttl(key)
        queued_sessions.append(
            {
                "session_id": session_id,
                "queued_at": timestamp_to_iso(timestamp),
                "ttl_seconds": ttl,
            }
        )

    granted_sessions = []
    for key in granted_keys:
        session_id = key.split(":", 1)[1]
        timestamp = int(redis_client.get(key))
        ttl = redis_client.ttl(key)
        granted_sessions.append(
            {
                "session_id": session_id,
                "granted_at": timestamp_to_iso(timestamp),
                "ttl_seconds": ttl,
            }
        )

    queued_sessions.sort(key=lambda x: x["queued_at"])
    granted_sessions.sort(key=lambda x: x["granted_at"])

    # Add blocking information
    blocking_info = None
    if BLOCKED_UNTIL_TIMESTAMP:
        try:
            if BLOCKED_UNTIL_TIMESTAMP.isdigit():
                blocked_until = int(BLOCKED_UNTIL_TIMESTAMP)
            else:
                blocked_until = int(
                    datetime.fromisoformat(
                        BLOCKED_UNTIL_TIMESTAMP.replace("Z", "+00:00")
                    ).timestamp()
                )

            current_time = int(time.time())
            block_start_time = blocked_until - (BLOCK_DURATION_MINUTES * 60)
            is_blocked = is_access_blocked_by_timestamp()

            blocking_info = {
                "is_blocked": is_blocked,
                "block_start_time": timestamp_to_iso(block_start_time * 1000),
                "block_end_time": timestamp_to_iso(blocked_until * 1000),
                "block_duration_minutes": BLOCK_DURATION_MINUTES,
            }
        except (ValueError, TypeError):
            blocking_info = {"error": "Invalid timestamp configuration"}

    return {
        "statusCode": 200,
        "body": {
            "summary": {
                "queued_users": len(queued_sessions),
                "active_users": len(granted_sessions),
                "max_users": MAX_USERS,
                "slots_available": MAX_USERS - len(granted_sessions),
            },
            "blocking": blocking_info,
            "queued_sessions": queued_sessions,
            "granted_sessions": granted_sessions,
        },
    }


def validate_access_token(query_params: dict) -> Dict[str, Any]:
    token = query_params.get("token", [None])[0]
    session_id = query_params.get("session", [None])[0]

    if not token:
        return {
            "statusCode": 400,
            "body": {"valid": False, "error": "Missing token parameter"},
        }

    if not session_id:
        return {
            "statusCode": 400,
            "body": {"valid": False, "error": "Missing session parameter"},
        }

    if not redis_client.exists(f"granted:{session_id}"):
        return {
            "statusCode": 200,
            "body": {"valid": False, "error": "Session not found or not granted"},
        }

    expected_token = generate_access_token(session_id)
    if token != expected_token:
        return {
            "statusCode": 200,
            "body": {"valid": False, "error": "Invalid token for session"},
        }

    granted_at = int(redis_client.get(f"granted:{session_id}"))
    ttl = redis_client.ttl(f"granted:{session_id}")

    return {
        "statusCode": 200,
        "body": {
            "valid": True,
            "session_id": session_id,
            "granted_at": timestamp_to_iso(granted_at),
            "expires_in": ttl,
        },
    }


def grant_session_with_secret(query_params: dict) -> Dict[str, Any]:
    secret = query_params.get("secret", [None])[0]
    next_url = query_params.get("next", ["/"])[0]

    if not secret or secret != SECRET:
        return {
            "statusCode": 403,
            "body": {"error": "Invalid or missing secret"},
        }

    session_id = str(uuid.uuid4())
    current_time = int(time.time() * 1000)

    redis_client.set(f"granted:{session_id}", current_time, ex=GRANTED_TTL)

    return handle_granted_session(session_id, next_url=next_url)
