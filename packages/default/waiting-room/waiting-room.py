from datetime import datetime
from urllib.parse import parse_qs

import redis
import time
import uuid
import os
import hashlib
from http.cookies import SimpleCookie
from typing import Optional, Dict, Any


redis_client = redis.from_url(os.environ["REDIS_LOCATION"], decode_responses=True)

# 10 minutes in queue, gets renewed on each check
QUEUED_TTL = 600
# 5 minutes of access time is blocked
GRANTED_TTL = 300
# 10 minutes validity for access token -> sliding window
# (you can still access even though your granted session expired, until this token expires)
ACCESS_TOKEN_TTL = 600

MAX_USERS = int(os.environ.get("WAITING_ROOM_MAX_USERS", "100"))
SECRET = os.environ["WAITING_ROOM_SECRET"]

SESSION_COOKIE_NAME = "waiting_room_session_id"
ACCESS_TOKEN_COOKIE_NAME = "waiting_room_access_token"


def main(event, context):
    try:
        path = event.get("http", {}).get("path", "/")
        query_string = event.get("http", {}).get("queryString", "")

        if path == "/stats":
            return get_queue_stats()

        if path == "/validate":
            return validate_access_token(query_string)

        promote_queued_users()

        session_id = get_session_id_from_cookie(event)

        if not session_id:
            return create_queued_session()

        if is_session_granted(session_id):
            return handle_granted_session(session_id)

        if is_session_queued(session_id):
            return handle_queued_session(session_id)

        return create_queued_session()

    except Exception as e:
        return {"statusCode": 500, "body": {"error": str(e)}}


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
    cookie[SESSION_COOKIE_NAME]["samesite"] = "Strict"
    cookie[SESSION_COOKIE_NAME]["max-age"] = 86400 * 30
    return cookie.output(header="").strip()


def create_access_token_cookie(access_token: str) -> str:
    cookie = SimpleCookie()
    cookie[ACCESS_TOKEN_COOKIE_NAME] = access_token
    cookie[ACCESS_TOKEN_COOKIE_NAME]["path"] = "/"
    cookie[ACCESS_TOKEN_COOKIE_NAME]["httponly"] = True
    cookie[ACCESS_TOKEN_COOKIE_NAME]["samesite"] = "Strict"
    cookie[ACCESS_TOKEN_COOKIE_NAME]["max-age"] = ACCESS_TOKEN_TTL
    return cookie.output(header="").strip()


def create_queued_session() -> Dict[str, Any]:
    session_id = str(uuid.uuid4())
    current_time = int(time.time() * 1000)

    redis_client.set(f"queued:{session_id}", current_time, ex=QUEUED_TTL)

    return handle_queued_session(session_id)


def handle_granted_session(session_id: str) -> Dict[str, Any]:
    granted_at = int(redis_client.get(f"granted:{session_id}"))
    ttl = redis_client.ttl(f"granted:{session_id}")
    access_token = generate_access_token(session_id)

    return {
        "statusCode": 200,
        "headers": {
            # both cookies need to exist for access
            "Set-Cookie": f"{create_access_token_cookie(access_token)}; {create_session_cookie(session_id)}"
        },
        "body": {
            "session_id": session_id,
            "status": "granted",
            "granted_at": timestamp_to_iso(granted_at),
            "expires_in": ttl,
            "access_token": access_token,
        },
    }


def handle_queued_session(session_id: str) -> Dict[str, Any]:
    redis_client.expire(f"queued:{session_id}", QUEUED_TTL)

    position = get_queue_position(session_id)
    queued_at = int(redis_client.get(f"queued:{session_id}"))

    return {
        "statusCode": 200,
        "headers": {"Set-Cookie": create_session_cookie(session_id)},
        "body": {
            "session_id": session_id,
            "status": "queued",
            "queued_at": timestamp_to_iso(queued_at),
            "position": position,
            "estimated_wait_time": calculate_wait_time(position),
        },
    }


def promote_queued_users():
    # batch promotion in a transaction

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
    available_slots = MAX_USERS - len(expiry_schedule)

    if position <= available_slots:
        return 0  # Immediate access

    slot_needed = position - available_slots
    if slot_needed <= len(expiry_schedule):
        return expiry_schedule[slot_needed - 1]

    # Need to wait for multiple session cycles
    return expiry_schedule[0] + ((slot_needed - len(expiry_schedule)) * GRANTED_TTL)


def get_queue_stats() -> Dict[str, Any]:
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

    return {
        "statusCode": 200,
        "body": {
            "summary": {
                "queued_users": len(queued_sessions),
                "active_users": len(granted_sessions),
                "max_users": MAX_USERS,
                "slots_available": MAX_USERS - len(granted_sessions),
            },
            "queued_sessions": queued_sessions,
            "granted_sessions": granted_sessions,
        },
    }


def validate_access_token(query_string: str) -> Dict[str, Any]:
    query_params = parse_qs(query_string)
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
