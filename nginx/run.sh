#!/bin/bash

# Set default values
WAITING_ROOM_ENABLED=${WAITING_ROOM_ENABLED:-"0"}
WAITING_ROOM_PROTECTED_PATH=${WAITING_ROOM_PROTECTED_PATH:-"/"}
WAITING_ROOM_UPSTREAM_URL=${WAITING_ROOM_UPSTREAM_URL:-"http://localhost:8000"}

# Replace environment variables in nginx config (Lua reads the rest directly via os.getenv)
envsubst "\${WAITING_ROOM_ENABLED} \${WAITING_ROOM_PROTECTED_PATH} \${WAITING_ROOM_UPSTREAM_URL}" < /usr/local/openresty/nginx/conf/nginx.conf > /tmp/nginx.conf
mv /tmp/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

# Start OpenResty
/usr/local/openresty/bin/openresty -g 'daemon off;'
