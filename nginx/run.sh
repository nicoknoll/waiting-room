#!/bin/bash

# Set default value for WAITING_ROOM_ENABLED
WAITING_ROOM_ENABLED=${WAITING_ROOM_ENABLED:-"0"}

# Replace environment variables in nginx config (only WAITING_ROOM_ENABLED, Lua reads the rest directly)
envsubst "\${WAITING_ROOM_ENABLED}" < /usr/local/openresty/nginx/conf/nginx.conf > /tmp/nginx.conf
mv /tmp/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

# Start OpenResty
/usr/local/openresty/bin/openresty -g 'daemon off;'
