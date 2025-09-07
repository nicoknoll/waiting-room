#!/bin/bash

# Set default value for WAITING_ROOM_ENABLED
WAITING_ROOM_ENABLED=${WAITING_ROOM_ENABLED:-"0"}

# Replace environment variables in nginx config
envsubst "\${WAITING_ROOM_ENABLED}" < /etc/nginx/conf.d/default.conf > /tmp/nginx.conf
mv /tmp/nginx.conf /etc/nginx/conf.d/default.conf

# Start nginx
nginx -g 'daemon off;'