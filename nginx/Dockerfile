FROM openresty/openresty:alpine

# Install pre-requisites
RUN apk update && \
    apk add --no-cache bash gettext

# Set working directory
WORKDIR /app

# link nginx logs to container stdout
RUN mkdir -p /var/log/nginx && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log

# Copy nginx/openresty config (replaces default entirely)
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

# Copy Lua code
COPY lua/ /usr/local/openresty/lua/

# Copy entrypoint script
COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

CMD ["/app/run.sh"]
