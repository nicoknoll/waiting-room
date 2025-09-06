FROM nginx:alpine-slim as runner

# ARG SERVER_URL
# ARG FRONTEND_URL

# Install pre-requisites
RUN apk update && \
    apk add --no-cache bash ca-certificates

# Set working directory
WORKDIR /app

# link nginx logs to container stdout
RUN ln -sf /dev/stdout /var/log/nginx/access.log && ln -sf /dev/stderr /var/log/nginx/error.log

# Clean up nginx configuration
RUN rm -rf /etc/nginx/sites-enabled/default /usr/share/nginx/html/* /etc/nginx/sites-available/*

# Setup NGINX with config
COPY ./nginx.conf /etc/nginx/conf.d/default.conf

# Copy entrypoint script
COPY run.sh /app/run.sh

RUN chmod +x /app/run.sh

# Start Nginx in the foreground
CMD ["/app/run.sh"]