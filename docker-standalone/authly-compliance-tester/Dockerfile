FROM nginx:alpine

# Install docker CLI to run commands in other containers
RUN apk add --no-cache docker-cli jq bash

# Copy the compliance tester files
COPY . /usr/share/nginx/html/

# Copy custom nginx configuration with proxy settings
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy bootstrap script
COPY bootstrap.sh /bootstrap.sh
RUN chmod +x /bootstrap.sh

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080

CMD ["/entrypoint.sh"]