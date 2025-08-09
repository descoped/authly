FROM adminer:latest

# Install required PHP extensions
USER root
RUN apk add --no-cache curl

# Copy our OAuth wrapper
COPY oauth-wrapper.php /var/www/html/index.php

# Set permissions
RUN chown -R www-data:www-data /var/www/html

USER www-data

# Environment variables for configuration
ENV AUTHLY_URL=http://authly-standalone:8000 \
    DB_SERVER=authly-standalone \
    DB_USERNAME=authly \
    DB_PASSWORD=authly \
    DB_NAME=authly \
    ADMINER_DESIGN=pepa-linha \
    REQUIRED_SCOPES=database:read,database:write

EXPOSE 8080