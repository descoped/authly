FROM httpd:2.4-alpine

# Install required modules and tools
RUN apk add --no-cache openssl

# Enable required Apache modules
RUN sed -i \
    -e 's/^#LoadModule rewrite_module/LoadModule rewrite_module/' \
    -e 's/^#LoadModule proxy_module/LoadModule proxy_module/' \
    -e 's/^#LoadModule proxy_http_module/LoadModule proxy_http_module/' \
    -e 's/^#LoadModule ssl_module/LoadModule ssl_module/' \
    -e 's/^#LoadModule headers_module/LoadModule headers_module/' \
    /usr/local/apache2/conf/httpd.conf

# Generate self-signed certificate for testing
RUN mkdir -p /usr/local/apache2/conf/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /usr/local/apache2/conf/ssl/server.key \
    -out /usr/local/apache2/conf/ssl/server.crt \
    -subj "/C=US/ST=Test/L=Test/O=Test/OU=Test/CN=localhost"

# Copy configuration files
COPY authly-proxy.conf /usr/local/apache2/conf/extra/authly-proxy.conf

# Include the custom configuration
RUN echo "Listen 8443" >> /usr/local/apache2/conf/httpd.conf && \
    echo "Include conf/extra/authly-proxy.conf" >> /usr/local/apache2/conf/httpd.conf

EXPOSE 8443