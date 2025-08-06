# Production Dockerfile for OIDC Conformance Suite
FROM eclipse-temurin:17

# Install required packages
RUN apt-get update && apt-get install -y redir curl && rm -rf /var/lib/apt/lists/*

# Create directory for the JAR
WORKDIR /server

# Copy the built JAR file
COPY conformance-suite/target/fapi-test-suite.jar /server/

# Default environment variables
ENV JAVA_OPTS="-Xmx2g -XX:MaxMetaspaceSize=512m"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:9999/api/info || exit 1

# Default command
CMD java ${JAVA_OPTS} \
    -jar /server/fapi-test-suite.jar \
    -Djdk.tls.maxHandshakeMessageSize=65536 \
    --fintechlabs.base_url=${BASE_URL:-https://localhost.emobix.co.uk:8443} \
    --fintechlabs.devmode=${DEVMODE:-true} \
    --fintechlabs.startredir=${STARTREDIR:-true}