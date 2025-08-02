# Multi-stage Dockerfile for Authly authentication service
FROM python:3.13-slim AS builder

# Build arguments for flexible installation
ARG USE_WHEEL=false

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies required for building
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install UV (use latest version)
RUN pip install --no-cache-dir uv

# Set work directory
WORKDIR /app

# Conditional installation based on build argument
RUN if [ "$USE_WHEEL" = "true" ]; then \
      echo "🎯 Installing from pre-built wheel..."; \
    else \
      echo "🔨 Building from source code..."; \
    fi

# Copy project files for dependency resolution
COPY pyproject.toml uv.lock README.md ./

# Extract version from pyproject.toml for build metadata
RUN python3 -c "import tomllib; version=tomllib.load(open('pyproject.toml', 'rb'))['project']['version']; print(f'Building Authly v{version}'); open('/tmp/VERSION', 'w').write(version)"

# Create directories
RUN mkdir -p /tmp/wheels

# Copy wheel files if they exist (will be provided by CI or local build)
# Use a shell command to handle optional copying
COPY . /tmp/context/
RUN if [ -d "/tmp/context/dist" ] && ls /tmp/context/dist/*.whl >/dev/null 2>&1; then \
      echo "📦 Found wheel files, copying..."; \
      cp /tmp/context/dist/*.whl /tmp/wheels/; \
      echo "true" > /tmp/has_wheels; \
    else \
      echo "🔨 No wheel files found, will build from source..."; \
      echo "false" > /tmp/has_wheels; \
    fi && \
    # Copy only the source code we need \
    cp -r /tmp/context/src /app/ && \
    rm -rf /tmp/context

# Source code is already copied above

# Install authly - conditional approach based on wheel detection
RUN if [ -f "/tmp/has_wheels" ] && [ "$(cat /tmp/has_wheels)" = "true" ] && ls /tmp/wheels/*.whl >/dev/null 2>&1; then \
      echo "🎯 Installing authly from wheel..."; \
      cd /tmp/wheels && uv pip install --system $(ls -t *.whl | head -1); \
      mkdir -p /app/.venv; \
    else \
      echo "🔨 Installing dependencies for source build..."; \
      uv sync --frozen --no-dev --no-cache; \
    fi

# Production stage
FROM python:3.13-slim AS production

# Pass build argument to production stage
ARG USE_WHEEL=false

# Set environment variables for production
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV AUTHLY_MODE="production"
ENV AUTHLY_BOOTSTRAP_ENABLED="true"

# Install system dependencies required for runtime
RUN apt-get update && apt-get install -y \
    libpq5 \
    postgresql-client \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with home directory
RUN groupadd -r authly && useradd -r -g authly -m -d /home/authly authly

# Set work directory
WORKDIR /app

# Copy source code from builder (always needed for fallback)
COPY --from=builder /app/src/ /app/src/

# Copy version information for runtime
COPY --from=builder /tmp/VERSION /app/VERSION

# Copy dependencies based on build type
RUN if [ "$USE_WHEEL" = "true" ]; then \
      echo "Wheel build - copying system-wide packages from builder"; \
    else \
      echo "Source build - copying .venv from builder"; \
    fi

# Copy Python packages from builder (wheel builds install system-wide)
COPY --from=builder /usr/local/lib/python3.13/site-packages/ /usr/local/lib/python3.13/site-packages/

# Copy executables from builder (for wheel build entry points)
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Copy .venv from builder (for source builds)
RUN mkdir -p /app/.venv
COPY --from=builder /app/.venv/ /app/.venv/

# Set environment variables based on build type
RUN if [ "$USE_WHEEL" = "true" ]; then \
      echo "Setting up environment for wheel build"; \
      echo 'export PATH="/usr/local/bin:$PATH"' > /app/env-setup.sh; \
      echo 'export PYTHONPATH=""' >> /app/env-setup.sh; \
    else \
      echo "Setting up environment for source build"; \
      echo 'export PATH="/app/.venv/bin:/usr/local/bin:$PATH"' > /app/env-setup.sh; \
      echo 'export PYTHONPATH="/app/src"' >> /app/env-setup.sh; \
    fi

# Set default environment - will be overridden by env-setup.sh if needed
ENV PATH="/usr/local/bin:$PATH"
ENV PYTHONPATH=""

# Copy database initialization script if it exists
COPY docker-postgres/init-db-and-user.sql /app/docker-postgres/init-db-and-user.sql

# Create logs directory for application logging
RUN mkdir -p /app/logs

# Set ownership for all app files
RUN chown -R authly:authly /app && chown -R authly:authly /home/authly

# Switch to non-root user
USER authly

# Expose port
EXPOSE 8000

# Health check using the unified resource manager
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Default command using the unified resource manager entry point
CMD ["/bin/bash", "-c", "source /app/env-setup.sh 2>/dev/null || true; exec python -m authly serve --host 0.0.0.0 --port 8000"]