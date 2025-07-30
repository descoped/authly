# Multi-stage Dockerfile for Authly authentication service
FROM python:3.13-slim AS builder

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

# Install UV (more specific version for reproducibility)
RUN pip install --no-cache-dir uv==0.5.11

# Set work directory
WORKDIR /app

# Copy UV project files (include uv.lock for reproducible builds)
COPY pyproject.toml uv.lock README.md ./

# Install dependencies using UV with specific flags
RUN uv sync --frozen --no-dev --no-cache

# Production stage
FROM python:3.13-slim AS production

# Set environment variables for production
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src"
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

# Copy virtual environment from builder stage
COPY --from=builder /app/.venv /app/.venv

# Copy application code
COPY src/ /app/src/

# Copy database initialization script if it exists
COPY docker/init-db-and-user.sql /app/docker/init-db-and-user.sql

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
CMD ["python", "-m", "authly", "serve", "--host", "0.0.0.0", "--port", "8000"]