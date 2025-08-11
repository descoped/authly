FROM python:3.13-alpine

# Install dependencies
RUN pip install --no-cache-dir \
    aiohttp \
    asyncpg \
    aioredis \
    PyJWT

# Copy proxy scripts
WORKDIR /app
COPY pg_proxy.py redis_proxy.py ./

# Make scripts executable
RUN chmod +x pg_proxy.py redis_proxy.py

# Default to PostgreSQL proxy
CMD ["python", "pg_proxy.py"]