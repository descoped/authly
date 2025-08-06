"""
Metrics router for Prometheus metrics endpoint.

This router provides the /metrics endpoint for Prometheus scraping,
following the existing dependency injection and security patterns.
"""

import logging

from fastapi import APIRouter, Depends, Request
from starlette.responses import Response

from authly.api.rate_limiter import RateLimiter
from authly.monitoring.metrics import metrics_handler

logger = logging.getLogger(__name__)

router = APIRouter(tags=["metrics"])


def get_metrics_rate_limiter() -> RateLimiter:
    """Get rate limiter for metrics endpoint.

    Uses more restrictive limits for metrics endpoint to prevent abuse.

    Returns:
        RateLimiter instance configured for metrics endpoint
    """
    return RateLimiter(max_requests=30, window_seconds=60)


@router.get("/metrics")
async def get_metrics(request: Request, rate_limiter: RateLimiter = Depends(get_metrics_rate_limiter)) -> Response:
    """
    Prometheus metrics endpoint.

    Returns metrics in Prometheus exposition format for scraping.
    Includes rate limiting to prevent abuse while allowing regular scraping.

    Returns:
        Response with Prometheus metrics in text/plain format
    """
    # Apply rate limiting using client IP
    client_ip = "unknown"
    if hasattr(request, "client") and request.client:
        client_ip = request.client.host

    await rate_limiter.check_rate_limit(f"metrics:{client_ip}")

    logger.debug("Serving Prometheus metrics")
    return metrics_handler()
