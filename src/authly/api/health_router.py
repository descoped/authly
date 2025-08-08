import logging

import psycopg
from fastapi import APIRouter, Depends

from authly._version import __version__
from authly.core.dependencies import get_database_connection

router = APIRouter()


@router.get("/health", tags=["health"])
async def health_check(db_connection=Depends(get_database_connection)) -> dict[str, str]:
    try:
        async with db_connection.cursor() as cur:
            await cur.execute("SELECT txid_current()")
            _ = await cur.fetchone()

        # Include version and psycopg driver information
        health_info = {
            "status": "healthy",
            "version": __version__,
            "database": "connected",
            "psycopg_driver": psycopg.pq.__impl__,
            "psycopg_version": psycopg.__version__,
        }

        return health_info
    except Exception as e:
        logging.error("Database connection error: %s", str(e))
        return {"status": "unhealthy", "version": __version__, "database": "error", "psycopg_driver": "unknown"}
