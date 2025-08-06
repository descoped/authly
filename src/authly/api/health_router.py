import logging

from fastapi import APIRouter, Depends

from authly.core.dependencies import get_database_connection

router = APIRouter()


@router.get("/health", tags=["health"])
async def health_check(db_connection=Depends(get_database_connection)) -> dict[str, str]:
    try:
        async with db_connection.cursor() as cur:
            await cur.execute("SELECT txid_current()")
            _ = await cur.fetchone()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        logging.error("Database connection error: %s", str(e))
        return {"status": "unhealthy", "database": "error"}
