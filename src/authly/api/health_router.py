import logging
from typing import Dict

from fastapi import APIRouter
from fastapi import Depends

from authly import authly_db_connection

router = APIRouter()


@router.get("/health", tags=["health"])
async def health_check(db_connection=Depends(authly_db_connection)) -> Dict[str, str]:
    try:
        async with db_connection.cursor() as cur:
            await cur.execute("SELECT txid_current()")
            _ = await cur.fetchone()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        logging.error("Database connection error: %s", str(e))
        return {"status": "unhealthy", "database": "error"}
