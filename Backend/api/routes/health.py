from datetime import datetime, timezone

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy import select

from config import settings
from core.database import get_db_context
from core.neo4j_client import neo4j_client

router = APIRouter()


@router.get("/health", tags=["Health"])
async def health_check() -> dict | JSONResponse:
    services = {
        "postgresql": "unreachable",
        "neo4j": "unreachable",
        "redis": "unreachable",
    }

    try:
        async with get_db_context() as db:
            await db.execute(select(1))
        services["postgresql"] = "ok"
    except Exception:
        services["postgresql"] = "unreachable"

    try:
        await neo4j_client.execute_query("RETURN 1 AS n")
        services["neo4j"] = "ok"
    except Exception:
        services["neo4j"] = "unreachable"

    redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        pong = await redis.ping()
        services["redis"] = "ok" if pong else "unreachable"
    except Exception:
        services["redis"] = "unreachable"
    finally:
        await redis.aclose()

    ok_count = sum(value == "ok" for value in services.values())
    if ok_count == 3:
        overall = "ok"
        status_code = status.HTTP_200_OK
    elif ok_count == 0:
        overall = "unhealthy"
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    else:
        overall = "degraded"
        status_code = status.HTTP_200_OK

    payload = {
        "status": overall,
        "version": settings.APP_VERSION,
        "services": services,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if status_code == status.HTTP_200_OK:
        return payload
    return JSONResponse(status_code=status_code, content=payload)
