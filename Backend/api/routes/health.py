from fastapi import APIRouter, Response, status
from redis.asyncio import Redis
from sqlalchemy import select

from config import settings
from core.database import get_db_context
from core.neo4j_client import neo4j_client
from .models import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check(response: Response) -> HealthResponse:
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
        status_code = status.HTTP_206_PARTIAL_CONTENT

    response.status_code = status_code
    return HealthResponse(overall=overall, services=services)
