from fastapi import APIRouter

from config import settings

router = APIRouter()


@router.get("/settings/public", tags=["Settings"])
async def get_public_settings() -> dict:
    return {
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION,
        "llm_provider": settings.LLM_PROVIDER,
        "llm_model": settings.LLM_MODEL,
        "llm_enabled": bool(settings.OPENAI_API_KEY or settings.DEEPSEEK_API_KEY),
        "hardcore_enabled": True,
        "max_crawl_depth": settings.MAX_CRAWL_DEPTH,
        "max_crawl_pages": settings.MAX_CRAWL_PAGES,
        "tc_version": settings.TC_CURRENT_VERSION,
    }
