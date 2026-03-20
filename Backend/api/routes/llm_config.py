from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api.deps import get_current_user
from config import settings
from core.llm_registry import LLMRegistry, PROVIDER_REGISTRY, ProviderConfig

router = APIRouter(prefix="/llm", tags=["LLM Config"])


class LLMTestRequest(BaseModel):
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None


@router.get("/providers")
async def list_providers() -> dict:
    return {
        "providers": LLMRegistry.supported_providers(),
        "current": {
            "provider": settings.LLM_PROVIDER,
            "model": settings.LLM_MODEL,
            "configured": settings.llm_configured,
            "base_url": settings.LLM_BASE_URL or "default",
        },
    }


@router.post("/test")
async def test_llm_connection(
    payload: LLMTestRequest,
    _current_user=Depends(get_current_user),
) -> dict:
    return await LLMRegistry.test_connection(
        provider=payload.provider,
        model=payload.model,
        api_key=payload.api_key,
        base_url=payload.base_url,
    )


@router.get("/status")
async def llm_status() -> dict:
    cfg = PROVIDER_REGISTRY.get(settings.LLM_PROVIDER, ProviderConfig(name="?"))
    return {
        "configured": settings.llm_configured,
        "provider": settings.LLM_PROVIDER,
        "model": settings.LLM_MODEL,
        "requires_key": cfg.requires_key,
    }
