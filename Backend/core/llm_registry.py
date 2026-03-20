import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from langchain_anthropic import ChatAnthropic
from langchain_community.chat_models import ChatCohere
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage
from langchain_groq import ChatGroq
from langchain_mistralai import ChatMistralAI
from langchain_openai import ChatOpenAI

from config import settings

logger = logging.getLogger(__name__)


@dataclass
class ProviderConfig:
    name: str
    requires_key: bool = True
    base_url: Optional[str] = None
    langchain_cls: str = ""


PROVIDER_REGISTRY: Dict[str, ProviderConfig] = {
    "openai": ProviderConfig(
        name="OpenAI",
        requires_key=True,
        base_url="https://api.openai.com/v1",
        langchain_cls="ChatOpenAI",
    ),
    "anthropic": ProviderConfig(
        name="Anthropic Claude",
        requires_key=True,
        base_url="https://api.anthropic.com",
        langchain_cls="ChatAnthropic",
    ),
    "deepseek": ProviderConfig(
        name="DeepSeek",
        requires_key=True,
        base_url="https://api.deepseek.com/v1",
        langchain_cls="ChatOpenAI",
    ),
    "groq": ProviderConfig(
        name="Groq",
        requires_key=True,
        base_url="https://api.groq.com/openai/v1",
        langchain_cls="ChatGroq",
    ),
    "ollama": ProviderConfig(
        name="Ollama (Local)",
        requires_key=False,
        base_url="http://localhost:11434/v1",
        langchain_cls="ChatOpenAI",
    ),
    "mistral": ProviderConfig(
        name="Mistral AI",
        requires_key=True,
        base_url="https://api.mistral.ai/v1",
        langchain_cls="ChatMistralAI",
    ),
    "together": ProviderConfig(
        name="Together AI",
        requires_key=True,
        base_url="https://api.together.xyz/v1",
        langchain_cls="ChatOpenAI",
    ),
    "nvidia": ProviderConfig(
        name="NVIDIA NIM",
        requires_key=True,
        base_url="https://integrate.api.nvidia.com/v1",
        langchain_cls="ChatOpenAI",
    ),
    "openrouter": ProviderConfig(
        name="OpenRouter",
        requires_key=True,
        base_url="https://openrouter.ai/api/v1",
        langchain_cls="ChatOpenAI",
    ),
    "cohere": ProviderConfig(
        name="Cohere",
        requires_key=True,
        base_url=None,
        langchain_cls="ChatCohere",
    ),
    "custom": ProviderConfig(
        name="Custom / Self-Hosted",
        requires_key=False,
        base_url=None,
        langchain_cls="ChatOpenAI",
    ),
}

PROVIDER_ALIASES: Dict[str, str] = {
    "nim": "nvidia",
    "nv": "nvidia",
}


class LLMRegistry:
    """Singleton factory for provider-agnostic LangChain chat clients."""

    _instance: Optional[BaseChatModel] = None
    _last_provider: str = ""
    _last_model: str = ""

    @classmethod
    def get_client(
        cls,
        override_provider: Optional[str] = None,
        override_model: Optional[str] = None,
        override_api_key: Optional[str] = None,
        override_base_url: Optional[str] = None,
    ) -> BaseChatModel:
        provider = (override_provider or settings.LLM_PROVIDER).lower().strip()
        provider = PROVIDER_ALIASES.get(provider, provider)
        model = override_model or settings.LLM_MODEL
        api_key = override_api_key or settings.effective_llm_api_key
        temperature = settings.LLM_TEMPERATURE
        max_tokens = settings.LLM_MAX_TOKENS
        timeout = settings.LLM_REQUEST_TIMEOUT

        provider_config = PROVIDER_REGISTRY.get(provider, ProviderConfig(name="custom"))
        base_url = override_base_url or (settings.LLM_BASE_URL or None) or provider_config.base_url

        cache_key = f"{provider}:{model}"
        if cls._instance and cls._last_provider == cache_key:
            return cls._instance

        config = PROVIDER_REGISTRY.get(provider)
        if not config:
            raise ValueError(
                f"Unknown LLM provider: '{provider}'. "
                f"Valid providers: {list(PROVIDER_REGISTRY.keys())}"
            )

        if config.requires_key and not api_key:
            raise ValueError(
                f"LLM provider '{provider}' requires an API key. "
                "Set LLM_API_KEY in your .env file."
            )

        if provider == "custom" and not base_url:
            raise ValueError("LLM provider 'custom' requires LLM_BASE_URL to be set.")

        client = cls._build_client(
            langchain_cls=config.langchain_cls,
            provider=provider,
            model=model,
            api_key=api_key,
            base_url=base_url,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
        )

        cls._instance = client
        cls._last_provider = cache_key
        cls._last_model = model

        logger.info(
            "LLM client initialized: provider=%s model=%s base_url=%s",
            provider,
            model,
            base_url or "default",
        )
        return client

    @classmethod
    def _build_client(
        cls,
        langchain_cls: str,
        provider: str,
        model: str,
        api_key: str,
        base_url: Optional[str],
        temperature: float,
        max_tokens: int,
        timeout: int,
    ) -> BaseChatModel:
        if langchain_cls == "ChatOpenAI":
            kwargs: Dict[str, Any] = {
                "model": model,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "timeout": timeout,
                "api_key": api_key or "ollama",
            }
            if base_url:
                kwargs["base_url"] = base_url
            if provider == "openrouter":
                kwargs["default_headers"] = {
                    "HTTP-Referer": "https://github.com/your-org/asre",
                    "X-Title": "ASRE Security Scanner",
                }
            return ChatOpenAI(**kwargs)

        if langchain_cls == "ChatAnthropic":
            return ChatAnthropic(
                model=model,
                api_key=api_key,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout,
            )

        if langchain_cls == "ChatGroq":
            return ChatGroq(
                model=model,
                api_key=api_key,
                temperature=temperature,
                max_tokens=max_tokens,
            )

        if langchain_cls == "ChatMistralAI":
            return ChatMistralAI(
                model=model,
                api_key=api_key,
                temperature=temperature,
                max_tokens=max_tokens,
            )

        if langchain_cls == "ChatCohere":
            return ChatCohere(
                model=model,
                cohere_api_key=api_key,
                temperature=temperature,
            )

        raise ValueError(
            f"Unknown langchain_cls: '{langchain_cls}'. "
            "This is a bug in PROVIDER_REGISTRY."
        )

    @classmethod
    async def test_connection(
        cls,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        active_provider = provider or settings.LLM_PROVIDER
        active_model = model or settings.LLM_MODEL
        try:
            client = cls.get_client(
                override_provider=provider,
                override_model=model,
                override_api_key=api_key,
                override_base_url=base_url,
            )
            response = await client.ainvoke([HumanMessage(content="Reply with just: OK")])
            content = str(getattr(response, "content", ""))
            return {
                "status": "ok",
                "provider": active_provider,
                "model": active_model,
                "response": content[:50],
            }
        except Exception as exc:
            return {
                "status": "error",
                "provider": active_provider,
                "model": active_model,
                "error": str(exc),
            }

    @classmethod
    def invalidate_cache(cls) -> None:
        cls._instance = None
        cls._last_provider = ""
        cls._last_model = ""

    @classmethod
    def supported_providers(cls) -> List[Dict[str, Any]]:
        return [
            {
                "id": provider_id,
                "name": config.name,
                "requires_key": config.requires_key,
                "default_base_url": config.base_url,
                "langchain_cls": config.langchain_cls,
            }
            for provider_id, config in PROVIDER_REGISTRY.items()
        ]
