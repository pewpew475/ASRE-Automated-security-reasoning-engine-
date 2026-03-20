from functools import lru_cache
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "ASRE - Automated Security Reasoning Engine"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    SECRET_KEY: str = Field(...)
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    BCRYPT_ROUNDS: int = 12

    DATABASE_URL: str = Field(...)
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_ECHO: bool = False

    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USERNAME: str = "neo4j"
    NEO4J_PASSWORD: str = Field(...)
    NEO4J_DATABASE: str = "neo4j"

    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    OPENAI_API_KEY: Optional[str] = None
    DEEPSEEK_API_KEY: Optional[str] = None
    LLM_PROVIDER: str = "openai"
    LLM_MODEL: str = "gpt-4o"
    LLM_MAX_TOKENS: int = 2048
    LLM_TEMPERATURE: float = 0.2

    MAX_CRAWL_DEPTH: int = 5
    MAX_CRAWL_PAGES: int = 100
    MAX_CONCURRENT_REQUESTS: int = 10
    REQUEST_TIMEOUT_SECONDS: int = 30
    SCAN_RATE_LIMIT_PER_SEC: int = 10
    HARDCORE_MAX_RATE_PER_SEC: int = 50

    SQLMAP_API_URL: str = "http://localhost:8775"
    NUCLEI_BINARY_PATH: str = "/usr/local/bin/nuclei"
    ZAP_API_URL: Optional[str] = "http://localhost:8080"
    ZAP_API_KEY: Optional[str] = None

    ALLOWED_ORIGINS: List[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://localhost:5173"]
    )

    REPORTS_DIR: str = "./reports"
    TEMPLATES_DIR: str = "./templates"

    DNS_VERIFICATION_PREFIX: str = "pentest-verify"
    CONSENT_EXPIRY_DAYS: int = 30
    TC_CURRENT_VERSION: str = "1.0.0"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
