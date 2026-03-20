import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import auth, health, llm_config, scan, settings_route, websocket
from config import settings
from core.database import init_db
from core.neo4j_client import neo4j_client


def _resolve_optional_middleware(path: str) -> type | None:
    module_name, class_name = path.rsplit(".", 1)
    try:
        module = __import__(module_name, fromlist=[class_name])
        middleware_class = getattr(module, class_name)
    except (ImportError, AttributeError):
        return None
    return middleware_class


@asynccontextmanager
async def lifespan(_: FastAPI):
    for directory in [
        settings.REPORTS_DIR,
        settings.TEMPLATES_DIR,
        "./data/logs",
        "./data/scans",
    ]:
        os.makedirs(directory, exist_ok=True)
    await init_db()
    await neo4j_client.connect()
    await neo4j_client.init_constraints()
    print("ASRE backend started ✓")
    try:
        yield
    finally:
        await neo4j_client.disconnect()
        print("ASRE backend stopped.")


app = FastAPI(
    title="ASRE - Automated Security Reasoning Engine",
    version="1.0.0",
    description="Dual-mode web application security scanner",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(getattr(settings, "ALLOWED_ORIGINS", ["http://localhost:3000"])),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for middleware_path in [
    "api.middleware.auth_middleware.AuthMiddleware",
    "api.middleware.consent_gate.ConsentGateMiddleware",
    "api.middleware.rate_limiter.RateLimiterMiddleware",
]:
    middleware_class = _resolve_optional_middleware(middleware_path)
    if middleware_class is not None:
        app.add_middleware(middleware_class)

app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scan.router, prefix="/api/scan", tags=["Scans"])
app.include_router(websocket.router, prefix="/ws", tags=["WebSocket"])
app.include_router(health.router, prefix="/", tags=["Health"])
app.include_router(settings_route.router, prefix="/api", tags=["Settings"])
app.include_router(llm_config.router, prefix="/api")


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "ASRE Backend",
        "version": "1.0.0",
        "docs": "/docs",
    }
