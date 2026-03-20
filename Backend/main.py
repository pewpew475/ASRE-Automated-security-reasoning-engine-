import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.middleware.auth_middleware import AuthMiddleware
from api.middleware.consent_gate import ConsentGateMiddleware
from api.middleware.rate_limiter import RateLimiterMiddleware
from api.routes import auth, consent, graph, report, scan, websocket
from config import settings
from core.database import init_db
from core.neo4j_client import neo4j_client


@asynccontextmanager
async def lifespan(_: FastAPI):
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    os.makedirs(settings.TEMPLATES_DIR, exist_ok=True)
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

app.add_middleware(AuthMiddleware)
app.add_middleware(ConsentGateMiddleware)
app.add_middleware(RateLimiterMiddleware)

app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scan.router, prefix="/api/scan", tags=["Scans"])
app.include_router(graph.router, prefix="/api/scan", tags=["Attack Graph"])
app.include_router(report.router, prefix="/api/report", tags=["Reports"])
app.include_router(consent.router, prefix="/api/consent", tags=["Consent"])
app.include_router(websocket.router, prefix="/ws", tags=["WebSocket"])


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "ASRE Backend",
        "version": "1.0.0",
        "docs": "/docs",
    }
