# ASRE v2.0

ASRE (Automated Security Reasoning Engine) is a dual-mode web app security scanner with attack-chain graphing, LLM-assisted impact analysis, and PDF reporting.

## Stack
- Backend: FastAPI, SQLAlchemy async, Celery, Redis, Neo4j, Alembic, WeasyPrint
- Frontend: React 18, TypeScript, Vite, Zustand, React Flow, Tailwind
- Infra: Docker Compose (Postgres, Redis, Neo4j)

## Quick Start (Windows)
1. Copy `.env.example` to `.env` if needed and adjust values.
2. Run `start.bat` from repository root.
3. Open:
- Frontend: http://localhost:3000
- Backend Docs: http://localhost:8000/docs

## Manual Start
1. Start infrastructure:
```bash
docker compose up -d postgres redis neo4j
```
2. Backend setup:
```bash
cd Backend
python -m venv .venv
.venv\\Scripts\\python -m pip install -r requirements.txt
.venv\\Scripts\\python -m alembic upgrade head
.venv\\Scripts\\python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
3. Worker:
```bash
cd Backend
.venv\\Scripts\\python -m celery -A tasks.celery_app.celery_app worker --loglevel=info
```
4. Frontend:
```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --port 3000
```

## Key API Routes Added
- `GET /api/scans/{scan_id}/graph`
- `GET /api/scans/{scan_id}/graph/chains`
- `GET /api/scans/{scan_id}/graph/export`
- `GET /api/reports/{scan_id}`
- `GET /api/reports/{scan_id}/download`
- `POST /api/reports/{scan_id}/regenerate`
- `DELETE /api/reports/{scan_id}`
- `POST /api/consent/init`
- `POST /api/consent/verify-domain`
- `POST /api/consent/lock-scope`
- `GET /api/consent/{consent_id}`
- `GET /api/consent/active`

## Notes
- The initial migration is in `Backend/alembic/versions/0001_initial.py`.
- Routes are wired in `Backend/main.py`.
- Alembic model imports are loaded in `Backend/alembic/env.py` via `from models import *`.
