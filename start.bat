@echo off
setlocal

echo [ASRE] Bootstrapping local environment...

where python >nul 2>nul
if errorlevel 1 (
  echo [ASRE] Python was not found in PATH.
  exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
  echo [ASRE] npm was not found in PATH.
  exit /b 1
)

where docker >nul 2>nul
if errorlevel 1 (
  echo [ASRE] Docker was not found in PATH.
  exit /b 1
)

if not exist Backend\.venv (
  echo [ASRE] Creating Python virtual environment...
  python -m venv Backend\.venv
)

echo [ASRE] Installing backend dependencies...
call Backend\.venv\Scripts\python -m pip install --upgrade pip
call Backend\.venv\Scripts\python -m pip install -r Backend\requirements.txt

echo [ASRE] Installing frontend dependencies...
call npm --prefix frontend install

echo [ASRE] Starting databases (Postgres, Redis, Neo4j)...
call docker compose up -d postgres redis neo4j

echo [ASRE] Applying database migrations...
cd /d Backend
call ..\.venv\Scripts\python -m alembic upgrade head
cd /d ..

echo [ASRE] Launching backend API, worker, and frontend dev server...
start "ASRE Backend API" cmd /k "cd /d %cd%\Backend && ..\.venv\Scripts\python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
start "ASRE Celery Worker" cmd /k "cd /d %cd%\Backend && ..\.venv\Scripts\python -m celery -A tasks.celery_app.celery_app worker --loglevel=info"
start "ASRE Frontend" cmd /k "cd /d %cd%\frontend && npm run dev -- --host 0.0.0.0 --port 3000"

echo [ASRE] Started.
echo [ASRE] API: http://localhost:8000/docs
echo [ASRE] Frontend: http://localhost:3000

exit /b 0
