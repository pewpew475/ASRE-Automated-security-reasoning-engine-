@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0"

:: Check if the script is run as Administrator
whoami /groups | find "S-1-5-32-544" >nul 2>&1
if errorlevel 1 (
  echo [ASRE] This script must be run as Administrator.
  exit /b 1
)

echo [ASRE] Starting services...

if not exist "setup.bat" (
  echo [ASRE] setup.bat not found.
  exit /b 1
)

if not exist ".env" (
  echo [ASRE] .env is missing.
  echo [ASRE] Run setup.bat first.
  exit /b 1
)

if not exist "Backend\.venv\Scripts\python.exe" (
  echo [ASRE] Backend virtual environment is missing.
  echo [ASRE] Run setup.bat first.
  exit /b 1
)

if not exist "frontend\node_modules" (
  echo [ASRE] frontend\node_modules is missing.
  echo [ASRE] Run setup.bat first.
  exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
  if exist "%ProgramFiles%\nodejs\npm.cmd" (
    set "PATH=%ProgramFiles%\nodejs;%PATH%"
  ) else (
    echo [ASRE] npm is not available.
    echo [ASRE] Run setup.bat first.
    exit /b 1
  )
)

set "DB_PORT=5432"
for /f %%P in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='%cd%\.env'; if(Test-Path -LiteralPath $p){ $line=(Get-Content -LiteralPath $p | Where-Object { $_ -like 'DATABASE_URL=*' } | Select-Object -First 1); if($line -match ':(\d+)/'){ $matches[1] } }"') do set "DB_PORT=%%P"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$db=%DB_PORT%; $checks=@(@{Name='PostgreSQL';Port=$db},@{Name='Redis';Port=6379},@{Name='Neo4j';Port=7687}); $missing=@(); foreach($c in $checks){ if(-not (Get-NetTCPConnection -State Listen -LocalPort $c.Port -ErrorAction SilentlyContinue)){ $missing += ($c.Name + ':' + $c.Port) } }; if($missing.Count -gt 0){ Write-Output ('MISSING:' + ($missing -join ', ')); exit 1 } else { Write-Output 'OK' }"
if errorlevel 1 (
  echo [ASRE] Local services are not ready.
  echo [ASRE] Required ports: PostgreSQL %DB_PORT%, Redis 6379, Neo4j 7687.
  echo [ASRE] Run services.bat, then run start.bat again.
  exit /b 1
)

set FONTCONFIG_FILE=C:\Windows\Fonts\fonts.conf

echo [ASRE] Launching backend API, worker, and frontend dev server...
start "ASRE Backend API" cmd /k "cd /d %cd%\Backend && .venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
:: Start Celery worker with solo pool for Windows compatibility
start "ASRE Celery Worker" cmd /k "cd /d %cd%\Backend && .venv\Scripts\python.exe -m celery -A tasks.celery_app.celery_app worker --loglevel=info --pool=solo"
start "ASRE Frontend" cmd /k "cd /d %cd%\frontend && npm run dev -- --host 0.0.0.0 --port 3000"

echo [ASRE] Started.
echo [ASRE] API: http://localhost:8000/docs
echo [ASRE] Frontend: http://localhost:3000
echo [ASRE] If this is your first run, use setup.bat before start.bat.

exit /b 0
