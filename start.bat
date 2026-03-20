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

set "API_PORT="
for /f "tokens=2 delims=:" %%P in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "$ports=@(8010,8000,8020,8030); foreach($port in $ports){ $listeners=Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique; foreach($ownerPid in $listeners){ $proc=Get-Process -Id ([int]$ownerPid) -ErrorAction SilentlyContinue; if($proc -and $proc.ProcessName -match '^python'){ try { Stop-Process -Id ([int]$ownerPid) -Force -ErrorAction Stop } catch {} } }; Start-Sleep -Milliseconds 300; $live=Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique; $hasLive=$false; foreach($lp in $live){ if(Get-Process -Id ([int]$lp) -ErrorAction SilentlyContinue){ $hasLive=$true } }; if(-not $hasLive){ Write-Output ('PORT:' + $port); exit 0 } }; Write-Output 'PORT:-1'; exit 1"') do set "API_PORT=%%P"
if "%API_PORT%"=="" (
  echo [ASRE] Could not allocate a free API port.
  echo [ASRE] Close any processes on 8000/8010/8020/8030 and try again.
  exit /b 1
)
if "%API_PORT%"=="-1" (
  echo [ASRE] Could not allocate a free API port.
  echo [ASRE] Close any processes on 8000/8010/8020/8030 and try again.
  exit /b 1
)

set "FONTCONFIG_FILE=%cd%\Backend\fonts.conf"
set "FONTCONFIG_PATH=%cd%\Backend"

echo [ASRE] Launching backend API, worker, and frontend dev server...
start "ASRE Backend API" cmd /k "cd /d %cd%\Backend && .venv\Scripts\python.exe -m uvicorn main:app --app-dir . --host 0.0.0.0 --port %API_PORT% --ws-ping-interval 20 --ws-ping-timeout 60"
:: Start Celery worker with solo pool for Windows compatibility
start "ASRE Celery Worker" cmd /k "cd /d %cd%\Backend && .venv\Scripts\python.exe -m celery -A tasks.celery_app.celery_app worker --loglevel=info --pool=solo"
start "ASRE Frontend" cmd /k "cd /d %cd%\frontend && set \"VITE_API_URL=http://localhost:%API_PORT%/api\" && npm run dev -- --host 0.0.0.0 --port 3000"

echo [ASRE] Started.
echo [ASRE] API: http://localhost:%API_PORT%/docs
echo [ASRE] Frontend: http://localhost:3000
echo [ASRE] If this is your first run, use setup.bat before start.bat.

exit /b 0
