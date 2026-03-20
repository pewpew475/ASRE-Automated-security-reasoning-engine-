@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0"

echo [ASRE Setup] Preparing local environment...

set "PYTHON_EXE=python.exe"
set "NPM_EXE=npm.cmd"

call :ensure_package_manager
if errorlevel 1 exit /b 1

call :ensure_python
if errorlevel 1 exit /b 1

call :ensure_node
if errorlevel 1 exit /b 1

call :ensure_env
if errorlevel 1 exit /b 1

call :check_local_services
if errorlevel 1 exit /b 1

if not exist "Backend\.venv\Scripts\python.exe" (
  echo [ASRE Setup] Creating Python virtual environment...
  call "%PYTHON_EXE%" -m venv "Backend\.venv"
  if errorlevel 1 (
    echo [ASRE Setup] Failed to create Python virtual environment.
    exit /b 1
  )
)

echo [ASRE Setup] Installing backend dependencies...
call "Backend\.venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 exit /b 1
call "Backend\.venv\Scripts\python.exe" -m pip install -r "Backend\requirements.txt"
if errorlevel 1 exit /b 1

echo [ASRE Setup] Installing frontend dependencies...
call "%NPM_EXE%" --prefix "frontend" install
if errorlevel 1 exit /b 1

echo [ASRE Setup] Applying database migrations...
pushd "Backend"
call ".venv\Scripts\python.exe" -m alembic upgrade head
if errorlevel 1 (
  echo [ASRE Setup] Alembic migration failed.
  popd
  exit /b 1
)
popd

echo [ASRE Setup] Complete.
echo [ASRE Setup] Next: edit .env with your LLM API key, then run start.bat
exit /b 0

:ensure_package_manager
where winget >nul 2>nul
if errorlevel 1 (
  where choco >nul 2>nul
  if errorlevel 1 (
    echo [ASRE Setup] Neither winget nor choco is available.
    echo [ASRE Setup] Install winget App Installer or Chocolatey and run setup.bat again.
    exit /b 1
  )
)
exit /b 0

:ensure_python
where python >nul 2>nul
if errorlevel 1 (
  echo [ASRE Setup] Python not found. Installing Python 3.11...
  call :install_pkg "Python.Python.3.11" "python311" "Python"
  if errorlevel 1 exit /b 1
)

where python >nul 2>nul
if errorlevel 1 (
  if exist "%LocalAppData%\Programs\Python\Python311\python.exe" (
    set "PYTHON_EXE=%LocalAppData%\Programs\Python\Python311\python.exe"
  ) else if exist "%ProgramFiles%\Python311\python.exe" (
    set "PYTHON_EXE=%ProgramFiles%\Python311\python.exe"
  ) else (
    echo [ASRE Setup] Python installation was attempted but python is still unavailable.
    exit /b 1
  )
) else (
  set "PYTHON_EXE=python.exe"
)

call "%PYTHON_EXE%" --version >nul 2>nul
if errorlevel 1 (
  echo [ASRE Setup] Python executable is not usable.
  exit /b 1
)

exit /b 0

:ensure_node
where npm >nul 2>nul
if errorlevel 1 (
  echo [ASRE Setup] Node.js/npm not found. Installing Node.js LTS...
  call :install_pkg "OpenJS.NodeJS.LTS" "nodejs-lts" "Node.js"
  if errorlevel 1 exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
  if exist "%ProgramFiles%\nodejs\npm.cmd" (
    set "NPM_EXE=%ProgramFiles%\nodejs\npm.cmd"
    set "PATH=%ProgramFiles%\nodejs;%PATH%"
  ) else (
    echo [ASRE Setup] Node.js installation was attempted but npm is still unavailable.
    exit /b 1
  )
) else (
  set "NPM_EXE=npm.cmd"
)

call "%NPM_EXE%" --version >nul 2>nul
if errorlevel 1 (
  echo [ASRE Setup] npm is present but not usable. Attempting Node.js repair install...
  call :install_pkg "OpenJS.NodeJS.LTS" "nodejs-lts" "Node.js"
  if errorlevel 1 exit /b 1

  if exist "%ProgramFiles%\nodejs\npm.cmd" (
    set "NPM_EXE=%ProgramFiles%\nodejs\npm.cmd"
    set "PATH=%ProgramFiles%\nodejs;%PATH%"
  )

  call "!NPM_EXE!" --version >nul 2>nul
  if errorlevel 1 (
    echo [ASRE Setup] npm is still not usable after repair.
    exit /b 1
  )
)

exit /b 0

:check_local_services
set "DB_PORT=5432"
for /f %%P in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='%cd%\.env'; if(Test-Path -LiteralPath $p){ $line=(Get-Content -LiteralPath $p | Where-Object { $_ -like 'DATABASE_URL=*' } | Select-Object -First 1); if($line -match ':(\d+)/'){ $matches[1] } }"') do set "DB_PORT=%%P"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$db=%DB_PORT%; $checks=@(@{Name='PostgreSQL';Port=$db},@{Name='Redis';Port=6379},@{Name='Neo4j';Port=7687}); $missing=@(); foreach($c in $checks){ if(-not (Get-NetTCPConnection -State Listen -LocalPort $c.Port -ErrorAction SilentlyContinue)){ $missing += ($c.Name + ':' + $c.Port) } }; if($missing.Count -gt 0){ Write-Output ('MISSING:' + ($missing -join ', ')); exit 1 } else { Write-Output 'OK' }"
if errorlevel 1 (
  echo [ASRE Setup] Required local services are not listening on all expected ports.
  echo [ASRE Setup] Needed: PostgreSQL %DB_PORT%, Redis 6379, Neo4j 7687.
  echo [ASRE Setup] Run services.bat to start them, then run setup.bat again.
  exit /b 1
)
exit /b 0

:ensure_env
if not exist ".env" (
  echo [ASRE Setup] Creating .env from .env.example...
  if not exist ".env.example" (
    echo [ASRE Setup] .env.example not found.
    exit /b 1
  )
  copy /y ".env.example" ".env" >nul
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='%cd%\\.env'; $c=Get-Content -Raw -LiteralPath $p; if($c -match 'SECRET_KEY=replace_with_secure_random_string' -or $c -match 'SECRET_KEY=YOUR_SECRET_KEY'){ $secret=[guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'); $c=$c -replace 'SECRET_KEY=.*','SECRET_KEY=' + $secret; Set-Content -NoNewline -LiteralPath $p -Value $c }"
if errorlevel 1 (
  echo [ASRE Setup] Failed to finalize .env values.
  exit /b 1
)

exit /b 0

:install_pkg
set "WG_ID=%~1"
set "CHOCO_ID=%~2"
set "PKG_LABEL=%~3"

where winget >nul 2>nul
if not errorlevel 1 (
  winget install -e --id %WG_ID% --accept-package-agreements --accept-source-agreements
  if not errorlevel 1 exit /b 0
)

where choco >nul 2>nul
if not errorlevel 1 (
  choco install -y %CHOCO_ID%
  if not errorlevel 1 exit /b 0
)

echo [ASRE Setup] Failed to install %PKG_LABEL% automatically.
echo [ASRE Setup] Install it manually and run setup.bat again.
exit /b 1
