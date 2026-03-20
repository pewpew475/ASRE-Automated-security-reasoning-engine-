@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0"

echo [ASRE Services] Starting local dependencies...

set "DB_PORT=5432"
for /f %%P in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='%cd%\.env'; if(Test-Path -LiteralPath $p){ $line=(Get-Content -LiteralPath $p | Where-Object { $_ -like 'DATABASE_URL=*' } | Select-Object -First 1); if($line -match ':(\d+)/'){ $matches[1] } }"') do set "DB_PORT=%%P"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=Get-Service -Name 'postgres*' -ErrorAction SilentlyContinue; if($s){'FOUND'} else {'MISSING'}" | findstr /I "MISSING" >nul
if not errorlevel 1 (
  echo [ASRE Services] PostgreSQL not found.
  echo [ASRE Services] STEP 1/3 Installing PostgreSQL...
  echo [ASRE Services] WAITING: PostgreSQL installer may open a setup wizard. Complete it, then return here.
  call :install_pkg "PostgreSQL.PostgreSQL.17" "postgresql" "PostgreSQL"
  if errorlevel 1 exit /b 1
  echo [ASRE Services] DONE: PostgreSQL installation step finished.
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=(Get-Service -Name 'redis*' -ErrorAction SilentlyContinue) + (Get-Service -Name 'memurai*' -ErrorAction SilentlyContinue); if($s){'FOUND'} else {'MISSING'}" | findstr /I "MISSING" >nul
if not errorlevel 1 (
  echo [ASRE Services] Redis not found.
  echo [ASRE Services] STEP 2/3 Installing Redis...
  echo [ASRE Services] WAITING: Redis installer may request admin approval. Complete it, then return here.
  call :install_pkg "Redis.Redis" "redis-64" "Redis"
  if errorlevel 1 (
    echo [ASRE Services] Redis installer not available or failed.
    echo [ASRE Services] WAITING: Trying Memurai Developer as Redis-compatible fallback...
    call :install_pkg "Memurai.MemuraiDeveloper" "memurai-developer" "Memurai Developer"
    if errorlevel 1 exit /b 1
  )
  echo [ASRE Services] DONE: Redis installation step finished.
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "$svc=Get-Service -Name 'neo4j*' -ErrorAction SilentlyContinue; $paths=@((Join-Path $env:ProgramFiles 'Neo4j Desktop\Neo4j Desktop.exe'),(Join-Path $env:LocalAppData 'Programs\Neo4j Desktop\Neo4j Desktop.exe'),(Join-Path $env:ProgramFiles 'Neo4j\Neo4j Desktop\Neo4j Desktop.exe')); $exe=$paths | Where-Object { Test-Path $_ } | Select-Object -First 1; if($svc -or $exe){'FOUND'} else {'MISSING'}" | findstr /I "MISSING" >nul
if not errorlevel 1 (
  echo [ASRE Services] Neo4j not found.
  echo [ASRE Services] STEP 3/3 Installing Neo4j Desktop...
  echo [ASRE Services] WAITING: Neo4j Desktop installer may open a setup wizard. Complete it, then return here.
  call :install_pkg "Neo4j.Neo4jDesktop" "neo4j-desktop" "Neo4j Desktop"
  if errorlevel 1 (
    echo [ASRE Services] WARNING: Neo4j Desktop install did not complete successfully.
    echo [ASRE Services] You can install it manually and run services.bat again.
  ) else (
    echo [ASRE Services] DONE: Neo4j Desktop installation step finished.
  )
)

echo [ASRE Services] Starting PostgreSQL services...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$services=Get-Service -Name 'postgres*' -ErrorAction SilentlyContinue; if($services){ foreach($s in $services){ if($s.Status -ne 'Running'){ Start-Service -Name $s.Name } }; 'POSTGRES:OK' } else { 'POSTGRES:NOT_INSTALLED' }"

echo [ASRE Services] Starting Redis services...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$services=@(Get-Service -Name 'redis*' -ErrorAction SilentlyContinue) + @(Get-Service -Name 'memurai*' -ErrorAction SilentlyContinue); if($services.Count -gt 0){ foreach($s in $services){ if($s.Status -ne 'Running'){ Start-Service -Name $s.Name } }; 'REDIS:OK' } else { 'REDIS:NOT_INSTALLED' }"

echo [ASRE Services] Starting Neo4j...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$services=Get-Service -Name 'neo4j*' -ErrorAction SilentlyContinue; if($services){ foreach($s in $services){ if($s.Status -ne 'Running'){ Start-Service -Name $s.Name } }; 'NEO4J_SERVICE:OK' } else { $paths=@((Join-Path $env:ProgramFiles 'Neo4j Desktop\Neo4j Desktop.exe'),(Join-Path $env:LocalAppData 'Programs\Neo4j Desktop\Neo4j Desktop.exe'),(Join-Path $env:ProgramFiles 'Neo4j\Neo4j Desktop\Neo4j Desktop.exe')); $exe=$paths | Where-Object { Test-Path $_ } | Select-Object -First 1; if($exe){ Start-Process -FilePath $exe; 'NEO4J_DESKTOP:LAUNCHED' } else { 'NEO4J:NOT_INSTALLED' } }"
echo [ASRE Services] NOTE: If Neo4j Desktop launched, start your local DBMS manually and keep Bolt on port 7687.

echo [ASRE Services] Verifying required ports: %DB_PORT%, 6379, 7687...
set /a WAIT_COUNT=0
:wait_ports
powershell -NoProfile -ExecutionPolicy Bypass -Command "$db=%DB_PORT%; $checks=@(@{Name='PostgreSQL';Port=$db},@{Name='Redis';Port=6379},@{Name='Neo4j';Port=7687}); $missing=@(); foreach($c in $checks){ if(-not (Get-NetTCPConnection -State Listen -LocalPort $c.Port -ErrorAction SilentlyContinue)){ $missing += ($c.Name + ':' + $c.Port) } }; if($missing.Count -gt 0){ Write-Output ('MISSING:' + ($missing -join ', ')); exit 1 } else { Write-Output 'OK'; exit 0 }"
if not errorlevel 1 goto :ports_ok

set /a WAIT_COUNT+=1
if !WAIT_COUNT! GEQ 60 (
  echo [ASRE Services] Some ports are still missing.
  echo [ASRE Services] If Neo4j Desktop opened, create/start a local DB and ensure Bolt port is 7687.
  echo [ASRE Services] If PostgreSQL is installed, confirm the Windows service is running and listening on %DB_PORT%.
  echo [ASRE Services] If Redis was just installed, restart terminal once and run services.bat again.
  echo [ASRE Services] Then run services.bat again.
  exit /b 1
)
timeout /t 2 /nobreak >nul
goto :wait_ports

:ports_ok

echo [ASRE Services] All required services are listening.
echo [ASRE Services] PostgreSQL:%DB_PORT% Redis:6379 Neo4j:7687
exit /b 0

:install_pkg
setlocal
set "WG_ID=%~1"
set "CHOCO_ID=%~2"
set "INSTALL_LABEL=%~3"

where winget >nul 2>nul
if not errorlevel 1 (
  echo [ASRE Services] Installing %INSTALL_LABEL% via winget...
  winget install -e --id %WG_ID% --accept-package-agreements --accept-source-agreements
  if not errorlevel 1 (
    call :validate_install "%INSTALL_LABEL%"
    if not errorlevel 1 (
      endlocal & exit /b 0
    )
    echo [ASRE Services] %INSTALL_LABEL% install command finished but validation failed.
  )
)

where choco >nul 2>nul
if not errorlevel 1 (
  echo [ASRE Services] Installing %INSTALL_LABEL% via choco...
  choco install -y %CHOCO_ID%
  if not errorlevel 1 (
    call :validate_install "%INSTALL_LABEL%"
    if not errorlevel 1 (
      endlocal & exit /b 0
    )
    echo [ASRE Services] %INSTALL_LABEL% install command finished but validation failed.
  )
)

echo [ASRE Services] Failed to install package: %INSTALL_LABEL% (%WG_ID%)
endlocal & exit /b 1

:validate_install
setlocal
set "VALIDATE_LABEL=%~1"
if /I "%VALIDATE_LABEL%"=="PostgreSQL" (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=Get-Service -Name 'postgres*' -ErrorAction SilentlyContinue; if($s){exit 0}else{exit 1}"
  set "RC=%errorlevel%"
  endlocal & exit /b %RC%
)

if /I "%VALIDATE_LABEL%"=="Redis" (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=@(Get-Service -Name 'redis*' -ErrorAction SilentlyContinue) + @(Get-Service -Name 'memurai*' -ErrorAction SilentlyContinue); if($s.Count -gt 0){exit 0}else{exit 1}"
  set "RC=%errorlevel%"
  endlocal & exit /b %RC%
)

if /I "%VALIDATE_LABEL%"=="Memurai Developer" (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=@(Get-Service -Name 'memurai*' -ErrorAction SilentlyContinue); if($s.Count -gt 0){exit 0}else{exit 1}"
  set "RC=%errorlevel%"
  endlocal & exit /b %RC%
)

if /I "%VALIDATE_LABEL%"=="Neo4j Desktop" (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$svc=Get-Service -Name 'neo4j*' -ErrorAction SilentlyContinue; $paths=@((Join-Path $env:ProgramFiles 'Neo4j Desktop\Neo4j Desktop.exe'),(Join-Path $env:LocalAppData 'Programs\Neo4j Desktop\Neo4j Desktop.exe'),(Join-Path $env:ProgramFiles 'Neo4j\Neo4j Desktop\Neo4j Desktop.exe')); $exe=$paths | Where-Object { Test-Path $_ } | Select-Object -First 1; if($svc -or $exe){exit 0}else{exit 1}"
  set "RC=%errorlevel%"
  endlocal & exit /b %RC%
)

endlocal & exit /b 1
