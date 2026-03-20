# ASRE Local Database Setup (Simple Step-by-Step)

This is a beginner-friendly guide for your local Windows PC.

You will set up:
1. PostgreSQL
2. Redis
3. Neo4j

Do them one at a time in this exact order.

---

## Before You Start

- Open **PowerShell as Administrator** for install/start commands.
- Your project folder is:

`C:\Users\pewpew\OneDrive\Desktop\Work[Important]\ASRE-Automated-security-reasoning-engine-`

Note: because your path contains `[ ]`, use `-LiteralPath` when needed.

---

## Step 1: PostgreSQL (First)

### 1.1 Install PostgreSQL

```powershell
winget install -e --id PostgreSQL.PostgreSQL
```

### 1.2 Start PostgreSQL service

List PostgreSQL services:

```powershell
Get-Service | Where-Object { $_.Name -match 'postgres' -or $_.DisplayName -match 'PostgreSQL' }
```

Start the service (replace with your real service name):

```powershell
Start-Service -Name postgresql-x64-17
```

If your service name is different, use that name.

### 1.3 Create project user and database

Open psql as admin user (`postgres`). Your machine uses port `5000`:

```powershell
psql -h localhost -p 5000 -U postgres -d postgres
```

Now run these SQL commands inside psql:

```sql
CREATE ROLE asre WITH LOGIN PASSWORD 'asre123';
CREATE DATABASE asre OWNER asre;
GRANT ALL PRIVILEGES ON DATABASE asre TO asre;
```

Exit psql:

```sql
\q
```

If the role already exists, run this instead:

```sql
ALTER ROLE asre WITH PASSWORD 'asre123';
```

### 1.4 Test PostgreSQL login

```powershell
psql -h localhost -p 5000 -U asre -d asre
```

If login works, PostgreSQL is ready.

---

## Step 2: Redis (Second)

### 2.1 Install Redis (Memurai Developer on Windows)

```powershell
winget install -e --id Memurai.MemuraiDeveloper
```

### 2.2 Start Redis/Memurai service

List service:

```powershell
Get-Service | Where-Object { $_.Name -match 'memurai|redis' -or $_.DisplayName -match 'Memurai|Redis' }
```

Start it (replace with your real service name):

```powershell
Start-Service -Name Memurai
```

### 2.3 Test Redis

```powershell
redis-cli -p 6379 PING
```

Expected output:

```text
PONG
```

If you get `PONG`, Redis is ready.

---

## Step 3: Neo4j (Third)

### 3.1 Install Neo4j Desktop

```powershell
winget install -e --id Neo4j.Neo4jDesktop
```

### 3.2 Open Neo4j Desktop and start DBMS

1. Open Neo4j Desktop.
2. Create a DBMS (or use existing one).
3. Set username/password (example: `neo4j` / `neo4j12345`).
4. Click **Start** on DBMS.

Important: Neo4j Desktop being installed is not enough. The DBMS must be started in the app.

### 3.3 Test Neo4j

Open browser:

- `http://localhost:7474`

Login with your Neo4j credentials.

Run this query:

```cypher
RETURN 1 AS ok;
```

If it returns `ok = 1`, Neo4j is ready.

---

## Step 4: Update .env for This Project

Open `.env` in project root and set these values:

```env
DATABASE_URL=postgresql+asyncpg://asre:asre123@localhost:5000/asre
POSTGRES_DB=asre
POSTGRES_USER=asre
POSTGRES_PASSWORD=asre123

REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/1

NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=neo4j12345
NEO4J_DATABASE=neo4j
```

If your password is different, change it here to match what you actually set.

---

## Step 5: Quick Port Check (Optional)

```powershell
netstat -ano | findstr LISTENING | findstr :5000
netstat -ano | findstr LISTENING | findstr :6379
netstat -ano | findstr LISTENING | findstr :7687
```

If each command prints a line, the service is listening.

---

## Step 6: Run the Project

In project folder:

```powershell
Set-Location -LiteralPath "C:\Users\pewpew\OneDrive\Desktop\Work[Important]\ASRE-Automated-security-reasoning-engine-"
.\services.bat
.\setup.bat
.\start.bat
```

---

## If Setup Fails on Database Password

If you see `InvalidPasswordError`, fix PostgreSQL password mismatch:

1. Login as postgres admin:

```powershell
psql -h localhost -p 5000 -U postgres -d postgres
```

2. Reset password:

```sql
ALTER ROLE asre WITH PASSWORD 'asre123';
\q
```

3. Make sure `.env` has the same password in `DATABASE_URL`.

That is it.