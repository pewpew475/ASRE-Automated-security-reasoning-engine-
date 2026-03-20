```text
 █████╗ ███████╗██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝
███████║███████╗██████╔╝█████╗
██╔══██║╚════██║██╔══██╗██╔══╝
██║  ██║███████║██║  ██║███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝

Automated Security Reasoning Engine v2.0
```

<p align="center"><strong>Scan. Chain. Reason. Report. All local.</strong></p>

<p align="center">
<img src="https://img.shields.io/badge/License-MIT-0a0a0a?style=for-the-badge" alt="MIT"> <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"> <img src="https://img.shields.io/badge/Node-20%20LTS-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="Node"> <img src="https://img.shields.io/badge/Docker-required-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"> <img src="https://img.shields.io/badge/Stars-1k%2B-gold?style=for-the-badge" alt="Stars"> <img src="https://img.shields.io/badge/PRs-welcome-brightgreen?style=for-the-badge" alt="PRs Welcome"> <img src="https://img.shields.io/badge/Made%20with-%E2%9D%A4%EF%B8%8F%20and%20caffeine-D00000?style=for-the-badge" alt="Made with love and caffeine">
</p>

ASRE is a self-hosted web application security scanner designed for local-first teams that need speed, control, and explainability.

It goes beyond vulnerability lists by chaining findings into realistic exploit paths and business impact narratives.

It is built for engineers, AppSec teams, and red/blue operators who want practical outputs they can ship fixes from.

---

## 📚 Table of Contents

- [🚀 Demo / Preview](#-demo--preview)
- [✨ Features](#-features)
- [🏗️ Architecture](#️-architecture)
- [⚡ Quick Start](#-quick-start)
- [🧩 Environment Configuration](#-environment-configuration)
- [🧪 Scan Modes](#-scan-modes)
- [🤖 LLM Providers Table](#-llm-providers-table)
- [🔄 Scan Pipeline Deep Dive](#-scan-pipeline-deep-dive)
- [🤝 Contributing](#-contributing)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🛡️ Security & Ethics](#️-security--ethics)
- [🧱 Tech Stack Badges](#-tech-stack-badges)
- [📄 License & Footer](#-license--footer)
- [📌 Appendix A: API Surface Snapshot](#-appendix-a-api-surface-snapshot)
- [📌 Appendix B: Vulnerability Matrix](#-appendix-b-vulnerability-matrix)
- [📌 Appendix C: Hardcore Checks Matrix](#-appendix-c-hardcore-checks-matrix)
- [📌 Appendix D: Local Ops Cheat Sheet](#-appendix-d-local-ops-cheat-sheet)

---

## 🚀 Demo / Preview

![ASRE Demo](./docs/assets/demo.gif)

See /docs/assets/ for screenshots of the dashboard, attack graph, and PDF report.

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ terminal@asre:~$ asre scan --target https://target.local --profile std  │
├──────────────────────────────────────────────────────────────────────────┤
│ 🕷️  Phase 1/6 Crawl      → 412 pages discovered                          │
│ 🔍  Phase 2/6 Scan       → XSS, IDOR, CSRF, SQLi, JWT flaw detected      │
│ ⚡  Hardcore Gate         → skipped (normal mode)                         │
│ 🕸️  Phase 3/6 Chain      → 7 exploit chains generated                     │
│ 🤖  Phase 4/6 Analyze    → LLM impact enriched for 33 findings            │
│ 🧪  Phase 5/6 PoC         → 33 reproducible snippets generated             │
│ 📄  Phase 6/6 Report      → ./data/reports/9f5b2a8e.pdf                   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

### 🔍 Detection

| Capability | What you get |
|---|---|
| 🔎 XSS detection | Reflected, stored, and DOM-based checks with context-aware payload sets. |
| 🧾 IDOR checks | Object reference fuzzing across route params, body fields, and hidden identifiers. |
| 🛡️ CSRF analysis | Token enforcement checks and unsafe method validation. |
| 💉 SQL injection probes | Error-based and behavior-based probes with safe confidence scoring. |
| 🌐 CORS misconfig scan | Wildcard origins, credential leakage, and policy edge-case detection. |
| 🔐 Broken authentication | Session controls, weak login paths, and auth boundary regressions. |
| 🪪 JWT flaws | Weak algorithms, claim misuse, expiration handling, signature bypass vectors. |
| 🧱 Missing security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. |
| 🚦 Rate-limit absence | Endpoint pressure checks for brute-force and resource abuse risks. |
| 🧠 Business logic abuse | Multi-step workflow tampering and state transition inconsistencies. |
| 👤 User enumeration | Differential response and timing checks in auth and recovery flows. |
| 🧬 CVE fingerprinting | Service/stack detection mapped to known high-signal exposure templates. |

### 🕸️ Graph Engine

| Capability | What you get |
|---|---|
| 🔗 Multi-hop chain builder | Entry → Vulnerability → Asset → Business Impact graph model in Neo4j. |
| 🧭 Path scoring | Chain severity weighted by exploitability, privilege gain, and blast radius. |
| 🧠 Relationship semantics | CHAINS_WITH, IMPACTS, ENABLES, and DEPENDS_ON link types for reasoning. |
| 🖼️ Interactive visualization | React Flow graph rendering with grouping, expansion, and filtering. |
| 📦 Graph export | JSON export for integrations, demos, and pipeline analytics. |
| 🪪 Ownership-safe queries | Scan ownership checks enforced at API boundary before graph access. |

### 🤖 AI Analysis

| Capability | What you get |
|---|---|
| 🌍 Universal LLM provider support | Switch provider in .env with no code changes. |
| 🧾 Developer-first narratives | Per-finding impact analysis tailored for implementation teams. |
| 🧭 OWASP + MITRE mapping | Standardized taxonomy alignment for reporting and governance. |
| 🔧 Practical fixes | Step-by-step remediation paths with implementation hints. |
| 🧑‍💼 Executive summary | High-level risk summary and suggested priorities for stakeholders. |
| 🧪 Model-agnostic contract | Same interface for OpenAI, Claude, Groq, DeepSeek, local Ollama, and more. |

### ⚡ Hardcore Mode

| Capability | What you get |
|---|---|
| 📡 SQLMap integration | Active SQLi exploitation checks via SQLMap REST API. |
| 🧨 Nuclei integration | 9000+ template CVE exposure validation under controlled scope. |
| 📈 Rate burst checks | Abuse simulation against login, reset, and API endpoints. |
| 🧪 User enumeration stress tests | Differential response/timing checks under pressure. |
| 🔐 JWT/session stress workflows | Token and session lifecycle abuse scenarios. |
| 🧷 Immutable audit trail | Consent + scope + action chain recorded and tamper resistant. |

> **Why ASRE?**
>
> Most scanners dump findings. ASRE explains attack paths, generates proof, and gives your team fixes they can execute now.

---

## 🏗️ Architecture

```text
	┌──────────────────────────────────────────────────────────────┐
	│                        ASRE v2.0                             │
	│                                                              │
	│   ┌─────────────────────────────────────────────────────┐   │
	│   │           React Frontend  :3000                     │   │
	│   │   Dashboard · Scan · Graph · Findings · Report      │   │
	│   └──────────────┬──────────────────┬───────────────────┘   │
	│                  │ REST API          │ WebSocket             │
	│   ┌──────────────▼──────────────────▼───────────────────┐   │
	│   │           FastAPI Backend  :8000                     │   │
	│   │   Auth · Scans · Graph · Reports · Consent · LLM    │   │
	│   └──────┬────────────┬───────────────┬─────────────────┘   │
	│          │            │               │                      │
	│   ┌──────▼──┐  ┌──────▼──┐  ┌────────▼────────┐           │
	│   │Postgres │  │  Neo4j  │  │     Redis        │           │
	│   │:5432    │  │  :7687  │  │     :6379        │           │
	│   │7 tables │  │  graph  │  │  task queue      │           │
	│   └─────────┘  └─────────┘  └────────┬─────────┘           │
	│                                       │                      │
	│                              ┌────────▼─────────┐           │
	│                              │   Celery Worker  │           │
	│                              │  6-phase pipeline│           │
	│                              └──────────────────┘           │
	│                                                              │
	│   Optional (--profile hardcore):                            │
	│   ┌─────────────┐   ┌─────────────────────────────────┐    │
	│   │ SQLMap :8775│   │ Nuclei (subprocess in container)│    │
	│   └─────────────┘   └─────────────────────────────────┘    │
	└──────────────────────────────────────────────────────────────┘
```

### Data Flow

1. User starts scan → FastAPI → Celery task queued.
2. Phase 1-6 pipeline runs → WebSocket streams progress.
3. Findings → PostgreSQL, graph nodes → Neo4j.
4. LLM called per finding → analysis stored in DB.
5. PDF generated → ./data/reports/{scan_id}.pdf.
6. React Flow renders attack graph from Neo4j query.

---

## ⚡ Quick Start

### Tab 1: Docker (Normal Mode)

```bash
git clone https://github.com/your-org/asre.git
cd asre
cp .env.example .env
docker compose up -d
docker compose logs -f
```

Expected output:
You should see healthy services for backend, frontend, postgres, redis, and neo4j. Open http://localhost:3000 and start your first scan.

### Tab 2: Docker (Hardcore Mode)

```bash
docker compose --profile hardcore up -d
```

Expected output:
You should see SQLMap service available and Nuclei-ready backend container behavior. Consent endpoints will enforce DNS verification before run.

### Tab 3: Dev Mode (manual, no Docker)

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r Backend/requirements.txt
cd frontend && npm install && cd ..
```

```bash
cd Backend
alembic upgrade head
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

```bash
cd frontend
npm run dev -- --host 0.0.0.0 --port 3000
```

Expected output:
API docs load at http://localhost:8000/docs, frontend loads at http://localhost:3000, and scan creation works from dashboard.

---

## 🧩 Environment Configuration

ASRE has 3 required values and everything else is optional. Seriously, that's it.

### Required

```env
# Used for JWT signing and auth integrity
SECRET_KEY=YOUR_SECRET_KEY

# PostgreSQL DB password used by API + migrations
POSTGRES_PASSWORD=YOUR_POSTGRES_PASSWORD

# Neo4j graph auth secret
NEO4J_PASSWORD=YOUR_NEO4J_PASSWORD
```

### LLM Providers (copy-paste one block)

```env
# =============================================
# LLM CONFIGURATION
# Pick ONE provider. Copy the block you want.
# =============================================

# - Option 1: OpenAI (default) -
LLM_PROVIDER=openai
LLM_API_KEY=sk-YOUR_OPENAI_KEY
LLM_MODEL=gpt-4o
LLM_BASE_URL=

# - Option 2: Anthropic Claude -
# LLM_PROVIDER=anthropic
# LLM_API_KEY=sk-ant-YOUR_ANTHROPIC_KEY
# LLM_MODEL=claude-3-5-sonnet-20241022
# LLM_BASE_URL=

# - Option 3: DeepSeek -
# LLM_PROVIDER=deepseek
# LLM_API_KEY=sk-YOUR_DEEPSEEK_KEY
# LLM_MODEL=deepseek-reasoner
# LLM_BASE_URL=

# - Option 4: Groq (fast + free tier) -
# LLM_PROVIDER=groq
# LLM_API_KEY=gsk_YOUR_GROQ_KEY
# LLM_MODEL=llama-3.3-70b-versatile
# LLM_BASE_URL=

# - Option 5: Ollama (fully local/offline) -
# LLM_PROVIDER=ollama
# LLM_API_KEY=
# LLM_MODEL=llama3.2
# LLM_BASE_URL=http://localhost:11434/v1

# - Option 6: Mistral AI -
# LLM_PROVIDER=mistral
# LLM_API_KEY=YOUR_MISTRAL_KEY
# LLM_MODEL=mistral-large-latest
# LLM_BASE_URL=

# - Option 7: OpenRouter (200+ models) -
# LLM_PROVIDER=openrouter
# LLM_API_KEY=sk-or-YOUR_OPENROUTER_KEY
# LLM_MODEL=anthropic/claude-3.5-sonnet
# LLM_BASE_URL=https://openrouter.ai/api/v1

# - Option 8: Together AI -
# LLM_PROVIDER=together
# LLM_API_KEY=YOUR_TOGETHER_KEY
# LLM_MODEL=meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo
# LLM_BASE_URL=

# - Option 9: Cohere -
# LLM_PROVIDER=cohere
# LLM_API_KEY=YOUR_COHERE_KEY
# LLM_MODEL=command-r-plus
# LLM_BASE_URL=

# - Option 10: Custom / vLLM / LM Studio -
# LLM_PROVIDER=custom
# LLM_API_KEY=not-required
# LLM_MODEL=your-model-name
# LLM_BASE_URL=http://your-server:8080/v1

# Tuning
LLM_TEMPERATURE=0.2
LLM_MAX_TOKENS=4096
LLM_REQUEST_TIMEOUT=120
```

### Optional Advanced

```env
MAX_CRAWL_DEPTH=5
MAX_CRAWL_PAGES=500
MAX_CONCURRENT_REQUESTS=10
REQUEST_TIMEOUT_SECONDS=30
SCAN_RATE_LIMIT_PER_SEC=10
HARDCORE_MAX_RATE_PER_SEC=50
```

Security note: Never commit .env — it's in .gitignore.

---

## 🧪 Scan Modes

| Dimension | Normal Mode | Hardcore Mode |
|---|---|---|
| Speed | Fast baseline security coverage | Slower, deeper active validation |
| Modules | Crawl + Probe + Chain + AI + PoC + Report | Normal mode + SQLMap + Nuclei + stress checks |
| Consent required | No | Yes |
| Domain ownership verification | No | DNS TXT required |
| Scope lock | No | Yes, immutable for run window |
| Audit trail | Standard logs | Immutable audit_logs recording |
| Recommended use | CI, pre-release, routine sweeps | Authorized deep testing windows |

Hardcore Mode consent flow:

```text
Step 1 ──→ Step 2 ──→ Step 3
Agree TC   DNS Verify  Lock Scope → 🔓 Scan Ready
```

> ⚠️ Hardcore Mode is for authorized targets only.
>
> DNS verification is cryptographic — it cannot be bypassed.

---

## 🤖 LLM Providers Table

| Provider | Key Required | Model Example | Status | Notes |
|---|---|---|---|---|
| OpenAI | Yes | gpt-4o | ✅ Stable | Best general default for strong technical explanation quality. |
| Anthropic | Yes | claude-3-5-sonnet-20241022 | ✅ Stable | Great for long-form remediation detail. |
| DeepSeek | Yes | deepseek-reasoner | ✅ Stable | Strong reasoning profile for chain narrative quality. |
| Groq | Yes | llama-3.3-70b-versatile | ✅ Stable | Great latency characteristics for high-volume findings. |
| Ollama | No | llama3.2, mistral | ✅ Stable | Full offline local analysis path. |
| Mistral AI | Yes | mistral-large-latest | ✅ Stable | Balanced precision/speed profile. |
| OpenRouter | Yes | anthropic/claude-3.5-sonnet | ✅ Stable | Broad model marketplace from one API endpoint. |
| Together AI | Yes | meta-llama/Meta-Llama-3.1-405B | ✅ Stable | Wide open model coverage for experimentation. |
| Cohere | Yes | command-r-plus | ✅ Stable | Solid enterprise-style summarization performance. |
| Custom/vLLM | Optional | any OpenAI-compatible endpoint | ✅ Stable | Bring your own endpoint with OpenAI-compatible payloads. |

No LLM? No problem. Findings, graphs, and PoCs are generated regardless. LLM only enriches the analysis.

> **Adding a new provider**
>
> 1. Add entry to core/llm_registry.py PROVIDER_REGISTRY.
> 2. Add package to requirements.txt.
> 3. Add example to .env.example.
>
> That's it. Zero other changes.

---

## 🔄 Scan Pipeline Deep Dive

| Phase | Module | Description |
|---|---|---|
| 🕷️ Phase 1 — Crawl | crawler.py | Async Playwright spider discovers routes, forms, and auth-gated surfaces. |
| 🔍 Phase 2 — Scan | rule_engine.py | 12 probe modules evaluate known web app vulnerability patterns in parallel. |
| 🕸️ Phase 3 — Chain | chain_builder.py | Neo4j attack graph links findings into realistic exploit and impact paths. |
| 🤖 Phase 4 — Analyze | llm_analyzer.py | Per-finding impact explanation, remediation plan, OWASP and MITRE mapping. |
| 🧪 Phase 5 — PoC | poc_generator.py | Generates curl and JavaScript fetch snippets for reproducibility. |
| 📄 Phase 6 — Report | report_engine.py | WeasyPrint + Jinja2 executive report generation to PDF artifact. |

### Attack Chain Logic

| Precondition A | Precondition B | Chain Outcome |
|---|---|---|
| XSS | Weak session controls | Account takeover |
| IDOR | Missing auth check | Privilege escalation |
| SQLi | Exposed admin auth path | Full compromise |
| CSRF | Sensitive state change endpoint | Unauthorized transaction execution |
| User enumeration | No rate limiting | Credential stuffing acceleration |
| JWT alg flaw | Insecure token validation | Identity forgery |
| CORS wildcard + credentials | Sensitive API cookies | Cross-origin data exfiltration |
| Missing CSP | Reflected XSS vector | Browser execution path expansion |
| Broken auth reset flow | User enumeration | Account reset abuse |
| CVE fingerprinted component | Known exploit chain | Rapid remote exploitation window |

---

## 🤝 Contributing

Contributions are welcome. If you can break it, harden it, explain it better, or make it faster, your PR belongs here.

### Where to contribute

| Area | File to edit | Difficulty |
|---|---|---|
| New probe/vuln | scanner/probes/ | ⭐ Easy |
| New LLM provider | core/llm_registry.py | ⭐ Easy |
| New PoC template | scanner/poc_generator | ⭐⭐ Medium |
| New Nuclei tags | hardcore/nuclei_runner | ⭐⭐ Medium |
| New chain rules | scanner/chain_builder | ⭐⭐⭐ Hard |
| New attack graph UI | frontend/graph/ | ⭐⭐⭐ Hard |

### Local dev setup

```bash
python -m venv .venv
pip install -r Backend/requirements.txt
cd frontend && npm install
```

### PR checklist

- [ ] New behavior has tests or a reproducible validation script.
- [ ] No secrets or credentials are committed.
- [ ] API and schema changes include migration notes.
- [ ] Documentation updated for any user-visible changes.
- [ ] Linting and type checks pass locally.

---

## 🛠️ Troubleshooting

<details>
<summary>🔴 Neo4j won't connect</summary>

**Symptom**: Graph endpoints return empty results or connection errors.

**Cause**: Bad `NEO4J_URI`/credentials or container not healthy yet.

**Fix command**:

```bash
docker compose logs neo4j --tail=200
```

```bash
docker compose restart neo4j
```

</details>

<details>
<summary>🔴 PostgreSQL migrations fail</summary>

**Symptom**: `alembic upgrade head` errors with auth or connection refusal.

**Cause**: Wrong `POSTGRES_PASSWORD` or DB service still booting.

**Fix command**:

```bash
docker compose logs postgres --tail=200
```

```bash
cd Backend && alembic upgrade head
```

</details>

<details>
<summary>🔴 Redis/Celery tasks stuck in PENDING</summary>

**Symptom**: Scans never move beyond queued state.

**Cause**: Worker not running or broker URL mismatch.

**Fix command**:

```bash
cd Backend && celery -A tasks.celery_app.celery_app worker --loglevel=info
```

```bash
docker compose logs redis --tail=100
```

</details>

<details>
<summary>🔴 Frontend loads but API calls fail (CORS)</summary>

**Symptom**: Browser console shows blocked cross-origin requests.

**Cause**: `ALLOWED_ORIGINS` missing current dev host/port.

**Fix command**:

```bash
grep ALLOWED_ORIGINS .env
```

```bash
docker compose restart backend
```

</details>

<details>
<summary>🔴 Hardcore mode blocked by consent checks</summary>

**Symptom**: Hardcore run refused with verification/scope lock errors.

**Cause**: DNS TXT verification not completed or scope expired.

**Fix command**:

```bash
curl -X POST http://localhost:8000/api/consent/verify-domain -H "Content-Type: application/json" -d "{\"consent_id\":\"YOUR_CONSENT_ID\",\"domain\":\"example.com\"}"
```

```bash
curl -X POST http://localhost:8000/api/consent/lock-scope -H "Content-Type: application/json" -d "{\"consent_id\":\"YOUR_CONSENT_ID\"}"
```

</details>

<details>
<summary>🔴 LLM configured but analysis is empty</summary>

**Symptom**: Findings exist, but impact/fix text is blank.

**Cause**: Invalid API key, wrong provider string, or incompatible model.

**Fix command**:

```bash
grep -E "LLM_PROVIDER|LLM_MODEL|LLM_BASE_URL" .env
```

```bash
docker compose restart backend worker
```

</details>

---

## 🛡️ Security & Ethics

**ASRE is a weapon. Use it responsibly.**

ASRE is built for authorized testing and defensive engineering. If you do not have permission, do not scan.

What ASRE will do:

- Detect and chain exploitable web application weakness patterns.
- Generate reproducible PoCs to support remediation and validation.
- Produce explainable technical and executive reporting outputs.
- Enforce explicit consent gates in Hardcore Mode.

What ASRE will not do:

- Bypass legal consent requirements.
- Remove DNS ownership checks in Hardcore Mode.
- Hide activity in authorized deep-testing workflows.
- Transmit your project data to third-party telemetry by default.

Hardcore Mode writes immutable audit records for consent lifecycle and active actions.

Responsible disclosure template: ./SECURITY.md#responsible-disclosure-template

---

## 🧱 Tech Stack Badges

<p>
<img src="https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI"> <img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL"> <img src="https://img.shields.io/badge/Neo4j-4581C3?style=flat-square&logo=neo4j&logoColor=white" alt="Neo4j"> <img src="https://img.shields.io/badge/Redis-DC382D?style=flat-square&logo=redis&logoColor=white" alt="Redis"> <img src="https://img.shields.io/badge/Celery-37814A?style=flat-square&logo=celery&logoColor=white" alt="Celery">
</p>

<p>
<img src="https://img.shields.io/badge/React-20232A?style=flat-square&logo=react&logoColor=61DAFB" alt="React"> <img src="https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript"> <img src="https://img.shields.io/badge/Vite-646CFF?style=flat-square&logo=vite&logoColor=white" alt="Vite"> <img src="https://img.shields.io/badge/Tailwind-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white" alt="Tailwind"> <img src="https://img.shields.io/badge/React%20Flow-111827?style=flat-square" alt="React Flow">
</p>

<p>
<img src="https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker"> <img src="https://img.shields.io/badge/Nginx-009639?style=flat-square&logo=nginx&logoColor=white" alt="Nginx"> <img src="https://img.shields.io/badge/LangChain-00A67E?style=flat-square" alt="LangChain"> <img src="https://img.shields.io/badge/WeasyPrint-2A2A2A?style=flat-square" alt="WeasyPrint">
</p>

---

## 📄 License & Footer

This project is licensed under the MIT License.

⭐ If ASRE saved you time, star the repo — it helps more developers find it.

---

Built by [your-org] · 2026

---

## 📌 Appendix A: API Surface Snapshot

| Router | Method | Path | Purpose |
|---|---|---|---|
| auth | POST | /api/auth/register | Create user account |
| auth | POST | /api/auth/login | Issue access and refresh tokens |
| auth | POST | /api/auth/refresh | Rotate access token |
| scans | POST | /api/scans | Create scan and enqueue pipeline |
| scans | GET | /api/scans | List user scans |
| scans | GET | /api/scans/{scan_id} | Get scan details |
| scans | DELETE | /api/scans/{scan_id} | Delete scan and related artifacts |
| graph | GET | /api/scans/{scan_id}/graph | Attack graph nodes and edges |
| graph | GET | /api/scans/{scan_id}/graph/chains | Highest impact chain candidates |
| graph | GET | /api/scans/{scan_id}/graph/export | Export graph as JSON |
| reports | GET | /api/reports/{scan_id} | Report metadata |
| reports | GET | /api/reports/{scan_id}/download | Binary PDF download |
| reports | POST | /api/reports/{scan_id}/regenerate | Requeue report generation |
| reports | DELETE | /api/reports/{scan_id} | Remove report artifact |
| consent | POST | /api/consent/init | Start hardcore consent workflow |
| consent | POST | /api/consent/verify-domain | Verify DNS TXT ownership |
| consent | POST | /api/consent/lock-scope | Immutable target lock |
| consent | GET | /api/consent/{consent_id} | Get consent status |
| consent | GET | /api/consent/active | List active consents |
| health | GET | /api/health | Service health check |
| ws | WS | /ws/scans/{scan_id} | Live phase/finding event stream |

### API Example: Create a normal scan

```bash
curl -X POST http://localhost:8000/api/scans \
	-H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
	-H "Content-Type: application/json" \
	-d '{
		"target_url": "https://target.local",
		"mode": "normal",
		"max_depth": 5,
		"max_pages": 500
	}'
```

### API Example: Create a hardcore scan

```bash
curl -X POST http://localhost:8000/api/scans \
	-H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
	-H "Content-Type: application/json" \
	-d '{
		"target_url": "https://target.local",
		"mode": "hardcore",
		"consent_id": "YOUR_CONSENT_ID"
	}'
```

### API Example: Read attack graph

```bash
curl -X GET http://localhost:8000/api/scans/YOUR_SCAN_ID/graph \
	-H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### API Example: Download report

```bash
curl -L -X GET http://localhost:8000/api/reports/YOUR_SCAN_ID/download \
	-H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
	-o report.pdf
```

### API Example: Verify domain ownership

```bash
curl -X POST http://localhost:8000/api/consent/verify-domain \
	-H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
	-H "Content-Type: application/json" \
	-d '{
		"consent_id": "YOUR_CONSENT_ID",
		"domain": "example.com"
	}'
```

---

## 📌 Appendix B: Vulnerability Matrix

| Vulnerability | Probe Signal | Confidence Strategy | Chain Link Potential | PoC Output |
|---|---|---|---|---|
| Reflected XSS | payload reflection + execution context | multi-payload verify | session hijack, account takeover | curl + fetch |
| Stored XSS | persisted payload returned to user context | read-after-write confirm | admin action abuse | fetch + browser snippet |
| DOM XSS | unsafe sink + source taint | sink reachability + payload response | token exfiltration | JS snippet |
| IDOR numeric | id traversal returns unauthorized object | ownership mismatch evidence | privilege escalation | curl loops |
| IDOR UUID | object UUID substitutions succeed | forbidden expected but not returned | data exposure chain | curl loops |
| CSRF missing token | state-changing endpoints accept no token | replay with foreign origin | unauthorized transaction | curl |
| SQLi error-based | DB-specific error signatures | payload family agreement | full compromise | curl/sqlmap seed |
| SQLi blind | timing behavior changes | repeated timing median | data extraction path | curl timing |
| CORS wildcard | Access-Control-Allow-Origin * | credential mode check | cross-site data theft | fetch |
| CORS reflect origin | dynamic origin echo | attacker origin replay | trust boundary bypass | fetch |
| Broken auth weak lockout | unlimited auth attempts | burst test threshold | credential stuffing chain | bash loop |
| Broken auth reset flaw | weak reset token or flow | token reuse/guessability evidence | account reset abuse | curl |
| JWT none/alg confusion | token accepted under wrong alg | signature bypass confirm | identity forgery | python snippet |
| JWT weak claims | exp/aud/iss not validated | claim mutation acceptance | lateral API abuse | python + curl |
| Missing CSP | no policy or unsafe inline config | script injection environment score | XSS reliability increase | header evidence |
| Missing HSTS | transport downgrade risk | header absence check | session interception chain | header evidence |
| Missing XFO | clickjacking possibility | frame policy absence | CSRF + UI redress | header evidence |
| Missing XCTO | MIME sniffing risk | header absence check | content confusion attacks | header evidence |
| Missing Referrer-Policy | URL leak risk | referrer over-disclosure path | token leak chaining | header evidence |
| Rate limit absent login | no throttling signs | request burst response trend | brute-force enablement | bash loop |
| Rate limit absent OTP | no throttle on challenge | attempt saturation | account takeover acceleration | bash loop |
| Business logic price tamper | critical field trust issue | multi-step replay | fraud chain | curl sequence |
| Business logic role workflow | role transitions lack server guard | unauthorized transition evidence | privilege escalation | curl sequence |
| User enumeration login | response discrepancy by account state | message and status divergence | targeted brute-force | curl compare |
| User enumeration reset | account presence leakage | time/response mismatch | targeted takeover | curl compare |
| CVE fingerprinted framework | vulnerable version match | signature + header/path pair | known exploit path | nuclei template |
| CVE fingerprinted CMS | exposed plugin/module versions | endpoint + version artifact | takeover path | nuclei template |
| CVE fingerprinted server | web server version issue | banner and behavior checks | pre-auth RCE chain | nuclei template |
| Session fixation | session identifier not rotated | login transition compare | account takeover | curl cookie |
| Session invalidation flaw | logout does not revoke token | post-logout replay | persistent hijack | curl replay |
| Access control bypass via method | endpoint differs by HTTP verb | method matrix mismatch | privilege bypass | curl matrix |
| Access control bypass via content-type | parser confusion by media type | equivalent payload accepted | validation bypass | curl |
| Open redirect auth flow | redirect target unsafely accepted | external domain redirect | phishing chain | curl |
| File upload validation bypass | content sniff or extension bypass | stored executable path | RCE pivot | curl multipart |
| Path traversal file read | ../ payloads resolve | normalized path leakage | secret extraction chain | curl |
| SSRF metadata access | internal host/protocol fetch allowed | blocked host bypass check | cloud credential theft | curl |
| Insecure deserialization signal | gadget-like payload behavior | crash/error semantics | code execution chain | payload request |
| Cache poisoning indicator | unkeyed header influence | cache hit inconsistency | persistent malicious content | curl |
| GraphQL introspection exposed | schema leakage in prod | introspection query response | attack surface mapping | graphql query |
| GraphQL auth bypass | field-level auth missing | unauthorized field read | data exfiltration | graphql query |

### Severity mapping heuristic

| Severity | Base CVSS-like Score | Typical Action |
|---|---|---|
| Critical | 9.0 - 10.0 | Patch immediately, isolate impact surface, verify exploit closure. |
| High | 7.0 - 8.9 | Prioritize in current sprint with regression guard tests. |
| Medium | 4.0 - 6.9 | Fix in planned hardening cycle with owner assignment. |
| Low | 0.1 - 3.9 | Track and close through quality/security debt workflows. |

### Evidence grading

| Grade | Meaning |
|---|---|
| A | Reproducible exploit with direct business impact evidence |
| B | Reproducible exploit with controlled technical impact evidence |
| C | High-signal indicator needing optional manual validation |
| D | Informational weakness with low exploit confidence |

---

## 📌 Appendix C: Hardcore Checks Matrix

| Stage | Tooling | Input | Output Artifact | Guard Rails |
|---|---|---|---|---|
| Consent init | API | target domain, terms acceptance | consent_id | authenticated user required |
| DNS verify | resolver + TXT lookup | _pentest-verify.<domain> | ownership_verified=true | record must include expected token |
| Scope lock | API + DB | verified consent_id | immutable locked scope | lock timestamp and actor captured |
| SQLMap preflight | SQLMap API | target + params | candidate SQLi vectors | max rate + timeout caps |
| SQLMap active | SQLMap API | selected endpoints | validated SQLi result set | scope restrictions enforced |
| Nuclei preflight | template filters | target + tags | approved template list | disallowed tags blocked |
| Nuclei run | subprocess | filtered templates | CVE hit list | execution timeout + allowlist |
| Rate burst | internal module | endpoint list | pressure-test metrics | hard cap per second |
| User enum stress | internal module | auth/reset endpoints | differential signals | retry ceilings |
| JWT stress | internal module | token samples | validation weakness matrix | no persistent mutation |
| Session stress | internal module | login/session paths | fixation/invalidation findings | explicit session boundaries |
| Audit finalize | DB write | run events | immutable audit chain | append-only semantics |

### Consent record data model snapshot

| Field | Type | Description |
|---|---|---|
| consent_id | UUID | primary identifier for hardcore authorization cycle |
| user_id | UUID | owner of consent flow |
| target_domain | string | domain asserted by user |
| dns_token | string | verification token expected in TXT record |
| verified_at | datetime | timestamp when ownership verified |
| scope_locked_at | datetime | timestamp when immutable scope lock occurred |
| scope_payload | json | normalized target/scope metadata |
| expires_at | datetime | consent validity limit |
| tc_version | string | accepted terms version |
| created_at | datetime | record creation timestamp |

### Audit log event taxonomy

| Event | Description |
|---|---|
| CONSENT_CREATED | user initialized hardcore consent |
| DNS_VERIFY_ATTEMPT | domain ownership check executed |
| DNS_VERIFIED | TXT verification succeeded |
| SCOPE_LOCKED | immutable scope lock committed |
| HARDCORE_RUN_REQUESTED | hardcore execution requested by owner |
| HARDCORE_RUN_STARTED | active test stage started |
| HARDCORE_SQLMAP_COMPLETED | SQLMap stage complete |
| HARDCORE_NUCLEI_COMPLETED | Nuclei stage complete |
| HARDCORE_RATE_LIMIT_CHECKED | rate stress stage complete |
| HARDCORE_USER_ENUM_CHECKED | enumeration stage complete |
| HARDCORE_JWT_CHECKED | JWT stress stage complete |
| HARDCORE_SESSION_CHECKED | session stage complete |
| HARDCORE_RUN_FINISHED | hardcore execution finalized |
| HARDCORE_RUN_BLOCKED | blocked due to missing/expired consent |

---

## 📌 Appendix D: Local Ops Cheat Sheet

### Service lifecycle

```bash
docker compose up -d
docker compose ps
docker compose logs -f
docker compose down
```

### Hardcore profile lifecycle

```bash
docker compose --profile hardcore up -d
docker compose --profile hardcore ps
docker compose --profile hardcore down
```

### Database and migration lifecycle

```bash
cd Backend
alembic upgrade head
alembic current
alembic history
```

### Celery worker lifecycle

```bash
cd Backend
celery -A tasks.celery_app.celery_app worker --loglevel=info
```

### Frontend lifecycle

```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --port 3000
npm run build
```

### Backend lifecycle

```bash
cd Backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Health checks

```bash
curl -X GET http://localhost:8000/api/health
curl -X GET http://localhost:8000/docs
curl -X GET http://localhost:3000
```

### Common cleanup

```bash
docker compose down -v
docker system prune -f
```

### Quick env sanity checks

```bash
grep -E "SECRET_KEY|POSTGRES_PASSWORD|NEO4J_PASSWORD" .env
grep -E "LLM_PROVIDER|LLM_MODEL|LLM_BASE_URL" .env
```

### Scan command snippets

```bash
curl -X POST http://localhost:8000/api/scans \
	-H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
	-H "Content-Type: application/json" \
	-d '{"target_url":"https://target.local","mode":"normal"}'
```

```bash
curl -X POST http://localhost:8000/api/scans \
	-H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
	-H "Content-Type: application/json" \
	-d '{"target_url":"https://target.local","mode":"hardcore","consent_id":"YOUR_CONSENT_ID"}'
```

### JSON event stream reference

```json
{
	"scan_id": "9f5b2a8e-1f04-4c7d-8d0a-92f2f783f944",
	"phase": "scan",
	"progress": 41,
	"finding_count": 17,
	"severity_breakdown": {
		"critical": 2,
		"high": 5,
		"medium": 7,
		"low": 3
	},
	"message": "JWT claim validation weakness confirmed"
}
```

### Minimal test plan

| Step | Expected Result |
|---|---|
| Register/login | token issuance succeeds |
| Create normal scan | job queued and progresses to phase 6 |
| View findings | findings list and detail render |
| View graph | nodes and edges appear in React Flow |
| Download report | PDF generated and downloadable |
| Hardcore consent init | consent_id returned |
| DNS verify | verification transitions to true |
| Scope lock | scope lock recorded and immutable |
| Hardcore scan start | run accepted only with valid consent |

### Recommended Git workflow

```bash
git checkout -b feat/your-feature
git add .
git commit -m "feat: add your feature"
git push origin feat/your-feature
```

### Release checklist snapshot

| Check | Status Target |
|---|---|
| Backend tests | passing |
| Frontend build | passing |
| Migration dry run | passing |
| Worker queue processing | passing |
| Graph generation | passing |
| Report generation | passing |
| Hardcore consent flow | passing |
| README examples | copy-paste validated |

---

## 📌 Extended Notes (for raw Markdown readability)

The sections above are intentionally formatted to stay readable in raw Markdown and rendered views.

ASRE is optimized for local-first execution where data boundaries matter.

You can run without cloud dependencies, without managed scanning services, and without external telemetry.

If your team needs reproducible outputs for developers and leadership in one pass, this is what ASRE was built for.

---

### Additional Table: Project Structure (key directories)

| Path | Role |
|---|---|
| backend/scanner/crawler.py | Phase 1 crawling |
| backend/scanner/rule_engine.py | Phase 2 detection orchestration |
| backend/scanner/probes/ | vulnerability-specific probes |
| backend/scanner/chain_builder.py | Phase 3 graph chain construction |
| backend/scanner/llm_analyzer.py | Phase 4 analysis enrichment |
| backend/scanner/poc_generator.py | Phase 5 PoC synthesis |
| backend/scanner/report_engine.py | Phase 6 PDF reporting |
| backend/scanner/hardcore/ | Hardcore mode modules |
| backend/core/llm_registry.py | universal provider abstraction |
| backend/core/neo4j_client.py | graph lifecycle + query wrapper |
| backend/core/database.py | async PostgreSQL engine/session |
| backend/api/routes/ | REST route handlers |
| backend/tasks/scan_tasks.py | Celery task pipeline |
| backend/templates/report.html | report template |
| frontend/src/components/graph/ | React Flow graph UI |
| frontend/src/components/scan/ | live scan progress components |
| frontend/src/components/findings/ | finding cards/details/PoC views |
| frontend/src/pages/ | app pages |
| docker-compose.yml | local infrastructure orchestration |
| .env.example | baseline configuration template |

---

### Additional Table: Pipeline timing expectations

| Phase | Typical Time | Heaviest Factors |
|---|---|---|
| Crawl | 20s - 180s | page count, auth complexity, JS rendering needs |
| Scan | 30s - 240s | endpoint volume, probe breadth |
| Chain | 2s - 20s | finding count, relationship density |
| Analyze | 10s - 300s | model latency, token limits |
| PoC | 2s - 30s | finding count and template complexity |
| Report | 3s - 40s | template density and artifact size |

---

### Additional Table: Default ports

| Service | Port | Purpose |
|---|---|---|
| Frontend | 3000 | UI |
| Backend API | 8000 | REST and WebSocket |
| PostgreSQL | 5432 | relational findings and metadata |
| Redis | 6379 | queue and caching |
| Neo4j Bolt | 7687 | graph queries |
| Neo4j Browser | 7474 | graph inspection UI |
| SQLMap API | 8775 | hardcore SQLi active checks |

---

### Additional Table: Recommended system resources

| Profile | CPU | RAM | Disk |
|---|---|---|---|
| Demo | 2 vCPU | 4 GB | 10 GB |
| Team local | 4 vCPU | 8 GB | 25 GB |
| Heavy hardcore scans | 8 vCPU | 16 GB | 50 GB |

---

### Additional Table: Report sections generated

| Section | Audience | Source |
|---|---|---|
| Executive summary | leadership | LLM + score aggregation |
| Risk heatmap | appsec | finding severity model |
| Finding details | engineering | scanner probes + evidence |
| PoC appendix | engineering | Phase 5 generated snippets |
| Attack chains | appsec + engineering | Neo4j path analysis |
| OWASP/MITRE mapping | governance | analysis enrichment |
| Remediation plan | engineering managers | LLM and rule-based templates |

---

### Additional Table: WebSocket event types

| Event | Meaning |
|---|---|
| scan_created | scan accepted and queued |
| phase_started | pipeline phase entered |
| progress | progress update |
| finding_detected | new finding arrived |
| chain_generated | graph chain completed |
| analysis_completed | LLM enrichment completed |
| report_generated | PDF artifact ready |
| scan_failed | terminal error |
| scan_completed | successful terminal state |

---

### Additional Table: Data retention ideas

| Artifact | Suggested Retention |
|---|---|
| Raw findings | 90 days |
| Reports | 180 days |
| Graph snapshots | 90 days |
| WebSocket logs | 14 days |
| Hardcore audit logs | 365+ days |

---

### Additional Table: Common user roles

| Role | Typical Actions |
|---|---|
| Developer | Run normal scan, inspect finding, fix code |
| AppSec engineer | Tune probes, analyze chains, validate closure |
| Team lead | review report summary and sprint priorities |
| Red team | execute authorized hardcore window |
| Blue team | monitor controls and remediation quality |

---

### Additional Table: Suggested CI stages

| Stage | Goal |
|---|---|
| Build | verify backend/frontend artifacts |
| Unit tests | protect parser/probe logic |
| Integration tests | validate API and DB paths |
| Security smoke | run baseline normal scan against test target |
| Report artifact check | ensure PDF generation path is healthy |

---

### Additional Table: Sample scan metadata schema

| Field | Type |
|---|---|
| scan_id | UUID |
| user_id | UUID |
| target_url | string |
| mode | enum(normal, hardcore) |
| started_at | datetime |
| completed_at | datetime |
| status | enum(queued, running, failed, completed) |
| findings_count | int |
| chain_count | int |
| report_path | string |

---

### Additional Table: Sample finding metadata schema

| Field | Type |
|---|---|
| finding_id | UUID |
| scan_id | UUID |
| vuln_type | string |
| severity | string |
| endpoint | string |
| method | string |
| evidence | json |
| remediation | text |
| owasp | string |
| mitre | string |

---

### Additional Table: Local-first principles in ASRE

| Principle | Implementation |
|---|---|
| Data locality | all services run in local containers |
| Provider optionality | LLM abstraction via provider registry |
| Deterministic outputs | persisted findings + versioned report templates |
| Explainability | attack graph + PoC + mapping + narrative |
| Controlled active testing | hardcore consent and immutable logs |

---

### Additional Table: What to monitor in production-like deployments

| Metric | Why it matters |
|---|---|
| queue latency | indicates worker health and throughput |
| scan duration by phase | reveals bottlenecks and regressions |
| findings confidence distribution | detects noisy probe behavior |
| graph node/edge volume | shows chain model scaling characteristics |
| report generation time | tracks PDF template/render health |
| hardcore block rate | validates consent gate enforcement |

---

### Final note

Build fast. Scan responsibly. Fix what matters first.
