# AI DevSecOps Control Plane

> Self-hosted security pipeline with local AI remediation — your code never leaves your infrastructure.

![Stack](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi)
![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat&logo=python)
![Ollama](https://img.shields.io/badge/LLM-Ollama%20local-black?style=flat)
![Bandit](https://img.shields.io/badge/SAST-Bandit%20%2B%20Semgrep-orange?style=flat)
![Tests](https://img.shields.io/badge/tests-117%20passing-brightgreen?style=flat)
![License](https://img.shields.io/badge/license-MIT-green?style=flat)

---

## What Is This?

AI DevSecOps Control Plane is a **local, self-hosted** platform that automates the full application security lifecycle:

1. Register source code projects (ZIP upload or Git clone).
2. Configure a **Scan Profile** (choose SAST / SCA / Quality / DAST engines).
3. Run scans — the `ScanOrchestrator` executes all selected tools in parallel.
4. Store normalized findings with **SLA deadlines** and a full **audit trail**.
5. Generate AI-powered remediations using a **local LLM via Ollama** — no code ever leaves your infrastructure.
6. Open real, reviewable GitHub Pull Requests with the patched code.
7. Extend into **agentic DAST with LangGraph**: Explorer, Attacker, and Verifier agents coordinating dynamic testing loops.

---

## Why Local AI?

Most commercial alternatives (Snyk, GitHub Copilot Autofix, SonarCloud) send your source code to external APIs to generate remediations. For regulated industries — banking, fintech, healthcare, government — where sending code to third-party APIs is a regulatory or contractual blocker, **local inference is not a technical detail, it is the value proposition**.

This platform runs the LLM on your own hardware via Ollama. The network boundary is your machine.

---

## Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI + Uvicorn |
| Database | SQLModel over SQLite (PostgreSQL-ready via `DATABASE_URL`) |
| SAST — Python | Bandit + Semgrep (`p/bandit`, `p/python`, `p/owasp-top-ten`) |
| SCA — Python | pip-audit (CVE + GHSA from PyPI advisory DB) |
| SAST — Angular/TS | Semgrep (`p/javascript`, `p/typescript`, `p/owasp-top-ten`) |
| SAST — Java | Semgrep (`p/java`, `p/owasp-top-ten`, `p/find-sec-bugs`) |
| SCA — Java | OWASP Dependency Check (NVD-backed CVE) |
| Quality — Python | Pylint (JSON output, HIGH/MEDIUM/LOW severity mapping) |
| Quality — Angular | ESLint (local `node_modules/.bin/eslint` or `npx`) |
| Quality — Any | SonarQube Community REST (Bearer token, issues import) |
| DAST | OWASP ZAP (spider + active scan, graceful degrade when ZAP unreachable) |
| Scan profiles | `ScanProfile` + `ScanOrchestrator` (ThreadPoolExecutor) |
| Finding lifecycle | open / fixed / regression / accepted\_risk / false\_positive + audit trail |
| SLA tracking | CRITICAL=3d · HIGH=7d · MEDIUM=30d · LOW=90d; API filter `?sla_status=` |
| Local LLM | Ollama → `qwen2.5-coder:14b` (configurable via `OLLAMA_MODEL`) |
| Agentic DAST | LangGraph StateGraph roadmap: Explorer Agent + Attacker Agent + Verifier Agent |
| GitHub Integration | GitHub App (JWT RS256 + installation token) + PR webhook + Check Run |
| CI/CD | GitHub Actions workflow (Bandit + pip-audit + Semgrep on every PR) |
| Frontend | Modular ES6 JS (`api.js`, `modal.js`, `diff.js`, `dashboard.js`) + Chart.js |

---

## Scanner Architecture

The platform uses a **profile-driven, multi-engine approach** for maximum coverage.

### Built-in engines

| Engine | Language | Type |
|---|---|---|
| Bandit | Python | SAST |
| Semgrep | Python / Angular / Java | SAST |
| pip-audit | Python | SCA (CVE) |
| OWASP Dependency Check | Java | SCA (CVE) |
| Pylint | Python | Quality |
| ESLint | Angular / TypeScript | Quality |
| SonarQube Community REST | Any | Quality |
| OWASP ZAP | Any HTTP/HTTPS target | DAST |

### Scan Profiles

`ScanProfile` records let you configure which engines run per project. The `ScanOrchestrator` runs SAST, DAST, and Quality runners in parallel using `ThreadPoolExecutor`, then deduplicates findings by SHA-256 fingerprint (`rule_id + file_path + line_number + description`).

Four built-in profiles ship by default:

| Profile | Engines |
|---|---|
| Python SAST | Bandit + Semgrep + pip-audit |
| Angular SAST | Semgrep |
| Java SAST | Semgrep + OWASP DC |
| Full Scan | All of the above + Quality when adapter configured |

### Target path resolution (`POST /api/scan`)

The general scan endpoint resolves the target in priority order:

1. **`target_path` in body** → path-traversal validation → run scan.
2. **`project_id` in body** → look up `project.target_path` in DB → validate → scan with project profile.
3. **No parameters** → fallback to `src/dummy_vulnerable_app.py` (retro-compat).

Path validation enforces that the resolved path stays inside `SCAN_ALLOWED_ROOTS` (default: project root + `workspace/uploads/`), blocking directory traversal.

### DAST target URL (`dast_target_url`)

When the active `ScanProfile` has `dast_enabled=true`, send the running application's URL alongside the scan request:

```json
POST /api/scan
{ "project_id": "...", "dast_target_url": "http://host.docker.internal:3000" }
```

- Only `http://` and `https://` schemes are accepted; anything else returns HTTP 400.
- If `dast_target_url` is omitted or blank, the DAST runner skips with a warning — the SAST/Quality runners still execute.
- The ZAP adapter reads `ZAP_BASE_URL` (default `http://localhost:8090`) and degrades to an empty result set when ZAP is unreachable.

---

## Agentic DAST Roadmap

Phase 4 adds dynamic application security testing through two complementary paths:

- **OWASP ZAP adapter**: API-driven spidering and active scans against running applications.
- **LangGraph agent loop**: a `StateGraph` where specialized agents collaborate, observe results, and iterate until findings are confirmed or rejected.

Planned agent roles:

| Agent | Responsibility |
|---|---|
| Explorer Agent | Crawl the target, discover routes, forms, parameters, and authentication boundaries. |
| Attacker Agent | Generate focused fuzzing payloads for XSS, injection, auth bypass, path traversal, and common OWASP Top 10 cases. |
| Verifier Agent | Reproduce candidate findings, reduce false positives, and emit normalized evidence for the existing finding lifecycle. |

```
Explorer Agent -> Attacker Agent -> Verifier Agent
   (crawl)        (fuzzing)         (confirm)
      ^________________feedback______________|
```

This is intentionally marked as roadmap: the current codebase already models `dast_tool` values such as `zap` and `agent_loop`, while the real ZAP adapter and LangGraph agent implementation belong to the next infrastructure/DAST phase.

---

## Supported Technologies

| Technology | SAST Engine | Remediation Prompt |
|---|---|---|
| Python | Bandit + Semgrep | Python-specific (OS injection, `shell=True`, unsafe deserialization, MD5/SHA1, TLS, path traversal) |
| Angular / TypeScript | Semgrep | Angular-specific (XSS via `innerHTML`, `DomSanitizer` bypass, hardcoded secrets → CI/CD injection pattern) |
| Java | Semgrep | Java AppSec (SQL injection, insecure crypto, TLS, `SecureRandom`, unsafe deserialization) |
| CSS / SCSS | SonarQube | CSS-specific (duplicate selectors, `!important` overuse, specificity issues) |
| HTML | SonarQube | HTML5 (XSS via `textContent`, `rel="noopener noreferrer"`, deprecated attributes) |

---

## Remediation Quality

AI remediations are technology-aware and context-aware:

- **Python findings**: AST guardrails enforce valid output; only the affected function is replaced (never a full-file replacement with a short snippet). Deterministic rules (S1192 duplicate literals, B324 weak hashes) are patched without calling the LLM.
- **Angular secret findings** (`apiKey`, `token`, `password`): the LLM is instructed to inject values from CI/CD environment variables or a backend `ConfigService` — never just empty the field.
- **Angular XSS findings**: `DomSanitizer` patterns, safe binding, Content Security Policy guidance.
- **Angular cognitive complexity (S3776)**: full enclosing function extracted from source and passed to the LLM for real refactoring, not placeholder generation.
- **Java findings**: cryptography upgrades, `PreparedStatement` patterns, secure TLS configuration.

Safety guardrails in `is_safe_to_apply()` block patches that delete functions, contain generic stubs (`// TODO: implement`, `refactoredFunction`, etc.), or remove more than 20% of source lines. Rejected patches fall back to a **proposal-only PR** (a Markdown file in `docs/remediations/`) — no source code is modified without human approval.

All remediations are proposed as Pull Requests. Nothing is committed automatically without human review.

---

## Finding Lifecycle

Each finding follows a tracked state machine:

```
open → fixed (re-scan confirms fix)
     → regression (re-scan finds it again after "fixed")
     → accepted_risk (human triage)
     → false_positive (human triage)
```

Every state transition is recorded in `FindingAuditEvent` with a required reason string. The dashboard exposes Accept Risk, False Positive, and History buttons per finding. Findings in `accepted_risk` or `false_positive` states are preserved across subsequent scans.

---

## Project Structure

```
AI-DevSecOps-Control-Plane/
├── src/
│   ├── api/
│   │   ├── main.py              ← FastAPI endpoints (scan, profiles, lifecycle, webhook, reports)
│   │   ├── database.py          ← SQLModel engine + default profile seed
│   │   └── models.py            ← ScanProfile, Project, Scan, Finding, Remediation, FindingAuditEvent
│   ├── scanners/
│   │   ├── base.py              ← BaseScannerAdapter
│   │   ├── orchestrator.py      ← ScanOrchestrator (ThreadPoolExecutor)
│   │   ├── bandit_adapter.py    ← Python SAST
│   │   ├── semgrep_adapter.py   ← Multi-language SAST
│   │   ├── pip_audit_adapter.py ← Python SCA (pip-audit)
│   │   ├── angular_adapter.py   ← Angular/TS scanner
│   │   ├── java_adapter.py      ← Java scanner
│   │   ├── odc_adapter.py       ← Java SCA (OWASP Dependency Check)
│   │   ├── pylint_adapter.py    ← Python Quality
│   │   ├── eslint_adapter.py    ← Angular/TypeScript Quality
│   │   ├── sonarqube_adapter.py ← SonarQube Community REST
│   │   └── escaneo.py           ← Adapter selection + finding upsert + SLA
│   ├── ai_engine/
│   │   └── remediator.py        ← Ollama + technology-aware prompts (Python/Angular/Java/CSS/HTML)
│   ├── integrations/
│   │   └── github_client.py     ← GitHub App PR automation + semantic patching + Check Run
│   └── dashboard/
│       ├── index.html           ← HTML shell (no inline JS/CSS)
│       ├── css/
│       │   ├── base.css         ← CSS variables, reset, animations
│       │   ├── layout.css       ← nav, bento grid, cards, findings table
│       │   └── modal.css        ← modal overlays, tabs, form panels
│       └── js/
│           ├── api.js           ← all fetch() wrappers
│           ├── utils.js         ← i18n (ES/EN), helpers, tool badges
│           ├── diff.js          ← LCS diff view + GitHub unified diff parser
│           ├── modal.js         ← project wizard, remediation modal, audit modal
│           ├── dashboard.js     ← findings render, scan trigger, charts, PDF export
│           └── main.js          ← entry point, event wiring, boot sequence
├── tests/                       ← 117 tests across 15 files
├── .github/
│   └── workflows/
│       └── devsecops-scan.yml   ← CI: Bandit + pip-audit + Semgrep on every PR
├── docker-compose.yml           ← api + ollama + ollama-init services
├── Dockerfile
├── .env.example
└── code/requirements.txt
```

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/mendozaErnest/ai-devsecops-control-plane
cd ai-devsecops-control-plane
pip install -r code/requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env with your GitHub App credentials and Ollama URL

# 3. Start Ollama (separate terminal)
ollama pull qwen2.5-coder:14b
ollama serve

# 4. Start the platform
uvicorn src.api.main:app --reload

# 5. Open dashboard
# http://127.0.0.1:8000
```

### Docker Compose

```bash
docker compose up -d
# Dashboard → http://localhost:8000
```

---

## GitHub App Setup

The platform integrates via a **GitHub App** (not a PAT), which is the recommended pattern for production integrations:

1. Create a GitHub App in your organization with `contents:write` and `pull_requests:write` permissions.
2. Generate and download the private key (`.pem`).
3. Install the App on your target repository.
4. Add to `.env`:

```env
GITHUB_APP_ID=<app-id>
GITHUB_INSTALLATION_ID=<installation-id>
GITHUB_PRIVATE_KEY_PATH=<path-to-key.pem>
GITHUB_REPO=<owner/repo>
GITHUB_BASE_BRANCH=main
```

---

## Security Roadmap

See [ROADMAP.md](ROADMAP.md) for the full sprint plan with implementation details.

### Phase 1 — Core platform ✅

| Surface | Tool |
|---|---|
| Python SAST | Bandit + Semgrep |
| Angular/TS SAST | Semgrep |
| Java SAST | Semgrep + OWASP DC |
| AI Remediation | Ollama local LLM — technology-aware prompts |
| GitHub PR automation | GitHub App — JWT RS256 + semantic patching |

### Phase 2 — Scan profiles + SCA + lifecycle ✅

| Area | Feature |
|---|---|
| SCA | CVE coverage for Python (pip-audit) and Java (OWASP DC) |
| Finding lifecycle | open / fixed / regression / accepted\_risk / false\_positive + audit trail |
| SLA tracking | Per-severity deadlines (3/7/30/90d) · API filter · dashboard badges |
| CI/CD | PR webhook + GitHub Check Run (blocks merge on criticals) |
| Scan profiles | `ScanProfile` model + `ScanOrchestrator` + 4 default profiles |
| Target path | Flexible `POST /api/scan` — resolves from body, project DB, or fallback |
| Dashboard | Modular ES6 JS/CSS · 2-step wizard · Chart.js reports · PDF export |

### Phase 3 — Quality + Hardening ✅

| Area | Feature |
|---|---|
| Quality — Python | Pylint adapter |
| Quality — Angular | ESLint adapter |
| Quality — Any | SonarQube Community REST adapter |
| Semantic patching | Python AST guardrails · JS/TS brace-counting · proposal-only PR fallback |
| Diff viewer | LCS diff + GitHub unified diff · side-by-side Antes/Después · scroll sync |
| Remediation cache | Lightweight cache check — no re-read of source file; Ollama called once per finding |

### Phase 4 — Infrastructure & DAST 🔜

| Surface | Tool |
|---|---|
| DAST | OWASP ZAP adapter (real implementation pending) |
| Agentic DAST | LangGraph StateGraph: Explorer Agent → Attacker Agent → Verifier Agent |
| Secret scanning | gitleaks |
| Docker + K8s YAML | Checkov |
| Container images | Trivy |
| K8s cluster | kube-bench |

---

## Why This Project Matters (for AppSec roles)

> "Working in the banking sector I was exposed to thousands of vulnerabilities managed through industrial tools (Fortify, SonarQube, Veracode). Outside of work I built the platform that automates that same cycle with local AI — because I understood the problem from the inside. The LLM runs on your infrastructure; code never crosses your network boundary."

Relevant keywords: `DevSecOps` · `AppSec` · `SAST` · `SCA` · `DAST` · `AI Remediation` · `Local LLM Inference` · `FastAPI` · `Kubernetes` · `OpenShift` · `Helm` · `Bandit` · `Semgrep` · `OWASP ZAP` · `Ollama` · `LangGraph` · `Vulnerability Management` · `Security Automation` · `GitHub App`
