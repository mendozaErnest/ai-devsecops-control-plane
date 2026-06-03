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
| Infra Security — IaC | Checkov (Dockerfile, K8s YAML, Helm, Terraform) — pip install |
| Infra Security — CVE | Trivy filesystem scan (no Docker daemon required) — binary |
| Infra Security — Secrets | Gitleaks detect (source scan, git history optional) — binary |
| Scan profiles | `ScanProfile` + `ScanOrchestrator` (ThreadPoolExecutor) |
| Finding lifecycle | open / fixed / regression / accepted\_risk / false\_positive + audit trail |
| SLA tracking | CRITICAL=3d · HIGH=7d · MEDIUM=30d · LOW=90d; API filter `?sla_status=` |
| Local LLM | Ollama → `qwen2.5-coder:14b` (configurable via `OLLAMA_MODEL`) |
| Agentic DAST | LangGraph StateGraph: Explorer Agent + Attacker Agent + Verifier Agent |
| ML Risk Scoring | XGBoost binary classifier (`src/ml/risk_scorer.py`) · `risk_score` [0–1] per finding · `POST /api/ml/train` · severity fallback when untrained |
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
| OWASP ZAP + LangGraph | Any HTTP/HTTPS target | Agentic DAST (Explorer → Attacker → Verifier loop) |
| Checkov | IaC files (Dockerfile, K8s YAML, Helm, Terraform) | Infra Security |
| Trivy | Any directory (filesystem scan, no Docker daemon) | Infra Security |
| Gitleaks | Any directory or git repository | Infra Security — Secret scanning |

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

## Agentic DAST (LangGraph)

Phase 4 ships a fully-wired agentic DAST loop driven by LangGraph. The LLM backend is **Ollama running locally** (no cloud calls). The loop wraps the existing OWASP ZAP REST API so every action runs against a real scanner.

```
Explorer Agent → Attacker Agent → Verifier Agent
   (crawl)         (fuzzing)         (confirm)
      ↑_______________feedback_____________↓
```

| Agent | Responsibility |
|---|---|
| Explorer Agent | Spider the target with ZAP, identify routes / forms / auth boundaries, optionally rank attack surface via Ollama. |
| Attacker Agent | Trigger ZAP active scan, generate focused payloads (XSS, SQLi, path traversal, auth bypass) per discovered form. |
| Verifier Agent | Re-request each alert; confirm XSS when payload is reflected, confirm missing-header alerts via live response inspection, otherwise trust ZAP evidence. |

### Endpoint

```json
POST /api/dast/agent/scan
{
  "target_url": "http://host.docker.internal:3000",
  "project_id": "<uuid optional>",
  "max_iterations": 3
}
```

Response:

```json
{
  "scan_id": "uuid",
  "status": "done",
  "confirmed_findings": [ /* normalized findings with tool="zap+langgraph" */ ],
  "false_positives_count": 2,
  "iterations_run": 1,
  "saved_findings": 5
}
```

Progress polling for the UI:

```
GET /api/dast/agent/scan/{scan_id}/status
→ { "status": "exploring" | "attacking" | "verifying" | "done" | "error", ... }
```

### Graceful degradation

- **LangGraph missing** → `POST /api/dast/agent/scan` returns HTTP 503 with `"LangGraph not available. Install langgraph and langchain_ollama."`.
- **Ollama missing** → agents skip LLM enrichment silently and fall back to deterministic ZAP-driven logic.
- **ZAP missing** → tool wrappers return empty results; the agent completes with 0 findings and no error.

### Dashboard integration

The profile builder ships a scanner item **"OWASP ZAP + LangGraph (Agentic)"** that maps to `dast_tool="agent_loop"`. When the active profile uses this tool, `runScan()` first triggers the agentic endpoint and polls `/status` (Exploring → Attacking → Verifying → Done) before running the standard SAST/Quality scan.

---

## ML Risk Scoring

Each finding returned by the API includes a `risk_score` field (float `[0.0 – 1.0]`) computed by an XGBoost binary classifier trained on the finding's feature vector: severity, tool, regression count, age in days, days to SLA deadline, and lifecycle status.

### Training

```json
POST /api/ml/train
→ { "precision": 0.87, "recall": 0.82, "roc_auc": 0.91, "n_samples": 142 }
```

Returns HTTP 400 if fewer than 10 findings exist in the database. The model is persisted to `models/risk_model.joblib` (configurable via `RISK_MODEL_PATH` env var).

### Graceful degradation

- **Model not trained yet** → `score_finding()` returns a deterministic severity-based fallback (CRITICAL=0.9, HIGH=0.7, MEDIUM=0.4, LOW=0.2).
- **xgboost / scikit-learn absent** → same fallback, no error; the module's defensive `try/except` import keeps the API running without ML dependencies.

### Dashboard

Each finding row shows a colour-coded progress bar (red ≥ 70 %, amber ≥ 40 %, blue otherwise) alongside the severity badge. The findings toolbar exposes a **Sort by risk** toggle and a **🧠 Reentrenar modelo** button that calls `POST /api/ml/train` and displays the returned metrics as feedback.

---

## Infrastructure Security Scanners

Three adapters cover IaC, container/filesystem CVEs, and secret leaks. Each degrades gracefully when its binary is absent: it logs a warning and returns an empty finding list without crashing the scan.

### Checkov (IaC)

Scans Dockerfile, Kubernetes YAML, Helm charts, and Terraform. Installed via pip — already in `code/requirements.txt`.

```bash
pip install checkov
```

Findings carry the Checkov check ID as `rule_id` (e.g. `CKV_DOCKER_2`, `CKV_K8S_14`) and the severity Checkov assigns (HIGH/MEDIUM/LOW/CRITICAL).

### Trivy (filesystem / CVE)

Scans the project directory for known CVEs in Python, Node, Go, and other language ecosystems using a local vulnerability DB. **No Docker daemon required** — `trivy fs` operates entirely on the filesystem.

```bash
# Debian / Ubuntu
sudo apt install trivy

# macOS
brew install aquasecurity/trivy/trivy

# Direct binary (Linux x86_64)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

Findings use the CVE ID as `rule_id`. The description includes the affected package version and the suggested fixed version.

### Gitleaks (secrets)

Detects hardcoded secrets, API keys, and credentials in source files. Uses `gitleaks detect --no-git` for a pure filesystem scan; omit `--no-git` (or configure the adapter) if you want full git-history scanning.

```bash
# macOS
brew install gitleaks

# Debian / Ubuntu (from GitHub releases)
GITLEAKS_VERSION=8.18.4
curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks
```

All secrets findings default to severity **HIGH** because exposed credentials are always critical-path risks.

### kube-bench

kube-bench (CIS Kubernetes benchmark) is planned as the next infra scanner. It is not included in this release because it requires a running Kubernetes cluster to operate, making it a poor fit for offline/local scans.

### Activating infra scanners via ScanProfile

Enable infra tools in the dashboard's profile builder (new **Infrastructure Security** slot) or via the API:

```json
POST /api/profiles
{
  "name": "Full Infra Scan",
  "infra_enabled": true,
  "infra_tools": "checkov,trivy,gitleaks",
  "sast_enabled": true,
  "sast_tools": "semgrep"
}
```

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

### Phase 4 — Infrastructure & DAST ✅

| Surface | Tool |
|---|---|
| DAST | OWASP ZAP (spider + active scan, graceful degrade) |
| Agentic DAST | LangGraph StateGraph: Explorer Agent → Attacker Agent → Verifier Agent |
| Observability | Prometheus metrics + Grafana dashboard (auto-provisioned) |
| ML Risk Scoring | XGBoost per-finding risk score · `POST /api/ml/train` · dashboard retrain button |
| Secret scanning | gitleaks (planned) |
| Docker + K8s YAML | Checkov (planned) |
| Container images | Trivy (planned) |

---

## Why This Project Matters (for AppSec roles)

> "Working in the banking sector I was exposed to thousands of vulnerabilities managed through industrial tools (Fortify, SonarQube, Veracode). Outside of work I built the platform that automates that same cycle with local AI — because I understood the problem from the inside. The LLM runs on your infrastructure; code never crosses your network boundary."

Relevant keywords: `DevSecOps` · `AppSec` · `SAST` · `SCA` · `DAST` · `AI Remediation` · `Local LLM Inference` · `ML Risk Scoring` · `XGBoost` · `FastAPI` · `Kubernetes` · `OpenShift` · `Helm` · `Bandit` · `Semgrep` · `OWASP ZAP` · `Ollama` · `LangGraph` · `Vulnerability Management` · `Security Automation` · `GitHub App`
