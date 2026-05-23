# AI DevSecOps Control Plane

> Self-hosted security pipeline with local AI remediation — your code never leaves your infrastructure.

![Stack](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi)
![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat&logo=python)
![Ollama](https://img.shields.io/badge/LLM-Ollama%20local-black?style=flat)
![Bandit](https://img.shields.io/badge/SAST-Bandit%20%2B%20Semgrep-orange?style=flat)
![License](https://img.shields.io/badge/license-MIT-green?style=flat)

---

## What Is This?

AI DevSecOps Control Plane is a **local, self-hosted** platform that automates the full application security lifecycle:

1. Register source code projects (local path, ZIP upload, or Git clone).
2. Scan them with SAST adapters per technology.
3. Store normalized findings in a local database.
4. Generate AI-powered remediations using a **local LLM via Ollama** — no code ever leaves your infrastructure.
5. Open real, reviewable GitHub Pull Requests with the patched code.

---

## Why Local AI?

Most commercial alternatives (Snyk, GitHub Copilot Autofix, SonarCloud) send your source code to external APIs to generate remediations. For banks, fintech, healthcare, and government — where sending code to third-party APIs is a regulatory or contractual blocker — **local inference is not a technical detail, it is the value proposition**.

This platform runs the LLM on your own hardware via Ollama. The network boundary is your machine.

---

## Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI + Uvicorn |
| Database | SQLModel over SQLite (PostgreSQL-ready) |
| SAST — Python | Bandit + Semgrep (`p/bandit`, `p/python`, `p/owasp-top-ten`) |
| SAST — Angular/TS | Semgrep (`p/javascript`, `p/typescript`, `p/owasp-top-ten`) |
| SAST — Java | Semgrep (`p/java`, `p/owasp-top-ten`, `p/find-sec-bugs`) |
| Local LLM | Ollama → `qwen2.5-coder:14b` |
| GitHub Integration | GitHub App (JWT RS256 + installation token) |
| Frontend | HTML + Vanilla JS + Tailwind CDN |

---

## Scanner Architecture

The platform uses a **dual-engine approach** for maximum coverage:

- **Bandit** (Python): fast, battle-tested, low false-positive rate for common CWEs.
- **Semgrep** (Python, Angular, Java): pattern-based semantic analysis, OWASP Top 10 rulesets, closest open-source equivalent to Fortify/Veracode rule quality.

When `SCANNER_ENGINE=both`, both engines run in parallel and findings are deduplicated by SHA-256 fingerprint (`rule_id + file_path + line_number`). This mirrors how enterprise platforms like Veracode correlate results from multiple analysis engines.

---

## Supported Technologies

| Technology | SAST Engine | Remediation Prompt |
|---|---|---|
| Python | Bandit + Semgrep | Python-specific (OS injection, shell=True, unsafe deserialization, MD5/SHA1, TLS, path traversal) |
| Angular / TypeScript | Semgrep | Angular-specific (XSS via innerHTML, DomSanitizer bypass, unsafe bindings, hardcoded secrets with CI/CD injection pattern) |
| Java | Semgrep | Java AppSec (SQL injection, insecure crypto, TLS, SecureRandom, unsafe deserialization) |

---

## Remediation Quality

AI remediations are technology-aware and context-aware:

- **Python findings**: guardrails enforce AST-valid output; only the affected function is replaced (never a full-file replacement with a short snippet).
- **Angular secret findings** (hardcoded `apiKey`, `token`, `password`): the LLM is instructed to show the correct injection pattern — reading from CI/CD environment variables or a backend `ConfigService` — never just emptying the field.
- **Angular XSS findings**: DomSanitizer usage, safe binding patterns, Content Security Policy guidance.
- **Java findings**: cryptography upgrades, PreparedStatement patterns, secure TLS configuration.

All remediations are proposed as Pull Requests. Nothing is committed automatically without human review.

---

## Project Structure

```
AI-DevSecOps-Control-Plane/
├── src/
│   ├── api/
│   │   ├── main.py              ← FastAPI endpoints
│   │   ├── database.py          ← SQLModel engine
│   │   └── models.py            ← Target, Scan, Finding, Remediation
│   ├── scanners/
│   │   ├── base.py              ← BaseScannerAdapter
│   │   ├── bandit_adapter.py    ← Python SAST
│   │   ├── semgrep_adapter.py   ← Multi-language SAST (Semgrep)
│   │   ├── angular_adapter.py   ← Angular/TS scanner
│   │   ├── java_adapter.py      ← Java scanner
│   │   └── escaneo.py           ← Orchestrator
│   ├── ai_engine/
│   │   └── remediator.py        ← Ollama + technology-aware prompts
│   ├── integrations/
│   │   └── github_client.py     ← GitHub App PR automation
│   └── dashboard/
│       └── index.html           ← SPA: projects, findings, auto-fix, PR
├── tests/
├── helm/                        ← Kubernetes deployment (roadmap)
├── docker-compose.yml
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

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full sprint plan with implementation details.

### Phase 1 — Implemented ✅

| Surface | Tool |
|---|---|
| Python SAST | Bandit + Semgrep (`p/bandit`, `p/python`, `p/owasp-top-ten`) |
| Angular/TS SAST | Semgrep (`p/javascript`, `p/typescript`, `p/owasp-top-ten`) |
| Java SAST | Semgrep (`p/java`, `p/owasp-top-ten`, `p/find-sec-bugs`) |
| AI Remediation | Ollama local LLM — technology-aware prompts |
| GitHub PR automation | GitHub App — JWT RS256 + semantic patching |

### Phase 2 — Sprint (1-2 weeks) 🔜

| Area | Feature | Tool/Approach |
|---|---|---|
| SCA | CVE coverage for Python libs | pip-audit |
| SCA | CVE coverage for Java libs | OWASP Dependency Check |
| Finding lifecycle | `fixed → regression` state transition | escaneo.py logic |
| Finding lifecycle | Accepted risk / false positive with audit trail | FindingAuditEvent model |
| Finding lifecycle | Reappearance history per finding | Audit events + `regression_count` |
| Finding lifecycle | SLA tracking by severity (3/7/30/90 days) | `sla_deadline` field + dashboard badge |
| Finding lifecycle | Reports per project (open/fixed/SLA/trends) | API endpoint + Chart.js dashboard |
| CI/CD | Automatic scan on every PR (webhook) | GitHub webhook + Check Run API |
| CI/CD | Block merge on critical findings | Check Run `conclusion: failure` |
| CI/CD | Reusable GitHub Actions workflow | `.github/workflows/devsecops-scan.yml` |

### Phase 3 — Infrastructure security 🔜

| Surface | Tool |
|---|---|
| Secret scanning | gitleaks |
| Docker + K8s YAML | Checkov |
| Container images | Trivy |
| K8s cluster hardening | kube-bench |

### Phase 4 — DAST 🔜

| Surface | Approach |
|---|---|
| Web application | LangGraph agent loop (crawler → attacker → verifier) |

---

## Why This Project Matters (for AppSec roles)

> "At sector bancario I resolved 3,000+ vulnerabilities using existing tools (Fortify, SonarQube, Veracode). Outside of work I built the platform that automates that same cycle with local AI — because I understood the problem from the inside. The LLM runs on your infrastructure; code never crosses your network boundary."

Relevant keywords: `DevSecOps` · `AppSec` · `SAST` · `SCA` · `AI Remediation` · `Local LLM Inference` · `FastAPI` · `Kubernetes` · `OpenShift` · `Helm` · `Bandit` · `Semgrep` · `Ollama` · `Vulnerability Management` · `Security Automation` · `GitHub App`

---

<!-- DRAFT NOTES — remove before publishing -->
<!--
TODO:
- Add demo GIF (dashboard → scan → auto-fix → PR)
- Add .env.example file
- Add badge for Python version and test coverage
- Add comparison table vs Snyk / GitHub Copilot Autofix / SonarCloud
- Add Architecture diagram (ASCII or Mermaid)
- DAST section: expand LangGraph agent loop description when implemented
-->
