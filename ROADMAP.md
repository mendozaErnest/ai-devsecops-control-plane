# AI DevSecOps Control Plane — Roadmap

## Completo ✅

### Phase 1 — Core Platform
- [x] FastAPI backend + SQLModel + SQLite
- [x] Bandit adapter (Python SAST)
- [x] Semgrep adapter (Python / Angular / Java SAST)
- [x] pip-audit adapter (Python SCA)
- [x] OWASP Dependency Check adapter (Java SCA)
- [x] ZIP upload + Git clone project onboarding
- [x] ScanProfile config layer (sast_tools, dast_enabled, quality_enabled)
- [x] ScanOrchestrator with ThreadPoolExecutor
- [x] 2-step project wizard in dashboard
- [x] Finding lifecycle: open / fixed / regression / accepted_risk / false_positive
- [x] Audit trail (FindingAuditEvent)
- [x] SLA deadlines: CRITICAL=3d, HIGH=7d, MEDIUM=30d, LOW=90d
- [x] Remediation via Ollama (local LLM)
- [x] GitHub App integration: JWT RS256, branch, PR creation
- [x] Semantic patching guardrails: Python AST, Angular/Java brace-counting
- [x] GitHub Actions CI workflow (SAST + SCA on PR and push)
- [x] GitHub Webhook: PR event → Check Run
- [x] Dashboard: Chart.js report (by_severity, by_status, top_rules)

### Phase 2 — PR Reliability + UX
- [x] `normalize_file_path_for_github()`: strips workspace/UUID/repo prefix → prevents PR 404
- [x] Remediation modal: GitHub-style diff view (red removed, green added)
- [x] Modal header: rule_id badge + short relative path
- [x] Strip backtick fences before rendering proposed code
- [x] `tests/test_github_path.py` (4 tests — 46 total)

### Tarea B — Tests + Docker
- [x] `tests/test_safe_patching_python.py` (6 tests — 52 total at Tarea B): build_safe_patched_content short patch, invalid patch, target not found, full-file replace, too-short guard, insert_missing_imports dedup
- [x] `docker-compose.yml`: services api + ollama + ollama-init, healthchecks, named volumes, no anonymous volumes
- [x] `Dockerfile`: python:3.12-slim base, installs code/requirements.txt, copies src/
- [x] `.env.example`: all required vars documented (GitHub App, OLLAMA_HOST, DATABASE_URL)

### Phase 2 — Dashboard UX II
- [x] Diff view split-screen: two-column Antes/Después (mobile → single column via `@media`)
- [x] ScanProfile cards: SVG icons (Py, Angular A, ☕ Java, shield Full Scan, gear Custom), real tool descriptions, stack badges, hover highlight
- [x] Project sidebar: severity mini-badges C / H / M / L per project
- [x] `GET /api/projects`: added `findings_summary: {CRITICAL, HIGH, MEDIUM, LOW, total}` to each project
- [x] Panel scan button `▶ Escanear` in findings panel header (synced spinner with header button)
- [x] Clone wizard step 2: GitHub / GitLab sub-selector with logos + dynamic URL placeholder

### Phase 2 — Dashboard UX III
- [x] Diff view: softer colors (#2a1212 / #122a12), per-column scroll (overflow-x/y:auto, max-height:380px), sticky line numbers (left:0)
- [x] Remediation modal: max-width:900px, max-height:85vh, diff wrapper flex:1, column headers sticky top:0
- [x] Header: removed redundant `▶ Escanear Proyecto` button — single scan entry point in project panel
- [x] Diff scroll clipping fix: parent wrapper `overflow:hidden` → `overflow:auto`; removed `height:100%` from `#diff-view` so columns drive height independently
- [x] PDF export: `⬇ Exportar PDF` button in Reporte tab — jsPDF + html2canvas + chart.toBase64Image() — cover page, executive summary, charts, top-50 findings table, footer with page numbers
- [x] `GET /api/projects` + `GET /api/projects/{id}`: include `last_scan_tool` and `last_scan_at` via efficient subquery (no N+1)

### Phase 2 — Dashboard UX IV (2026-05-25)
- [x] Table pagination: PAGE_SIZE=20, prev/next + page buttons, "X–Y de N" counter
- [x] Filter chips (All/Critical/High/Breach) functional — filter + sort + reset to page 1
- [x] Action button icons: Fix ✨ sparkles, Risk ⚠ triangle, FP ✗ circle, History 🕐 clock
- [x] PR button: rocket SVG icon
- [x] HIGH severity color: orange → red (#ef4444) across CSS, chart colors, and meta chip
- [x] Hero card: reduced padding (9px→6px), gap (7px→4px), figure font (28px→24px)
- [x] KPI spark charts: reduced height (40px→26px)
- [x] Severity badge pill inline in table rows (CRIT/HIGH/MED/LOW with color coding)
- [x] Remediation modal description: ES↔EN toggle button (shows when BANDIT_ES translation exists); BANDIT_ES dictionary covers ~35 common Bandit rules
- [x] PDF margins: container width uses contentW/2 so canvas=contentW after scale=2; addImage with PDF_MARGIN=22px horizontal offset

### Phase 2 — Dashboard UX V (2026-05-25)
- [x] PDF top/bottom margins: PDF_TOP=14, PDF_BOT=22; footer centered at `pageH - PDF_BOT/2` — no content overlap on any page
- [x] Export button relocated: removed from global header → sticky bar inside #findings-report-view only; PDF document icon, red (#c62828), "Exportar como PDF" / "Export as PDF"
- [x] Export button i18n: `btn-export-pdf` key in both locales; label updated by `applyI18n()` via data-i18n; `finally` block uses `t("btn-export-pdf")` to restore label
- [x] Report chart spacing: `#report-content` flex-column gap:10px; KPI grid margin-bottom:0; charts-grid gap:10px; chart-label font-size:.72rem, margin-bottom:6px

### Phase 2 — Reliability & Dedup (2026-05-25)
- [x] PR button icon inline: `white-space:nowrap` on button + `flex-shrink:0;display:block` on SVG — icon and text always on same line
- [x] Remediation cache: `POST /api/remediate/{id}` checks for existing `Remediation` row first; returns `cached:true` without calling Ollama; dashboard shows differentiated feedback
- [x] PR persistence: `Remediation.pr_url` + `Remediation.pr_branch` fields; SQLite migration in `ensure_sqlite_schema()`
- [x] PR deduplication: `GET /api/remediate/{id}/pr` returns persisted PR data; `POST` checks GitHub for open PR before creating a new one; persists result
- [x] `get_existing_open_pr_for_branch()` wrapper in `github_client.py` — manages httpx client internally
- [x] Dashboard `checkExistingPR()`: silently pre-fills PR link when modal opens if PR already exists
- [x] `CombinedScannerAdapter.tool_name`: concatenates all child tool names with `+`

### Phase 3 — Quality First (2026-05-26)
- [x] Pylint quality adapter for Python: JSON parsing, HIGH/MEDIUM/LOW mapping, missing-binary handling
- [x] ESLint quality adapter for Angular/TypeScript: local `node_modules/.bin/eslint` or `npx --no-install eslint`, JSON parsing, missing-binary handling
- [x] SonarQube Community REST adapter: imports unresolved issues via `SONARQUBE_URL`, `SONARQUBE_TOKEN`, optional `SONARQUBE_PROJECT_KEY`
- [x] `ScanOrchestrator._run_quality`: routes `quality_tool=pylint|eslint`, reports tool errors without crashing the scan
- [x] Dashboard custom profile: Code Quality selectable; creates a real ScanProfile with `quality_enabled` + `quality_tool`
- [x] Tests: adapter normalization/missing binary + orchestrator Quality success/error paths

### Phase 3 — SonarQube Integration Hardening (2026-05-25)
- [x] Bearer token auth (`Authorization: Bearer <token>`) replacing Basic Auth — SonarQube Community v26+ compatible
- [x] `run_sonar_scan(target_path)`: sonar-scanner CLI subprocess with graceful RuntimeError if not in PATH
- [x] `fetch_sonar_issues(page_size)`: standalone REST function with 401/404 explicit errors
- [x] `_sonar_env()`: centralized env-var helper (SONARQUBE_URL / TOKEN / PROJECT_KEY)
- [x] `POST /api/scan/sonar`: endpoint that optionally triggers CLI then fetches + persists issues
- [x] `SONARQUBE_URL` updated to `http://localhost:9000` in `.env` for local dev
- [x] SonarQube project `ai-devsecops-control-plane` created via REST API
- [x] Token validated: `{"valid": true}` via `GET /api/authentication/validate`
- [x] Tests updated: removed `auth=(token, "")` from mock clients (Bearer is the auth path now)

---

## Pendiente

### Bug crítico
- [x] `orchestrator._run_sast`: instanciar adapters directamente sin `os.environ["SCANNER_ENGINE"]`
- [x] `CombinedScannerAdapter.tool_name`: concatenar nombres de todos los hijos

### Phase 3 — Quality + DAST
- [ ] DAST adapter real (OWASP ZAP)
- [x] Quality adapter ligero (Pylint / ESLint)
- [x] Quality adapter SonarQube Community
- [ ] Post-patch validation: `tsc --noEmit` (Angular), `javac`/Maven (Java)
- [x] Diff view with LCS for line-level precision — `renderDiffView` v9: `max-height:calc(85vh-200px)` scroll (no DOM parent manipulation), `CONTEXT=20`, pad rows `#161b22` (visible neutral), aligned delete/insert rows, real line numbers, `···` separators, snippet fallback
- [ ] Multi-finding PR (batch remediation in one branch)
- [ ] Webhook: block merge on open critical findings

### Phase 3 — sonar-scanner CLI + PR Format (2026-05-26)
- [x] `sonar-scanner` CLI 6.2.1 installed in `~/.local/bin/sonar-scanner`
- [x] `sonar-project.properties` in repo root (token excluded, passed at runtime)
- [x] First real analysis: 125 issues in SonarQube project `ai-devsecops-control-plane`
- [x] `run_sonar_scan()`: fallback path detection for `~/.local/bin` and `/opt/sonar-scanner` when binary not in PATH
- [x] `build_pr_body()` restructured: `🔒 Security Fix — {severity} [{rule_id}]`, Herramienta/Archivo, Problema, Fix aplicado (extracted code block), Referencias CWE, footer ES
- [x] Dashboard `buildToolBadge()`: color-coded pill per scanner (SonarQube blue, Bandit yellow, Semgrep lightblue, ESLint red, Pylint green)
- [x] Dashboard `detectTool(finding)`: infers scanner from `rule_id` namespace (`python:`, `gitlab.bandit.`, `B\d{3}`, etc.) — fixes badge showing wrong tool for SonarQube findings
- [x] `GET /api/ping` 500 fix: add `iputils-ping` to Dockerfile + `FileNotFoundError` → HTTP 503 + `timeout=15` in `subprocess.run`
