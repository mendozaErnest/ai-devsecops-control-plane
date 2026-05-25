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

### Phase 2 — Dashboard UX II
- [x] Diff view split-screen: two-column Antes/Después (mobile → single column via `@media`)
- [x] ScanProfile cards: SVG icons (Py, Angular A, ☕ Java, shield Full Scan, gear Custom), real tool descriptions, stack badges, hover highlight
- [x] Project sidebar: severity mini-badges C / H / M / L per project
- [x] `GET /api/projects`: added `findings_summary: {CRITICAL, HIGH, MEDIUM, LOW, total}` to each project
- [x] Panel scan button `▶ Escanear` in findings panel header (synced spinner with header button)
- [x] Clone wizard step 2: GitHub / GitLab sub-selector with logos + dynamic URL placeholder

### Phase 2 — Dashboard UX III
- [x] Diff view: softer colors (#2a1212 / #122a12), per-column scroll (overflow-x/y:auto, max-height:380px), sticky line numbers (left:0)
- [x] Remediation modal: max-height:85vh, diff wrapper flex:1 (fills available height), column headers sticky top:0
- [x] Header: removed redundant `▶ Escanear Proyecto` button — single scan entry point in project panel
- [x] PDF export: `⬇ Exportar PDF` button in Reporte tab — jsPDF + html2canvas + chart.toBase64Image() — cover page, executive summary, charts, top-50 findings table, footer with page numbers
- [x] `GET /api/projects` + `GET /api/projects/{id}`: include `last_scan_tool` and `last_scan_at` via efficient subquery (no N+1)

---

## Pendiente

### Bug crítico
- [x] `orchestrator._run_sast`: instanciar adapters directamente sin `os.environ["SCANNER_ENGINE"]`
- [ ] `CombinedScannerAdapter.tool_name`: concatenar nombres de todos los hijos (pendiente)

### Phase 3 — Quality + DAST
- [ ] DAST adapter real (OWASP ZAP)
- [ ] Quality adapter (SonarQube Community / Pylint / ESLint)
- [ ] Post-patch validation: `tsc --noEmit` (Angular), `javac`/Maven (Java)
- [ ] Diff view with LCS for line-level precision (currently shows all-old then all-new)
- [ ] Multi-finding PR (batch remediation in one branch)
- [ ] Webhook: block merge on open critical findings
