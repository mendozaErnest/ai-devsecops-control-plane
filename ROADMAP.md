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

### Phase 2 — Generalizar target_path (ítem 23, 2026-05-27)
- [x] `ScanRequest`: `project_id`, `target_path`, `profile_id`, `technology` todos opcionales; anteriormente `target_path` y `technology` eran obligatorios
- [x] `POST /api/scan`: resolución por prioridad — 1) `target_path` explícito → `validate_scan_target` → `run_scan`; 2) `project_id` → `project.target_path` en DB → `scan_project` (con profile override); 3) fallback `dummy_vulnerable_app.py`
- [x] `validate_scan_target`: ya existente — remap legacy path + check existencia (404) + check en allowed roots (403)
- [x] `get_allowed_scan_roots` + `SCAN_ALLOWED_ROOTS` env var: ya existente — documentada en `.env.example`
- [x] `api.js` `triggerScan(projectId, profileId)`: nueva función export — llama `POST /api/scan` con `{project_id, profile_id}`
- [x] `tests/test_target_path_validation.py` (4 tests): valid path inside workspace, path traversal blocked (403), nonexistent path (404), fallback to dummy retro-compat

### Phase 3 — Quality + DAST
- [x] DAST adapter real (OWASP ZAP) — `ZapAdapter` con spider + active scan via REST; `_run_dast` orquestrado con `dast_target_url` desde `POST /api/scan` y `POST /api/projects/{id}/scan`; ZAP en docker-compose arranca por defecto (puerto 8090) con healthcheck y `restart: unless-stopped`; degrada gracefully si ZAP no responde; URL inválida → HTTP 400 desde `resolve_dast_target_url`; 6 tests nuevos en `test_dast_orchestrator.py`
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

### Phase 3 — Modal PR Diff + Badge Fix (2026-05-26)
- [x] `get_pr_diff(pr_url)` in `github_client.py`: fetches real GitHub unified diff via App auth (`Accept: application/vnd.github.v3.diff`)
- [x] `GET /api/findings/{finding_id}/pr-diff`: new endpoint — looks up `Remediation.pr_url`, returns real diff; `{"diff": null}` if no PR
- [x] `renderGitHubDiff(rawDiff)` in dashboard: parses unified diff, calls `renderDiffView` with before/after content, appends "✓ Diff real del PR en GitHub" badge
- [x] `checkExistingPR()` updated: when PR exists, also fetches and renders real GitHub diff (overrides Ollama diff)
- [x] `detectTool()` bug fix: `python.lang.*`, `gitlab.*` dot-notation → Semgrep (not SonarQube); SonarQube detected only by `namespace:Snumber` format (e.g. `python:S8415`)

### Phase 3 — Modal diff side-by-side completo (2026-05-26)
- [x] `renderGitHubDiff()` reescrita: async, obtiene archivo completo via `/api/findings/{id}/file_content`, aplica patch para construir DESPUÉS, muestra archivo completo en ambos paneles
- [x] Panel ANTES: archivo original, líneas eliminadas resaltadas rojo (#3d1a1a / #ff9090)
- [x] Panel DESPUÉS: archivo parcheado (patch aplicado), líneas añadidas resaltadas verde (#1a3d1a / #90ff90)
- [x] Header: `— Antes | ✓ Diff real del PR en GitHub | + Después` — sin toggle
- [x] Auto-scroll al primer cambio (firstChanged - 5 líneas) en ambos paneles
- [x] Scroll sincronizado entre paneles
- [x] `buildDiffToolbar()` simplificada: eliminados botones "Ver diff" / "Ver archivo"
- [x] `showFullFileView()` eliminada (ya no necesaria)

### Phase 3 — Bug fixes modal diff + PR creation (2026-05-26)
- [x] Bug1 `buildAntesRows`: añade `fi = h0` explícito tras el fill loop — garantiza sincronía con `oldStart` del hunk; nunca usa `c.content` del diff como contenido de línea
- [x] Bug1 `buildDespuesRows`: misma corrección de sincronía `fi = h0`
- [x] Bug1 CSS: añade clase `fb-warning` (amarillo) y mapeo en `showFeedback()`
- [x] Bug2 `_apply_approximate_anchor`: 3 estrategias fallback (line-range+AST → comentario insertado → force-patch); nunca lanza `GitHubClientError` por fallo de ancla
- [x] Bug2 `create_security_pr`: propaga `anchor_warning` en el dict de retorno
- [x] Bug2 `POST /api/remediate/{id}/pr`: devuelve 200 con `warning` + `status: created_with_warning` cuando el ancla fue aproximada
- [x] Bug2 dashboard `createPullRequest()`: muestra `renderPullRequestSuccess` + aviso amarillo cuando `result.warning` está presente; no deshabilita el botón

### Phase 3 — Bug fixes modal remediación (2026-05-26)
- [x] P1 `GET /api/findings/{id}/pr-diff`: filtra `.where(Remediation.pr_url != None)` antes de `.order_by(id.desc())` — evita que una fila más reciente sin `pr_url` tape a la que sí lo tiene
- [x] P2 `showRemediationModal()` / `hideRemediationModal()`: `document.body.style.overflow = 'hidden'` al abrir, `''` al cerrar — bloquea scroll del fondo mientras el modal está abierto
- [x] P3 scroll sync ANTES/DESPUÉS: añade `scrollLeft` a los listeners existentes + `requestAnimationFrame` para reset del flag — sincroniza scroll vertical y horizontal en ambas direcciones

### Phase 3 — Dashboard JS/CSS Refactor (2026-05-26)
- [x] `index.html` rewritten as pure HTML shell (no inline `<style>` or `<script>`)
- [x] `css/base.css`: CSS variables, reset, scrollbar, animations (pulse-dot, spin-anim, blink-red)
- [x] `css/layout.css`: nav, bento grid, cards, hero, KPI, wave, workers, findings list, pagination, view-toggle, chips
- [x] `css/modal.css`: modal overlays, tab buttons (tab-btn/tab-active/tab-inactive), form panels, severity badges, project button, table row hover, report card styles
- [x] `js/utils.js`: i18n strings (ES/EN), `applyI18n()`, `t()`, `setLang()`, `currentLang`, `buildToolBadge()`, `detectTool()`, `cleanCodeFences()`, `shortPath()`, `BANDIT_ES`
- [x] `js/api.js`: all `fetch()` wrappers — `apiFetch()`, projects, findings, scan, remediation, PR, audit, file content, PR diff, report
- [x] `js/diff.js`: LCS-based `renderDiffView()`, GitHub unified-diff `renderGitHubDiff()`, `buildDiffToolbar()`
- [x] `js/modal.js`: project modal 2-step wizard, remediation modal, branch-confirm modal, reason modal, audit modal — all lifecycle wiring
- [x] `js/dashboard.js`: findings render + pagination + filter chips, scan trigger, chart rendering, PDF export
- [x] `js/main.js`: entry point — imports all modules, wires events, language toggle, scroll listener, boot sequence
- [x] `src/api/main.py`: added `StaticFiles` mount at `/static` → `src/dashboard/` directory; `from fastapi.staticfiles import StaticFiles`
- [x] 65 tests passing (no regression)

### Phase 3 — Post-Refactor CSS/JS Bug Fixes (2026-05-26)
- [x] `layout.css` line 116: `.project-menu.open { display: none !important }` → `display: block !important` — CSS refactor had inverted the open state, permanently hiding the projects popover
- [x] `dashboard.js` `wireDashboardEvents()`: wire `.repo` click to toggle `#projects-popover .open`; outside-click and Escape key close the popover
- [x] `dashboard.js` `selectProject()`: close popover automatically on project selection

### Phase 3 — Critical Bug Fixes: Modal Diff + Destructive Commits (2026-05-26)
- [x] **P1** `modal.js` epoch guard: `_modalEpoch` counter — incremented on every `showRemediationModal` call; async IIFE and `checkExistingPR` capture epoch and self-abort if stale; `diffView.innerHTML` cleared immediately with loading placeholder; `hideRemediationModal` also increments epoch to cancel in-flight fetches
- [x] **P2** `diff.js` ANTES real-file: `renderDiffView` no longer uses LCS "deleted" lines (leftDiff) for the ANTES column when `fileData` is available — instead shows real file lines marked type `"hi"` (subtle blue); prevents Ollama's descriptive text (`- Use Annotated type hints…`) from appearing as deleted code
- [x] **P3** `github_client.py` `is_safe_to_apply(original, patched)`: 3 guardrails — >20% line removal, generic stub signals (`some_api_endpoint`, `some_dependency`, `# Function body remains unchanged`, …), function deletion detection
- [x] **P3** `github_client.py` `create_proposal_pr(finding_details, text, reason)`: creates branch `security-proposal-{id}` + commits `docs/remediations/{id}.md` with Ollama proposal — no source code modified; opens PR titled `⚠️ Manual review: {rule_id}`
- [x] **P3** `github_client.py` `create_security_pr`: calls `is_safe_to_apply` after computing patched content; raises `GitHubClientError(code="safety_check_failed")` if unsafe; returns `pr_type="code_fix"` when safe
- [x] **P3** `main.py` endpoint `POST /api/remediate/{id}/pr`: catches `safety_check_failed` → routes to `create_proposal_pr`; response includes `pr_type` ("code_fix" | "proposal") and `warning` / `status` fields
- [x] **P3** `modal.js` PR type badge: `renderPullRequestSuccess(prUrl, prType)` shows yellow **"⚠ PR de propuesta"** badge or green **"✓ Fix aplicado"** badge; `createPullRequest` shows differentiated feedback for proposals
- [x] PR #16 confirmed NOT merged in main — no revert needed

### Phase 3 — Technology Inference Fix (2026-05-26)
- [x] `remediator.py` `infer_technology_from_finding(rule_id, file_path)`: new function — priority 1 = rule_id namespace (`javascript:`, `typescript:`, `web:`, `python:`, `java:`, `squid:`, `gitlab.bandit.`, `B\d{3}`, Semgrep dot-namespaces), priority 2 = file extension (`.html`/`.js`/`.ts` → angular, `.py` → python, `.java`/`.kt` → java), returns `None` when insufficient evidence so caller falls back to project technology
- [x] `remediator.py` `enrich_finding_details`: calls `infer_technology_from_finding` first — if it returns a value, uses it directly; otherwise falls back to `finding_details["technology"]` → project DB lookup
- [x] `main.py` `build_finding_details`: imports `infer_technology_from_finding`; uses inferred technology over project technology so both `generate_patch` (prompt selection) and `create_security_pr` (patch strategy) use the correct language
- [x] `tests/test_technology_inference.py` (29 tests): SonarQube JS/TS/Python/Java namespaces, Bandit rules, Semgrep dot-namespaces, file extension fallbacks, None for unknown, regression test `javascript:S3358 in index.html → angular` (the reported bug)

### Phase 3 — CSS/HTML Remediation Support + Diff Viewer Guard (2026-05-27)
- [x] `remediator.py` `build_css_prompt()`: strict-contract CSS/SCSS prompt — returns only a ` ```css ` fenced block, never Python; guides: deduplicate selectors, no !important, keep specificity
- [x] `remediator.py` `build_html_prompt()`: strict-contract HTML5 prompt — returns only a ` ```html ` fenced block; security guides: `rel="noopener noreferrer"`, autocomplete attrs, no deprecated attrs, XSS via textContent
- [x] `remediator.py` `build_prompt()`: dispatches `technology="css"` → `build_css_prompt()` and `"html"` → `build_html_prompt()`; fixes `css:S4666` (.fb-error duplicate selector) generating Python `# No code needed` response
- [x] `remediator.py` `normalize_technology()`: recognises `css:*/web:css*` rule namespaces → "css"; `html.*/html:*/web:html*` → "html"; `.css/.scss/.sass/.less` extensions → "css"; `.html/.htm/.jinja/.j2` → "html"; placed before the rule_id check so CSS rule in .html file stays "css"
- [x] `remediator.py` `build_safe_fallback_code()`: CSS fallback → `/* AI unavailable */`; HTML fallback → `<!-- AI unavailable -->`; both return `code_snippet` unchanged when available
- [x] `github_client.py` `normalize_patch_technology()`: added `"javascript"` → `"angular"` coercion (already had typescript); CSS/HTML pass-through verified
- [x] `github_client.py` `code_fence_label_for_technology()`: `"css"` → `"css"`, `"html"` → `"html"` — correct fence label in PR body
- [x] `github_client.py` `extract_generic_code_block()`: `labels_by_technology` includes `"css": ("css","scss","sass","less")` and `"html": ("html","htm")` — extracts CSS/HTML blocks from Ollama response
- [x] `github_client.py` `normalize_patch_technology_for_finding()`: rule_id CSS/HTML namespaces + file extension fallback for `.css/.scss/.html/.htm/.jinja` files
- [x] `diff.js` `renderDiffView()`: guard for null/empty snippet — shows "Sin código disponible" message when both sides empty; `forceReplacement=true` when `safeSnippet === safeProposed` forcing explicit delete+insert ops (eliminates "all-blue left column" bug); `effectiveSnippet`/`effectiveProposed` guard prevents undefined access
- [x] `tests/test_remediator.py` (3 tests): `test_css_technology_detection`, `test_html_file_technology_detection`, `test_css_prompt_no_python`
- [x] `tests/test_remediation_language_guards.py` (4 tests): JavaScript rule in .html not patched as Python; frontend remediation rejects Python function block; cached Python remediation invalid for JS finding; JS fence valid for JS/HTML finding
- [x] `tests/test_safe_patching_python.py` expanded to 12 tests (+6: S1192 constant extraction, S1192 rejects invented functions, B324 deterministic PBKDF2 patch, B324 rejects renamed SHA256 function)

### Phase 3 — is_safe_to_apply + Angular Prompt JS Guards (2026-05-27)
- [x] **Root cause (PR #31 bad fix)**: `is_safe_to_apply` function-deletion check used `r"def (\w+)\("` (Python only) — missed JS named-function deletions like `async function postLifecycle(`; stub-signal list lacked JS/TS hallucination markers (`"// Method implementation here"` etc.); angular prompt allowed generating fake TypeScript class examples
- [x] `github_client.py` `_extract_named_functions(source)`: new helper — extracts function names from Python (`def`) and JavaScript/TypeScript (`function` declarations, including `async function`); used in `is_safe_to_apply` check 3
- [x] `github_client.py` `is_safe_to_apply` check 2: extended stub signals with JS/TS hallucination markers: `"// Method implementation here"`, `"// Example of a method that"`, `"// Corrected usage of the method"`, `"// Assuming the problematic function"`, `"problematicFunction"`, `"callProblematic"`
- [x] `github_client.py` `is_safe_to_apply` check 3: now uses `_extract_named_functions` instead of raw Python-only regex — detects deletion of JS functions like `postLifecycle`
- [x] `remediator.py` `_base_angular_prompt`: added explicit constraints against generating new TS classes/generic examples; S930-specific guidance (fix function signature OR fix call site); JS-in-HTML hint when `javascript:*` rule targets `.html` file; includes `expected_function` name hint when available; code context block re-labeled `javascript` instead of `angular`
- [x] `tests/test_remediation_language_guards.py` expanded to 10 tests (+6): JS function deletion blocked; function-deletion fires in isolation without stub signals; `_extract_named_functions` finds Python + JS names; S930 prompt includes argument guidance; angular prompt forbids new class creation
- [x] 113 tests passing — no regression

### Phase 3 — Fix PR Solution Inconsistency (2026-05-27)
- [x] **Root cause**: `remediation_matches_finding_technology()` called `validate_remediation_patch()` which re-read the local source file and re-applied the patch; any local edit to the file (`M src/api/main.py`) caused the cache check to fail → Ollama re-called → different patch each time
- [x] `main.py` `cached_remediation_is_reusable(patch_diff, finding_details)`: lightweight cache check — verifies only that the stored patch contains a valid code block for the inferred technology; does NOT read or re-apply to local source file; special-cased for S1192/B324 deterministic rules
- [x] `main.py` `remediate_finding`: replaced `remediation_matches_finding_technology` with `cached_remediation_is_reusable` in the cache-hit branch — Ollama now called only once per finding; same patch always returned
- [x] `main.py` `GET /api/remediate/{finding_id}/preview-diff`: new endpoint — applies `build_safe_patched_content` to local source file and returns `{original, patched}` for accurate diff preview before PR creation; 404 if source not accessible locally
- [x] `github_client.py`: imported `looks_like_python_only_prose` into `main.py` for use in `cached_remediation_is_reusable`
- [x] `api.js` `getRemediationPreview(findingId)`: new fetch wrapper for `GET /api/remediate/{id}/preview-diff`; returns `null` on non-200 responses
- [x] `diff.js` `renderPreviewDiff(diffViewEl, originalContent, patchedContent)`: full-file LCS diff with 5-line context collapse; badge "✓ Vista previa exacta del PR" in green; uses shared module-level `computeDiff` and `normalizeLines`
- [x] `diff.js` refactor: extracted `computeDiff` and `normalizeLines` to module scope — eliminates duplicate implementation (S4144); nested-ternary in `buildColumn`/`buildCol` replaced with explicit `if/else` (S3358)
- [x] `modal.js` IIFE updated: `Promise.allSettled([getSourceFile, getRemediationPreview])` fetches both in parallel; if preview available → `renderPreviewDiff` (exact match with PR); otherwise falls back to `renderDiffView` (AI proposal with context)
- [x] 107 tests passing — no regression

### Phase 2 — Finding Lifecycle (2026-05-27)
- [x] `escaneo.py` `persist_scan()`: regression detection on re-scan — `fixed` → `regression`, increments `regression_count`, creates `FindingAuditEvent(event_type="regression")`
- [x] `escaneo.py` `upsert_finding()`: same regression logic for Bandit upsert path
- [x] `escaneo.py`: `accepted_risk` / `false_positive` findings are skipped on re-scan (human decision preserved)
- [x] `models.py` `FindingAuditEvent`: table with `finding_id`, `event_type`, `from_status`, `to_status`, `reason`, `created_at`
- [x] `main.py` `POST /api/findings/{id}/accept-risk`: sets status `accepted_risk` + audit event
- [x] `main.py` `POST /api/findings/{id}/false-positive`: sets status `false_positive` + audit event
- [x] `main.py` `GET /api/findings/{id}/audit`: returns full audit trail with `current_status` + `regression_count`
- [x] `dashboard.js` `buildLifecycleBadge()`: status badges — open (blue), regression (red + ↩N counter), fixed (green), accepted_risk (yellow), false_positive (grey)
- [x] `dashboard.js` `buildActionButtons()`: Accept Risk + False Positive buttons hidden for already-ignored findings; History button always shown
- [x] `modal.js` `openReasonModal()`: capture reason via modal textarea (not `prompt()`)
- [x] `modal.js` `openAuditModal()`: renders audit event timeline for a finding
- [x] `modal.js` `postLifecycle()`: POSTs triage action + refreshes findings without page reload
- [x] `utils.js` `lifecycleStyle()`: CSS-in-JS map for all 5 lifecycle states

### Phase 3 — Bug Fixes: Modal Empty Diff + JS Placeholder Patches (2026-05-27)
- [x] **Bug 1** `diff.js` `renderDiffView()` line 67: `toDiffLines()` referenced but never defined → `ReferenceError` → diff area permanently empty when `renderPreviewDiff` fallback fires; fixed to `normalizeLines(effectiveProposed)`
- [x] **Bug 2** `main.py` `enrich_js_finding_context()`: new function — reads source file, calls `find_enclosing_js_function()` to extract the full enclosing function for Angular/JS findings; overrides `code_snippet` so Ollama gets the complete body (not just 1-2 lines); prevents placeholder generation for cognitive-complexity rules like `javascript:S3776`
- [x] **Bug 2** `main.py` `find_enclosing_js_function(source, line_number)`: regex-based JS/TS function extractor — handles `function name()`, `const name = function()`, `const name = () =>`, TS class methods via `ts_line_looks_like_method_signature`; uses existing `find_braced_block_range` for brace-counting; returns `(name, source)` tuple
- [x] **Bug 2** `main.py` `build_finding_details()`: calls `enrich_js_finding_context(details)` after `enrich_python_finding_context(details)` — non-Python enrichment now runs for Angular/JS findings
- [x] **Bug 2** `main.py` imports: added `find_braced_block_range`, `ts_line_looks_like_method_signature` from `github_client`; added `import re`
- [x] **Bug 3** `remediator.py` `_base_angular_prompt()`: adds `cognitive_complexity_guidance` for `s3776`-family rules — demands real refactoring, forbids placeholder/refactoredFunction/TODO; includes `full_function_section` block when `expected_function_source` differs from `code_snippet` (full function context from enrichment); global contract now explicitly bans placeholders/stubs
- [x] **Bug 4** `main.py` `remediate_finding`: replaced 422 with graceful `200 + validation_warning` when `validate_remediation_patch` fails — patch saved with `outcome="manual_review"`; modal always opens; frontend shows orange warning banner
- [x] **Bug 4** `main.py` `create_remediation_pr`: `manual_review` patches skip code-fix PR entirely → go straight to `create_proposal_pr`; language-mismatch 409 check still applies to stale patches that differ by technology
- [x] **Bug 4** `dashboard.js` `remediateFinding()`: checks `result.validation_warning` — shows warning feedback but still opens modal; success message unchanged for valid patches
- [x] **Bug 5** `github_client.py` `is_safe_to_apply` stub signals: added 8 JS placeholder signals — `"function refactoredFunction"`, `"refactoredFunction()"`, `"// Placeholder for the refactored function"`, `"// Implement the refactored logic"`, `"// TODO: implement"`, `"// TODO: refactor"`, `"// implement refactored"`, `"// insert refactored"`
- [x] 113 tests passing — no regression

### Phase 2 — SLA Tracking Visibility (2026-05-27)

- [x] `main.py` `_SLA_EXEMPT_STATUSES`: constant set `{"accepted_risk", "false_positive", "fixed"}` — lifecycle-exempt from active SLA
- [x] `main.py` `get_sla_status(finding, now)`: returns `"ok"` / `"warning"` (deadline ≤3 days away) / `"breached"` (past deadline) / `"exempt"` / `"unknown"` (null deadline); timezone-naive `sla_deadline` normalized with `.replace(tzinfo=timezone.utc)` before comparison
- [x] `main.py` `GET /api/findings`: accepts `?sla_status=` query param; includes `sla_status` + `sla_deadline` in each finding dict
- [x] `main.py` `GET /api/projects/{id}/findings`: includes `sla_status` + `sla_deadline` in each finding dict (dashboard endpoint)
- [x] `dashboard.js` `buildSlaBadge()`: uses server-provided `sla_status`; shows deadline as `MMM DD` date label (not remaining duration); client-side fallback when `sla_status` absent; empty `<span>` for `exempt` status
- [x] `dashboard.js` helpers: `effectiveSlaStatus()`, `_buildSlaFoot(breached, warning)`, `_countSlaStatuses(records)`, `_pct(n, total)`, `_updateRadialArcs(counts, total)` — extracted to reduce S3776 cognitive complexity from 23 → ~14 (below pre-existing baseline of 17)
- [x] `dashboard.js` `updateCounters()`: KPI footer shows `🔴 N vencidos` and `⚠ N por vencer` when > 0; populates `#sla-breaches` and `#sla-foot` elements
- [x] 113 tests passing — no regression

### Phase 3 — Configuration Page UX (2026-05-28)
- [x] `modal.css` `.builder-palette`: `max-height: 430px` → `min-height: 520px` — all palette chips visible without hidden scroll (CAMBIO 1)
- [x] `profile-builder-view.js` `initProfileBuilderView()`: always calls `createEmptyProfileBuilderState()` on load — form starts empty regardless of sessionStorage (CAMBIO 2)
- [x] `profile-builder-view.js` module-level `activeProfileId` / `activeProfile`: profile activation tracked independently from the builder draft form
- [x] `profile-builder-view.js` `activateProfile(profile)`: "Usar" button marks card visually active, shows "Perfil activo: X" label, enables header buttons — does NOT fill builder form, does NOT open modal (CAMBIO 3)
- [x] `profile-builder-view.js` `updateActionButtons()`: "Agregar proyecto" + "Ver proyectos escaneados" header buttons disabled (opacity .45 / not-allowed) until a profile is activated via "Usar" (CAMBIO 4)
- [x] `profile-builder-view.js` `renderSavedProfiles()`: removed `tabIndex`, `role="button"`, `title` and card-level click/keydown handlers — only the "Usar" button acts (CAMBIO 3)
- [x] `index.html`: added `<div id="active-profile-label">` between panel head and saved-profiles-list for the active-profile indicator
- [x] `layout.css` `.saved-profile-item`: `cursor: pointer` → `cursor: default`; removed card `:hover/:focus` highlight (cards no longer interactive)
- [x] `dashboard.js` `buildScannerIconBadge(toolKey)`: per-tool colored badge (monospace short label) using `TOOL_BADGE_COLOR` map (CAMBIO 4b)
- [x] `dashboard.js` `TOOL_BADGE_COLOR`: color map matching existing `scan-chip` per-tool colors
- [x] `dashboard.js` `renderProjects()`: parses `project.last_scan_tool` (split by `+`), normalizes each key via `normalizeToolKey()`, renders scanner icon badges below severity row
- [x] 124 tests passing — no regression

### Phase 3 — Dashboard UX: Scanner Filter Icons + Routing (2026-05-28)
- [x] `dashboard.js` `renderScannerFilterIcons()`: detects all scanners present in loaded findings via `detectTool()`; renders scanner chips (All + one per tool) in `#scanner-filter-icons`; hidden when only 1 scanner
- [x] `dashboard.js` `setActiveScannerFilter(key)`: updates `activeScannerFilter`, rebuilds `filteredFindings`, re-renders page + refreshes chip active states
- [x] `dashboard.js` `getFilteredSorted()`: applies `activeScannerFilter` before severity filter — scanner and severity filters compose independently
- [x] `dashboard.js` `loadFindings()`: resets `activeScannerFilter = "all"` on project change; calls `renderScannerFilterIcons()`; `tableStatus` shows count only (removed "python · repo" text)
- [x] `index.html`: added `<div id="scanner-filter-icons" class="scanner-filt">` between severity chips and export button
- [x] `layout.css`: `.scanner-filt` (flex container with left-border separator) + `.scan-chip` base + per-tool color variants (semgrep blue, bandit amber, sonarqube sky, eslint purple, pylint green, zap red, pip-audit lightblue, odc orange) + `.on` active state with matching glow
- [x] `main.js` `showAppView(view, push)`: pushes `history.pushState({ view })` on each navigation — browser back/forward now works
- [x] `main.js` `popstate` listener: calls `showAppView(e.state.view, false)` to restore view without double-pushing
- [x] `main.js` boot: reads hash on load (`#configuration` | `#projects` | `#reports`); uses `history.replaceState` for initial entry
- [x] 124 tests passing — no regression

### Phase 3 — Scan Crash Fix + Visibility + SonarQube Language (2026-05-28)
- [x] `dashboard.js` `runScan()`: removed undefined `updateDastTargetUrlInput()` call (ReferenceError crash on every scan); replaced with inline `selectedProjectProfile()` check — if DAST enabled, prompts for target URL via `globalThis.prompt`; otherwise passes `null` gracefully
- [x] `dashboard.js` `runScan()`: enriched success feedback — shows `scan_summary` per-tool counts `[bandit: 12 · semgrep: 4]`, `warnings` (ℹ), `errors` (⚠), and differentiates `"info"` / `"success"` / `"warning"` message types; "Sin hallazgos nuevos" message when 0 saved
- [x] `sonarqube_adapter.py` `run_sonar_scan()`: removed hardcoded `-Dsonar.language=py` — CLI now auto-detects language; Angular/TypeScript/Java projects are analyzed correctly
- [x] `orchestrator.py` `OrchestratorResult`: added `scan_summary: dict` (tool → count from pre-dedup findings) and `warnings: list` (non-fatal notices)
- [x] `orchestrator.py` `run()`: handles tuple `(findings, notices)` return from `_run_quality` — appends notices to `warnings`; builds `scan_summary` by counting `finding.tool` across all findings; passes both fields to `OrchestratorResult`
- [x] `orchestrator.py` `_run_quality()`: returns `(findings, notices)` tuple; appends tech-incompatible notice (`"pylint: tecnología 'angular' no compatible — saltado"`) instead of silently skipping; appends 0-findings notice when adapter connects but returns empty; only raises RuntimeError for real adapter errors
- [x] `api/main.py` `_scan_with_profile()`: includes `warnings` and `scan_summary` in response dict
- [x] 124 tests passing — no regression

### Phase 3 — SonarQube + Profile Builder Fixes (2026-05-28)
- [x] `sonarqube_adapter.py` `normalize_issue()`: sets `tool="sonarqube"` on each Finding — fixes findings being persisted with wrong tool label (SAST adapter name) when scanning with a profile that includes SonarQube quality tool
- [x] `orchestrator.py` `_run_quality()`: rewrote to support comma-separated quality tools ("pylint,sonarqube"); expanded tech sets — pylint covers django/flask, eslint covers react, sonarqube covers django/flask/java-spring; degrades per-tool (logs error + continues) instead of failing entire quality runner; raises RuntimeError only if ALL tools fail and 0 findings returned
- [x] `profile-builder-state.js` `canDropScannerOnTechnology()`: removed ZAP "necesitará URL" warning — DAST URL is provided at scan time, not profile creation time
- [x] `profile-builder-state.js` `validateProfileDraft()`: removed 1-quality-tool restriction (`quality.length > 1` error)
- [x] `profile-builder-state.js` `toScanProfilePayload()`: `quality_tool` now joins multiple tools with comma ("pylint,sonarqube")
- [x] `profile-builder-state.js` `profileScanners()`: splits comma-separated `quality_tool` when reconstructing draft from saved profile
- [x] `dashboard.js` `STACK_ICON_META`: replaced text `mark` with full inline SVG `icon` for every tool (Python interlock, Angular A, TypeScript box+T, Java cup, Semgrep magnifier+cross, Bandit shield+!, ZAP bolt, Pylint check-circle, ESLint hexagon, SonarQube radar waves, pip-audit package+check, odc shield+check)
- [x] `dashboard.js` `updateScanStackIcons()`: shows active profile name chip before tool chips; renders SVG icons via `item.icon`
- [x] `layout.css`: added `.scan-stack-icons`, `.scan-stack-profile`, `.scan-stack-chip` (surface-2 bg + left-border 2.5px), `.scan-stack-icon`, `.scan-stack-label`, `.scan-stack-empty` + 8 tone color variants (python/angular/typescript/java/sast/dast/quality/sca)
- [x] 124 tests passing — no regression

### Phase 4 — Observabilidad: Prometheus + Grafana (feat/observability, 2026-06-02) ✅
- [x] `src/metrics/security_metrics.py`: 6 custom Prometheus metrics — `findings_total` (Counter, labels severity+tool), `remediations_generated_total` (Counter, label source), `regressions_detected_total` (Counter), `sla_breached_findings` (Gauge), `scan_duration_seconds` (Histogram, label tool), `remediation_latency_seconds` (Histogram, label source). Noop stubs when `prometheus_client` absent — main flow never breaks.
- [x] `src/api/main.py`: `prometheus_fastapi_instrumentator.Instrumentator` instruments app and exposes `GET /metrics` (try/except for graceful degradation). Imports `record_remediation`, `record_scan_duration`, `update_sla_breached_gauge`. `_refresh_sla_breached_gauge()` counts open/regression findings with SLA breached; called in `on_startup` and after `_scan_with_profile`. `record_remediation("db_cache"|"ollama"|"fallback")` on each remediation path; `remediation_latency_seconds` observed on Ollama calls.
- [x] `src/scanners/escaneo.py`: `persist_scan()` calls `record_finding(severity, tool)` per finding and `record_regression()` on regression detection.
- [x] `docker-compose.yml`: added `prometheus` (prom/prometheus:latest, port 9090) and `grafana` (grafana/grafana:latest, port 3000, anonymous Viewer, no login form). Named volumes `prometheus_data` and `grafana_data` added.
- [x] `infra/prometheus/prometheus.yml`: global scrape_interval 15s; job `ai-devsecops-api` → `api:8000` on `/metrics`.
- [x] `infra/grafana/provisioning/datasources/prometheus.yml`: Prometheus datasource, isDefault=true, url `http://prometheus:9090`.
- [x] `infra/grafana/provisioning/dashboards/dashboard.yml`: file provider, path `/etc/grafana/provisioning/dashboards`, auto-refresh 30s.
- [x] `infra/grafana/provisioning/dashboards/devsecops.json`: 6-panel dashboard — findings by severity (barchart), regression rate (stat), SLA breached (stat red if >0), remediation latency p50/p95 (timeseries), remediation source ratio (piechart), scan duration by tool (timeseries).
- [x] `code/requirements.txt`: added `prometheus-fastapi-instrumentator>=6.1.0`.
- [x] `tests/test_metrics.py` (7 tests): GET /metrics returns 200 text/plain, record_finding no raise, record_regression no raise, persist_scan calls record_finding per finding, cache hit records db_cache, ollama latency observed, SLA breached gauge reflects real DB count.
- [x] 130 tests passing (6 new + 1 skipped when prometheus_fastapi_instrumentator not installed) — no regression.

### Phase 4 — DAST Real con ZAP (2026-06-02) ✅
- [x] `src/api/main.py` `ScanRequest`: campo `target_url` renombrado a `dast_target_url` para reflejar explícitamente que solo aplica a DAST runner; validación movida del `field_validator` (que daba 422) a `resolve_dast_target_url()` helper (devuelve HTTP 400 limpio); endpoints `POST /api/scan` y `POST /api/projects/{id}/scan` llaman `resolve_dast_target_url(request.dast_target_url)` antes de despachar.
- [x] `src/api/main.py` `scan_project()` + `_scan_with_profile()`: firma renombrada `target_url` → `dast_target_url`; pasa la URL al `ScanOrchestrator.run()` que la rutea al `_run_dast` runner.
- [x] `src/dashboard/js/api.js` `scanProject()`: body envía `dast_target_url` (antes `target_url`).
- [x] `src/dashboard/js/dashboard.js` `runScan()`: prompt al usuario por URL DAST cuando perfil tiene `dast_enabled=true`; pasa al endpoint via `scanProject(projectId, dastTargetUrl)`.
- [x] `docker-compose.yml`: servicio `zap` ya no requiere profile `dast` — arranca por defecto con `restart: unless-stopped`, healthcheck nuevo (`wget /JSON/core/view/version/`), 30s interval, 60s start_period. Variable de entorno del servicio api cambiada de `ZAP_API_URL: http://zap:8080` (errónea) a `ZAP_BASE_URL: http://zap:8090` (correcta — el adapter usa esa variable).
- [x] `.env.example`: documentadas `ZAP_BASE_URL` (default `http://localhost:8090`) y `ZAP_API_KEY` (vacío por defecto, ZAP arranca con `api.disablekey=true`).
- [x] `README.md`: Stack actualizado con fila DAST; tabla de Built-in engines incluye OWASP ZAP; nueva sección "DAST target URL (`dast_target_url`)" con ejemplo de request.
- [x] `tests/test_dast_orchestrator.py` (6 tests):
  - `test_orchestrator_skips_dast_without_url`: `dast_enabled=True` sin URL → findings vacíos, no error.
  - `test_orchestrator_forwards_dast_url`: orquestador instancia ZapAdapter con la URL correcta via `execute_scan(target)`.
  - `test_zap_adapter_calls_spider_with_target_url`: mock httpx — verifica que el adapter llama `/JSON/spider/action/scan/` con `url=<target>`.
  - `test_post_scan_rejects_ftp_dast_url`: `ftp://` → HTTP 400 (no 422 ni 500).
  - `test_post_scan_accepts_blank_dast_url`: `""` se trata como None → 200.
  - `test_post_scan_passes_valid_dast_url_to_project`: `project_id + dast_target_url` → `scan_project()` recibe la URL.

### Phase 4 — Agentic DAST con LangGraph (2026-06-02) ✅
- [x] `src/dast_agent/state.py`: `DastAgentState` TypedDict con campos `discovered_routes`, `discovered_forms`, `discovered_auth_boundaries`, `attack_payloads`, `raw_alerts`, `confirmed_findings`, `false_positives`, `iteration`, `max_iterations`, `status`, `error`; `empty_state()` factory para inicialización.
- [x] `src/dast_agent/tools.py`: wrappers REST ZAP sin lanzar — `spider_crawl()` ejecuta scan + poll + extracción de rutas; `active_scan()` dispara active scan y devuelve completed flag; `get_alerts()` lee alertas por base URL; `verify_alert()` re-fetch la URL del alert y confirma XSS si payload aparece en respuesta, ausencia de header de seguridad, o trusts ZAP evidence si no hay verificador automático.
- [x] `src/dast_agent/agents.py`: `explorer_agent()` (spider + ranking via LLM); `attacker_agent()` (active scan + payload generation por forms descubiertos); `verifier_agent()` (verify_alert por cada raw_alert + normalize a Finding-dict con `tool="zap+langgraph"`); helper `_try_ollama_llm()` retorna None si langchain_ollama o Ollama no disponibles → agentes corren con lógica determinística sin LLM.
- [x] `src/dast_agent/graph.py`: `build_dast_graph()` arma StateGraph LangGraph con explorer→attacker→verifier; `should_continue(state)` retorna END si iteration ≥ max_iterations / error / status=done / sin rutas, sino "attacker" para loop. Detecta langgraph ausente y expone `LANGGRAPH_AVAILABLE` flag.
- [x] `src/dast_agent/runner.py`: `run_dast_agent(target_url, project_id, max_iterations, scan_id)` async — envuelve cada nodo con `_wrap_node()` que actualiza `_active_scans` dict (threading.Lock); `get_scan_status(scan_id)` para polling; nunca lanza — retorna dict con `status="error"` si LangGraph falta o invocación falla.
- [x] `src/api/main.py` `POST /api/dast/agent/scan`: nuevo endpoint que valida URL (400) primero, luego chequea `LANGGRAPH_AVAILABLE` (503 con mensaje claro), corre el agente, convierte `confirmed_findings` dicts → `Finding` rows y persiste via `persist_scan()` con `_NullAdapter("zap+langgraph")`. `max_iterations` cap entre 1 y 5.
- [x] `src/api/main.py` `GET /api/dast/agent/scan/{scan_id}/status`: endpoint de polling, retorna snapshot del tracker (`status`, `iteration`, `confirmed_count`, `false_positives_count`, `error`, timestamps); 404 si scan_id desconocido.
- [x] `src/api/main.py` `DastAgentScanRequest`: Pydantic model con `target_url`, `project_id` (opcional), `max_iterations` (default 3).
- [x] `src/api/main.py` `_persist_agentic_findings()`: helper que mapea dicts → Finding objects e invoca `persist_scan` reusando la infraestructura SAST existente.
- [x] `src/dashboard/js/profile-builder-state.js`: nuevo scanner item `zap-agent` ("OWASP ZAP + LangGraph (Agentic)"); `COMPATIBILITY_MATRIX["zap-agent"]` con tech list completa; `resolveDastTool(dast)` → `"agent_loop"` si selecciona zap-agent, `"zap"` si selecciona zap, sino null; `profileScanners()` lee `dast_tool="agent_loop"` y reconstruye `zap-agent` en draft.
- [x] `src/dashboard/js/api.js`: nuevas funciones `runAgenticDastScan({targetUrl, projectId, maxIterations})` y `getAgenticDastStatus(scanId)`.
- [x] `src/dashboard/js/dashboard.js` `runAgenticDastFlow()`: orquesta llamada al endpoint Agentic + polling cada 2s del status; muestra labels "🤖 Explorando rutas / Atacando / Verificando" según fase del agente; reporta confirmed/false_positives/iterations_run en feedback. `runScan()` detecta `profile.dast_tool === "agent_loop"` y dispara este flujo antes del scan SAST/Quality normal.
- [x] `code/requirements.txt`: `langgraph>=0.2.0`, `langchain-ollama>=0.1.0`, `langchain-core>=0.2.0`.
- [x] `tests/test_dast_agent.py` (9 passed + 1 skip): `should_continue` con max iterations / sin rutas / on error / con rutas → loop; `verify_alert` XSS confirmado cuando payload reflejado / rechazado cuando ausente; `run_dast_agent` con ZAP mockeado retorna estructura correcta (skip si langgraph no instalado); endpoint 400 URL inválida, 503 cuando `LANGGRAPH_AVAILABLE=False`, 404 status desconocido.

### Phase 4 — ML Risk Scoring (feat/ml-risk-scoring, 2026-06-02) ✅
- [x] `src/ml/risk_scorer.py`: XGBoost + scikit-learn model. `train_model(findings)` → XGBClassifier persisted with joblib. `score_finding(finding)` → float [0.0–1.0]; severity fallback when no model.
- [x] `GET /api/findings` + `GET /api/projects/{id}/findings`: add `risk_score: float` per finding.
- [x] `POST /api/ml/train`: train on all DB findings, return `{precision, recall, roc_auc, n_samples}`; 400 if < 10 findings.
- [x] Dashboard: risk_score progress bar/badge alongside severity; sort by risk_score; "🧠 Reentrenar modelo" button.
- [x] `code/requirements.txt`: add `xgboost>=2.0.0`, `scikit-learn>=1.4.0`, `joblib>=1.3.0`.
