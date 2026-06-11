# AI DevSecOps Control Plane - Contexto Actual Para Handoff

Ultima actualizacion: 2026-06-10 (Fase 4 fixes: modal sin selects deprecated, Agentic DAST error propagation + reachability pre-check, diff remediacion unificado — 169 tests)

Este documento esta pensado para entregar a Claude Sonnet 4.6 en VSCode como agente tecnico para que pueda continuar el proyecto sin perder contexto. Distingue entre lo implementado actualmente en el repo y los siguientes pasos recomendados.

---

## Resumen Ejecutivo

AI DevSecOps Control Plane es una plataforma AppSec de orquestacion local/self-hosted:

1. Configurar un ScanProfile (elegir herramientas SAST/DAST/Quality).
2. Registrar proyectos (ZIP upload o Git clone).
3. ScanOrchestrator ejecuta las herramientas seleccionadas en paralelo.
4. Persistir hallazgos normalizados con SLA deadline y ciclo de vida.
5. Generar remediaciones con LLM local via Ollama.
6. Crear Pull Requests reales en GitHub con parches revisables.

El codigo nunca sale de la infraestructura del usuario.

---

## Ruta Local Del Repo

```text
/home/zamaer/Documentos/codigo-general/AI-DevSecOps-Control-Plane
```

---

## Agente De Implementacion

VSCode + Claude Sonnet 4.6. Instalar siempre con el pip del entorno:

```bash
/home/zamaer/anaconda3/envs/devsecops-control-plane/bin/pip install -r code/requirements.txt
```

---

## Stack Actual

- Backend: FastAPI + Uvicorn.
- Base de datos: SQLModel sobre SQLite (PostgreSQL-ready via DATABASE_URL).
- Dashboard: SPA estatica HTML/JavaScript/Tailwind servida desde GET /; JS/CSS en src/dashboard/js/ y src/dashboard/css/ montados en /static via FastAPI StaticFiles.
- Scanners SAST: Bandit + Semgrep (Python), Semgrep (Angular/Java).
- Scanners SCA: pip-audit (Python), OWASP Dependency Check (Java).
- Scanners Quality: Pylint (Python), ESLint (Angular/TypeScript), SonarQube Community REST.
- Scanners Infra: Checkov (IaC: Dockerfile/K8s/Helm/Terraform), Trivy (filesystem CVE), Gitleaks (secret scanning). Todos degradan gracefully si el binario no está instalado.
- Scanner DAST: OWASP ZAP (spider + active scan via REST, degrada con gracia si ZAP no responde).
- Agentic DAST: LangGraph Explorer → Attacker → Verifier (loop iterativo); LLM backend Ollama local; degrada cuando LangGraph/Ollama no disponibles (endpoint 503 / agente skip LLM).
- Orquestacion: ScanProfile + ScanOrchestrator con ThreadPoolExecutor.
- SLA deadlines: CRITICAL=3d, HIGH=7d, MEDIUM=30d, LOW=90d.
- IA local: Ollama, modelo por defecto qwen2.5-coder:14b.
- GitHub: GitHub App con JWT RS256; webhook PR con Check Run; GitHub Actions CI.
- Observabilidad: Prometheus (/metrics via prometheus-fastapi-instrumentator), Grafana (provisioning automatico en infra/grafana/), metricas custom en src/metrics/security_metrics.py.
- ML Risk Scoring: XGBoost + scikit-learn (src/ml/risk_scorer.py). score_finding(finding) → float [0.0–1.0] con fallback por severidad. train_model(findings) → XGBClassifier persistido con joblib. POST /api/ml/train entrena en todos los findings de la DB; 400 si < 10 findings. Dashboard: badge/progress bar de risk_score por finding, sort-by-risk, botón "🧠 Reentrenar modelo". Label = outcome real (regression_count>0 OR status=="regression" OR SLA vencido) vía `_label_from_finding()`; features (5): [severity_enc, tool_enc, days_age, days_to_deadline, confidence_enc] — sin status_enc ni regression_count para evitar feature leakage.
- Validacion: python3 -m compileall src + python3 -m pytest tests/ -v (167 passing + 2 warnings cuando LangGraph/prometheus_fastapi_instrumentator instalados; 169 passing en total con los 4 tests nuevos del DAST agent).

Dependencias en code/requirements.txt:

```text
fastapi
uvicorn
bandit
sqlmodel
psycopg2-binary
httpx>=0.27.0
PyJWT>=2.8.0
cryptography>=42.0.0
python-multipart>=0.0.9
semgrep>=1.163.0
pytest>=8.0.0
pylint>=3.0.0
prometheus-fastapi-instrumentator>=6.1.0
xgboost>=2.0.0
scikit-learn>=1.4.0
joblib>=1.3.0
```

---

## Archivos Clave

```text
src/api/main.py
src/api/models.py
src/api/database.py
src/scanners/escaneo.py
src/scanners/orchestrator.py          ← ScanOrchestrator (Phase 2)
src/scanners/base.py
src/scanners/bandit_adapter.py
src/scanners/angular_adapter.py
src/scanners/java_adapter.py
src/scanners/semgrep_adapter.py
src/scanners/pip_audit_adapter.py     ← Python SCA
src/scanners/odc_adapter.py           ← Java SCA (OWASP DC)
src/scanners/pylint_adapter.py        ← Python Quality
src/scanners/eslint_adapter.py        ← Angular/TypeScript Quality
src/scanners/sonarqube_adapter.py     ← SonarQube Community Quality REST
src/scanners/zap_adapter.py           ← OWASP ZAP DAST (spider + active scan, graceful degrade)
src/scanners/checkov_adapter.py       ← Checkov IaC scanner (Dockerfile/K8s/Helm/Terraform)
src/scanners/trivy_adapter.py         ← Trivy filesystem CVE scanner (no Docker daemon)
src/scanners/gitleaks_adapter.py      ← Gitleaks secret scanner (source + git history optional)
src/dast_agent/__init__.py            ← Exposición de runner + LANGGRAPH_AVAILABLE flag
src/dast_agent/state.py               ← DastAgentState TypedDict para LangGraph
src/dast_agent/tools.py               ← Wrappers REST ZAP: spider_crawl, active_scan, get_alerts, verify_alert
src/dast_agent/agents.py              ← explorer_agent, attacker_agent, verifier_agent (con Ollama opcional)
src/dast_agent/graph.py               ← build_dast_graph() + should_continue()
src/dast_agent/runner.py              ← run_dast_agent(target_url, project_id, max_iterations) + status tracking
src/ai_engine/remediator.py
src/integrations/github_client.py
src/dashboard/index.html          ← HTML-only shell (no inline JS/CSS)
src/dashboard/css/base.css        ← CSS variables, reset, animations
src/dashboard/css/layout.css      ← nav, bento, cards, table
src/dashboard/css/modal.css       ← modal, tabs, form panels
src/dashboard/js/utils.js         ← i18n, helpers, tool badges
src/dashboard/js/api.js           ← all fetch() calls centralised
src/dashboard/js/diff.js          ← diff view rendering (LCS + GitHub)
src/dashboard/js/modal.js         ← all modal lifecycle
src/dashboard/js/dashboard.js     ← findings, scan, report, PDF
src/dashboard/js/main.js          ← entry point, event wiring
src/metrics/security_metrics.py   ← Prometheus custom metrics (findings_total, remediations, SLA gauge, scan duration)
src/ml/__init__.py                ← Package init
src/ml/risk_scorer.py             ← XGBoost ML risk scorer (score_finding, train_model, severity fallback)
infra/prometheus/prometheus.yml   ← Prometheus scrape config (scrapes api:8000/metrics)
infra/grafana/provisioning/       ← Grafana datasource + dashboard JSON auto-provisioned
code/requirements.txt
.github/workflows/devsecops-scan.yml  ← CI workflow
docs/ai-current-project-context.md
ROADMAP.md
tests/
```

---

## Modelo De Datos

Entidades en src/api/models.py:

- ScanProfile: configura que herramientas correr (SAST/DAST/Quality). PK int autoincrement. Tabla: scanprofile.
- Project: proyecto escaneable con name, source_type, target_path, technology, scan_profile_id (FK scanprofile).
- Target: entidad legacy de compatibilidad.
- Scan: ejecucion de scanner asociada a Project.
- Finding: hallazgo normalizado con status (open/fixed/regression/false_positive/accepted_risk), first_seen_at, sla_deadline, regression_count.
- FindingAuditEvent: historial de cambios de estado de findings.
- Remediation: remediacion generada por IA para un Finding.
- MetricsSnapshot: metricas por target.

Relacion para remediacion dinamica:
  Finding -> Scan -> Project -> technology

Relacion para orquestacion:
  Project -> ScanProfile -> ScanOrchestrator -> [SAST | DAST placeholder | Quality]

### ScanProfile Fields

```python
class ScanProfile(SQLModel, table=True):
    __tablename__ = "scanprofile"
    id: Optional[int]            # autoincrement PK
    name: str
    description: Optional[str]
    sast_enabled: bool = True
    sast_tools: str = "semgrep"  # "bandit" | "semgrep" | "both"
    sast_rulesets: Optional[str]
    dast_enabled: bool = False
    dast_tool: Optional[str]     # "zap" | "agent_loop" | None
    quality_enabled: bool = False
    quality_tool: Optional[str]  # "sonarqube" | "pylint" | "eslint" | None
    infra_enabled: bool = False
    infra_tools: Optional[str]   # "checkov,trivy,gitleaks" CSV
    created_at: datetime
```

Perfiles por defecto sembrados en startup (idempotente):

| id | Nombre       | sast_tools |
|----|--------------|------------|
| 1  | Python SAST  | both       |
| 2  | Angular SAST | semgrep    |
| 3  | Java SAST    | semgrep    |
| 4  | Full Scan    | both       |

---

## BUG RESUELTO — Semgrep no corria via ScanOrchestrator ✅

### Causa raiz (resuelta 2026-05-23)

_run_sast() usaba os.environ["SCANNER_ENGINE"] para comunicar el adapter
al helper get_scanner_adapter(). Setear env vars en threads de
ThreadPoolExecutor es unreliable: el valor podia no estar disponible o
ser sobreescrito por threads concurrentes, causando que "both" cayera al
default (bandit+pip-audit en lugar de bandit+semgrep).

### Fix aplicado

_run_sast() ahora instancia adapters directamente segun profile.sast_tools,
sin pasar por os.environ ni por el helper modular. Tests de mocks actualizados
para parchear BanditAdapter y CombinedScannerAdapter en su modulo de origen.

---

## API Actual

- GET  /                                    → dashboard
- GET  /api/findings                        → lista hallazgos (acepta ?sla_status=ok|warning|breached|exempt|unknown; incluye sla_status + sla_deadline en cada finding)
- GET  /api/projects                        → lista proyectos
- GET  /api/projects/{id}                   → proyecto por id
- GET  /api/projects/{id}/findings          → findings del proyecto (incluye sla_status + sla_deadline en cada finding)
- POST /api/projects/{id}/scan              → re-escanear proyecto
- POST /api/projects/upload-zip             → ZIP + crear proyecto + scan
- POST /api/projects/clone-repo             → clonar repo + scan
- POST /api/scan                            → scan legacy por path
- GET  /api/ai-status                       → estado Ollama
- POST /api/remediate/{finding_id}          → genera remediacion
- POST /api/remediate/{finding_id}/pr       → crea PR en GitHub
- DELETE /api/remediate/{finding_id}/pr     → elimina rama security-fix-*
- GET  /api/ping?ip=...                     → ping seguro sin shell=True
- GET  /api/profiles                        → lista ScanProfiles
- POST /api/profiles                        → crea ScanProfile
- GET  /api/profiles/{id}                   → perfil por id
- PUT  /api/profiles/{id}                   → actualiza perfil
- GET  /api/findings/{finding_id}/file_content → contenido completo del archivo fuente
- GET  /api/findings/{finding_id}/pr-diff  → diff real del PR de GitHub (via Remediation.pr_url)
- GET  /api/remediate/{finding_id}/preview-diff → before/after exacto que el PR commitiría (build_safe_patched_content local)
- GET  /api/reports/project/{id}            → reporte by_severity/status/top_rules
- POST /api/scan/sonar                      → fetch SonarQube issues + persist (CLI optional)
- POST /api/findings/{finding_id}/accept-risk  → triage: mark as accepted_risk + audit event
- POST /api/findings/{finding_id}/false-positive → triage: mark as false_positive + audit event
- GET  /api/findings/{finding_id}/audit        → historial de audit events del finding
- POST /api/webhooks/github                 → webhook PR con HMAC-SHA256
- GET  /metrics                             → Prometheus metrics (text/plain; auto-expuesto por prometheus_fastapi_instrumentator)
- POST /api/dast/agent/scan                 → Agentic DAST (Explorer/Attacker/Verifier) — 400 URL inválida, 503 si LangGraph no instalado
- GET  /api/dast/agent/scan/{scan_id}/status → polling de progreso para Agentic DAST en curso (exploring/attacking/verifying/done/error)
- POST /api/ml/train                        → entrena XGBoost en todos los findings de la DB; retorna {precision, recall, roc_auc, n_samples}; 400 si < 10 findings

---

## Flujo De Scanners

get_scanner_adapter(technology) en src/scanners/escaneo.py:

- python + SCANNER_ENGINE=bandit   → CombinedScannerAdapter([Bandit, PipAudit])
- python + SCANNER_ENGINE=semgrep  → CombinedScannerAdapter([Semgrep, PipAudit])
- python + SCANNER_ENGINE=both     → CombinedScannerAdapter([Bandit, Semgrep, PipAudit])
- angular / typescript             → AngularAdapter
- java + SCANNER_ENGINE=semgrep    → CombinedScannerAdapter([Semgrep(java), OdcAdapter])
- java (default)                   → CombinedScannerAdapter([JavaAdapter, OdcAdapter])

ScanOrchestrator._run_sast() instancia adapters directamente segun sast_tools. ✅
No usa os.environ ni helpers externos — thread-safe por diseno.

ScanOrchestrator._run_infra() ejecuta los tres adapters de seguridad de infraestructura: ✅

- infra_tools=checkov → CheckovAdapter: `checkov -d <target> --compact -o json`
- infra_tools=trivy   → TrivyAdapter: `trivy fs --format json <target>`
- infra_tools=gitleaks → GitleaksAdapter: `gitleaks detect --source <target> --report-format json --no-git`
- Soporta CSV multi-tool ("checkov,trivy,gitleaks"). Retorna (findings, notices).
- Binarios externos (trivy, gitleaks) degradan a [] + WARNING si no están en PATH.
- Checkov está en requirements.txt (pip install checkov).

ScanOrchestrator._run_quality() ejecuta adapters reales segun ScanProfile:

- python + quality_tool=pylint → PylintAdapter.
- angular/typescript + quality_tool=eslint → EslintAdapter.
- python/angular/typescript/java + quality_tool=sonarqube → SonarQubeAdapter REST.
- Retorna `(findings, notices)` tuple. `notices` incluye mensajes de tecnología-incompatible y "0 hallazgos encontrados" para dar visibilidad al usuario sin lanzar error.
- Si falta el binario (`pylint`, `node_modules/.bin/eslint` o `npx --no-install eslint`), el adapter retorna [] y el orquestador reporta el error sin tumbar todo el scan.
- SonarQube usa `SONARQUBE_URL`, `SONARQUBE_TOKEN` y `SONARQUBE_PROJECT_KEY`; si no hay project key deriva una desde target_path.
- Auth: Bearer token (`Authorization: Bearer <token>`), no Basic Auth — compatible con SonarQube Community v26+.
- `run_sonar_scan(target_path)`: invoca sonar-scanner CLI como subprocess sin `-Dsonar.language` — auto-detección de lenguaje (Angular/TS/Java funciona correctamente).
- `fetch_sonar_issues(page_size)`: consulta REST `/api/issues/search` con Bearer token; valida 401/404 con mensajes claros.
- `POST /api/scan/sonar`: intenta CLI (graceful skip), llama `SonarQubeAdapter.execute_scan()`, persiste con `persist_scan()`.
- `SONARQUBE_URL` en `.env` apunta a `http://localhost:9000` para dev local; cambiar a `http://sonarqube:9000` en Docker.
- `OrchestratorResult` incluye `scan_summary: dict` (tool → count) y `warnings: list` (notices no-fatales). `_scan_with_profile()` expone ambos en la respuesta HTTP.

---

## Guardrails De Parches (github_client.py)

### normalize_file_path_for_github(file_path) ✅

Convierte rutas absolutas del workspace local en rutas relativas para la GitHub API.
- `/…/UUID/repo/src/api/main.py`   → `src/api/main.py`   (proyectos clonados)
- `/…/UUID/source/src/api/main.py` → `src/api/main.py`   (proyectos ZIP)
- `/…/workspace/uploads/UUID/X/…`  → parte relativa via split en 3 segmentos
- `src/api/main.py` ya relativo    → sin cambio, sin warning
- `/etc/passwd` sin patron         → devuelve original + WARNING en log
Llamada en `create_security_pr()` justo al extraer `file_path` de `finding_details`.

### Python:
- extract_python_code_block(): extrae bloque python fenced y valida con ast.parse.
- should_replace_full_file(): bloquea reemplazo completo si original > 100 lineas y patch < 30.
- find_enclosing_function_range(): AST para encontrar funcion que contiene la linea vulnerable.
- build_safe_patched_content(): guardrail central, valida con ast.parse, rechaza vacio.

Angular/TypeScript:
- find_ts_method_range(content, line_start): brace-counting, incluye decoradores @Component etc. Retorna (start, end) o None.
- find_ts_class_range(content, class_name): fallback por nombre de clase.

Java:
- find_java_method_range(content, line_start): brace-counting, incluye anotaciones @Override etc. Retorna (start, end) o None.
- find_java_class_range(content, class_name): fallback por nombre de clase.

CSS/HTML: ✅
- normalize_patch_technology_for_finding(): reglas css:*/web:css* → "css"; html.*/html:*/web:html* → "html".
- code_fence_label_for_technology("css") → "css"; code_fence_label_for_technology("html") → "html".
- extract_generic_code_block(): labels_by_technology incluye css: ("css","scss","sass","less") y html: ("html","htm").
- extract_code_block_for_technology(): rechaza bloque de función Python si el finding es CSS/HTML.
- build_safe_patched_content(): CSS/HTML usa build_lightweight_patched_content() con guardrail de tamaño.
- build_safe_fallback_code(): CSS → `/* AI unavailable */`; HTML → `<!-- AI unavailable -->`.

Orden de fallback: semantico (metodo) → clase → rango de lineas.
Guardrail de tamano: archivo > 30 lineas, resultado < 60% del original → rechazar.

---

## Prompts De Remediacion (remediator.py)

- build_python_prompt(finding): prompt Python con contrato estricto AST.
- build_angular_prompt(finding): detecta si es secret (ANG-SECRET-* o snippet con apiKey/token/password) y agrega instruccion CI/CD. XSS no recibe esa instruccion.
  - Incluye `expected_function_source` completa si fue enriquecida por `enrich_js_finding_context` (evita placeholders). ✅
  - Guia especial para S3776/cognitive_complexity: exige refactoring real, prohíbe placeholder/refactoredFunction/TODO. ✅
  - Prohíbe explícitamente placeholders en el contrato de salida: "NUNCA uses placeholders, comentarios TODO ni funciones stub". ✅
- build_java_prompt(finding): contrato Java AppSec.
- build_css_prompt(finding): prompt dedicado CSS/SCSS; contrato estricto "devuelve solo un bloque ```css```; NUNCA Python". Guias: eliminar selectores duplicados, sin !important innecesario. ✅
- build_html_prompt(finding): prompt dedicado HTML5; guias de seguridad (rel=noopener, autocomplete, XSS). ✅

Deteccion de CSS/HTML (normalize_technology + infer_technology_from_finding):
  - Namespace rule_id: css:* / web:css* → "css"; html.* / html:* / web:html* → "html"
  - Extension de archivo: .css/.scss/.sass/.less → "css"; .html/.htm/.jinja/.j2 → "html"
  - Orden de precedencia: rule_id namespace > file extension > project technology.
  - Ejemplo: css:S4666 en index.html → technology="css" → build_css_prompt ✅

Deteccion de secrets en Angular:
  SECRET_PREFIXES = ('ANG-SECRET', 'SEMGREP-SECRET', ...)
  SECRET_KEYWORDS = ('apikey', 'token', 'secret', 'password', 'credential', 'auth', 'key')

---

## Dashboard

Dashboard refactored (2026-05-26) — index.html is now pure HTML; all JS and CSS extracted to separate modules:
- src/dashboard/css/base.css: CSS variables, reset, animations, scrollbar styles
- src/dashboard/css/layout.css: nav, bento grid, cards, table, findings list, pagination
- src/dashboard/css/modal.css: modal overlays, tab buttons, form panels, severity badge overrides
- src/dashboard/js/utils.js: i18n strings (ES/EN), applyI18n(), t(), setLang(), tool badge helpers
- src/dashboard/js/api.js: all fetch() wrappers (loadProjects, loadFindings, createProject, createPR, etc.)
- src/dashboard/js/diff.js: LCS-based renderDiffView(), GitHub unified-diff renderGitHubDiff(); renderPreviewDiff() para diff full-file exacto (usa original/patched del servidor); guard para snippet null/vacío; computeDiff y normalizeLines a scope módulo (sin duplicación S4144)
- src/dashboard/js/modal.js: project modal wizard, remediation modal, branch-confirm modal, reason/audit modals
- src/dashboard/js/dashboard.js: findings render + pagination, scan trigger, report/PDF export, chart rendering
- src/dashboard/js/main.js: entry point — imports all modules, wires events, boot sequence
- src/api/main.py: StaticFiles mount at /static → src/dashboard/ directory

src/dashboard/index.html capacidades actuales:
- Vista de proyectos con contador de findings + mini-badges de severidad C/H/M/L por proyecto.
  - Backend: GET /api/projects incluye findings_summary: {CRITICAL, HIGH, MEDIUM, LOW, total}.
- Modal 2 pasos: Paso 1 = seleccion de ScanProfile (cards), Paso 2 = ZIP/clone.
  - Paso 1: cards con iconos SVG inline (Py azul, Angular rojo, Java ☕, Full Scan escudo, Custom engranaje), descripcion de herramientas y badge de stack. Hover resaltado via CSS .profile-card.
  - Paso 2: sub-selector GitHub / GitLab con SVG logos; placeholder del input de URL cambia segun seleccion (setCloneSource()).
- Badge de origen del scanner: `detectTool(finding)` infiere la herramienta por `rule_id` namespace. SonarQube se detecta por formato `namespace:Snumber` (e.g. `python:S8415`). Dot-notation (`python.lang.*`, `gitlab.*`, `python.flask.*`) → Semgrep. `B\d{3}` → Bandit. Fallback al campo `finding.tool`. SonarQube=azul, Bandit=amarillo, Semgrep=celeste, ESLint=rojo, Pylint=verde. ✅
- Panel Custom con DAST deshabilitado (Proximamente) y Quality habilitable; crea ScanProfile real con `quality_tool=pylint` para Python o `quality_tool=eslint` para Angular/TypeScript.
- Tabla de hallazgos con paginacion (PAGE_SIZE=20), badge de severidad inline (CRIT/HIGH/MED/LOW pill rojo/naranja/amarillo/azul).
- Filtros chip funcionales: Todos / Critical / High / Breach — resetean a pagina 1. ✅
- Botones de accion con iconos SVG: Fix (✨ sparkles), Riesgo (⚠ triangulo), FP (✗ circulo), Historial (🕐 reloj). ✅
- Severidades HIGH en rojo (#ef4444) — unificado CSS + JS + charts. ✅
- Hero card padding reducido (6px vs 9px, gap 4px vs 7px, figura 24px vs 28px). ✅
- KPI spark reducido (26px vs 40px). ✅
- Auto-Fix → modal de remediacion → PR button (icono cohete SVG). ✅
  - Header con badge rule_id + path relativo corto (shortPath()).
  - Vista diff split-screen dos columnas: izquierda "Antes" (rojo, lineas −), derecha "Despues" (verde, lineas +). En mobile (< 640px) colapsa a columna unica via media query.
  - Si el finding tiene PR en GitHub (Remediation.pr_url), el modal sobreescribe el diff de Ollama con el diff real del commit via GET /api/findings/{id}/pr-diff + renderGitHubDiff(). Badge verde confirmatorio. ✅
  - renderGitHubDiff(): vista side-by-side completa — panel ANTES (archivo original, líneas eliminadas en rojo #3d1a1a) y panel DESPUÉS (archivo parcheado, líneas añadidas en verde #1a3d1a). Sin toggle. Scroll sincronizado (vertical + horizontal). Auto-scroll al primer cambio. ✅
  - GET /api/findings/{id}/pr-diff: filtra WHERE pr_url IS NOT NULL — evita que una fila de remediación más reciente sin pr_url tape a la que sí lo tiene. ✅
  - body scroll lock: document.body.style.overflow='hidden' al abrir modal, '' al cerrar — todos los caminos (X, backdrop click, ESC). ✅
  - Codigo propuesto se limpia de backtick fences antes de mostrar (cleanCodeFences()).
  - Panel descripcion con toggle ES↔EN: muestra traduccion del diccionario BANDIT_ES (~35 reglas cubiertas) o original ingles. Boton oculto si descripcion ES = EN (sin traduccion disponible). ✅
- Tab Reportes con graficas Chart.js (by_severity, by_status, overdue).
- PDF export: contenedor 377px (la mitad del contentW para scale=2), addImage con margen horizontal PDF_MARGIN=22px; footer con numero de pagina en margen. ✅
- PDF márgenes top/bottom: PDF_TOP=14, PDF_BOT=22; footer en `pageH - PDF_BOT/2` — sin solapamiento en ninguna página. ✅
- Botón Export relocalizado: eliminado del header global → sticky bar dentro de `#findings-report-view`; ícono PDF documento, rojo #c62828; i18n `btn-export-pdf` ES/EN. ✅
- Spacing gráficas reporte: `#report-content` flex-column gap:10px; KPI grid margin:0; charts gap:10px; label .72rem / margin-bottom:6px. ✅
- Indicador AI Engine Online/Offline.

---

## Tests Actuales

```text
tests/test_angular_prompt.py               (4 tests)
tests/test_finding_upsert.py               (6 tests)
tests/test_file_content_path.py            (2 tests)
tests/test_github_path.py                  (4 tests)
tests/test_odc_adapter.py                  (5 tests)
tests/test_pip_audit_adapter.py            (5 tests)
tests/test_quality_adapters.py             (7 tests)
tests/test_remediation_language_guards.py  (10 tests) ← +6: JS function deletion, _extract_named_functions, S930 prompt guards
tests/test_remediator.py                   (3 tests)  ← CSS technology detection + prompt
tests/test_safe_patching_python.py         (12 tests) ← S1192 constant + B324 weak-hash
tests/test_scan_profile.py                 (11 tests)
tests/test_semantic_patching.py            (11 tests)
tests/test_semgrep_adapter.py              (4 tests)
tests/test_target_path_validation.py       (4 tests)  ← valid path, path traversal, nonexistent, fallback dummy
tests/test_technology_inference.py         (29 tests)
tests/test_zap_adapter.py                  (4 tests)
tests/test_dast_orchestrator.py            (6 tests) ← Phase 4 DAST: plumbing dast_target_url end-to-end
tests/test_dast_agent.py                   (13 passed + 1 skip) ← Phase 4 + Fase 4 fixes: should_continue + verify_alert + endpoint 400/503/404 + active_scan ZAP error propagation + target_reachable + explorer fail-fast
tests/test_metrics.py                      (7 tests) ← Phase 4: Prometheus metrics integration
tests/test_risk_scorer.py                  (6 tests) ← Phase 4 ML: fallback severidad, train_model (label=outcome real), features sin leakage, POST /api/ml/train 400, risk_score en GET /api/findings, degradación sin ML libs
tests/test_checkov_adapter.py              (4 tests) ← Phase 4 Infra: single-framework JSON, multi-framework, missing binary, empty stdout
tests/test_trivy_adapter.py                (4 tests) ← Phase 4 Infra: vulnerabilities normalized, CVSS fallback, missing binary, empty stdout
tests/test_gitleaks_adapter.py             (4 tests) ← Phase 4 Infra: leaks normalized, no leaks, missing binary, FileNotFoundError
Total: 169 passed, 2 warnings (167+2 cuando LangGraph + prometheus_fastapi_instrumentator instalados) ← verificado tras Fase 4 fixes (2026-06-10)
```

Fix del SQLite en-memoria para tests: usar poolclass=StaticPool para que
todas las conexiones compartan la misma instancia en-memoria.

---

## Estado Git

Historial limpio en GitHub (main):
  docs: README with architecture, roadmap and validated scan results
  feat(patching): semantic method/class detection for Angular/TypeScript and Java
  feat(scanner+ai): dual-engine semgrep, angular secret prompt, dedup fix
  feat(scanners): multi-tech adapters Angular, Java, Python + ZIP/repo upload
  Initial commit: AI DevSecOps Control Plane

Phase 2 aun no commiteado completamente. Bugs del orquestador y tool_name ya resueltos en codigo local.

Reglas permanentes:
- No hacer git reset --hard.
- No revertir cambios existentes sin permiso explicito.
- No commitear .env, .pem, dev_database.db*, workspace/uploads/*.

---

## Phase 4 — Infraestructura: Seguridad de Infraestructura ✅

1. ✅ CheckovAdapter: `checkov -d <target> --compact -o json`; parsea single y multi-framework JSON; severity desde top-level o `check.severity`; degradación graceful. Instalación: `pip install checkov` (ya en requirements.txt).
2. ✅ TrivyAdapter: `trivy fs --format json <target>`; parsea `Results[].Vulnerabilities[]`; severity desde `Severity` o CVSS V3Score fallback; descripción incluye versión fija. Binario externo — ver README.
3. ✅ GitleaksAdapter: `gitleaks detect --source <target> --report-format json --report-path <tmp> --no-git --exit-code 0`; lee JSON del archivo temporal; severity HIGH para todos los secretos. Binario externo — ver README.
4. ✅ ScanProfile: `infra_enabled: bool` + `infra_tools: Optional[str]` CSV; migración SQLite en `ensure_sqlite_schema()`.
5. ✅ ScanOrchestrator: `_run_infra()` runner con `_adapter_map` dinámico; misma interfaz tuple `(findings, notices)` que `_run_quality()`; activo cuando `profile.infra_enabled=True`.
6. ✅ Dashboard: slot "infra" en profile-builder-state.js; STACK_ICON_META + TOOL_BADGE_COLOR + TOOL_CHIP_META + normalizeToolKey + CSS tones para checkov/trivy/gitleaks.
7. kube-bench (CIS K8s benchmark) — PENDIENTE; requiere cluster K8s activo.

---

## Auditoria Fase 4 (2026-06-10)

- Tests: 169 passed ✅
- Servicios Docker: ZAP healthy (v2.17.0), Prometheus, Grafana, SonarQube OK. API corre como uvicorn local (no en Docker).
- ZAP conectividad: `extra_hosts: host-gateway` ya estaba en docker-compose.yml ✅. ZAP no puede alcanzar http://host.docker.internal:8000 porque uvicorn escucha en 127.0.0.1 (no 0.0.0.0). Solución documentada en .env.example: usar `--host 0.0.0.0` para que ZAP alcance la app desde Docker.
- Smoke test §3: ZIP→scan→remediation→preview ✅. PR bloqueado porque dummy_vulnerable_app.py no está en el repo remoto (esperado, no es falla de credenciales).
- Bug nuevo documentado: la función `active_scan()` descartaba el body de error de ZAP (`{"code":…,"message":…}`) — corregido en esta sesión (ver Fase 4 fixes).

## Fase 4 Fixes (2026-06-10) ✅

### Fix 1 — Modal: select de tecnología deprecated eliminado
- `src/dashboard/index.html`: `<select id="zip-technology">` y `<select id="repo-technology">` reemplazados por `<div id="zip-tech-chip" class="tech-readonly-chip">`.
- `src/dashboard/css/modal.css`: nueva clase `.tech-readonly-chip` con badge visual de tecnología de solo lectura.
- `src/dashboard/js/modal.js`: `uploadZipProject()` y `cloneRepoProject()` leen la tecnología de `getPrimaryApiTechnology(wizardProfileDraft)`; `syncTechnologySelectsFromProfile()` reemplazada por `renderTechChipsForStep2()` que rellena el chip desde el draft al entrar al paso 2.
- `src/dashboard/js/utils.js`: claves i18n `tech-chip-label`, `tech-chip-primary`, `tech-chip-from-profile` (ES y EN).
- Garantía: no se puede crear inconsistencia entre el select y el perfil — la tecnología siempre viene del perfil.

### Fix 2 — Agentic DAST: propagación de errores ZAP + pre-check de alcanzabilidad
- `src/dast_agent/tools.py`: nueva función `_extract_zap_error(payload, fallback)` extrae `code` y `message` del payload JSON de ZAP; `active_scan()` y `spider_crawl()` ahora incluyen el error real en `result["error"]` (ej. `"ZAP active scan failed to start: url_not_found — Provided URL is not in the Sites tree"`).
- `src/dast_agent/tools.py`: nueva función `target_reachable(target_url) -> dict` — llama `accessUrl` de ZAP y devuelve `{"reachable": bool, "error": str|None}`; incluye hint `host.docker.internal` si falla.
- `src/dast_agent/agents.py`: `explorer_agent()` llama `target_reachable()` ANTES del spider; si no es alcanzable → `state["status"]="error"`, `state["error"]=<mensaje detallado>`, retorna inmediatamente (el grafo `should_continue` termina en END).
- `src/dashboard/js/dashboard.js`: `runAgenticDastFlow()` obtiene el status final del endpoint de polling para mostrar el error detallado; formato mejorado de feedback: `"X iteraciones · Y confirmados · Z falsos positivos"` o `"falló (N iter): <error>"`.
- `.env.example`: sección nueva documentando que para targets en el host con uvicorn, usar `--host 0.0.0.0` y `http://host.docker.internal:<port>` como target URL.
- `tests/test_dast_agent.py`: 4 tests nuevos — `active_scan` con error ZAP JSON, `target_reachable` failure y success, `explorer_agent` fail-fast con target inalcanzable.

### Fix 3 — Diff de remediación unificado: preview = PR diff, sin panel en blanco
- `src/dashboard/js/diff.js`: `renderPreviewDiff()` reescrita para usar el mismo renderer `buildPanel` que el diff real de GitHub — mismos colores, mismo formato de líneas `+`/`-`, scroll sincronizado, auto-scroll al primer cambio. Label actualizado: `"⚡ Vista previa del fix (lo que el PR aplicará)"`. `renderDiffView()` label actualizado: `"⚠ Vista aproximada — propuesta Ollama sin aplicar"`.
- `src/dashboard/js/modal.js`:
  - `showRemediationModal()`: `_usingGitHubDiff = false` siempre al abrir — el IIFE ahora renderiza el preview para TODOS los proyectos (incluyendo repo); agrega `console.warn` cuando el preview falla.
  - `checkExistingPR()`: si no hay PR → devuelve sin renderizar (deja el preview del IIFE); si hay PR → establece `_usingGitHubDiff = true` ANTES de `renderGitHubPrDiff` para que el IIFE en vuelo salte el render.
  - `renderGitHubPrDiff()`: elimina `renderDiffStatus("Cargando diff real desde GitHub...")` al inicio — el panel muestra el preview mientras el diff de GitHub carga; solo llama `renderDiffStatus` si el panel está vacío y el diff falla.
- Diagnóstico: el endpoint `preview-diff` funciona correctamente para proyectos repo (`source_type="repo"`) — HTTP 200 con `original` y `patched`. El bug era puramente de frontend (`_usingGitHubDiff=true` impedía que el IIFE llamara `renderPreviewDiff`).

---

## Riesgos Conocidos

16. Trivy y Gitleaks son binarios externos — si no están en PATH el adapter retorna [] con WARNING. No crash, pero el usuario debe instalarlos manualmente (ver README). Checkov sí está en requirements.txt como dependencia pip.
17. kube-bench requiere un cluster K8s activo para ejecutar los benchmarks CIS; no es viable en scans locales/offline. Candidato para la siguiente iteración cuando exista entorno de testing con K8s.
18. ML risk model — el `models/risk_model.joblib` existente fue entrenado con 6 features; tras el fix de leakage `score_finding()` produce 5 features. Hasta que se re-entrene (`POST /api/ml/train`), `predict_proba` lanza por mismatch de shape → `score_finding` degrada con gracia al fallback por severidad (try/except ya existente). Re-entrenar regenera el .joblib con 5 features y resuelve el mismatch.

1. ✅ RESUELTO — DAST runner real: `_run_dast` instancia `ZapAdapter` cuando `profile.dast_enabled=True` y se pasa `dast_target_url` válida. Sin URL → salta gracefully (no error). ZAP no disponible → adapter degrada a `[]`.
2. Validacion Angular/Java es heuristica (brace-counting), no parser real.
3. Java Quality local sigue pendiente; SonarQube requiere sonar-scanner CLI instalado para analizar y poblar findings (0 issues hasta primer análisis CLI). Nota: ya no hardcodea `-Dsonar.language=py` — el CLI auto-detecta Angular/TS/Java.
7. sonar-scanner CLI instalado en ~/.local/bin/sonar-scanner v6.2.1. Primer análisis real ejecutado: 125 issues importados. sonar-project.properties en raíz del repo. Para dispararlo desde el endpoint POST /api/scan/sonar se requiere reiniciar el servidor (fallback path ya codificado en run_sonar_scan).
8. GET /api/ping — binario `ping` no estaba en python:3.12-slim. Fix: iputils-ping añadido al Dockerfile + FileNotFoundError → HTTP 503 graceful en el endpoint (requerirá `docker compose build api && docker compose up -d api` para que el rebuild aplique).
4. workspace/ puede contener uploads temporales; no versionar.
5. ensure_sqlite_schema() es SQLite-only; desactivar para PostgreSQL.
6. El contexto del archivo usa Finding.line_start; si el scanner reporta una línea incorrecta el contexto puede mostrar código diferente al snippet real.
9. ✅ RESUELTO — CSS refactor introducía `.project-menu.open { display: none !important; }` en layout.css (línea 116), bloqueando el popover de proyectos. Corregido a `display: block !important;`.
10. ✅ RESUELTO — Modal diff estado cacheado entre findings: epoch guard en modal.js invalida callbacks async de findings anteriores.
11. ✅ RESUELTO — Panel ANTES mostraba texto de Ollama como código eliminado: renderDiffView ahora usa líneas reales del archivo para el panel ANTES cuando fileData está disponible.
12. ✅ RESUELTO — `toDiffLines` era referenciado pero nunca definido en diff.js (line 67): fallaba silenciosamente y dejaba el área de diff completamente vacía. Corregido a `normalizeLines`.
13. ✅ RESUELTO — Parches JS/SonarQube (ej. `javascript:S3776`) generaban placeholders porque el code_snippet era solo 1-2 líneas. Fix: `enrich_js_finding_context` en main.py extrae la función completa con `find_enclosing_js_function` (regex + brace-counting via `find_braced_block_range`).
14. ✅ RESUELTO — Algunos modales no se abrían cuando `validate_remediation_patch` devolvía False (422): ahora el endpoint guarda el parche con `outcome="manual_review"` y devuelve 200 con `validation_warning`; el modal siempre abre y muestra el parche con banner de advertencia. PR creation con `manual_review` va directamente a `create_proposal_pr`.
15. ✅ RESUELTO — Placeholders de refactoring JS (`function refactoredFunction`, `// Placeholder for the refactored function`, etc.) no eran detectados por `is_safe_to_apply`. Añadidos 8 nuevas señales de stub al guardrail.
12. ✅ RESUELTO — Commits destructivos (PR #16 nunca mergeado): is_safe_to_apply() detecta stubs genéricos y funciones eliminadas; create_proposal_pr() crea PR solo con Markdown para revisión manual.

---

## Proximos Pasos Recomendados

Infra Security (siguiente iteracion):
1. kube-bench: CIS Kubernetes Benchmark — siguiente scanner infra candidato. Requiere cluster K8s activo; implementar como adapter con graceful degrade cuando `kubectl` o el binario kube-bench no están disponibles.
2. Remediation prompts para findings Checkov/Trivy/Gitleaks: actualmente no hay prompts LLM para IaC — agregar `build_infra_prompt()` en remediator.py.
3. Validar scan real con un proyecto que tenga Dockerfile o terraform/ para confirmar que Checkov encuentra hallazgos end-to-end.

Inmediato (proxima sesion):
1. ✅ sonar-scanner CLI instalado y primer análisis real ejecutado (125 issues).
2. ✅ Crash `updateDastTargetUrlInput is not defined` corregido — `runScan()` ya no falla.
3. ✅ SonarQube CLI ya no hardcodea `-Dsonar.language=py` — Angular/TS analizado correctamente.
4. ✅ Visibilidad de scan: `scan_summary`, `warnings` y mensajes de 0-findings en feedback post-scan.
5. Próximo: probar scan real con ZIP Angular + perfil SonarQube para verificar que el CLI ahora detecta TypeScript correctamente. Recordar ejecutar sonar-scanner CLI antes de escanear desde el dashboard (o usar `POST /api/scan/sonar` que lo dispara automáticamente).
2. ✅ build_pr_body() con formato estructurado (🔒 Security Fix, Herramienta, Problema, Fix aplicado, Referencias CWE).
3. ✅ Badge de origen en dashboard — detectTool(finding) por rule_id namespace; SonarQube/Bandit/Semgrep/ESLint/Pylint coloreados.
4. ✅ Ping 500 corregido — iputils-ping en Dockerfile + FileNotFoundError graceful (HTTP 503) + timeout 15s.
5. ✅ Bug1 modal ANTES: buildAntesRows sincroniza fi=h0 antes de procesar cada hunk; nunca usa c.content del diff como código.
6. ✅ Bug2 PR creation: _apply_approximate_anchor con 3 estrategias (line-range+AST, comentario insertado, force-patch); siempre devuelve (candidate, warning) sin lanzar error. Endpoint devuelve 200+warning. Dashboard muestra link al PR + aviso amarillo (no error rojo).
7. ✅ P1 modal: GET /api/findings/{id}/pr-diff filtra pr_url IS NOT NULL — finding XXE ahora muestra diff real del PR.
8. ✅ P2 modal: body scroll lock (overflow:hidden) al abrir, unlock al cerrar — X, backdrop, ESC.
9. ✅ P3 modal: scroll sync vertical + horizontal (scrollTop + scrollLeft) con requestAnimationFrame flag reset.
10. ✅ Dashboard refactor: index.html → HTML-only; todo el JS/CSS extraído a módulos ES6 separados; StaticFiles mount en /static.
11. ✅ Post-refactor bug fix: `layout.css` `.project-menu.open` corregido (`none` → `block`); `dashboard.js` wireDashboardEvents() tiene toggle del popover de proyectos (.repo click → toggle .open, click exterior → close, Escape → close); selectProject() cierra el popover al seleccionar.
12. ✅ Fix tecnología: infer_technology_from_finding(rule_id, file_path) en remediator.py. Orden de precedencia: 1) namespace del rule_id (javascript:, python:, java:, B\d{3}, semgrep.*), 2) extensión del archivo (.html/.js/.ts → angular, .py → python, .java/.kt → java), 3) project.technology como fallback. Importado y usado en build_finding_details() de main.py. 29 tests nuevos en test_technology_inference.py. Corrige el bug donde un proyecto Python con findings SonarQube en archivos JS/HTML recibía prompt Python → Ollama generaba código Python para JS.
13. ✅ Fix crítico P1: modal epoch guard en modal.js — _modalEpoch incrementa en cada apertura; IIFE async y checkExistingPR capturan epoch y abortan si ya no es el finding activo. diffView limpiado inmediatamente con "Cargando diff…" al abrir. hideRemediationModal también incrementa epoch.
14. ✅ Fix crítico P2: renderDiffView en diff.js — panel ANTES siempre usa líneas reales del archivo (fileData.content) marcadas con tipo "hi" (tono azul). Nunca usa leftDiff (líneas LCS "eliminadas") que podían provenir del texto descriptivo de Ollama. Tipo "hi" añadido al objeto STYLE.
15. ✅ Fix crítico P3: is_safe_to_apply() en github_client.py — valida 3 guardrails: >20% líneas eliminadas, señales de stub genérico, funciones eliminadas. create_proposal_pr() crea PR solo con docs/remediations/{id}.md sin tocar código. create_security_pr() llama is_safe_to_apply() y lanza safety_check_failed. Endpoint catch safety_check_failed → create_proposal_pr(); respuesta incluye pr_type ("code_fix"|"proposal"). Badge frontend ⚠/✓ en modal.
16. ✅ CSS/HTML remediación: build_css_prompt() + build_html_prompt() con contrato estricto (solo bloque ```css``` / ```html```, nunca Python/JS). normalize_technology() y infer_technology_from_finding() reconocen css:*/web:css* y html.*/html:*/web:html*. github_client.py: normalize_patch_technology_for_finding, code_fence_label_for_technology y extract_generic_code_block actualizados. build_safe_fallback_code() con fallbacks CSS y HTML. Ejemplo resuelto: css:S4666 (selector duplicado .fb-error) → Ollama recibe prompt CSS → genera selector consolidado, no "# No Python code needed".
17. ✅ Diff viewer guard (diff.js): renderDiffView ahora tiene guard explícito para snippet null/vacío. Si ambos son vacíos → mensaje "Sin código disponible". Si snippet vacío pero proposed existe → lado izquierdo muestra placeholder y lado derecho muestra proposed. Si snippet === proposed → forceReplacement=true → ops delete+insert explícitos (nunca queda solo lineas azules).
18. ✅ Fix PR solution inconsistency (2026-05-27): `cached_remediation_is_reusable()` en main.py — cache check que NO re-lee archivo fuente local (archivo editado localmente ya no invalida la remediación cacheada → Ollama no se re-llama → el patch siempre es el mismo). `GET /api/remediate/{id}/preview-diff` aplica build_safe_patched_content en el archivo local y devuelve {original, patched}. `renderPreviewDiff()` en diff.js muestra diff full-file exacto con badge "✓ Vista previa exacta del PR". IIFE en modal.js usa Promise.allSettled para obtener fileData + previewData en paralelo; si preview disponible usa renderPreviewDiff, si no cae a renderDiffView. computeDiff y normalizeLines extraídos a scope módulo.
19. ✅ is_safe_to_apply extendido a JS/TS: _extract_named_functions detecta `function funcName(` además de Python `def`. Stub signals JS agregados. Angular prompt fortalecido contra clase TypeScript inventada (S930).
20. ✅ SLA tracking visibility: get_sla_status() + _SLA_EXEMPT_STATUSES en main.py (ok/warning/breached/exempt/unknown); ?sla_status= filter en GET /api/findings; sla_status + sla_deadline en ambos endpoints de findings; buildSlaBadge muestra fecha deadline en MMM DD; KPI counters 🔴 N vencidos / ⚠ N por vencer en #sla-foot.
21. ✅ Generalizar target_path (ítem 23 Phase 2): ScanRequest ahora acepta project_id/target_path/profile_id/technology opcionales. POST /api/scan resuelve: 1) target_path explícito → validate_scan_target → run_scan; 2) project_id → project.target_path en DB → validate_scan_target → scan_project (con profile override si profile_id dado); 3) ninguno → fallback dummy_vulnerable_app.py. triggerScan(projectId, profileId) añadida en api.js. SCAN_ALLOWED_ROOTS documentada en .env.example. 4 tests nuevos: valid path, path traversal bloqueado, path inexistente, fallback retro-compat.
22. `docker compose build api && docker compose up -d api` — rebuild para que iputils-ping entre en el contenedor.
23. Reiniciar servidor uvicorn para que POST /api/scan/sonar active CLI automáticamente (scan_submitted: true).
24. DAST adapter real con OWASP ZAP o validacion post-patch `tsc --noEmit` / Maven-Java.
25. ✅ Configuration page UX: palette min-height 520px, form vacío al cargar, tarjetas no-clickable con "Usar" como único gatillo, botones header deshabilitados hasta activar perfil, scanner icon badges en lista de proyectos (last_scan_tool split por "+").
26. ✅ SonarQube findings fix: normalize_issue() ahora setea tool="sonarqube" en cada Finding — findings persistidos con tool correcto en lugar del SAST tool del profile. _run_quality() expandido para django/flask/java-spring/react; soporta herramientas quality comma-separated ("pylint,sonarqube"); degrada gracefully por herramienta (solo lanza RuntimeError si TODAS fallan).
27. ✅ ZAP profile builder: warning "necesitará URL antes de ejecutar DAST" eliminado — URL se provee al momento del scan, no al crear el perfil. canDropScannerOnTechnology() ya no bloquea ni advierte por URL faltante al agregar ZAP.
28. ✅ Multi-quality-tool: restricción "solo una herramienta Quality" removida del builder. toScanProfilePayload() une múltiples con coma ("pylint,sonarqube"). profileScanners() divide y reconstruye al cargar perfil guardado. Orchestrator soporta CSV completo.
29. ✅ Scan-stack header overhaul: CSS .scan-stack-chip/.scan-stack-profile/.scan-stack-icon/.scan-stack-empty/tone-classes añadidas a layout.css. STACK_ICON_META reemplaza text marks con SVG icons por tool (Python serpientes, Angular A, TypeScript rect+T, Java taza, Semgrep lupa, Bandit escudo+!, ZAP rayo, Pylint ✓, ESLint hexágono, SonarQube ondas, pip-audit paquete, Dep Check escudo). updateScanStackIcons() muestra nombre del perfil activo antes de los chips.

Phase 2 ya implementado ✅:
- normalize_file_path_for_github(): rutas absolutas workspace→relativas para GitHub API.
- Modal de remediacion: badge rule_id + path relativo, diff view rojo/verde, limpieza de backticks.
- Diff view split-screen dos columnas (Antes / Despues), responsive en mobile.
- Diff Viewer v9: scroll via `max-height:calc(85vh - 200px)` explícito (elimina manipulación del padre DOM); CONTEXT=20 líneas; pad rows usan `#161b22` (gris visible) en vez de casi-negro, haciendo el espacio de alineamiento distinguible. ✅
- Dashboard UX 2026-05-25: paginación tabla (20 items/página), filtros chip activos, iconos SVG en botones, HIGH→rojo, hero margins reducidos, toggle ES/EN descripción modal, PDF con márgenes. ✅
- Dashboard UX V 2026-05-25: PDF top/bottom margins fix (PDF_TOP=14, PDF_BOT=22, footer centrado), botón Export → tab Reporte sticky bar (ícono doc PDF, rojo, i18n), spacing gráficas (flex gap:10px). ✅
- PR button icon inline: white-space:nowrap + flex-shrink:0;display:block en SVG. ✅
- Fix cacheado: POST /api/remediate/{id} retorna cached:true si ya existe remediación — sin llamar Ollama. ✅
- PR persistido: Remediation.pr_url + pr_branch; GET /api/remediate/{id}/pr; POST detecta PR abierto y lo retorna (cached:true) sin duplicar. ✅
- Dashboard: checkExistingPR() precarga el link al PR al abrir modal; feedback diferenciado cached/nuevo. ✅
- ScanProfile cards con iconos SVG, descripciones reales de herramientas, tool badges y hover.
- Mini-badges de severidad C/H/M/L en lista de proyectos; GET /api/projects incluye findings_summary.
- Boton "▶ Escanear" en panel de findings. Header global sin boton redundante de scan.
- Sub-selector GitHub / GitLab en Paso 2 del wizard con placeholder dinamico.
- Diff view: colores suaves (#2a1212/#122a12), scroll por columna, line numbers sticky.
- Modal remediacion: max-width:900px, max-height:85vh, diff wrapper flex:1.
- Diff scroll clipping fix: parent wrapper overflow:hidden → overflow:auto; height:100% eliminado de #diff-view para que las columnas dicten su altura (max-height:380px;overflow-y:auto). ✅
- Boton global "▶ Escanear Proyecto" eliminado del header; punto unico: panel de findings. ✅
- PDF export via jsPDF + html2canvas + chart.toBase64Image() (portada, resumen, graficas, top-50 findings).
- GET /api/projects + GET /api/projects/{id}: last_scan_tool y last_scan_at via subquery eficiente.
- orchestrator._run_sast: instancia adapters directamente (sin os.environ). ✅
- GET /api/remediate/{finding_id}/pr: retorna pr_url/branch o 404. ✅
- POST /api/remediate/{finding_id}/pr: detecta PR abierto existente (get_existing_open_pr_for_branch), persiste pr_url+pr_branch en BD. ✅
- Remediation model: campos pr_url y pr_branch (TEXT, nullable). SQLite migration en ensure_sqlite_schema(). ✅
- SLA tracking visibility: get_sla_status(finding, now) → ok/warning/breached/exempt/unknown; _SLA_EXEMPT_STATUSES={accepted_risk,false_positive,fixed}; timezone-naive sla_deadline normalizado con .replace(tzinfo=timezone.utc); ?sla_status= filter en GET /api/findings; sla_status+sla_deadline en ambos endpoints de findings; buildSlaBadge usa sla_status del servidor y muestra deadline como fecha MMM DD; KPI counters 🔴 N vencidos / ⚠ N por vencer en #sla-foot (solo cuando > 0). ✅

Tarea B ya implementado ✅:
- tests/test_safe_patching_python.py: 6 tests cubriendo build_safe_patched_content() y helpers.
- docker-compose.yml: servicios api, ollama, ollama-init con healthchecks y named volumes.
- Dockerfile: python:3.12-slim, instala code/requirements.txt, copia src/.
- .env.example: todas las variables documentadas (GitHub App, OLLAMA_HOST, DATABASE_URL).

Phase 3:
1. ✅ DAST adapter real (OWASP ZAP) — `ZapAdapter` con spider + active scan via REST, `_run_dast` orquestrado con `dast_target_url` desde `POST /api/scan`. Docker-compose con ZAP default-on (puerto 8090) + healthcheck.
2. Validacion post-patch: tsc --noEmit (Angular), javac/Maven (Java).
3. Multi-finding PR (batch remediation en una rama).

Phase 4 (Agentic DAST):
1. ✅ Loop LangGraph Explorer → Attacker → Verifier (`src/dast_agent/`), backend LLM Ollama local. Endpoint `POST /api/dast/agent/scan` + polling `GET /api/dast/agent/scan/{scan_id}/status`. Persistencia con `tool="zap+langgraph"`. Dashboard: scanner item "OWASP ZAP + LangGraph (Agentic)" en profile builder con `dast_tool="agent_loop"`; `runScan()` dispara `runAgenticDastFlow()` antes del scan SAST/Quality normal cuando el perfil activa agent_loop.

Phase 4 — Observabilidad (feat/observability ✅):
1. ✅ src/metrics/security_metrics.py: Counter findings_total, Counter remediations_generated_total (db_cache/ollama/fallback), Counter regressions_detected_total, Gauge sla_breached_findings, Histogram scan_duration_seconds, Histogram remediation_latency_seconds. Stubs noop cuando prometheus_client no está instalado.
2. ✅ main.py: prometheus_fastapi_instrumentator instrumenta app y expone GET /metrics. Importa record_remediation, record_scan_duration, update_sla_breached_gauge. _refresh_sla_breached_gauge() cuenta findings open/regression con SLA vencido; llamada en on_startup y post-scan.
3. ✅ escaneo.py: persist_scan() llama record_finding(severity, tool) por cada finding y record_regression() en regresiones.
4. ✅ docker-compose.yml: servicios prometheus (prom/prometheus:latest, port 9090) y grafana (grafana/grafana:latest, port 3000, anonymous Viewer).
5. ✅ infra/prometheus/prometheus.yml: scrape api:8000/metrics cada 15s.
6. ✅ infra/grafana/provisioning/: datasource Prometheus + dashboard JSON con 6 paneles (findings por severidad, tasa regresión, SLA vencido, latencia p50/p95, ratio fuente remediación, duración escaneos).
7. ✅ tests/test_metrics.py (7 tests): /metrics 200, record_finding no raise, record_regression no raise, persist_scan llama record_finding, cache hit llama db_cache, latencia ollama observada, SLA gauge refleja count real.

Phase 4 — ML Risk Scoring (feat/ml-risk-scoring 2026-06-02) ✅:
1. ✅ src/ml/risk_scorer.py: score_finding(finding) → float [0.0–1.0] con fallback por severidad (CRITICAL=0.9, HIGH=0.7, MEDIUM=0.4, LOW=0.2). train_model(findings) → XGBClassifier + joblib. Modelo en models/risk_model.joblib (configurable via RISK_MODEL_PATH).
2. ✅ GET /api/findings + GET /api/projects/{id}/findings: incluyen risk_score: float por finding (score del modelo o fallback).
3. ✅ POST /api/ml/train: entrena sobre todos los findings de la DB, persiste modelo, retorna {precision, recall, roc_auc, n_samples}; HTTP 400 si < 10 findings.
4. ✅ Dashboard: buildRiskBadge() muestra progress bar + % por finding. Sort-by-risk toggle. Botón "🧠 Reentrenar modelo" con feedback de métricas. Controles inyectados por renderMlControls() junto al botón Refresh.
5. ✅ code/requirements.txt: xgboost>=2.0.0, scikit-learn>=1.4.0, joblib>=1.3.0 instalados.
6. ✅ tests/test_risk_scorer.py: 5 tests — fallback por severidad, train_model con dataset mínimo, POST /api/ml/train 400, risk_score en GET /api/findings, degradación cuando _ML_AVAILABLE=False.

Phase 4 — ML: Fix de feature leakage en risk_scorer (2026-06-03) ✅:
1. ✅ Causa raíz: el label viejo era `severity in {CRITICAL,HIGH} AND status in {open,regression}`, y `severity_enc` (feature 0) + `status_enc` (feature 5) estaban en el vector → el modelo memorizaba la regla del label (precision/recall/roc_auc = 1.0).
2. ✅ Nuevo label en `_label_from_finding(finding)`: `1 si (regression_count > 0 OR status=="regression" OR sla_breached) else 0`, donde `sla_breached = sla_deadline is not None AND sla_deadline < ahora_utc`. Outcome real "el finding recurrió o incumplió SLA"; no usa severity/confidence/tool.
3. ✅ `_features_from_finding()` ahora devuelve 5 features: `[severity_enc, tool_enc, days_age, days_to_deadline, confidence_enc]`. ELIMINADOS `status_enc` (filtraba status=="regression") y `regression_count` (es parte del label). AÑADIDO `confidence_enc` (`_CONFIDENCE_ENCODE = {HIGH:3, MEDIUM:2, LOW:1}`). Lógica de days_age / days_to_deadline sin cambios.
4. ✅ `train_model()`: `y = [_label_from_finding(f) for f in findings]`; mensaje del ValueError de clase única reescrito para explicar "no regressions or SLA breaches present" en vez de "CRITICAL/HIGH open". Resto del pipeline (split estratificado, hiperparámetros XGBClassifier, joblib.dump, return dict) sin cambios.
5. ✅ `score_finding()` sin cambios de lógica (5 features consistentes con el modelo entrenado); fallback por severidad intacto.
6. ✅ tests/test_risk_scorer.py → 6 tests: `test_train_model_minimal_dataset` reconstruido (6 positivos regresión/SLA + 8 negativos open); nuevo `test_features_exclude_leakage_columns` (vector longitud 5; mismo vector pese a status/regression_count distintos; label diferente).
7. ℹ️ Nota de producción: al re-entrenar con `POST /api/ml/train` sobre la base real, es esperado y CORRECTO que (a) devuelva 400/ValueError de clase única si no hay findings con regresión ni SLA vencido, o (b) las métricas bajen de 1.0 a valores realistas. No reintroducir severity/status en el label para "arreglar" un 400.
8. ✅ Modelo existente models/risk_model.joblib NO borrado desde código — se regenera re-entrenando (el .joblib viejo fue entrenado con 6 features y será reemplazado al próximo train).

---

## Comandos Utiles

```bash
# Levantar backend
uvicorn src.api.main:app --reload

# Validar compilacion
python3 -m compileall src

# Tests
python3 -m pytest tests/ -v

# Scanner por CLI
python3 -m src.scanners.escaneo <target_path> python
python3 -m src.scanners.escaneo <target_path> angular
python3 -m src.scanners.escaneo <target_path> java

# Instalar dependencias (usar siempre el pip del entorno)
/home/zamaer/anaconda3/envs/devsecops-control-plane/bin/pip install -r code/requirements.txt
```

---

## Reglas Para La Siguiente IA

- Leer este archivo y ROADMAP.md antes de cualquier cambio.
- Priorizar el codigo actual sobre cualquier descripcion antigua en este documento.
- No leer ni exponer secretos reales.
- No commitear .env, .pem, SQLite local, WAL/SHM ni workspace/uploads/.
- Mantener remediaciones estrictamente por tecnologia: Angular no recibe parche Python.
- Para Python, conservar guardrails AST fuertes (ast.parse).
- Si se toca GitHub PR automation, mantener rama security-fix-{finding_id} y PR idempotente.
- Si se modifica el dashboard, probar manualmente ZIP/repo → scan → Auto-Fix → PR.

---

## Narrativa Profesional

Este proyecto posiciona a Ernesto para roles de AppSec Engineer, DevSecOps Engineer o Platform Security Engineer.

Pitch:
  "Construi un control plane de seguridad self-hosted que orquesta
  multiples herramientas (Bandit, Semgrep, pip-audit, OWASP DC),
  automatiza remediacion con LLM local, y propone fixes como Pull
  Requests revisables. El codigo nunca sale de la infraestructura."

Keywords: DevSecOps, AppSec, SAST, SCA, AppSec Orchestration,
AI Remediation, Local LLM Inference, FastAPI, Kubernetes, OpenShift,
Helm, Bandit, Semgrep, OWASP ZAP, SonarQube, Ollama, LangGraph,
Vulnerability Management, Security Automation, GitHub App.
