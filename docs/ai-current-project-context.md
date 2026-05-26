# AI DevSecOps Control Plane - Contexto Actual Para Handoff

Ultima actualizacion: 2026-05-26 (Quality-first: Pylint/ESLint/SonarQube adapters, dashboard custom Quality profile, Docker ZAP/Sonar ready)

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
- Dashboard: SPA estatica HTML/JavaScript/Tailwind servida desde GET /.
- Scanners SAST: Bandit + Semgrep (Python), Semgrep (Angular/Java).
- Scanners SCA: pip-audit (Python), OWASP Dependency Check (Java).
- Scanners Quality: Pylint (Python), ESLint (Angular/TypeScript), SonarQube Community REST.
- Orquestacion: ScanProfile + ScanOrchestrator con ThreadPoolExecutor.
- SLA deadlines: CRITICAL=3d, HIGH=7d, MEDIUM=30d, LOW=90d.
- IA local: Ollama, modelo por defecto qwen2.5-coder:14b.
- GitHub: GitHub App con JWT RS256; webhook PR con Check Run; GitHub Actions CI.
- Validacion: python3 -m compileall src + python3 -m pytest tests/ -v (65 tests).

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
src/ai_engine/remediator.py
src/integrations/github_client.py
src/dashboard/index.html
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
- GET  /api/findings                        → lista hallazgos
- GET  /api/projects                        → lista proyectos
- GET  /api/projects/{id}                   → proyecto por id
- GET  /api/projects/{id}/findings          → findings del proyecto
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
- GET  /api/reports/project/{id}            → reporte by_severity/status/top_rules
- POST /api/webhooks/github                 → webhook PR con HMAC-SHA256

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

ScanOrchestrator._run_quality() ejecuta adapters reales segun ScanProfile:

- python + quality_tool=pylint → PylintAdapter.
- angular/typescript + quality_tool=eslint → EslintAdapter.
- python/angular/typescript/java + quality_tool=sonarqube → SonarQubeAdapter REST.
- Java Quality por CLI local queda pendiente; Java puede consumir findings SonarQube si el proyecto ya fue analizado en Sonar.
- Si falta el binario (`pylint`, `node_modules/.bin/eslint` o `npx --no-install eslint`), el adapter retorna [] y el orquestador reporta el error sin tumbar todo el scan.
- SonarQube usa `SONARQUBE_URL`, `SONARQUBE_TOKEN` y opcionalmente `SONARQUBE_PROJECT_KEY`; si no hay project key deriva una desde el nombre del target_path.

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

Orden de fallback: semantico (metodo) → clase → rango de lineas.
Guardrail de tamano: archivo > 30 lineas, resultado < 60% del original → rechazar.

---

## Prompts De Remediacion (remediator.py)

- build_python_prompt(finding): prompt Python con contrato estricto AST.
- build_angular_prompt(finding): detecta si es secret (ANG-SECRET-* o snippet con apiKey/token/password) y agrega instruccion CI/CD. XSS no recibe esa instruccion.
- build_java_prompt(finding): contrato Java AppSec.

Deteccion de secrets en Angular:
  SECRET_PREFIXES = ('ANG-SECRET', 'SEMGREP-SECRET', ...)
  SECRET_KEYWORDS = ('apikey', 'token', 'secret', 'password', 'credential', 'auth', 'key')

---

## Dashboard

src/dashboard/index.html capacidades actuales:
- Vista de proyectos con contador de findings + mini-badges de severidad C/H/M/L por proyecto.
  - Backend: GET /api/projects incluye findings_summary: {CRITICAL, HIGH, MEDIUM, LOW, total}.
- Modal 2 pasos: Paso 1 = seleccion de ScanProfile (cards), Paso 2 = ZIP/clone.
  - Paso 1: cards con iconos SVG inline (Py azul, Angular rojo, Java ☕, Full Scan escudo, Custom engranaje), descripcion de herramientas y badge de stack. Hover resaltado via CSS .profile-card.
  - Paso 2: sub-selector GitHub / GitLab con SVG logos; placeholder del input de URL cambia segun seleccion (setCloneSource()).
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
tests/test_angular_prompt.py          (4 tests)
tests/test_finding_upsert.py          (6 tests)
tests/test_file_content_path.py       (2 tests)
tests/test_github_path.py             (4 tests)
tests/test_odc_adapter.py             (5 tests)
tests/test_pip_audit_adapter.py       (5 tests)
tests/test_quality_adapters.py        (7 tests)
tests/test_safe_patching_python.py    (6 tests)  ← nuevo
tests/test_scan_profile.py            (11 tests)
tests/test_semantic_patching.py       (11 tests)
tests/test_semgrep_adapter.py         (4 tests)
Total: 65 passed
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

## Riesgos Conocidos

1. DAST runner sigue como placeholder — retorna [].
2. Validacion Angular/Java es heuristica (brace-counting), no parser real.
3. Java Quality local sigue pendiente; SonarQube requiere proyecto previamente analizado para devolver findings.
4. workspace/ puede contener uploads temporales; no versionar.
5. ensure_sqlite_schema() es SQLite-only; desactivar para PostgreSQL.
6. El contexto del archivo usa Finding.line_start; si el scanner reporta una línea incorrecta el contexto puede mostrar código diferente al snippet real.

---

## Proximos Pasos Recomendados

Inmediato (proxima sesion):
1. DAST adapter real con OWASP ZAP o validacion post-patch `tsc --noEmit` / Maven-Java.

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

Tarea B ya implementado ✅:
- tests/test_safe_patching_python.py: 6 tests cubriendo build_safe_patched_content() y helpers.
- docker-compose.yml: servicios api, ollama, ollama-init con healthchecks y named volumes.
- Dockerfile: python:3.12-slim, instala code/requirements.txt, copia src/.
- .env.example: todas las variables documentadas (GitHub App, OLLAMA_HOST, DATABASE_URL).

Phase 3:
1. DAST adapter real (OWASP ZAP).
2. Validacion post-patch: tsc --noEmit (Angular), javac/Maven (Java).
3. Multi-finding PR (batch remediation en una rama).

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
