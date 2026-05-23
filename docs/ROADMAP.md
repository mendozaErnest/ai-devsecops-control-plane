# Roadmap — AI DevSecOps Control Plane

Ultima actualizacion: 2026-05-23

Objetivo: plataforma AppSec de orquestacion que conecta multiples
herramientas (SAST, DAST, Quality) con AI remediation local.
Implementacion con VSCode + Claude Sonnet 4.6 como agente.

---

## Progreso vs. Veracode/Fortify

| Area | % actual | % objetivo post-Phase 2 |
|---|---|---|
| SAST Python | 60% | 70% |
| SAST Angular/Java | 35% | 50% |
| Remediacion IA | 90% | 90% (ya es el diferenciador) |
| Ciclo de vida findings | 30% | 75% |
| CI/CD integration | 20% | 70% |
| **Promedio global** | **47%** | **~72%** |

---

## Phase 1 — SAST Core ✅ Completa

| Capacidad | Estado |
|---|---|
| Python SAST: Bandit + Semgrep dual-engine con deduplicacion | ✅ |
| Angular/TS SAST: Semgrep (XSS, secrets, unsafe bindings) | ✅ |
| Java SAST: Semgrep (SQL injection, crypto, TLS) | ✅ |
| AI remediation: Ollama local, prompts por tecnologia | ✅ |
| Parcheo semantico: find_ts_method_range, find_java_method_range | ✅ |
| GitHub App PR automation: rama por finding, PR idempotente | ✅ |
| Python SCA: pip-audit | ✅ |
| Java SCA: OWASP Dependency Check adapter | ✅ |
| Webhook PR + GitHub Check Run | ✅ |
| GitHub Actions CI workflow | ✅ |

---

## Phase 2 — Scan Profile + Orquestacion 🔨 En progreso

### Completo en esta fase

| Capacidad | Estado |
|---|---|
| Modelo ScanProfile (SAST/DAST/Quality tool selector) | ✅ |
| 4 perfiles por defecto sembrados en startup (idempotente) | ✅ |
| Endpoints GET/POST/PUT /api/profiles | ✅ |
| ScanOrchestrator con ThreadPoolExecutor | ✅ |
| DAST runner placeholder (retorna [] sin crash) | ✅ |
| Quality runner placeholder (retorna [] sin crash) | ✅ |
| FK scan_profile_id en Project | ✅ |
| UI wizard 2 pasos: perfil → ZIP/clone | ✅ |
| Tab Reportes en dashboard (Chart.js) | ✅ |
| GET /api/reports/project/{id} | ✅ |
| Modelo FindingAuditEvent | ✅ |
| Campo regression_count y sla_deadline en Finding | ✅ |

### Pendiente inmediato — BUG CRITICO

| Item | Detalle |
|---|---|
| **FIX: Semgrep no corre via ScanOrchestrator** | _run_sast usa os.environ en thread (unreliable). Fix: instanciar adapters directamente segun profile.sast_tools sin os.environ. Ver ai-current-project-context.md seccion BUG CRITICO. |
| **FIX: CombinedScannerAdapter.tool_name** | Solo muestra primer hijo. Debe concatenar todos con "+". |

### Pendiente — Ciclo de vida

| Item | Brecha que cierra | Complejidad |
|---|---|---|
| Estado `regression` cuando finding reaparece | `fixed → regression` al re-escanear | Baja |
| `accepted_risk` / `false_positive` con audit trail | Triage workflow como Fortify | Media |
| Historial de reapariciones en dashboard | regression_count + audit events | Baja |
| Endpoints POST /api/findings/{id}/accept-risk y /false-positive | Acciones de triage con razon obligatoria | Media |

Orden de implementacion: regression → accepted_risk/false_positive → historial.
La logica de regression es prerequisito para que SLA y reportes tengan datos reales.

### Pendiente — SLA y Reportes

| Item | Brecha que cierra | Complejidad |
|---|---|---|
| SLA tracking con badge en dashboard (verde/amarillo/rojo) | SLA tracking por severidad | Media |
| GET /api/findings?sla_status=breached | Filtro de findings vencidos | Baja |
| Reporte por proyecto con trend 30 dias | Reportes por equipo/proyecto | Media |

### Pendiente — CI/CD

| Item | Brecha que cierra | Complejidad |
|---|---|---|
| POST /api/webhooks/github con HMAC-SHA256 | Scan automatico en cada PR | Media |
| GitHub Check Run: conclusion=failure si hay CRITICAL/HIGH | Block merge si hay criticos | Baja (sale del webhook) |
| .github/workflows/devsecops-scan.yml reutilizable | Plugin GitHub Actions | Baja |

---

## Phase 3 — Adapters Reales DAST y Quality 🔜

| Item | Herramienta | Prerequisito |
|---|---|---|
| DAST adapter real | OWASP ZAP REST API | ZAP corriendo en Docker |
| Code Quality adapter | SonarQube Community REST API | SonarQube en Docker |
| Pylint / ESLint adapter | CLI directo | Sin servidor externo |
| Semgrep framework rulesets | p/django, p/flask, p/java-spring | Solo agregar al diccionario |

---

## Phase 4 — Infraestructura y DAST Agentivo 🔜

| Surface | Tool |
|---|---|
| Docker + K8s YAML + Helm | Checkov |
| Container images | Trivy |
| Secret scanning en historial git | gitleaks |
| K8s cluster hardening | kube-bench |

DAST agentivo con LangGraph StateGraph:

```
Explorer Agent → Attacker Agent → Verifier Agent
   (crawl)        (fuzzing)         (confirmar)
      ↑______________feedback______________↑
```

---

## Brechas Fuera De Alcance A Corto Plazo

- Taint analysis cross-metodo/cross-archivo: requiere IR/AST completo del proyecto.
- Analisis por bytecode Java: requiere compilacion real + instrumentacion JVM.
- Dependencias transitivas profundas: pip-audit/OWASP DC cubren directas; las transitivas profundas requieren resolucion de grafos completa.
- Fortify/Veracode real: requieren licencia y API key de pago. En la UI aparecen como opciones con badge [Requiere licencia] que internamente rutean a Semgrep con rulesets enterprise.

---

## Orden De Implementacion Recomendado

```
Sesion actual:  Fix bug orchestrator Semgrep + tool_name
Dia 1-2:        regression → accepted_risk/false_positive → historial
Dia 3-4:        SLA tracking → reportes con trend
Dia 5-6:        Webhook PR → Check Run → block merge (sale gratis)
Dia 7:          GitHub Actions workflow reutilizable
Dia 8-9:        DAST ZAP adapter (Docker prerequisito)
Dia 10:         Semgrep framework rulesets (p/django, p/flask, p/java-spring)
```
