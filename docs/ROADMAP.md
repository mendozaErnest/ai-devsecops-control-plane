# Roadmap — Cierre de Brechas vs Veracode/Fortify

Última actualización: 2026-05-23

Objetivo: cerrar las brechas identificadas en la comparativa enterprise en **1-2 semanas** con Windsurf + Claude como agentes de implementación. Cada ítem es directamente rastreable a un ❌ de la tabla comparativa.

---

## Resumen de brechas priorizadas

| Área | Brecha (❌ en comparativa) | Sprint | Complejidad |
|---|---|---|---|
| SCA / CVEs | Cobertura de CVEs conocidos en libs | Semana 1 | Baja |
| SCA / CVEs | Análisis de dependencias (transitivas parcial) | Semana 1 | Baja |
| Ciclo de vida | Estado `regression` cuando finding reaparece | Semana 1 | Baja |
| Ciclo de vida | `accepted_risk` / `false_positive` con audit trail | Semana 1 | Media |
| Ciclo de vida | Historial de reapariciones por finding | Semana 1 | Baja |
| Ciclo de vida | SLA tracking por severidad | Semana 2 | Media |
| Ciclo de vida | Reportes por equipo/proyecto | Semana 2 | Media |
| CI/CD | Webhook: scan automático en cada PR | Semana 2 | Media |
| CI/CD | GitHub Actions workflow reutilizable | Semana 2 | Baja |
| CI/CD | Block merge si hay findings críticos | Semana 2 | Baja |

Brechas **fuera de alcance en 2 semanas** (requieren motor de análisis estático completo):
- Taint analysis cross-método / cross-archivo — necesita IR/AST completo del proyecto.
- Análisis por bytecode Java — requiere compilación real + instrumentación JVM.
- Dependencias transitivas completas — pip-audit/OWASP DC cubren las directas; las transitivas profundas requieren resolución de grafos que estas herramientas ya hacen parcialmente.

---

## Semana 1 — SCA layer + ciclo de vida de findings

### S1-1: SCA Python con pip-audit

**Brecha que cierra:** `Cobertura de CVEs conocidos en libs ❌`

**Qué hacer:**
- Crear `src/scanners/pip_audit_adapter.py` como `BaseScannerAdapter` para tecnología `python`.
- Ejecutar `pip-audit --format json --output -` sobre el directorio del proyecto target.
- Normalizar salida a `Finding` con `severity` mapeado desde `fix_versions` ausente → `HIGH`.
- Registrar `rule_id = "SCA-PIP-{vuln_id}"` para distinguir de SAST.
- Orquestador en `escaneo.py`: cuando `technology == python`, correr Bandit + Semgrep + pip-audit en paralelo.

**Archivos a crear/modificar:**
- `src/scanners/pip_audit_adapter.py` (nuevo)
- `src/scanners/escaneo.py` (agregar pip-audit al pipeline Python)
- `code/requirements.txt` (agregar `pip-audit`)

---

### S1-2: SCA Java con OWASP Dependency Check

**Brecha que cierra:** `Cobertura de CVEs conocidos en libs ❌` para Java

**Qué hacer:**
- Crear `src/scanners/odc_adapter.py` que detecte si el target tiene `pom.xml` o `build.gradle`.
- Ejecutar `dependency-check --scan <path> --format JSON --out <tmp>` como subprocess.
- Parsear `dependency-check-report.json` → normalizar a `Finding`.
- Agregar al pipeline Java en `escaneo.py`.

**Prerequisito externo:** OWASP Dependency Check CLI instalado (`brew install dependency-check` / package manager).

**Archivos a crear/modificar:**
- `src/scanners/odc_adapter.py` (nuevo)
- `src/scanners/escaneo.py`

---

### S1-3: Estado `regression` en el ciclo de vida

**Brecha que cierra:** `Estados: open/fixed/regression ❌`

El modelo de datos ya tiene el campo `status` en `Finding`. La lógica de regresión está documentada como pendiente en `escaneo.py`.

**Qué hacer:**
- En `run_scan()`, cuando se detecta un finding ya existente con `status == "fixed"`, cambiarlo a `status = "regression"` en lugar de `"open"`.
- Agregar campo `regression_count: int = 0` a `Finding` + migración.
- Incrementar `regression_count` cada vez que ocurra la transición `fixed → regression`.
- Respetar `accepted_risk` y `false_positive`: si el finding está en esos estados, NO reabrirlo.

**Archivos a modificar:**
- `src/api/models.py` (campo `regression_count`)
- `src/scanners/escaneo.py` (lógica de transición de estado)

---

### S1-4: Accepted risk y false positive con audit trail

**Brecha que cierra:** `Accepted risk / false positive ❌` (el modelo existe pero no está integrado)

**Qué hacer:**
- Crear tabla `FindingAuditEvent` con campos: `finding_id`, `event_type` (`status_change`, `accepted_risk`, `false_positive`), `from_status`, `to_status`, `reason`, `created_at`.
- Agregar endpoints:
  - `POST /api/findings/{finding_id}/accept-risk` — body: `{ "reason": "..." }`.
  - `POST /api/findings/{finding_id}/false-positive` — body: `{ "reason": "..." }`.
  - `GET /api/findings/{finding_id}/audit` — historial de eventos.
- En el dashboard: botones "Accept Risk" y "False Positive" en la fila del finding, con modal de razón obligatoria.
- La lógica de regresión (S1-3) debe respetar estos estados.

**Archivos a crear/modificar:**
- `src/api/models.py` (nuevo modelo `FindingAuditEvent`)
- `src/api/main.py` (3 endpoints nuevos)
- `src/dashboard/index.html` (botones + modal)

---

### S1-5: Historial de reapariciones

**Brecha que cierra:** `Historial de reapariciones ❌`

Implementado automáticamente con S1-3 + S1-4: `FindingAuditEvent` registra cada transición de estado con timestamp. El endpoint `GET /api/findings/{finding_id}/audit` sirve el historial completo.

**Adicional en dashboard:**
- Columna "Reapariciones" en la tabla de findings usando `regression_count`.
- Tooltip o modal con el historial de audit al hacer click.

---

## Semana 2 — SLA, reporting y CI/CD integration

### S2-1: SLA tracking por severidad

**Brecha que cierra:** `SLA tracking por severidad ❌`

**Qué hacer:**
- Agregar campo `sla_deadline: datetime | None` a `Finding`, calculado al crear el finding según severidad:
  - `critical`: +3 días hábiles.
  - `high`: +7 días hábiles.
  - `medium`: +30 días hábiles.
  - `low`: +90 días hábiles.
- Agregar campo `sla_status: str` derivado (`on_track`, `at_risk`, `breached`).
- Endpoint `GET /api/findings?sla_status=breached` para filtrar.
- Dashboard: badge de SLA en cada finding (verde/amarillo/rojo).

**Archivos a modificar:**
- `src/api/models.py`
- `src/api/main.py`
- `src/scanners/escaneo.py` (calcular `sla_deadline` al persistir finding)
- `src/dashboard/index.html`

---

### S2-2: Reportes por equipo/proyecto

**Brecha que cierra:** `Reportes por equipo/proyecto ❌`

**Qué hacer:**
- Endpoint `GET /api/reports/project/{project_id}` que devuelva:
  - Total findings por severidad.
  - Findings open / fixed / regression / accepted_risk / false_positive.
  - SLA breached count.
  - Top 5 reglas más frecuentes.
  - Trend: findings abiertos en los últimos 30 días (por fecha de scan).
- Endpoint `GET /api/reports/summary` para todos los proyectos.
- Dashboard: nueva pestaña "Reports" con gráficos simples (Chart.js CDN).

**Archivos a modificar:**
- `src/api/main.py` (2 endpoints nuevos)
- `src/dashboard/index.html` (pestaña Reports + Chart.js)

---

### S2-3: Webhook — scan automático en cada PR

**Brecha que cierra:** `Scan en cada PR automático ❌`

**Qué hacer:**
- Endpoint `POST /api/webhooks/github` que valide firma HMAC-SHA256 del webhook.
- Procesar eventos `pull_request` con `action: opened | synchronize | reopened`.
- Extraer repo, branch, PR number del payload.
- Clonar/actualizar el branch del PR en `workspace/` y ejecutar scan.
- Publicar resultado como GitHub Check Run (`POST /repos/{owner}/{repo}/check-runs`) con estado `success` o `failure`.
- Variable de entorno: `GITHUB_WEBHOOK_SECRET`.

**Archivos a crear/modificar:**
- `src/api/main.py` (endpoint webhook)
- `src/integrations/github_client.py` (método `create_check_run()`)
- `.env.example` (agregar `GITHUB_WEBHOOK_SECRET`)

---

### S2-4: Block merge si hay findings críticos

**Brecha que cierra:** `Block merge si hay críticos ❌`

Implementado como parte de S2-3: el Check Run que se crea tiene `conclusion: failure` si existen findings con `severity == "critical"` o `severity == "high"` en estado `open`. GitHub bloquea el merge automáticamente cuando un Check Run requerido falla.

**Configuración adicional documentada en README:**
- Ir a Settings → Branches → Branch protection rules.
- Marcar "Require status checks to pass" y seleccionar el check `ai-devsecops/scan`.

---

### S2-5: GitHub Actions workflow reutilizable

**Brecha que cierra:** `Plugin GitHub Actions ❌`

**Qué hacer:**
- Crear `.github/workflows/devsecops-scan.yml` como workflow template.
- El workflow llama al API de la plataforma via `POST /api/projects/clone-repo` o `POST /api/webhooks/github`.
- Output: URL del reporte en el dashboard como anotación del PR.
- Variante self-hosted (plataforma corriendo en runner) y variante remota (plataforma como servicio interno).

**Archivos a crear:**
- `.github/workflows/devsecops-scan.yml`

---

## Estado actual vs. objetivo post-sprint

| Área | % actual | % post-sprint (estimado) |
|---|---|---|
| SAST Python | 60% | 70% (+ SCA layer) |
| SAST Angular/Java | 35% | 45% (+ SCA Java, + build validation) |
| Remediación IA | 90% | 90% (sin cambios, ya es el diferenciador) |
| Ciclo de vida findings | 30% | 75% (regression, accepted_risk, SLA, historial, reportes) |
| CI/CD integration | 20% | 70% (webhook, Actions, block merge) |
| **Promedio global** | **47%** | **~70%** |

---

## Orden de implementación recomendado

```
Día 1-2:  S1-3 (regression) → S1-4 (accepted_risk/false_positive) → S1-5 (historial)
Día 3-4:  S1-1 (pip-audit) → S1-2 (OWASP DC)
Día 5-6:  S2-1 (SLA tracking) → S2-2 (reportes)
Día 7-8:  S2-3 (webhook PR) → S2-4 (block merge — sale gratis de S2-3)
Día 9-10: S2-5 (GitHub Actions workflow) + tests de integración
```

El orden prioriza primero el ciclo de vida porque es la brecha más grande (30%) y porque `regression` + `accepted_risk` son prerequisitos para que SLA y reportes tengan datos reales.
