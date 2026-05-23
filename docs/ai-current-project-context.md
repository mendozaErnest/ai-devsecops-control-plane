# AI DevSecOps Control Plane - Contexto Actual Para Handoff

Ultima actualizacion: 2026-05-23

Este documento esta pensado para entregar a otra IA o agente tecnico para que pueda continuar el proyecto sin perder contexto. Distingue entre lo implementado actualmente en el repo y los siguientes pasos recomendados.

## Resumen Ejecutivo

AI DevSecOps Control Plane es una plataforma local/self-hosted para automatizar el ciclo de vida de seguridad de aplicaciones:

1. Registrar proyectos de codigo fuente.
2. Escanearlos con adaptadores SAST por tecnologia.
3. Persistir hallazgos normalizados en base de datos.
4. Generar remediaciones con un LLM local via Ollama.
5. Crear Pull Requests reales en GitHub con parches revisables.

La propuesta central del producto es que el codigo no salga de la infraestructura del usuario. El LLM corre localmente y GitHub se integra mediante GitHub App.

## Ruta Local Del Repo

```text
/home/zamaer/Documentos/codigo-general/AI-DevSecOps-Control-Plane
```

## Stack Actual

- Backend: FastAPI.
- Base de datos: SQLModel sobre SQLite por defecto.
- Dashboard: SPA estatica en HTML/JavaScript/Tailwind servida desde `GET /`.
- Scanners: adaptadores para Python, Angular/TypeScript y Java.
- Python SAST: Bandit.
- IA local: Ollama.
- Modelo por defecto: `qwen2.5-coder:14b`.
- GitHub: GitHub App con JWT RS256 e installation token.
- Validacion basica: `python3 -m compileall src`.

Dependencias relevantes en `code/requirements.txt`:

```text
fastapi
uvicorn
bandit
sqlmodel
psycopg2-binary
httpx>=0.27.0
PyJWT>=2.8.0
cryptography>=42.0.0
```

## Archivos Clave

```text
src/api/main.py
src/api/models.py
src/api/database.py
src/scanners/escaneo.py
src/scanners/base.py
src/scanners/bandit_adapter.py
src/scanners/angular_adapter.py
src/scanners/java_adapter.py
src/ai_engine/remediator.py
src/integrations/github_client.py
src/dashboard/index.html
code/requirements.txt
.gitignore
docs/ai-current-project-context.md
```

## Modelo De Datos

Definido en `src/api/models.py`.

Entidades principales:

- `Target`: target legacy/compatibilidad para scans.
- `Project`: proyecto escaneable, con `name`, `source_type`, `target_path` y `technology`.
- `Scan`: ejecucion de scanner asociada a `Project` y opcionalmente a `Target`.
- `Finding`: hallazgo normalizado asociado a un `Scan`.
- `Remediation`: remediacion generada por IA asociada a un `Finding`.
- `MetricsSnapshot`: metricas por target.

Relacion importante para remediacion dinamica:

```text
Finding -> Scan -> Project -> technology
```

Tecnologias soportadas actualmente:

```text
python
angular
typescript
java
```

Internamente `typescript` se normaliza como `angular` en los flujos de remediacion.

## API Actual

Definida en `src/api/main.py`.

Endpoints principales:

- `GET /`: sirve el dashboard.
- `GET /api/findings`: lista hallazgos.
- `GET /api/projects`: lista proyectos con conteos.
- `GET /api/projects/{project_id}`: obtiene un proyecto.
- `GET /api/projects/{project_id}/findings`: lista findings de un proyecto.
- `POST /api/projects/{project_id}/scan`: reescanea un proyecto.
- `POST /api/projects/upload-zip`: sube un ZIP, crea proyecto y escanea.
- `POST /api/projects/clone-repo`: clona repo Git, crea proyecto y escanea.
- `POST /api/scan`: endpoint legacy para escanear un path permitido.
- `GET /api/ai-status`: revisa disponibilidad de Ollama.
- `POST /api/remediate/{finding_id}`: genera remediacion con Ollama y la persiste.
- `POST /api/remediate/{finding_id}/pr`: crea PR real con la ultima remediacion.
- `DELETE /api/remediate/{finding_id}/pr`: elimina la rama `security-fix-{finding_id}`.
- `GET /api/ping?ip=...`: endpoint de ejemplo seguro; valida IPv4 y ejecuta `ping` sin `shell=True`.

Seguridad de rutas de scan:

- `validate_scan_target()` restringe escaneos a `PROJECT_ROOT`, `WORKSPACE_ROOT` o `SCAN_ALLOWED_ROOTS`.
- ZIP upload usa extraccion segura para evitar path traversal.

## Flujo De Proyectos Y Scanners

El orquestador esta en `src/scanners/escaneo.py`.

`get_scanner_adapter(technology)` selecciona:

- `python` -> `BanditAdapter`
- `angular` o `typescript` -> `AngularAdapter`
- `java` -> `JavaAdapter`

`run_scan(target_path, technology, project_id=None)`:

1. Valida que exista un adaptador.
2. Ejecuta el scanner de la tecnologia.
3. Persiste `Target`, `Scan` y `Finding`.
4. Deduplica hallazgos por fingerprint SHA-256.
5. Si un finding ya existe, lo vuelve a marcar como `open`.

Pendiente recomendado:

- Implementar logica de regresiones y estados:
  - `fixed` -> `regression` si reaparece.
  - respetar `accepted_risk` y `false_positive`.

## Remediador IA Local

Archivo: `src/ai_engine/remediator.py`.

Estado actual importante:

- El remediador ya no esta hardcodeado a Python.
- Recupera tecnologia desde base de datos usando:

```text
Finding -> Scan -> Project -> technology
```

- `enrich_finding_details()` agrega `technology` al contexto.
- `build_prompt()` despacha a prompt especifico:
  - `build_python_prompt()`
  - `build_angular_prompt()`
  - `build_java_prompt()`

### Prompt Python

Rol: motor AI DevSecOps para parches Python.

Contrato:

- Debe devolver exactamente un bloque fenced `python`.
- El bloque debe ser Python valido.
- No debe mezclar lenguajes bajo ninguna circunstancia.
- Debe incluir la funcion completa afectada.
- Sigue enfocado en hallazgos SAST tipo Bandit:
  - OS injection.
  - imports inseguros.
  - `shell=True`.
  - deserializacion insegura.
  - MD5/SHA1.
  - validacion TLS.
  - path traversal.

### Prompt Angular

Rol: "Eres un Arquitecto Senior de Frontend y Experto en Seguridad en Angular/TypeScript".

Contrato:

- Devuelve bloque fenced `typescript`, `html` o `angular`.
- El contenido debe ser TypeScript/HTML valido para Angular.
- Prohibido devolver Python, Java, Bash, diffs o pseudocodigo.
- Debe mitigar problemas como:
  - uso inseguro de `innerHTML`.
  - sanitizacion incorrecta.
  - mal uso de `DomSanitizer`.
  - bindings inseguros.
  - URLs, estilos o scripts dinamicos desde entrada de usuario.

### Prompt Java

Rol: "Eres un Ingeniero Principal de Software Java y Experto en AppSec Criptografica y Web".

Contrato:

- Devuelve bloque fenced `java`.
- El contenido debe ser Java nativo valido.
- Prohibido devolver Python, TypeScript, HTML, Bash, diffs o pseudocodigo.
- Debe mitigar problemas como:
  - MD5/SHA-1.
  - SQL injection con `PreparedStatement`.
  - TLS inseguro.
  - `SecureRandom`.
  - deserializacion insegura.
  - validacion de entradas y rutas.

## GitHub App Y Pull Requests

Archivo: `src/integrations/github_client.py`.

Variables esperadas:

```env
GITHUB_APP_ID=<github-app-id>
GITHUB_INSTALLATION_ID=<installation-id>
GITHUB_PRIVATE_KEY_PATH=<path-to-private-key-pem>
GITHUB_REPO=<owner/repo>
GITHUB_BASE_BRANCH=main
```

No exponer ni copiar llaves `.pem`, tokens o `.env` en respuestas, docs publicos o commits.

Flujo de auth:

1. Carga `.env`.
2. Lee `GITHUB_APP_ID`, `GITHUB_INSTALLATION_ID`, `GITHUB_PRIVATE_KEY_PATH`, `GITHUB_REPO`.
3. Genera JWT RS256 con `PyJWT`.
4. Intercambia JWT por installation token:

```text
POST /app/installations/{installation_id}/access_tokens
```

5. Usa `Authorization: Bearer <installation_token>`.

## Flujo Actual De PR

Funcion: `create_security_pr(finding_details, remediation_text)`.

1. Obtiene SHA de `GITHUB_BASE_BRANCH`.
2. Crea rama `security-fix-{finding_id}`.
3. Si la rama ya existe, la reancla al SHA base con `PATCH /git/refs/heads/{branch}`.
4. Extrae el bloque de codigo de la remediacion segun tecnologia:
   - Python: `extract_python_code_block()` con validacion AST.
   - Angular/Java: `extract_generic_code_block()` con etiquetas permitidas.
5. Descarga el archivo vulnerable desde GitHub.
6. Construye contenido parcheado.
7. Hace commit en la rama.
8. Abre PR.
9. Si ya existe PR abierto para la rama, devuelve ese PR.

Nota critica:

- Ya no se crean archivos `docs/remediations/*.md`.
- La explicacion de IA va en el body del PR.

## Guardrails De Parches

### Python

Python mantiene guardrails fuertes basados en AST:

- Extrae solo bloque fenced `python` o `py`.
- Limpia wrappers/prosa.
- Valida con `ast.parse`.
- Exige funcion completa (`def` o `async def`) para parches cortos.
- Inserta imports faltantes de forma controlada.
- Reemplaza solo la funcion afectada cuando el snippet es corto.
- Rechaza:
  - bloque vacio.
  - Python invalido.
  - archivo resultante vacio.
  - archivo grande reducido de forma sospechosa.
  - reemplazo completo con snippet corto.

Funciones clave:

```text
extract_python_code_block()
split_patch_imports_and_function()
find_enclosing_function_range()
find_function_range_by_name()
find_function_range_by_signature()
build_safe_python_patched_content()
build_safe_patched_content()
```

### Angular Y Java

El filtro AST de Python ya no se ejecuta para Angular/Java.

Para tecnologias no Python se usa validacion ligera:

- Extrae bloque fenced esperado:
  - Angular: `typescript`, `ts`, `html`, `angular`.
  - Java: `java`.
- Si hay fences pero ninguno coincide con la tecnologia, falla con error claro.
- Reemplaza full-file solo si el parche tiene tamano comparable.
- Si es snippet corto, reemplaza el rango `line_start` - `line_end`.
- Valida delimitadores balanceados `{}`, `()`, `[]`.
- Para HTML no trata comillas como strings, para evitar falsos positivos con atributos.
- Rechaza salida vacia o archivo final inesperadamente corto.

Funciones clave:

```text
normalize_patch_technology()
code_fence_label_for_technology()
extract_generic_code_block()
has_balanced_delimiters()
build_lightweight_patched_content()
```

Limitacion actual:

- Angular/Java todavia no tienen parseo semantico real ni compilacion. Es intencional por ahora para no romper con `ast.parse`.

Siguiente paso recomendado:

- Angular: usar `npm test`, `npm run build`, `tsc --noEmit` o parser TypeScript si el repo target lo soporta.
- Java: usar `javac`, Maven o Gradle segun deteccion de proyecto.

## Dashboard

Archivo: `src/dashboard/index.html`.

Capacidades actuales:

- Vista de proyectos.
- Carga de ZIP.
- Clonado de repo Git.
- Selector de tecnologia (`python`, `angular`, `java`).
- Tabla de hallazgos.
- Boton Auto-Fix.
- Modal de remediacion.
- Boton "Convertir a Pull Request".
- Link al PR creado.
- Boton para eliminar rama remota.
- Estado de Ollama via `/api/ai-status`.

El dashboard llama:

```text
POST /api/remediate/{finding_id}
POST /api/remediate/{finding_id}/pr
DELETE /api/remediate/{finding_id}/pr
```

## Estado Git Actual Observado

El worktree esta sucio. Hay cambios modificados y archivos nuevos no trackeados. No asumir que todo esta commiteado.

Modificados:

```text
.gitignore
code/requirements.txt
src/ai_engine/remediator.py
src/api/database.py
src/api/main.py
src/api/models.py
src/dashboard/index.html
src/integrations/github_client.py
src/scanners/escaneo.py
```

No trackeados observados:

```text
angular-vuln-lab.zip
create_test_zips.py
docs/ai-handoff-context.md
java-vuln-lab.zip
src/scanners/angular_adapter.py
src/scanners/bandit_adapter.py
src/scanners/base.py
src/scanners/java_adapter.py
tests/
workspace/
```

Regla para el siguiente agente:

- No hacer `git reset --hard`.
- No revertir cambios existentes sin permiso explicito.
- Leer antes de editar porque muchas mejoras ya existen en el worktree.

## Validacion Ejecutada

Despues de dinamizar el remediador y ajustar guardrails por tecnologia, se ejecuto:

```bash
python3 -m compileall src
```

Resultado:

```text
Listing 'src'...
Listing 'src/ai_engine'...
Listing 'src/api'...
Listing 'src/dashboard'...
Listing 'src/integrations'...
Listing 'src/scanners'...
```

Compilacion exitosa.

## Bug Critico Reciente Ya Corregido

Problema:

Cuando se solicitaba remediacion para Angular, el motor local sugeria un parche Python usando `subprocess`, porque el System Prompt en `src/ai_engine/remediator.py` estaba hardcodeado a Python.

Correccion aplicada:

- El remediador ahora detecta tecnologia desde DB.
- `build_prompt()` es dinamico por tecnologia.
- Angular recibe rol y contrato de Angular/TypeScript.
- Java recibe rol y contrato de Java/AppSec.
- Todos los prompts prohiben mezclar lenguajes.
- GitHub guardrails ya no usan `ast.parse` para Angular/Java.

## Riesgos Conocidos

1. La validacion Angular/Java es ligera.
2. Los parches Angular/Java por ahora reemplazan rango de lineas, no unidad semantica completa.
3. No hay confirmacion en este documento de que exista suite de tests completa.
4. El worktree contiene archivos no trackeados y cambios amplios.
5. Los ZIP de laboratorio pueden ser datos de prueba; no asumir que deben commitearse.
6. `workspace/` probablemente contiene uploads o codigo temporal; revisar `.gitignore` antes de versionar.

## Proximos Pasos Recomendados

Prioridad alta:

1. Agregar tests para `src/ai_engine/remediator.py`:
   - finding Python genera prompt Python.
   - finding Angular genera prompt Angular y prohibe Python.
   - finding Java genera prompt Java y prohibe TypeScript/Python.

2. Agregar tests para `src/integrations/github_client.py`:
   - `extract_python_code_block()`.
   - `extract_generic_code_block()` con fences correctos e incorrectos.
   - `build_safe_python_patched_content()`.
   - `build_lightweight_patched_content()` para Angular/Java.

3. Mejorar parcheo Angular/Java:
   - Angular TS: detectar metodo/clase/componente.
   - Angular HTML: detectar bloque o atributo vulnerable con contexto.
   - Java: detectar metodo con parser o heuristica por llaves.

4. Implementar validacion por proyecto:
   - Python: `python -m compileall`, `pytest`.
   - Angular: `npm run build`, `tsc --noEmit`.
   - Java: Maven/Gradle/Javac segun archivos presentes.

5. Revisar `.gitignore` para asegurar:
   - `.env*`
   - `*.pem`
   - `dev_database.db*`
   - `__pycache__/`
   - entornos virtuales
   - `workspace/`

## Comandos Utiles

Instalar dependencias:

```bash
pip install -r code/requirements.txt
```

Levantar backend:

```bash
uvicorn src.api.main:app --reload
```

Validar Python:

```bash
python3 -m compileall src
```

Ejecutar scanner por CLI:

```bash
python3 -m src.scanners.escaneo <target_path> python
python3 -m src.scanners.escaneo <target_path> angular
python3 -m src.scanners.escaneo <target_path> java
```

Buscar residuos del flujo viejo de markdown PR:

```bash
rg "docs/remediations|build_remediation_markdown|markdown_path" src
```

## Reglas Para La Siguiente IA

- Priorizar el codigo actual sobre cualquier descripcion antigua.
- No leer ni exponer secretos reales.
- No commitear `.env`, `.pem`, SQLite local, WAL/SHM ni workspace de uploads.
- Mantener remediaciones estrictamente por tecnologia.
- No permitir que Angular reciba parches Python.
- No permitir que Java reciba parches TypeScript/Python.
- Para Python, conservar guardrails AST fuertes.
- Para Angular/Java, mejorar validacion sin pasar por `ast.parse`.
- Si se toca GitHub PR automation, mantener el comportamiento de rama `security-fix-{finding_id}` y PR idempotente.
- Si se modifica el dashboard, probar manualmente el flujo ZIP/repo -> scan -> Auto-Fix -> PR.

## Narrativa Profesional Del Proyecto

Este proyecto posiciona a Ernesto para roles de AppSec Engineer, DevSecOps Engineer o Platform Security Engineer.

Pitch breve:

```text
Construi un control plane de seguridad self-hosted que automatiza el ciclo completo: escaneo SAST/SCA, remediacion con LLM local, codigo sin salir de la infraestructura y verificacion automatica del fix.
```

Keywords:

```text
DevSecOps
AppSec
SAST
SCA
AI Remediation
Local LLM Inference
FastAPI
Kubernetes
OpenShift
Helm
Security Automation
Vulnerability Management
Bandit
pip-audit
Trivy
Checkov
Semgrep
GitHub App
Ollama
```
