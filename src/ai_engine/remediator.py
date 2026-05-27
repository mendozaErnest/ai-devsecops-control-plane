import asyncio
import ast
import json
import os
import re
import textwrap
import urllib.error
import urllib.request
import uuid

from sqlmodel import Session

from src.api.database import engine
from src.api.models import Finding, Scan, Project


_OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_URL = f"{_OLLAMA_HOST}/api/generate"
OLLAMA_TAGS_URL = f"{_OLLAMA_HOST}/api/tags"
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:14b")
OLLAMA_HEALTH_TIMEOUT_SECONDS = 2
SUPPORTED_TECHNOLOGIES = {"python", "angular", "typescript", "java", "css", "html"}
ANGULAR_SECRET_KEYWORDS = (
    "apikey",
    "token",
    "secret",
    "password",
    "credential",
    "auth",
    "key",
)
ANGULAR_SECRET_PREFIXES = (
    "ANG-SECRET",
    "SEMGREP-SECRET",
    "javascript.lang.security.audit.hardcoded",
)

CSS_EXTENSIONS = (".css", ".scss", ".sass", ".less")
HTML_EXTENSIONS = (".html", ".htm", ".jinja", ".j2")


def normalize_technology(value: object, file_path: str = "") -> str:
    technology = str(value or "").strip().lower()

    if technology == "typescript":
        return "angular"
    if technology in {"python", "angular", "java", "css", "html"}:
        return technology

    # rule_id namespaces: css:S*, web:css*, html.*, html:*, web:html*
    # Rule namespaces win over extension so css:S4666 in an .html file remains CSS.
    rule_lower = technology  # already lowercased
    if rule_lower.startswith(("css:", "web:css")):
        return "css"
    if rule_lower.startswith(("html.", "html:", "web:html")):
        return "html"

    # Inferir por extensión de archivo cuando no hay valor explícito
    fp = str(file_path or "").lower()
    if any(fp.endswith(ext) for ext in CSS_EXTENSIONS):
        return "css"
    if any(fp.endswith(ext) for ext in HTML_EXTENSIONS):
        return "html"

    return "python"


# ---------------------------------------------------------------------------
# Technology inference from rule_id / file_path
# ---------------------------------------------------------------------------
# Bandit rules are B + 3 digits (B101, B501, etc.)
_BANDIT_RULE_RE = re.compile(r"^B\d{3}$", re.IGNORECASE)

# SonarQube JS/TS namespaces that should always use the Angular/JS prompt
_JS_RULE_PREFIXES = ("javascript:", "typescript:", "jsts.")

# CSS / HTML namespaces
_CSS_RULE_PREFIXES = ("css:", "web:css")
_HTML_RULE_PREFIXES = ("html.", "html:", "web:html")

# SonarQube Java namespaces
_JAVA_RULE_PREFIXES = ("java:", "kotlin:", "squid:")

# File extensions that override project technology
_JS_EXTENSIONS  = (".js", ".ts", ".jsx", ".tsx", ".vue", ".mjs", ".cjs")
_JAVA_EXTENSIONS = (".java", ".kt", ".kts", ".groovy", ".scala")


def infer_technology_from_finding(rule_id: str, file_path: str) -> str | None:
    """Infer the actual *language* technology from rule_id namespace or file extension.

    This is the source of truth for prompt selection and patch strategy.  It
    takes precedence over ``project.technology`` so that, for example, a Python
    project that also has SonarQube findings in ``.html``, ``.css``, ``.js`` or
    ``.java`` files gets the matching prompt instead of the Python prompt.

    Returns one of ``"python"``, ``"angular"``, ``"java"``, ``"css"``,
    ``"html"`` — or ``None`` when the evidence is insufficient (caller should
    fall back to project technology).
    """
    rule_lower  = (rule_id   or "").lower().strip()
    path_lower  = (file_path or "").lower().strip()

    # ── Infer from rule_id namespace (most authoritative signal) ──────────────
    if any(rule_lower.startswith(p) for p in _CSS_RULE_PREFIXES):
        return "css"
    if any(rule_lower.startswith(p) for p in _HTML_RULE_PREFIXES):
        return "html"
    if any(rule_lower.startswith(p) for p in _JS_RULE_PREFIXES):
        return "angular"
    if rule_lower.startswith(("python:", "gitlab.bandit.")):
        return "python"
    if rule_lower.startswith(("semgrep.python.", "python.lang.", "python.flask.", "python.django.")):
        return "python"
    if _BANDIT_RULE_RE.match(rule_id or ""):           # e.g. B501, B101
        return "python"
    if any(rule_lower.startswith(p) for p in _JAVA_RULE_PREFIXES):
        return "java"
    if rule_lower.startswith(("semgrep.java.", "java.lang.", "java.spring.")):
        return "java"

    # ── Infer from file extension ─────────────────────────────────────────────
    if any(path_lower.endswith(ext) for ext in CSS_EXTENSIONS):
        return "css"
    if any(path_lower.endswith(ext) for ext in HTML_EXTENSIONS):
        return "html"
    if any(path_lower.endswith(ext) for ext in _JS_EXTENSIONS):
        return "angular"
    if path_lower.endswith(".py"):
        return "python"
    if any(path_lower.endswith(ext) for ext in _JAVA_EXTENSIONS):
        return "java"

    return None  # caller uses project technology as fallback


def get_finding_technology(finding_id: object) -> str | None:
    if not finding_id:
        return None

    try:
        parsed_finding_id = uuid.UUID(str(finding_id))
    except (TypeError, ValueError):
        return None

    with Session(engine) as session:
        finding = session.get(Finding, parsed_finding_id)

        if not finding:
            return None

        scan = session.get(Scan, finding.scan_id)

        if not scan or not scan.project_id:
            return None

        project = session.get(Project, scan.project_id)

        if not project:
            return None

        return normalize_technology(project.technology)


def enrich_finding_details(finding_details: dict) -> dict:
    # Priority 1: infer from rule_id / file_path (most specific signal)
    inferred = infer_technology_from_finding(
        finding_details.get("rule_id", ""),
        finding_details.get("file_path", ""),
    )
    if inferred:
        return {**finding_details, "technology": inferred}

    # Priority 2: explicit technology already in the dict (from build_finding_details)
    # Priority 3: look up via project (DB query)
    technology = (
        finding_details.get("technology")
        or get_finding_technology(finding_details.get("id"))
        or finding_details.get("rule_id", "")
    )
    return {
        **finding_details,
        "technology": normalize_technology(technology, finding_details.get("file_path", "")),
    }


def _request_ollama_tags() -> dict:
    request = urllib.request.Request(OLLAMA_TAGS_URL, method="GET")

    with urllib.request.urlopen(request, timeout=OLLAMA_HEALTH_TIMEOUT_SECONDS) as response:
        body = response.read().decode("utf-8")

    return json.loads(body)


async def check_ollama_status() -> dict:
    try:
        await asyncio.to_thread(_request_ollama_tags)
    except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return {
            "available": False,
            "reason": "Ollama service offline",
            "detail": str(exc),
        }

    return {
        "available": True,
        "model": OLLAMA_MODEL,
    }


def build_python_prompt(finding_details: dict) -> str:
    expected_function = finding_details.get("expected_function") or "UNKNOWN"
    expected_function_source = (
        finding_details.get("expected_function_source")
        or finding_details.get("code_snippet", "")
    )
    return f"""
You are an AI DevSecOps remediation engine. Generate one surgical Python patch
for the following security finding.

Strict output contract:
- Return exactly one fenced code block labeled python.
- Do not write any prose before or after the fenced code block.
- The fenced block must contain valid Python only.
- UNDER NO CIRCUMSTANCES mix programming languages. The final patch must be
  Python that can be parsed by Python tooling.
- The fenced block must include the complete affected function, including its
  def or async def header and the full corrected function body.
- Preserve the exact affected function name and signature. The affected function
  is: {expected_function}.
- Do not invent new functions, routes, decorators, fake database helpers, fake
  models, sample endpoints, or placeholders.
- Do not rename the affected function. If the function cannot be fixed safely
  with the provided context, return the original affected function unchanged.
- Use standard 4-space indentation inside the function.
- Never return loose statements, partial snippets, commented-out examples, or
  explanation-only code.
- Do not return only imports. If an import is necessary, include the import at
  the top of the same fenced block and still include the complete affected
  function below it.
- Do not include line numbers, markdown text, diff markers, or shell prompts.
- Keep explanation out of the response. Security rationale belongs in code
  comments only when it is necessary for safe review.

Rule ID: {finding_details.get("rule_id", "UNKNOWN")}
Severity: {finding_details.get("severity", "UNKNOWN")}
Confidence: {finding_details.get("confidence", "UNKNOWN")}
File: {finding_details.get("file_path", "UNKNOWN")}
Lines: {finding_details.get("line_start", "UNKNOWN")} - {finding_details.get("line_end", "UNKNOWN")}
Description: {finding_details.get("description", "")}

Code context:
```python
{finding_details.get("code_snippet", "")}
```

Affected function that must be preserved:
```python
{expected_function_source}
```

Security context:
- Prefer parameterized SQL queries over string concatenation.
- Prefer secrets over random for security tokens.
- Never use shell=True with user input.
- Never deserialize untrusted pickle or unsafe YAML.
- Use modern password hashing and avoid MD5/SHA1.
- Keep TLS certificate validation enabled.
- Validate and normalize paths to prevent traversal.
""".strip()


def is_angular_secret_finding(finding_details: dict) -> bool:
    rule_id = str(finding_details.get("rule_id") or "")
    snippet = str(finding_details.get("code_snippet") or "").lower()

    return (
        any(rule_id.upper().startswith(prefix.upper()) for prefix in ANGULAR_SECRET_PREFIXES)
        or any(keyword in snippet for keyword in ANGULAR_SECRET_KEYWORDS)
    )


def build_angular_secret_instruction() -> str:
    return """
INSTRUCCION ESPECIAL — HALLAZGO DE SECRET HARDCODEADO:
El valor sensible NUNCA debe aparecer en el codigo fuente ni en el bundle.
- Si el archivo es environment.ts: deja el campo vacio con un comentario
  indicando que el valor real se inyecta desde CI/CD:
  // Valor real: NG_APP_API_KEY=${{ secrets.API_KEY }} en el pipeline
- Muestra como leer la variable con process.env o import.meta.env.
- Si el secret se necesita en runtime: usa un ConfigService que haga
  GET /api/config al backend; el frontend nunca recibe el secret directo.
Devuelve el archivo TypeScript completo con los comentarios de CI/CD incluidos.
""".strip()


def _base_angular_prompt(finding_details: dict) -> str:
    expected_function = finding_details.get("expected_function") or ""
    expected_function_source = finding_details.get("expected_function_source") or ""
    code_snippet = finding_details.get("code_snippet", "")
    rule_id = finding_details.get("rule_id", "UNKNOWN")
    file_path = finding_details.get("file_path", "UNKNOWN")
    rule_lower = str(rule_id).lower()

    # Extra guidance for argument-count rules (S930) or JS rules in HTML files
    is_js_rule_in_html = (
        rule_lower.startswith(("javascript:", "typescript:", "jsts."))
        and str(file_path).lower().endswith((".html", ".htm"))
    )
    s930_guidance = ""
    if rule_lower == "javascript:s930" or "s930" in rule_lower:
        s930_guidance = (
            "\n- Esta regla indica que una funcion se llama con MAS argumentos de los"
            " que declara. Correccion valida: (a) agrega el parametro faltante a la"
            " firma de la funcion existente, o (b) elimina el argumento extra del"
            " sitio de llamada. Elige la opcion que preserve la logica original."
        )

    # Guidance for Cognitive Complexity rules (S3776 and similar)
    cognitive_complexity_guidance = ""
    if "s3776" in rule_lower or "cognitive_complexity" in rule_lower:
        cognitive_complexity_guidance = (
            "\n- Esta regla reporta Complejidad Cognitiva excesiva en la funcion."
            " DEBES devolver la funcion COMPLETA original con la logica refactorizada:"
            " extrae subfunciones auxiliares, simplifica cadenas if/else o usa early"
            " returns para reducir el anidamiento. NUNCA devuelvas un placeholder, un"
            " comentario TODO ni una funcion llamada refactoredFunction. El nombre de"
            " la funcion original debe preservarse exactamente."
        )

    function_hint = ""
    if expected_function:
        function_hint = (
            f"\nNombre de la funcion afectada: {expected_function}\n"
            "Debes preservar exactamente ese nombre y su logica; solo corrige el"
            " problema especifico reportado."
        )

    html_js_hint = ""
    if is_js_rule_in_html:
        html_js_hint = (
            "\n- El hallazgo apunta a JavaScript embebido dentro de un archivo HTML."
            " Devuelve SOLO el fragmento JavaScript corregido dentro de un bloque"
            " ```javascript```. No devuelvas markup HTML ni TypeScript externo."
        )

    # Include the full function source when available (from JS enrichment), so
    # the model has the complete body to refactor — not just a 1-2 line snippet.
    full_function_section = ""
    if expected_function_source and expected_function_source != code_snippet:
        full_function_section = (
            f"\nFuncion completa que debe ser refactorizada:\n"
            f"```javascript\n{expected_function_source}\n```"
        )

    return f"""
Eres un Arquitecto Senior de Frontend y Experto en Seguridad en Angular/TypeScript.
Genera un parche quirurgico para el siguiente hallazgo de seguridad.

Contrato estricto de salida:
- Devuelve exactamente un bloque de codigo fenced, etiquetado como typescript,
  javascript, html o angular segun el archivo afectado.
- No escribas prosa antes ni despues del bloque fenced.
- El bloque debe contener exclusivamente TypeScript, JavaScript o HTML valido.
- BAJO NINGUNA CIRCUNSTANCIA mezcles lenguajes. No devuelvas Python, Java,
  Bash, diffs ni pseudocodigo.
- Si el archivo es .ts, el parche final debe compilar como TypeScript de Angular.
- Si el hallazgo apunta a JavaScript inline dentro de .html, devuelve solo el
  fragmento JavaScript minimo corregido dentro de un bloque `javascript`.
- Si el archivo es .html y el problema esta en markup/template, el parche final
  debe ser plantilla Angular/HTML valida.
- Incluye el reemplazo COMPLETO de la funcion o metodo afectado que corrige el
  hallazgo sin romper el contexto. Nunca devuelvas solo una parte de la funcion.
- No incluyas numeros de linea, marcadores de diff, prompts de shell ni texto
  Markdown fuera del bloque de codigo.
- NUNCA crees una nueva clase TypeScript, un nuevo componente Angular ni un
  ejemplo ilustrativo generico desconectado del codigo existente. El parche debe
  ser aplicable directamente al archivo afectado sin contexto adicional.
- NUNCA uses placeholders, comentarios TODO ni funciones stub como
  refactoredFunction. Implementa el fix real con la logica completa.
- No elimines funciones ni metodos que ya existan en el archivo. Si necesitas
  modificar una funcion, incluye su version completa corregida.{s930_guidance}{cognitive_complexity_guidance}{html_js_hint}

Rule ID: {rule_id}
Severity: {finding_details.get("severity", "UNKNOWN")}
Confidence: {finding_details.get("confidence", "UNKNOWN")}
File: {file_path}
Lines: {finding_details.get("line_start", "UNKNOWN")} - {finding_details.get("line_end", "UNKNOWN")}
Description: {finding_details.get("description", "")}{function_hint}

Code context:
```javascript
{code_snippet}
```
{full_function_section}
Security context:
- Evita inyectar HTML no confiable con innerHTML.
- Usa interpolation, property binding y pipes seguros cuando sea posible.
- Si necesitas DomSanitizer, usalo solo con datos confiables y el contexto
  correcto; no uses bypassSecurityTrust* para silenciar hallazgos sin validar
  origen y transformacion.
- Normaliza, valida y codifica valores antes de renderizarlos en plantillas.
- Evita construir URLs, estilos o scripts dinamicos desde entrada de usuario.
""".strip()


def build_angular_prompt(finding_details: dict) -> str:
    prompt = _base_angular_prompt(finding_details)

    if is_angular_secret_finding(finding_details):
        prompt += f"\n\n{build_angular_secret_instruction()}"

    return prompt


def build_java_prompt(finding_details: dict) -> str:
    return f"""
Eres un Ingeniero Principal de Software Java y Experto en AppSec Criptografica y Web.
Genera un parche quirurgico para el siguiente hallazgo de seguridad.

Contrato estricto de salida:
- Devuelve exactamente un bloque de codigo fenced etiquetado java.
- No escribas prosa antes ni despues del bloque fenced.
- El bloque debe contener exclusivamente Java nativo valido.
- BAJO NINGUNA CIRCUNSTANCIA mezcles lenguajes. No devuelvas Python,
  TypeScript, HTML, Bash, diffs ni pseudocodigo.
- El parche final debe compilar como Java compatible con el estilo del archivo
  afectado.
- Incluye el reemplazo completo del metodo, bloque o clase minima afectada que
  corrige el hallazgo.
- No incluyas numeros de linea, marcadores de diff, prompts de shell ni texto
  Markdown fuera del bloque de codigo.

Rule ID: {finding_details.get("rule_id", "UNKNOWN")}
Severity: {finding_details.get("severity", "UNKNOWN")}
Confidence: {finding_details.get("confidence", "UNKNOWN")}
File: {finding_details.get("file_path", "UNKNOWN")}
Lines: {finding_details.get("line_start", "UNKNOWN")} - {finding_details.get("line_end", "UNKNOWN")}
Description: {finding_details.get("description", "")}

Code context:
```java
{finding_details.get("code_snippet", "")}
```

Security context:
- Reemplaza MD5/SHA-1 por algoritmos modernos segun el caso de uso.
- Usa PreparedStatement o APIs equivalentes para queries parametrizadas.
- Mantiene validacion TLS y evita trust managers inseguros.
- Usa SecureRandom para valores criptograficos.
- Evita deserializacion insegura y validacion debil de rutas o entradas.
""".strip()


def build_css_prompt(finding_details: dict) -> str:
    return f"""
Eres un Ingeniero Frontend Senior especialista en CSS/SCSS y calidad de codigo.
Genera un parche quirurgico para el siguiente hallazgo de analisis estatico.

Contrato estricto de salida:
- Devuelve exactamente un bloque de codigo fenced etiquetado `css`.
- No escribas prosa, comentarios ni explicaciones fuera del bloque fenced.
- El bloque debe contener CSS/SCSS valido y aplicable.
- NUNCA devuelvas python, javascript, typescript, java ni pseudocodigo.
- Incluye unicamente el fragmento CSS minimo corregido (el selector o regla afectada).
- No incluyas numeros de linea ni marcadores de diff.

Rule ID: {finding_details.get("rule_id", "UNKNOWN")}
Severity: {finding_details.get("severity", "UNKNOWN")}
File: {finding_details.get("file_path", "UNKNOWN")}
Lines: {finding_details.get("line_start", "UNKNOWN")} - {finding_details.get("line_end", "UNKNOWN")}
Description: {finding_details.get("description", "")}

Code context:
```css
{finding_details.get("code_snippet", "")}
```

Guias de seguridad y calidad CSS:
- Elimina selectores duplicados; consolida sus propiedades en la primera ocurrencia.
- No uses `!important` a menos que ya este presente y sea necesario.
- Manten la especificidad original del selector.
- Si el problema es un selector duplicado, devuelve SOLO el bloque fusionado correcto,
  eliminando el duplicado.
""".strip()


def build_html_prompt(finding_details: dict) -> str:
    return f"""
Eres un Ingeniero Frontend Senior especialista en HTML semantico, accesibilidad y seguridad web.
Genera un parche quirurgico para el siguiente hallazgo de analisis estatico.

Contrato estricto de salida:
- Devuelve exactamente un bloque de codigo fenced etiquetado `html`.
- No escribas prosa, comentarios ni explicaciones fuera del bloque fenced.
- El bloque debe contener HTML5 valido.
- NUNCA devuelvas python, javascript ni pseudocodigo.
- Incluye unicamente el fragmento HTML minimo corregido.
- No incluyas numeros de linea ni marcadores de diff.

Rule ID: {finding_details.get("rule_id", "UNKNOWN")}
Severity: {finding_details.get("severity", "UNKNOWN")}
File: {finding_details.get("file_path", "UNKNOWN")}
Lines: {finding_details.get("line_start", "UNKNOWN")} - {finding_details.get("line_end", "UNKNOWN")}
Description: {finding_details.get("description", "")}

Code context:
```html
{finding_details.get("code_snippet", "")}
```

Guias de seguridad HTML:
- Agrega atributos `rel="noopener noreferrer"` en `<a target="_blank">`.
- Usa `autocomplete="off"` / `autocomplete="new-password"` donde corresponda.
- No uses atributos deprecated (e.g., `<font>`, `align=`, `border=` en table).
- Para XSS: usa textContent en vez de innerHTML donde aplique.
- Corrige el problema minimo reportado sin alterar estructura circundante.
""".strip()


def build_prompt(finding_details: dict) -> str:
    finding_details = enrich_finding_details(finding_details)
    technology = finding_details["technology"]

    if technology == "angular":
        return build_angular_prompt(finding_details)

    if technology == "java":
        return build_java_prompt(finding_details)

    if technology == "css":
        return build_css_prompt(finding_details)

    if technology == "html":
        return build_html_prompt(finding_details)

    return build_python_prompt(finding_details)


def strip_line_numbers(code: str) -> str:
    cleaned_lines = []

    for raw_line in code.replace("\r\n", "\n").replace("\r", "\n").splitlines():
        cleaned_lines.append(re.sub(r"^\s*\d+\s+", "", raw_line))

    return textwrap.dedent("\n".join(cleaned_lines)).strip()


def extract_python_signature(code: str) -> str | None:
    match = re.search(r"^\s*(async\s+def|def)\s+([A-Za-z_]\w*)\s*\((.*?)\)\s*(?:->\s*[^:]+)?\s*:", code, re.MULTILINE | re.DOTALL)

    if not match:
        return None

    signature = match.group(0).strip()
    return re.sub(r"\s+", " ", signature)


def build_safe_fallback_code(finding_details: dict) -> str:
    technology = normalize_technology(
        finding_details.get("technology") or finding_details.get("rule_id", ""),
        finding_details.get("file_path", ""),
    )

    if technology == "angular":
        code_snippet = strip_line_numbers(str(finding_details.get("code_snippet") or ""))

        if code_snippet:
            return code_snippet

        return (
            "throw new Error("
            "'Local AI remediation engine is unavailable; regenerate this Angular patch before use.'"
            ");"
        )

    if technology == "java":
        code_snippet = strip_line_numbers(str(finding_details.get("code_snippet") or ""))

        if code_snippet:
            return code_snippet

        return (
            "throw new UnsupportedOperationException("
            "\"Local AI remediation engine is unavailable; regenerate this Java patch before use.\""
            ");"
        )

    if technology == "css":
        code_snippet = strip_line_numbers(str(finding_details.get("code_snippet") or ""))

        if code_snippet:
            return code_snippet

        return "/* AI remediation engine unavailable; regenerate before use. */"

    if technology == "html":
        code_snippet = strip_line_numbers(str(finding_details.get("code_snippet") or ""))

        if code_snippet:
            return code_snippet

        return "<!-- AI remediation engine unavailable; regenerate before use. -->"

    code_snippet = strip_line_numbers(str(finding_details.get("code_snippet") or ""))

    if code_snippet:
        try:
            ast.parse(code_snippet)
        except SyntaxError:
            signature = extract_python_signature(code_snippet)

            if signature:
                return (
                    f"{signature}\n"
                    "    \"\"\"Fallback placeholder generated while the local AI engine is unavailable.\"\"\"\n"
                    "    raise RuntimeError(\"Local AI remediation engine is unavailable; regenerate this patch before use.\")"
                )
        else:
            return code_snippet

    return (
        "def local_ai_remediation_unavailable():\n"
        "    \"\"\"Fallback placeholder generated while the local AI engine is unavailable.\"\"\"\n"
        "    raise RuntimeError(\"Local AI remediation engine is unavailable; regenerate this patch before use.\")"
    )


def fallback_patch(finding_details: dict) -> str:
    finding_details = enrich_finding_details(finding_details)
    rule_id = finding_details.get("rule_id", "UNKNOWN")
    description = finding_details.get("description", "Security finding")
    file_path = finding_details.get("file_path", "the affected file")
    technology = finding_details.get("technology", "python")
    fallback_code = build_safe_fallback_code(finding_details)
    label = "python" if technology == "python" else technology

    return f"""Fallback Patch

Ollama is not available locally, so this placeholder is intentionally not a real fix.
Regenerate the remediation when the local AI engine is online before opening a PR.

Finding: {rule_id}
File: {file_path}
Issue: {description}

Suggested {technology} remediation:
```{label}
{fallback_code}
```

This fallback is intentionally conservative so downstream parsers fail closed with clear context.
"""


def _request_patch(prompt: str, finding_details: dict) -> str:
    payload = json.dumps(
        {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=45) as response:
        body = response.read().decode("utf-8")

    data = json.loads(body)
    return data.get("response", "").strip() or fallback_patch(
        {
            **finding_details,
            "description": f"{finding_details.get('description', '')} (Fallback reason: Empty Ollama response)",
        }
    )


async def generate_patch(finding_details: dict) -> str:
    finding_details = enrich_finding_details(finding_details)
    prompt = build_prompt(finding_details)

    try:
        return await asyncio.to_thread(_request_patch, prompt, finding_details)
    except urllib.error.HTTPError as exc:
        error_text = exc.read().decode("utf-8", errors="replace")
        print(f"Ollama request failed with status {exc.code}: {error_text}")
        return fallback_patch(
            {
                **finding_details,
                "description": f"{finding_details.get('description', '')} (Fallback reason: HTTP {exc.code}: {error_text})",
            }
        )
    except urllib.error.URLError as exc:
        print(f"Ollama request failed: {exc}")
        return fallback_patch(
            {
                **finding_details,
                "description": f"{finding_details.get('description', '')} (Fallback reason: {exc})",
            }
        )
    except (OSError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"Ollama request failed: {exc}")
        return fallback_patch(
            {
                **finding_details,
                "description": f"{finding_details.get('description', '')} (Fallback reason: {exc})",
            }
        )
