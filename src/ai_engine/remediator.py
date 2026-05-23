import asyncio
import ast
import json
import re
import textwrap
import urllib.error
import urllib.request
import uuid

from sqlmodel import Session

from src.api.database import engine
from src.api.models import Finding, Scan, Project


OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"
OLLAMA_MODEL = "qwen2.5-coder:14b"
OLLAMA_HEALTH_TIMEOUT_SECONDS = 2
SUPPORTED_TECHNOLOGIES = {"python", "angular", "typescript", "java"}


def normalize_technology(value: object) -> str:
    technology = str(value or "python").strip().lower()

    if technology == "typescript":
        return "angular"

    if technology not in SUPPORTED_TECHNOLOGIES:
        return "python"

    return technology


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
    technology = finding_details.get("technology") or get_finding_technology(finding_details.get("id"))
    return {
        **finding_details,
        "technology": normalize_technology(technology),
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

Security context:
- Prefer parameterized SQL queries over string concatenation.
- Prefer secrets over random for security tokens.
- Never use shell=True with user input.
- Never deserialize untrusted pickle or unsafe YAML.
- Use modern password hashing and avoid MD5/SHA1.
- Keep TLS certificate validation enabled.
- Validate and normalize paths to prevent traversal.
""".strip()


def build_angular_prompt(finding_details: dict) -> str:
    return f"""
Eres un Arquitecto Senior de Frontend y Experto en Seguridad en Angular/TypeScript.
Genera un parche quirurgico para el siguiente hallazgo de seguridad.

Contrato estricto de salida:
- Devuelve exactamente un bloque de codigo fenced, etiquetado como typescript,
  html o angular segun el archivo afectado.
- No escribas prosa antes ni despues del bloque fenced.
- El bloque debe contener exclusivamente TypeScript o HTML valido para Angular.
- BAJO NINGUNA CIRCUNSTANCIA mezcles lenguajes. No devuelvas Python, Java,
  Bash, diffs ni pseudocodigo.
- Si el archivo es .ts, el parche final debe compilar como TypeScript de Angular.
- Si el archivo es .html, el parche final debe ser plantilla Angular/HTML valida.
- Incluye el reemplazo completo del metodo, binding, template fragment o bloque
  afectado que corrige el hallazgo sin romper el contexto Angular.
- No incluyas numeros de linea, marcadores de diff, prompts de shell ni texto
  Markdown fuera del bloque de codigo.

Rule ID: {finding_details.get("rule_id", "UNKNOWN")}
Severity: {finding_details.get("severity", "UNKNOWN")}
Confidence: {finding_details.get("confidence", "UNKNOWN")}
File: {finding_details.get("file_path", "UNKNOWN")}
Lines: {finding_details.get("line_start", "UNKNOWN")} - {finding_details.get("line_end", "UNKNOWN")}
Description: {finding_details.get("description", "")}

Code context:
```angular
{finding_details.get("code_snippet", "")}
```

Security context:
- Evita inyectar HTML no confiable con innerHTML.
- Usa interpolation, property binding y pipes seguros cuando sea posible.
- Si necesitas DomSanitizer, usalo solo con datos confiables y el contexto
  correcto; no uses bypassSecurityTrust* para silenciar hallazgos sin validar
  origen y transformacion.
- Normaliza, valida y codifica valores antes de renderizarlos en plantillas.
- Evita construir URLs, estilos o scripts dinamicos desde entrada de usuario.
""".strip()


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


def build_prompt(finding_details: dict) -> str:
    finding_details = enrich_finding_details(finding_details)
    technology = finding_details["technology"]

    if technology == "angular":
        return build_angular_prompt(finding_details)

    if technology == "java":
        return build_java_prompt(finding_details)

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
    technology = normalize_technology(finding_details.get("technology"))

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
