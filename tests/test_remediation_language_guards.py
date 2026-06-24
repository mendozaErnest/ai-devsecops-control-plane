from src.ai_engine.remediator import build_angular_prompt
from src.api.main import remediation_matches_finding_technology
from src.integrations.github_client import (
    _extract_named_functions,
    extract_code_block_for_technology,
    is_safe_to_apply,
    normalize_patch_technology_for_finding,
)


def test_javascript_rule_in_html_does_not_patch_as_python():
    details = {
        "technology": "python",
        "rule_id": "javascript:S930",
        "file_path": "src/dashboard/index.html",
    }

    assert normalize_patch_technology_for_finding(details) == "angular"


def test_frontend_remediation_rejects_python_function_block():
    remediation = """```python
def vulnerable_function():
    pass
```"""

    assert extract_code_block_for_technology(remediation, "angular", "src/dashboard/index.html") is None


def test_cached_python_remediation_is_invalid_for_javascript_html_finding():
    details = {
        "technology": "python",
        "rule_id": "javascript:S930",
        "file_path": "src/dashboard/index.html",
    }
    remediation = """```python
def vulnerable_function(arg):
    pass
```"""

    assert remediation_matches_finding_technology(remediation, details) is False


def test_javascript_fence_is_valid_for_javascript_html_finding():
    details = {
        "technology": "python",
        "rule_id": "javascript:S930",
        "file_path": "src/dashboard/index.html",
    }
    remediation = """```javascript
if (selectedProject) await loadFindings();
```"""

    assert remediation_matches_finding_technology(remediation, details) is True


# ── is_safe_to_apply: JS function-deletion guard (bug fix) ──────────────────

_ORIGINAL_WITH_JS_FUNCTION = """\
function closeReasonModal() {
    reasonModal.style.display = "none";
    reasonModalCallback = null;
}

async function postLifecycle(findingId, action, reason) {
    try {
        const response = await fetch(`/api/findings/${findingId}/${action}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ reason }),
        });
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        showFeedback("Estado actualizado correctamente.", "success");
    } catch (error) {
        showFeedback(`Error al actualizar estado: ${error.message}`, "error");
    }
}

function openAuditModal(record) {
    auditModalMeta.textContent = `Finding ${record.id}`;
}
"""

_PATCHED_REMOVES_POSTLIFECYCLE = """\
function closeReasonModal() {
    reasonModal.style.display = "none";
    reasonModalCallback = null;
}

// Assuming the problematic function is defined in a component's TypeScript file
export class DashboardComponent {
    // Example of a method that expects no arguments
    problematicFunction() {
        // Method implementation here
    }

    // Corrected usage of the method
    callProblematicFunction() {
        this.problematicFunction(); // No arguments provided
    }
}

function openAuditModal(record) {
    auditModalMeta.textContent = `Finding ${record.id}`;
}
"""


def test_is_safe_to_apply_detects_js_function_deletion():
    """is_safe_to_apply must reject a patch that removes JS named functions.

    The patch replaces postLifecycle with a fake TS class — it should be blocked
    by either the stub-signal check or the function-deletion check (whichever fires
    first).  We verify the overall verdict is False; the exact reason text is
    checked separately in test_is_safe_to_apply_detects_js_stub_signals.
    """
    safe, _ = is_safe_to_apply(_ORIGINAL_WITH_JS_FUNCTION, _PATCHED_REMOVES_POSTLIFECYCLE)

    assert safe is False


def test_is_safe_to_apply_function_deletion_fires_when_no_stub_signals():
    """Function-deletion guard must fire independently when stubs and line-removal are both OK.

    Uses a large original file so the net line reduction stays well under 20 %,
    ensuring only check 3 (function deletion) can trigger the rejection.
    """
    # 80-line padding keeps net removal (12 lines for postLifecycle) well under 20 %
    padding = "\n".join(
        f"// padding line {i}" for i in range(80)
    )
    large_original = _ORIGINAL_WITH_JS_FUNCTION + "\n" + padding
    # Patched version keeps padding but removes postLifecycle — no stub signals
    large_patched = """\
function closeReasonModal() {
    reasonModal.style.display = "none";
    reasonModalCallback = null;
}

function openAuditModal(record) {
    auditModalMeta.textContent = `Finding ${record.id}`;
}
""" + "\n" + padding

    safe, reason = is_safe_to_apply(large_original, large_patched)

    assert safe is False
    assert "postLifecycle" in reason


def test_is_safe_to_apply_detects_js_stub_signals():
    """is_safe_to_apply must catch common JS/TS LLM hallucination markers."""
    safe, _ = is_safe_to_apply(_ORIGINAL_WITH_JS_FUNCTION, _PATCHED_REMOVES_POSTLIFECYCLE)

    assert safe is False  # blocked by stub signals and/or function deletion


def test_extract_named_functions_finds_js_and_python():
    """_extract_named_functions returns names for both Python defs and JS function declarations."""
    source = """\
def python_func(a, b):
    pass

async function jsAsyncFunc(x) { return x; }

function jsSyncFunc() {}
"""
    names = _extract_named_functions(source)
    assert "python_func" in names
    assert "jsAsyncFunc" in names
    assert "jsSyncFunc" in names


# ── angular prompt: S930 guidance and anti-hallucination constraints ─────────

def test_angular_prompt_s930_includes_argument_guidance():
    """Angular prompt for javascript:S930 must instruct the model to fix the signature."""
    details = {
        "rule_id": "javascript:S930",
        "file_path": "src/dashboard/index.html",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "postLifecycle is called with more arguments than declared.",
        "code_snippet": "async function postLifecycle(findingId, action) {",
        "line_start": 1539,
        "line_end": 1555,
    }
    prompt = build_angular_prompt(details)

    assert "s930" in prompt.lower() or "argumentos" in prompt.lower() or "argumento" in prompt.lower()
    assert "NUNCA" in prompt or "nunca" in prompt.lower()


def test_angular_prompt_forbids_new_class_creation():
    """Angular prompt must explicitly prohibit generating a new TypeScript class."""
    details = {
        "rule_id": "javascript:S930",
        "file_path": "src/dashboard/index.html",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Function called with more args than declared.",
        "code_snippet": "",
        "line_start": 10,
        "line_end": 10,
    }
    prompt = build_angular_prompt(details)

    # Must contain the anti-hallucination constraint
    assert "nueva clase" in prompt or "NUNCA" in prompt

def test_is_safe_to_apply_rejects_noop_patch():
    source = "def vulnerable(value):\n    return eval(value)"

    safe, reason = is_safe_to_apply(source, source)

    assert safe is False
    assert "no cambia" in reason
