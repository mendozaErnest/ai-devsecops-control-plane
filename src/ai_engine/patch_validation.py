"""Semantic safety checks for AI-generated source patches.

LLM output is untrusted.  These checks complement syntax and patch-size
guardrails by rejecting Python patches that still contain the reported
vulnerability or silently change the affected function's public contract.
"""

from __future__ import annotations

import ast
from typing import Iterable


COMMAND_INJECTION_RULES = {"B602", "B603", "B604", "B605", "B606", "B607"}
UNSAFE_DESERIALIZATION_RULES = {"B301", "B302", "B506"}
WEAK_CRYPTO_RULES = {"B303", "B304", "B305", "B324"}
INSECURE_RANDOM_RULES = {"B311"}
TLS_VALIDATION_RULES = {"B501"}
SQL_INJECTION_RULES = {"B608"}
CODE_EXECUTION_RULES = {"B102", "B307"}

_SUBPROCESS_CALLS = {
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.run",
}
_SHELL_WRAPPERS = {
    "bash",
    "cmd",
    "cmd.exe",
    "dash",
    "ksh",
    "powershell",
    "powershell.exe",
    "pwsh",
    "sh",
    "zsh",
}


def _rule_id(finding_details: dict) -> str:
    return str(finding_details.get("rule_id") or "").upper()


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _function_nodes(tree: ast.AST) -> Iterable[ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _find_affected_function(
    tree: ast.AST,
    finding_details: dict,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    expected_name = str(finding_details.get("expected_function") or "").strip()
    if expected_name:
        return next((node for node in _function_nodes(tree) if node.name == expected_name), None)

    try:
        line_start = int(finding_details.get("line_start") or 0)
    except (TypeError, ValueError):
        line_start = 0

    if line_start:
        candidates = [
            node
            for node in _function_nodes(tree)
            if node.lineno <= line_start <= (getattr(node, "end_lineno", node.lineno) or node.lineno)
        ]
        if candidates:
            return min(candidates, key=lambda node: (node.end_lineno or node.lineno) - node.lineno)

    nodes = list(_function_nodes(tree))
    return nodes[0] if len(nodes) == 1 else None


def _signature_shape(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple:
    args = node.args

    def arg_shape(arg: ast.arg) -> tuple[str, str]:
        annotation = ast.unparse(arg.annotation) if arg.annotation is not None else ""
        return arg.arg, annotation

    return (
        isinstance(node, ast.AsyncFunctionDef),
        tuple(arg_shape(arg) for arg in args.posonlyargs),
        tuple(arg_shape(arg) for arg in args.args),
        arg_shape(args.vararg) if args.vararg else None,
        tuple(arg_shape(arg) for arg in args.kwonlyargs),
        arg_shape(args.kwarg) if args.kwarg else None,
        len(args.defaults),
        tuple(default is not None for default in args.kw_defaults),
        ast.unparse(node.returns) if node.returns is not None else "",
    )


def _direct_return_value(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ast.AST | None:
    returns = [
        child
        for child in node.body
        if isinstance(child, ast.Return) and child.value is not None
    ]
    return returns[-1].value if returns else None


def _return_contract(value: ast.AST | None) -> str | None:
    if isinstance(value, ast.Call):
        name = _call_name(value.func)
        if name == "subprocess.Popen":
            return "process_handle"
        if name in {"os.system", "subprocess.call", "subprocess.check_call"}:
            return "exit_code"
        if name == "subprocess.run":
            return "completed_process"
        if name == "subprocess.check_output":
            return "output"

    if isinstance(value, ast.Attribute) and value.attr == "returncode":
        return "exit_code"

    return None


def _dynamic_sql_expression(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr == "format"
    return False


def _assigned_values(function: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, ast.AST]:
    values: dict[str, ast.AST] = {}
    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    values[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            values[node.target.id] = node.value
    return values


def _validate_command_injection(
    original_function: ast.FunctionDef | ast.AsyncFunctionDef,
    patched_function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[bool, str]:
    original_contract = _return_contract(_direct_return_value(original_function))
    patched_contract = _return_contract(_direct_return_value(patched_function))
    if original_contract and patched_contract != original_contract:
        return False, (
            "El fix cambia el contrato de retorno de la función "
            f"({original_contract} -> {patched_contract or 'desconocido'})."
        )

    subprocess_seen = False
    for node in ast.walk(patched_function):
        if not isinstance(node, ast.Call):
            continue

        name = _call_name(node.func)
        if name in {"os.system", "os.popen"}:
            return False, f"El fix conserva la API insegura `{name}`."
        if name not in _SUBPROCESS_CALLS:
            continue

        subprocess_seen = True
        if _is_true(_keyword(node, "shell")):
            return False, "El fix todavía usa `shell=True`."
        if not node.args or not isinstance(node.args[0], (ast.List, ast.Tuple)):
            return False, "El comando de subprocess debe usar argumentos en lista/tupla, no un string."

        command_items = list(node.args[0].elts)
        executable = _literal_string(command_items[0]) if command_items else None
        if not executable:
            return False, "El ejecutable de subprocess debe provenir de una constante o allowlist."
        if executable.lower() in _SHELL_WRAPPERS:
            return False, f"El fix invoca el shell `{executable}` indirectamente."

        if executable.lower() == "tar":
            first_dynamic = next(
                (index for index, item in enumerate(command_items[1:], start=1)
                 if _literal_string(item) is None),
                None,
            )
            separator_index = next(
                (index for index, item in enumerate(command_items)
                 if _literal_string(item) == "--"),
                None,
            )
            if first_dynamic is not None and (
                separator_index is None or separator_index > first_dynamic
            ):
                return False, (
                    "Los operandos variables de `tar` deben ir después de `--` "
                    "para impedir option injection."
                )

    if not subprocess_seen:
        return False, "El fix no contiene una sustitución segura basada en subprocess."
    return True, "ok"


def _validate_rule_semantics(
    patched_function: ast.FunctionDef | ast.AsyncFunctionDef,
    rule_id: str,
) -> tuple[bool, str]:
    assignments = _assigned_values(patched_function)

    for node in ast.walk(patched_function):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)

        if rule_id in UNSAFE_DESERIALIZATION_RULES:
            if name in {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads"}:
                return False, f"El fix conserva deserialización insegura mediante `{name}`."
            if name == "yaml.load":
                loader = _keyword(node, "Loader")
                loader_name = _call_name(loader) if loader else ""
                if loader_name not in {"yaml.SafeLoader", "SafeLoader"}:
                    return False, "El fix debe usar `yaml.safe_load` o `yaml.SafeLoader`."

        if rule_id in WEAK_CRYPTO_RULES and name in {
            "hashlib.md5",
            "hashlib.sha1",
            "Crypto.Hash.MD2.new",
            "Crypto.Hash.MD4.new",
            "Crypto.Hash.MD5.new",
            "Crypto.Hash.SHA.new",
        }:
            return False, f"El fix conserva el algoritmo criptográfico débil `{name}`."

        if rule_id in INSECURE_RANDOM_RULES and name.startswith("random."):
            return False, f"El fix conserva PRNG no criptográfico mediante `{name}`."

        if rule_id in TLS_VALIDATION_RULES and name.startswith(("requests.", "httpx.")):
            verify = _keyword(node, "verify")
            if isinstance(verify, ast.Constant) and verify.value is False:
                return False, "El fix todavía desactiva la validación TLS con `verify=False`."

        if rule_id in CODE_EXECUTION_RULES and name in {"eval", "exec"}:
            return False, f"El fix conserva ejecución dinámica insegura mediante `{name}`."

        if rule_id in SQL_INJECTION_RULES and (
            name.endswith(".execute") or name.endswith(".executemany")
        ) and node.args:
            query = node.args[0]
            if isinstance(query, ast.Name):
                query = assignments.get(query.id, query)
            if _dynamic_sql_expression(query):
                return False, "El fix conserva una consulta SQL construida dinámicamente."

    return True, "ok"


def validate_python_security_semantics(
    original_content: str,
    patched_content: str,
    finding_details: dict,
) -> tuple[bool, str]:
    """Reject semantically unsafe Python remediations.

    This function intentionally fails closed only for checks it can establish
    from the AST.  Scanner re-verification remains required before a finding can
    be considered fixed.
    """
    try:
        original_tree = ast.parse(original_content)
        patched_tree = ast.parse(patched_content)
    except SyntaxError as exc:
        return False, f"El código no puede validarse semánticamente: {exc.msg}."

    original_function = _find_affected_function(original_tree, finding_details)
    patched_details = dict(finding_details)
    if original_function and not patched_details.get("expected_function"):
        patched_details["expected_function"] = original_function.name
    patched_function = _find_affected_function(patched_tree, patched_details)

    if original_function and not patched_function:
        return False, f"El fix eliminó la función afectada `{original_function.name}`."
    if original_function and patched_function:
        if _signature_shape(original_function) != _signature_shape(patched_function):
            return False, (
                f"El fix cambió la firma pública de `{original_function.name}`; "
                "debe preservar parámetros, async/sync y anotaciones."
            )

    rule_id = _rule_id(finding_details)
    if not patched_function:
        return True, "ok"
    if rule_id in COMMAND_INJECTION_RULES:
        safe, reason = _validate_command_injection(original_function or patched_function, patched_function)
        if not safe:
            return safe, reason

    return _validate_rule_semantics(patched_function, rule_id)
