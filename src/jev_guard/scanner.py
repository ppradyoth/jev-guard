from __future__ import annotations

import ast
from pathlib import Path

from .findings import Finding
from .rules import (
    DANGEROUS_TOOLS,
    JEV_IMPORT_ROOTS,
    RULES,
    THRESHOLD_KWARGS,
    UNTRUSTED_HINTS,
)

GUARDRAIL_CALLS = frozenset({"AutoModeMiddleware", "TypeSafeClassifier"})
STATE_CALLS = GUARDRAIL_CALLS | {"invoke"}
DECISION_ATTRS = frozenset({"noul", "nouls", "choice", "choices", "score", "scores"})


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _string_literals(node: ast.AST) -> list[str]:
    return [
        c.value
        for c in ast.walk(node)
        if isinstance(c, ast.Constant) and isinstance(c.value, str)
    ]


def _has_dangerous(node: ast.AST) -> bool:
    for s in _string_literals(node):
        low = s.lower()
        if any(tok in low for tok in DANGEROUS_TOOLS):
            return True
    return False


def _state_values(call: ast.Call) -> list[ast.AST]:
    vals: list[ast.AST] = []
    for kw in call.keywords:
        if kw.arg == "state":
            vals.append(kw.value)
    for arg in call.args:
        if isinstance(arg, ast.Dict):
            for key, val in zip(arg.keys, arg.values, strict=False):
                if isinstance(key, ast.Constant) and key.value == "state":
                    vals.append(val)
    return vals


def _references_untrusted(node: ast.AST) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            nm = n.id.lower()
            if any(h in nm for h in UNTRUSTED_HINTS):
                return True
    return False


def _finding(code: str, file: str, line: int) -> Finding:
    severity, message, remediation = RULES[code]
    return Finding(code, severity, file, line, message, remediation)


def scan_source(source: str, filename: str) -> list[Finding]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    uses_jev = any(
        isinstance(n, (ast.Import, ast.ImportFrom))
        and (
            any(a.name.split(".")[0] in JEV_IMPORT_ROOTS for a in n.names)
            or (getattr(n, "module", "") or "").split(".")[0] in JEV_IMPORT_ROOTS
        )
        for n in ast.walk(tree)
    )
    if not uses_jev:
        return []

    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    has_automode = any(_call_name(c) == "AutoModeMiddleware" for c in calls)
    reads_confidence = any(
        isinstance(n, ast.Attribute) and "confidence" in n.attr.lower()
        for n in ast.walk(tree)
    ) or any(kw.arg in THRESHOLD_KWARGS for c in calls for kw in c.keywords if kw.arg)

    findings: list[Finding] = []
    guarded = False

    for call in calls:
        name = _call_name(call)
        kwargs = {kw.arg for kw in call.keywords if kw.arg}

        if name in GUARDRAIL_CALLS:
            guarded = True
            findings.append(_finding("JG005", filename, call.lineno))
            if not (kwargs & THRESHOLD_KWARGS):
                findings.append(_finding("JG001", filename, call.lineno))

        if name in STATE_CALLS:
            for value in _state_values(call):
                if _references_untrusted(value):
                    findings.append(_finding("JG004", filename, call.lineno))
                    break

        if name in {"create_agent", "ToolNode"}:
            for kw in call.keywords:
                if kw.arg == "tools" and _has_dangerous(kw.value) and not has_automode:
                    findings.append(_finding("JG002", filename, call.lineno))

    if guarded:
        decisions = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and n.attr in DECISION_ATTRS
        ]
        if decisions and not reads_confidence:
            findings.append(_finding("JG003", filename, decisions[0].lineno))

    return sorted(findings, key=lambda f: (-f.severity, f.line))


def scan_path(path: str | Path) -> list[Finding]:
    p = Path(path)
    files = [p] if p.is_file() else sorted(p.rglob("*.py"))
    findings: list[Finding] = []
    for f in files:
        try:
            findings.extend(scan_source(f.read_text(encoding="utf-8"), str(f)))
        except (UnicodeDecodeError, OSError):
            continue
    return findings
