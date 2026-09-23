from __future__ import annotations

import ast
import io
import tokenize
from pathlib import Path

from .config import Config
from .findings import Finding
from .rules import (
    ABSTAIN_TOKENS,
    BLOCK_KWARGS,
    DANGEROUS_TOOLS,
    ESCALATE_KWARGS,
    ESCALATE_VOCAB,
    JEV_IMPORT_ROOTS,
    RULES,
    THRESHOLD_KWARGS,
    UNTRUSTED_HINTS,
)

BASE_GUARDRAIL_CALLS = frozenset({"AutoModeMiddleware", "TypeSafeClassifier"})
DECISION_ATTRS = frozenset({"noul", "nouls", "choice", "choices", "score", "scores"})
_SUPPRESS = "jev-guard:"


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


def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _name_is_untrusted(name: str) -> bool:
    low = name.lower()
    return any(h in low for h in UNTRUSTED_HINTS)


class Taint:
    """Module-level, name-based taint with fixed-point propagation."""

    def __init__(self, tree: ast.AST, dangerous_tools: frozenset[str]):
        self.dangerous_tools = dangerous_tools
        self.untrusted: set[str] = set()
        self.dangerous: set[str] = set()
        assigns: list[tuple[str, ast.AST]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigns.append((target.id, node.value))
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.value is not None:
                    assigns.append((node.target.id, node.value))
        for name, _ in assigns:
            if _name_is_untrusted(name):
                self.untrusted.add(name)
        for _ in range(6):
            changed = False
            for name, value in assigns:
                if name not in self.untrusted and self._value_untrusted(value):
                    self.untrusted.add(name)
                    changed = True
                if name not in self.dangerous and self._value_dangerous(value):
                    self.dangerous.add(name)
                    changed = True
            if not changed:
                break

    def _value_untrusted(self, node: ast.AST) -> bool:
        for nm in _names(node):
            if _name_is_untrusted(nm) or nm in self.untrusted:
                return True
        return False

    def _value_dangerous(self, node: ast.AST) -> bool:
        for s in _string_literals(node):
            low = s.lower()
            if any(tok in low for tok in self.dangerous_tools):
                return True
        return any(nm in self.dangerous for nm in _names(node))

    def refs_untrusted(self, node: ast.AST) -> bool:
        return self._value_untrusted(node)

    def is_dangerous(self, node: ast.AST) -> bool:
        return self._value_dangerous(node)


def _suppressions(source: str) -> dict[int, object]:
    out: dict[int, object] = {}
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for tok in tokens:
            if tok.type != tokenize.COMMENT or _SUPPRESS not in tok.string:
                continue
            body = tok.string.split(_SUPPRESS, 1)[1].strip()
            if not body.lower().startswith("ignore"):
                continue
            rest = body[len("ignore"):].strip()
            line = tok.start[0]
            if not rest:
                out[line] = "ALL"
            else:
                out[line] = {c.strip().upper() for c in rest.replace(",", " ").split()}
    except (tokenize.TokenError, IndentationError):
        pass
    return out


def _numeric(node: ast.AST) -> float | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    return None


def _finding(code: str, file: str, line: int, config: Config) -> Finding:
    severity, message, remediation = RULES[code]
    severity = config.severity_overrides.get(code, severity)
    return Finding(code, severity, file, line, message, remediation)


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


def _instruction_values(tree: ast.AST) -> list[ast.AST]:
    vals: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "instructions":
                    vals.append(kw.value)
        if isinstance(node, ast.Dict):
            for key, val in zip(node.keys, node.values, strict=False):
                if isinstance(key, ast.Constant) and key.value == "instructions":
                    vals.append(val)
    return vals


def _choice_option_strings(tree: ast.AST) -> list[tuple[int, list[str]]]:
    """For each choice question, return (line, option labels). Handles both
    Choice(options=[...]) / Choice(criteria={...}) and dict questions with
    {"type": "choice", "options"|"criteria": ...}."""
    out: list[tuple[int, list[str]]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) == "Choice":
            opts = [
                kw.value for kw in node.keywords if kw.arg in {"options", "criteria"}
            ]
            labels = [s for v in opts for s in _option_labels(v)]
            if labels:
                out.append((node.lineno, labels))
        if isinstance(node, ast.Dict):
            is_choice = any(
                isinstance(k, ast.Constant) and k.value == "type"
                and isinstance(v, ast.Constant) and v.value == "choice"
                for k, v in zip(node.keys, node.values, strict=False)
            )
            if not is_choice:
                continue
            for k, v in zip(node.keys, node.values, strict=False):
                if isinstance(k, ast.Constant) and k.value in {"options", "criteria"}:
                    labels = _option_labels(v)
                    if labels:
                        out.append((getattr(node, "lineno", 1), labels))
    return out


def _option_labels(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Dict):
        return [
            k.value for k in node.keys
            if isinstance(k, ast.Constant) and isinstance(k.value, str)
        ]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [
            e.value for e in node.elts
            if isinstance(e, ast.Constant) and isinstance(e.value, str)
        ]
    return []


def _has_abstain(labels: list[str]) -> bool:
    for label in labels:
        low = label.lower()
        if any(tok in low for tok in ABSTAIN_TOKENS):
            return True
    return False


def scan_source(source: str, filename: str, config: Config | None = None) -> list[Finding]:
    config = config or Config()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    import_roots = JEV_IMPORT_ROOTS | config.extra_import_roots
    uses_jev = any(
        isinstance(n, (ast.Import, ast.ImportFrom))
        and (
            any(a.name.split(".")[0] in import_roots for a in n.names)
            or (getattr(n, "module", "") or "").split(".")[0] in import_roots
        )
        for n in ast.walk(tree)
    )
    if not uses_jev:
        return []

    dangerous_tools = DANGEROUS_TOOLS | config.extra_dangerous_tools
    guardrail_calls = BASE_GUARDRAIL_CALLS | config.extra_guardrail_calls
    state_calls = guardrail_calls | {"invoke"}
    taint = Taint(tree, dangerous_tools)

    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    has_automode = any(_call_name(c) == "AutoModeMiddleware" for c in calls)
    reads_confidence = any(
        isinstance(n, ast.Attribute) and "confidence" in n.attr.lower()
        for n in ast.walk(tree)
    ) or any(kw.arg in THRESHOLD_KWARGS for c in calls for kw in c.keywords if kw.arg)

    module_names = {n.id.lower() for n in ast.walk(tree) if isinstance(n, ast.Name)}
    module_attrs = {n.attr.lower() for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    # Only strings that are actually returned count as an escalation signal — a
    # docstring or comment mentioning "review" is prose, not a routing path.
    returned_strings = " ".join(
        c.value.lower()
        for r in ast.walk(tree)
        if isinstance(r, ast.Return) and r.value is not None
        for c in ast.walk(r.value)
        if isinstance(c, ast.Constant) and isinstance(c.value, str)
    )
    has_escalation = (
        any(v in nm for v in ESCALATE_VOCAB for nm in module_names | module_attrs)
        or any(v in returned_strings for v in ESCALATE_VOCAB)
    )

    findings: list[Finding] = []
    guarded = False
    dangerous_context = bool(taint.dangerous)

    def emit(code: str, line: int) -> None:
        findings.append(_finding(code, filename, line, config))

    for call in calls:
        name = _call_name(call)
        kwargs = {kw.arg for kw in call.keywords if kw.arg}

        if name in guardrail_calls:
            guarded = True
            emit("JG005", call.lineno)
            if not (kwargs & THRESHOLD_KWARGS):
                emit("JG001", call.lineno)
            for kw in call.keywords:
                val = _numeric(kw.value)
                if val is None:
                    continue
                if kw.arg in BLOCK_KWARGS and val > 0.7:
                    emit("JG006", call.lineno)
                elif kw.arg in ESCALATE_KWARGS and val < 0.3:
                    emit("JG006", call.lineno)

        if name in state_calls:
            for value in _state_values(call):
                if taint.refs_untrusted(value):
                    emit("JG004", call.lineno)
                    break

        if name in guardrail_calls or name in {"create_agent", "ToolNode"}:
            for kw in call.keywords:
                if kw.arg == "tools" and taint.is_dangerous(kw.value):
                    dangerous_context = True

        if name in {"create_agent", "ToolNode"}:
            for kw in call.keywords:
                if kw.arg == "tools" and taint.is_dangerous(kw.value) and not has_automode:
                    emit("JG002", call.lineno)

    for value in _instruction_values(tree):
        if taint.refs_untrusted(value):
            emit("JG007", value.lineno if hasattr(value, "lineno") else 1)

    if guarded:
        decisions = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and n.attr in DECISION_ATTRS
        ]
        if decisions and not reads_confidence:
            emit("JG003", decisions[0].lineno)
        if dangerous_context and not has_escalation:
            emit("JG009", next(
                (c.lineno for c in calls if _call_name(c) in guardrail_calls), 1))

    for line, labels in _choice_option_strings(tree):
        if not _has_abstain(labels):
            emit("JG008", line)

    suppress = _suppressions(source)
    result = []
    seen: set[tuple[str, int]] = set()
    for f in findings:
        if f.code in config.disabled or (f.code, f.line) in seen:
            continue
        rule = suppress.get(f.line)
        if rule == "ALL" or (isinstance(rule, set) and f.code in rule):
            continue
        seen.add((f.code, f.line))
        result.append(f)
    return sorted(result, key=lambda f: (-f.severity, f.line, f.code))


def scan_path(path: str | Path, config: Config | None = None) -> list[Finding]:
    p = Path(path)
    config = config or Config.load(p)
    files = [p] if p.is_file() else sorted(p.rglob("*.py"))
    findings: list[Finding] = []
    for f in files:
        try:
            findings.extend(scan_source(f.read_text(encoding="utf-8"), str(f), config))
        except (UnicodeDecodeError, OSError):
            continue
    return findings
