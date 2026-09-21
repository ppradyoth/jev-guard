from __future__ import annotations

from .findings import Severity

# Names of tools whose misuse is high-impact. Matched case-insensitively as a
# substring of a tool string literal (e.g. "python_repl" matches "python").
DANGEROUS_TOOLS = frozenset({
    "bash", "shell", "sh", "exec", "execute", "eval", "python", "repl",
    "run_code", "code_interpreter", "sql", "database", "delete", "drop",
    "terminal", "subprocess", "os_system", "system", "write_file", "fs_write",
    "http", "request", "requests", "fetch", "send_email", "email", "transfer",
})

# kwargs that indicate a caller has actually configured how the guardrail
# decides to block, rather than relying on Jev's default point decision.
THRESHOLD_KWARGS = frozenset({
    "threshold", "thresholds", "confidence", "min_confidence", "block_threshold",
    "block_at", "decision_threshold", "review_threshold", "auto_threshold",
    "escalate_below", "on_low_confidence",
})

# Variable name fragments suggesting attacker-influenced content that should not
# flow unmodified into a guardrail's `state`.
UNTRUSTED_HINTS = frozenset({
    "user", "input", "message", "msg", "content", "payload", "request",
    "body", "prompt", "query", "tool_output", "tool_result", "external",
    "untrusted", "email_body", "resume", "ticket",
})

JEV_IMPORT_ROOTS = frozenset({"langchain_typesafe", "typesafe"})

RULES = {
    "JG001": (
        Severity.HIGH,
        "Jev guardrail gates actions with no configured confidence threshold",
        "AutoModeMiddleware/classifier blocks on Jev's default decision. "
        "'Zero hallucinations' is a type guarantee, not a correctness one: a "
        "confidently-wrong noul still lets a dangerous call through. Set an "
        "explicit threshold and escalate below it.",
    ),
    "JG002": (
        Severity.CRITICAL,
        "Dangerous tool exposed to an agent with no Jev guardrail present",
        "A high-impact tool (bash/sql/http/...) is wired into the agent but no "
        "AutoModeMiddleware appears in this module. Add a guardrail or remove "
        "the tool from the autonomous path.",
    ),
    "JG003": (
        Severity.MEDIUM,
        "Jev decision consumed without checking calibrated confidence",
        "A .noul/.choice/.score value is used to branch but the module never "
        "reads a confidence field. Calibration is Jev's entire value; acting on "
        "the point estimate discards it. Gate the branch on confidence.",
    ),
    "JG004": (
        Severity.MEDIUM,
        "Untrusted content flows into a Jev guardrail's state",
        "The `state` argument is built from an attacker-influenceable variable. "
        "If text in `state` can override the question `instructions`, the "
        "guardrail is injectable by the very input it inspects. Separate and "
        "sanitize untrusted state.",
    ),
    "JG005": (
        Severity.INFO,
        "Jev used as a security control",
        "Validate block/escalate thresholds against your own adversarial "
        "workload. Jev's published evals are self-graded on non-adversarial "
        "distributions; calibration under attack is unproven.",
    ),
}
