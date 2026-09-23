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

# kwargs that indicate a caller has configured how the guardrail decides to
# block, rather than relying on Jev's default point decision.
THRESHOLD_KWARGS = frozenset({
    "threshold", "thresholds", "confidence", "min_confidence", "block_threshold",
    "block_at", "decision_threshold", "review_threshold", "auto_threshold",
    "escalate_below", "on_low_confidence",
})

# kwargs whose value is a probability above which the guardrail *blocks*. A high
# value here means "only block when almost certain" -> most attacks pass.
BLOCK_KWARGS = frozenset({
    "threshold", "block_threshold", "block_at", "decision_threshold", "auto_threshold",
})

# kwargs whose value is a confidence below which the guardrail *escalates*. A low
# value here means "almost never escalate" -> low-confidence calls silently pass.
ESCALATE_KWARGS = frozenset({
    "min_confidence", "escalate_below", "review_threshold", "confidence",
})

# Variable name fragments suggesting attacker-influenced content.
UNTRUSTED_HINTS = frozenset({
    "user", "input", "message", "msg", "content", "payload", "request",
    "body", "prompt", "query", "tool_output", "tool_result", "external",
    "untrusted", "email_body", "resume", "ticket", "comment", "webhook",
})

# An escape option in a choice question, so a forced-choice model isn't made to
# pick a wrong answer when none fits. Matched against option labels/keys.
ABSTAIN_TOKENS = frozenset({
    "none", "no", "unsure", "unknown", "unclear", "uncertain", "abstain",
    "escalate", "human", "review", "other", "na", "n/a", "cannot", "no_decision",
    "needs_review", "idk", "defer",
})

# Evidence that code can route a decision to something smarter than Jev instead
# of only block/allow. Matched against names and string literals in the module.
ESCALATE_VOCAB = frozenset({
    "escalate", "human", "review", "approve", "manual", "queue", "handoff",
    "oversight", "on_low_confidence", "escalate_below", "ask_human",
    "needs_review", "second_opinion", "defer",
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
    "JG006": (
        Severity.MEDIUM,
        "Jev guardrail threshold set in an unsafe band",
        "The block threshold is set so high (or the escalate-below confidence so "
        "low) that the guardrail only reacts to near-certain danger. Adversarial "
        "input is designed to sit in the ambiguous middle. Bias the block "
        "threshold low and escalate generously.",
    ),
    "JG007": (
        Severity.HIGH,
        "Untrusted content interpolated into a Jev question's instructions",
        "Attacker-influenceable text is concatenated or formatted into the "
        "`instructions` of a question. That lets the inspected content rewrite "
        "the question itself, collapsing the guardrail. Keep instructions static "
        "and pass untrusted data only as `state`.",
    ),
    "JG008": (
        Severity.HIGH,
        "Forced-choice question has no abstain option",
        "A `choice` question offers only substantive options, so the model must "
        "pick one even when none fits — a forced-choice model does not abstain, it "
        "guesses, often confidently. Add an explicit escape option (none / unsure / "
        "escalate) and route to a human or a stronger model when it wins.",
    ),
    "JG009": (
        Severity.HIGH,
        "Jev is the terminal judge of a dangerous action, with no escalation path",
        "A Jev decision gates a high-impact action but the code can only block or "
        "allow — it never routes to a human or a stronger model. Jev is a router, "
        "not a judge: an un-abstaining classifier should decide *whether to ask "
        "someone smarter*, not be the final word on an irreversible action. Add a "
        "low-confidence escalation branch.",
    ),
}
