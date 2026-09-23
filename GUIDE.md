# jev-guard: usage guide

A practical guide to what this tool is for, when it helps, when it doesn't, what to use instead, and how much to trust it.

## The one idea

Jev's headline safety property is that it **cannot hallucinate and cannot emit a type error**. Both are true and both are about *structure*. Neither says the answer is *right*.

A guardrail's job is to be right about "is this action dangerous?" A type-safe wrong answer is still a wrong answer — and because it's well-formed, your code will act on it without hesitation. The failure is quieter than an LLM going off the rails, which makes it more dangerous in a system with latency guarantees or buried several layers deep.

`jev-guard` finds the places in your code where a well-formed-but-possibly-wrong decision is trusted more than it should be.

## The design principle: router, not judge

Jev is a forced-choice model. Give it options and it picks one — it does **not
abstain**. Give it three wrong options and it returns one of them, sometimes at
high confidence. "No hallucination" guarantees the answer is well-formed, not
that it is right, and the confidence number is only useful if it stays honest
under adversarial input (unproven — that's what a live probe measures).

The safe shape follows from this:

- **Use Jev to route, never to judge.** Its job is to decide *whether to ask
  someone smarter* — a stronger model or a human — not to be the final word on
  an irreversible action. `jev-guard` flags a Jev decision that terminally gates
  a dangerous action with no escalation path (JG009).
- **Always give a forced choice an escape hatch.** Every `choice` question that
  drives a security decision needs a `none` / `unsure` / `escalate` option, and
  code that routes to review when it wins. A choice with only substantive
  options makes the model guess (JG008).
- **Escalate on low confidence.** Reading the confidence isn't enough; branch on
  it. High confidence acts, low confidence goes to a human or a stronger model.

Put deterministically: Jev belongs on the *triage* path (is this change worth
waking the expensive reviewer?), not on the *verdict* path. A triage gate is
still a control surface an attacker will shape their input to slip — so
threat-model it, don't sprinkle it in as a free lookup.

## When to use it

- You use `langchain_typesafe`, `AutoModeMiddleware`, or `TypeSafeClassifier` anywhere a decision leads to an action — routing, tool gating, auto-approval, content moderation.
- A Jev decision sits on the path to something irreversible: shell, SQL, HTTP, money movement, sending mail, writing files.
- You're adding Jev to an agent and want a checklist before it ships.
- You want a cheap CI gate that fails the build when someone wires a dangerous tool behind a default-threshold guardrail.
- You're reviewing someone else's agent and want a fast map of where the trust boundaries are.

## When NOT to use it

- **You want proof you're exploitable.** This tool points at code smells. It does not run the model or demonstrate a bypass. Use a live probe harness for that (see below).
- **You want to measure Jev's actual calibration.** That needs a labeled adversarial dataset and real API calls, not static analysis.
- **Your guardrail isn't in Python**, or is assembled dynamically / behind heavy abstraction. AST matching will miss it. A miss here is not a clean bill of health.
- **You're using Jev for non-safety classification** (analytics, feature extraction, map-reduce over data) where a wrong answer is a data-quality issue, not a security event. jev-guard's severities assume a security context; here they'll over-alarm.
- **As your only control.** A linter is a smoke detector, not a sprinkler. Passing jev-guard means "no obvious footguns," not "safe."

## How to read the findings

- **JG002 (CRITICAL)** — a dangerous tool with no guardrail at all. Fix first; this is the unguarded case.
- **JG001 (HIGH)** — a guardrail exists but blocks on the model's default decision with no threshold. Set an explicit block threshold *and* an escalate-below-confidence path.
- **JG003 (MEDIUM)** — you're acting on the point estimate and throwing away the confidence, which is the entire reason to use Jev over a coin flip. Gate the branch on confidence.
- **JG004 (MEDIUM)** — untrusted text flows into `state`. If content in `state` can override the question `instructions`, the guardrail is injectable by the input it's inspecting. Keep untrusted state structurally separate and sanitized.
- **JG005 (INFO)** — informational marker that a security decision runs through Jev. Not a defect; a prompt to validate thresholds on *your* adversarial workload, because the published evals are self-graded on non-adversarial distributions.

## Fixing the common case

The default `AutoModeMiddleware(tools=["bash"])` (JG001) becomes defensible when you make the decision boundary explicit and add an escalation path for low confidence:

```python
guardrail = AutoModeMiddleware(
    tools=["bash"],
    block_threshold=0.2,       # block generously; err toward blocking
    escalate_below=0.85,       # low confidence -> human, not silent allow
)
```

And consume decisions with the confidence, not without it:

```python
decision = resp.nouls["danger"]
if decision.confidence < 0.85:
    return escalate_to_human()
return "block" if decision.noul > 0.2 else "allow"
```

## Alternatives and complements

`jev-guard` is a narrow static linter. Reach for these depending on what you actually need:

| Need | Use |
|------|-----|
| Prove a specific bypass exists | A live probe harness: send known-dangerous states through your real guardrail config and measure block rate. jev-guard tells you where; this tells you whether. |
| Measure calibration under attack | A labeled adversarial dataset + reliability diagram (clean vs. adversarial). This is research, not linting. |
| General agent/tool security review | OWASP Top 10 for Agentic Applications, MAESTRO threat modeling, or a manual review of the whole trust boundary — not just the Jev call. |
| Prompt-injection coverage for an LLM in the loop | A dedicated injection test suite. jev-guard only checks the *guardrail's* input surface (JG004), not the primary model's. |
| Broad Python security patterns | Semgrep / CodeQL. jev-guard is Jev-specific and deliberately shallow; general SAST catches the rest. |
| Runtime enforcement | jev-guard is build-time only. Pair it with a runtime allow/deny layer that doesn't depend on a probabilistic classifier for hard-stop actions. |

A defensible design uses Jev for *soft* routing and triage, and keeps a deterministic, non-probabilistic hard stop in front of anything irreversible. jev-guard is one check in that stack, not the stack.

## Self-assessment: how much to trust this tool

Honest limitations, so you calibrate your own confidence in *it*:

- **It's heuristic, not sound.** It matches names and shapes in the AST. Rename a variable or wrap the call and it goes blind. Absence of findings is not evidence of safety.
- **It can raise false positives.** JG004 keys off variable names that *look* untrusted (`user_`, `message`, `payload`). A safe file that happens to use those names will alarm. Read every finding; don't auto-fail blindly on MEDIUM.
- **It can raise false negatives.** Dynamic construction, indirection, non-literal tool lists, config-driven wiring, and any non-Python guardrail are invisible to it.
- **The rules encode a point of view, not a standard.** There is no published secure-usage spec for Jev yet — it's a week old. These rules are one security engineer's reading of two blog posts and the documented API, and they will change as the real failure modes get mapped.
- **The severities assume a security context.** In a non-safety use of Jev, they over-state risk.
- **It does not touch the model.** Every claim about calibration and hallucination in this repo is reasoning about the vendor's own marketing, not independent measurement. Treat it as a hypothesis to test, not a result.

Use it as a fast first pass and a CI tripwire. Do not use it as the thing that lets you sign off.
