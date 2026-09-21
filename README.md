# jev-guard

Static auditor for code that uses [Jev / TypeSafe "System One" models](https://typesafe.ai) as a security guardrail.

**Thesis: type-safe is not the same as correct.** Jev can't emit a type error and it can't hallucinate a field — but "no hallucination" is a guarantee about *shape*, not about *truth*. A guardrail that returns a confidently wrong `noul: 0.02` for a `rm -rf /` still lets the call through. If you gate `bash` on that number, the type safety bought you nothing.

`jev-guard` scans your code for the ways a Jev-based guardrail fails open. It runs entirely offline — it reads your source, not the model — so it needs no API key and costs nothing.

## Why this exists

Two things shipped in September 2026:

- TypeSafe released **Jev**, marketed for "score, judge, verify, guardrail, and detect jailbreaks."
- LangChain shipped **`AutoModeMiddleware`**, which uses Jev to classify tool calls as dangerous and block them before they run — the classifier pattern that used to live inside the closed-source parts of Claude Code / Codex / Cursor, now open to every agent.

The documented example is literally `AutoModeMiddleware(tools=["bash"])` — a shell gate with **no threshold set**, relying on the model's default point decision. That is the exact shape `jev-guard` was built to catch.

## Install

```bash
pip install jev-guard      # once published
# or, from source:
git clone https://github.com/ppradyoth/jev-guard && cd jev-guard
pip install -e .
```

## Use

```bash
jev-guard scan path/to/agent.py        # scan a file
jev-guard scan src/                     # scan a tree
jev-guard scan src/ --format json       # machine-readable
jev-guard scan src/ --fail-on HIGH      # CI gate (default): exit 1 on HIGH+
jev-guard rules                         # list what it checks
```

Exit code is non-zero when any finding is at or above `--fail-on`, so it drops straight into CI:

```yaml
- run: jev-guard scan src/ --fail-on HIGH
```

## What it flags

| Code  | Severity | What |
|-------|----------|------|
| JG001 | HIGH     | Jev guardrail gates actions with no configured confidence threshold (blocks on the model default). |
| JG002 | CRITICAL | A dangerous tool (`bash`/`sql`/`http`/...) is wired into an agent with no `AutoModeMiddleware` present. |
| JG003 | MEDIUM   | A `.noul`/`.choice`/`.score` decision is used to branch without ever reading a confidence field. |
| JG004 | MEDIUM   | Attacker-influenceable content flows straight into a guardrail's `state` (injection surface). |
| JG005 | INFO     | Jev is being used as a security control — reminder to validate thresholds against your own adversarial data. |

Full rationale and remediation for each: [`GUIDE.md`](GUIDE.md).

## Example

```
$ jev-guard scan examples/vulnerable_agent.py
examples/vulnerable_agent.py:5  [HIGH] JG001  Jev guardrail gates actions with no configured confidence threshold
    ↳ Set an explicit threshold and escalate below it.
examples/vulnerable_agent.py:11 [MEDIUM] JG004  Untrusted content flows into a Jev guardrail's state
    ↳ Separate and sanitize untrusted state.
...
```

## Scope and honesty

This is a **heuristic linter, not a prover.** It reads Python, matches the LangChain `langchain_typesafe` surface, and reasons about obvious patterns. It will miss guardrails assembled dynamically, wrapped in your own abstractions, or written in another language, and it can raise false positives on safe code that names a variable `user_config`. It does not test the model, measure real calibration, or prove exploitability. It tells you *where to look*, not *that you're owned*.

For what it can and can't do, and when to reach for something else, read [`GUIDE.md`](GUIDE.md).

## License

MIT. Not affiliated with TypeSafe AI or LangChain.
