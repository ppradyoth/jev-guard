# jev-guard

[![ci](https://github.com/ppradyoth/jev-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/ppradyoth/jev-guard/actions/workflows/ci.yml) [![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) ![python](https://img.shields.io/badge/python-3.10%2B-blue)

**A static code scanner (SAST-style linter).** It reads your Python source and flags insecure usage of [Jev / TypeSafe "System One" models](https://typesafe.ai) when they're used as a security guardrail.

> jev-guard is **not** a guardrail and it does **not** run at runtime, call the model, or touch the network. It is a build-time analysis tool — think `ruff`/`bandit`, scoped to Jev guardrail patterns. It tells you where your guardrail *code* is misconfigured; it does not do any guarding itself.

**Thesis: type-safe is not the same as correct.** Jev can't emit a type error and it can't hallucinate a field — but "no hallucination" is a guarantee about *shape*, not about *truth*. A guardrail that returns a confidently wrong `noul: 0.02` for a `rm -rf /` still lets the call through. If you gate `bash` on that number, the type safety bought you nothing.

`jev-guard` scans your code for the ways a Jev-based guardrail fails open. It runs entirely offline — it reads your source, not the model — so it needs no API key and costs nothing.

## Why this exists

Two things shipped in September 2026:

- TypeSafe released **Jev**, marketed for "score, judge, verify, guardrail, and detect jailbreaks."
- LangChain shipped **`AutoModeMiddleware`**, which uses Jev to classify tool calls as dangerous and block them before they run — the classifier pattern that used to live inside the closed-source parts of Claude Code / Codex / Cursor, now open to every agent.

The documented example is literally `AutoModeMiddleware(tools=["bash"])` — a shell gate with **no threshold set**, relying on the model's default point decision. That is the exact shape `jev-guard` was built to catch.

## Install

```bash
pip install jevg           # PyPI package name (the CLI command is still `jev-guard`)
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

## In CI (GitHub Action)

```yaml
- uses: ppradyoth/jev-guard@v0.3.0
  with:
    path: src/
    fail-on: HIGH
```

Surface findings in the **Security** tab by emitting SARIF and uploading it —
see [`examples/github-workflow.yml`](examples/github-workflow.yml).

## Pre-commit

```yaml
repos:
  - repo: https://github.com/ppradyoth/jev-guard
    rev: v0.3.0
    hooks:
      - id: jev-guard
```

## What it flags

| Code  | Severity | What |
|-------|----------|------|
| JG001 | HIGH     | Jev guardrail gates actions with no configured confidence threshold (blocks on the model default). |
| JG002 | CRITICAL | A dangerous tool (`bash`/`sql`/`http`/...) is wired into an agent with no `AutoModeMiddleware` present. |
| JG003 | MEDIUM   | A `.noul`/`.choice`/`.score` decision is used to branch without ever reading a confidence field. |
| JG004 | MEDIUM   | Attacker-influenceable content flows straight into a guardrail's `state` (injection surface). |
| JG005 | INFO     | Jev is being used as a security control — reminder to validate thresholds against your own adversarial data. |
| JG006 | MEDIUM   | Threshold set in an unsafe band (blocks only near-certain danger / almost never escalates). |
| JG007 | HIGH     | Untrusted content interpolated into a question's `instructions` — the inspected text can rewrite the question. |

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

## Configuration

Drop a `.jev-guard.toml` at your repo root (jev-guard walks up to find it):

```toml
[jev-guard]
disable = ["JG005"]            # rules to silence entirely

[jev-guard.severity]
JG004 = "HIGH"                 # bump a rule's severity

[jev-guard.extra]
dangerous_tools = ["wire_transfer", "post_tweet"]   # your own high-impact tools
import_roots    = ["my_typesafe_wrapper"]           # if you wrap the SDK
guardrail_calls = ["MyGuardrail"]                   # your own guardrail factory
```

Silence a single line inline:

```python
guardrail = AutoModeMiddleware(tools=["bash"])  # jev-guard: ignore JG001
another = AutoModeMiddleware(tools=["bash"])     # jev-guard: ignore
```

jev-guard follows assignments, so indirection is caught — `tools = ["bash"]; create_agent(tools=tools)` and `s = user_msg; classifier.invoke({"state": s})` both flag.

## Scope and honesty

This is a **heuristic linter, not a prover.** It reads Python, matches the LangChain `langchain_typesafe` surface, and reasons about obvious patterns. It will miss guardrails assembled dynamically, wrapped in your own abstractions, or written in another language, and it can raise false positives on safe code that names a variable `user_config`. It does not test the model, measure real calibration, or prove exploitability. It tells you *where to look*, not *that you're owned*.

For what it can and can't do, and when to reach for something else, read [`GUIDE.md`](GUIDE.md).

## License

MIT. Not affiliated with TypeSafe AI or LangChain.
