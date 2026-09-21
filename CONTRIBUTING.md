# Contributing to jev-guard

Thanks for helping map how Jev-based guardrails fail. This is a young tool for a
young model class; rules will change as the real failure modes get measured.

## Setup

```bash
git clone https://github.com/ppradyoth/jev-guard && cd jev-guard
uv venv && . .venv/bin/activate
uv pip install -e ".[dev]"
pytest -q && ruff check .
```

## Ground rules

- **Every rule ships with fixtures.** A vulnerable fixture that triggers it and a
  safe fixture that must not. No fixture, no merge.
- **Prefer evidence over intuition.** If a rule is motivated by an observed Jev
  failure, link it. If it's a pattern heuristic, say so in the rule's remediation
  text — we are honest about what is measured vs. reasoned.
- **No false-positive land mines.** A rule that fires on idiomatic safe code is
  worse than no rule; people stop trusting the whole tool.
- Keep the scanner offline. jev-guard never calls the model or the network.
- Match the existing style: `ruff` clean, no comments unless the *why* is
  non-obvious.

## Adding a rule

See [`docs/adding-a-rule.md`](docs/adding-a-rule.md) for the step-by-step.

## Reporting a Jev guardrail failure you measured

Open an issue with the empirical evidence (state, config, decision, confidence).
Measured failures are how we grow the ruleset — they're the most valuable
contribution you can make.
