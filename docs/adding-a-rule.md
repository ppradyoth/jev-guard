# Adding a rule

A rule is ~15 lines across three files. Worked example: `JG00X`.

## 1. Declare it — `src/jev_guard/rules.py`

Add an entry to `RULES`:

```python
"JG00X": (
    Severity.HIGH,
    "One-line statement of the defect",
    "How to fix it, and — if this is a heuristic rather than a measured "
    "failure — say so plainly here.",
),
```

If your rule needs new vocabulary (tool names, kwarg names), add it to the
frozensets at the top of the file so `.jev-guard.toml` can extend it too.

## 2. Detect it — `src/jev_guard/scanner.py`

Inside `scan_source`, emit from the appropriate place:

```python
emit("JG00X", node.lineno)
```

Use the `Taint` helper (`taint.refs_untrusted(node)`, `taint.is_dangerous(node)`)
so your rule follows variable assignments instead of only matching literals at
the call site. Match on the AST, never on raw text.

## 3. Prove it — `tests/`

Add a vulnerable case that must trigger and a safe case that must not:

```python
def test_jg00x_triggers():
    assert "JG00X" in codes(VULNERABLE_SRC)

def test_jg00x_clean():
    assert "JG00X" not in codes(SAFE_SRC)
```

Run `pytest -q && ruff check .`, update `CHANGELOG.md`, open the PR.

## Severity guide

| Severity | Use for |
|----------|---------|
| CRITICAL | Dangerous action reachable with no guardrail at all. |
| HIGH     | Guardrail present but structurally bypassable / injectable. |
| MEDIUM   | Guardrail present but degraded (calibration ignored, unsafe band). |
| LOW/INFO | Advisory; not a defect on its own. |
