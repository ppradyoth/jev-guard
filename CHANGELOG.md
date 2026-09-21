# Changelog

All notable changes to jev-guard are documented here. Versioning is semver.

## [0.3.0] - 2026-09-22

### Added
- **SARIF output** (`--format sarif`) for GitHub code-scanning / the Security tab.
- **`--output/-o`** to write a report to a file.
- **Composite GitHub Action** (`ppradyoth/jev-guard@v0.3.0`) and a **pre-commit
  hook** (`.pre-commit-hooks.yaml`) for one-line CI/local adoption.
- `--version` flag.
- Contributor docs: `CONTRIBUTING.md`, `docs/adding-a-rule.md`, issue templates.
- Example consumer workflow that uploads SARIF to code scanning.

### Note
- Generalization beyond Jev is via `.jev-guard.toml` (`extra.import_roots`,
  `extra.guardrail_calls`, `extra.dangerous_tools`) — point jev-guard at any
  System One-style guardrail without a code change.

## [0.2.0] - 2026-09-22

### Added
- Name-based **taint tracking** with fixed-point propagation: dangerous tools
  and untrusted `state` are now caught through variable assignments and chains,
  not just at the literal call site (JG002, JG004).
- **JG006** — guardrail threshold set in an unsafe band (blocks only on
  near-certain danger, or almost never escalates).
- **JG007** — untrusted content interpolated into a question's `instructions`.
- **`.jev-guard.toml`** config: disable rules, override severities, and extend
  the dangerous-tool / import-root / guardrail-call sets. Discovered by walking
  up from the scan path.
- **Inline suppression**: `# jev-guard: ignore` (all) or `# jev-guard: ignore JG001,JG004`.
- Findings are de-duplicated by (rule, line).

## [0.1.0] - 2026-09-21

### Added
- Initial release: JG001–JG005, AST scanner, `scan`/`rules` CLI, text/JSON
  output, CI gate via `--fail-on`, tests, docs, MIT license.
