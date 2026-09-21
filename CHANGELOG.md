# Changelog

All notable changes to jev-guard are documented here. Versioning is semver.

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
