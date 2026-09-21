from __future__ import annotations

import argparse
import sys

from . import __version__
from .findings import Severity
from .formats import to_json, to_sarif
from .rules import RULES
from .scanner import scan_path

_COLORS = {
    Severity.CRITICAL: "\033[41;97m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[94m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"


def _fmt_text(findings, use_color: bool) -> str:
    if not findings:
        return "jev-guard: no findings."
    lines = []
    for f in findings:
        tag = f.severity.name
        if use_color:
            tag = f"{_COLORS[f.severity]}{tag}{_RESET}"
        lines.append(f"{f.file}:{f.line}  [{tag}] {f.code}  {f.message}")
        lines.append(f"    ↳ {f.remediation}")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.name] = counts.get(f.severity.name, 0) + 1
    summary = ", ".join(f"{v} {k.lower()}" for k, v in counts.items())
    lines.append(f"\n{len(findings)} finding(s): {summary}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="jev-guard",
        description="Audit code that uses Jev / TypeSafe System One models as a guardrail.",
    )
    parser.add_argument("--version", action="version", version=f"jev-guard {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Scan a file or directory.")
    scan.add_argument("path")
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--min-severity", default="INFO")
    scan.add_argument("--fail-on", default="HIGH")
    scan.add_argument("--output", "-o", help="Write report to a file instead of stdout.")
    scan.add_argument("--no-color", action="store_true")

    sub.add_parser("rules", help="List the rules jev-guard checks.")

    args = parser.parse_args(argv)

    if args.cmd == "rules":
        for code, (severity, message, remediation) in sorted(RULES.items()):
            print(f"{code}  [{severity.name}]  {message}")
            print(f"    {remediation}\n")
        return 0

    min_sev = Severity.parse(args.min_severity)
    fail_on = Severity.parse(args.fail_on)
    findings = [f for f in scan_path(args.path) if f.severity >= min_sev]

    if args.format == "json":
        report = to_json(findings)
    elif args.format == "sarif":
        report = to_sarif(findings, __version__)
    else:
        use_color = (not args.no_color) and sys.stdout.isatty() and not args.output
        report = _fmt_text(findings, use_color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        print(report)

    return 1 if any(f.severity >= fail_on for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
