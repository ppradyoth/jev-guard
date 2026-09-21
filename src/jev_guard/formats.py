from __future__ import annotations

import json

from .findings import Finding, Severity
from .rules import RULES

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_INFO_URI = "https://github.com/ppradyoth/jev-guard"


def to_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def to_sarif(findings: list[Finding], version: str) -> str:
    rules = [
        {
            "id": code,
            "name": code,
            "shortDescription": {"text": message},
            "fullDescription": {"text": remediation},
            "defaultConfiguration": {"level": _SARIF_LEVEL[severity]},
            "helpUri": f"{_INFO_URI}/blob/main/GUIDE.md",
        }
        for code, (severity, message, remediation) in sorted(RULES.items())
    ]
    results = [
        {
            "ruleId": f.code,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.message} — {f.remediation}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": max(f.line, 1)},
                    }
                }
            ],
        }
        for f in findings
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "jev-guard",
                        "version": version,
                        "informationUri": _INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
