from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

from .findings import Severity

CONFIG_NAME = ".jev-guard.toml"


@dataclass
class Config:
    disabled: frozenset[str] = frozenset()
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    extra_dangerous_tools: frozenset[str] = frozenset()
    extra_import_roots: frozenset[str] = frozenset()
    extra_guardrail_calls: frozenset[str] = frozenset()

    @classmethod
    def load(cls, start: str | Path) -> Config:
        path = _find(Path(start))
        if path is None:
            return cls()
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            return cls()
        section = data.get("jev-guard", data)
        overrides = {
            code.upper(): Severity.parse(name)
            for code, name in (section.get("severity") or {}).items()
        }
        extra = section.get("extra") or {}
        return cls(
            disabled=frozenset(c.upper() for c in section.get("disable", [])),
            severity_overrides=overrides,
            extra_dangerous_tools=frozenset(extra.get("dangerous_tools", [])),
            extra_import_roots=frozenset(extra.get("import_roots", [])),
            extra_guardrail_calls=frozenset(extra.get("guardrail_calls", [])),
        )


def _find(start: Path) -> Path | None:
    start = start.resolve()
    directory = start if start.is_dir() else start.parent
    for candidate in [directory, *directory.parents]:
        cfg = candidate / CONFIG_NAME
        if cfg.is_file():
            return cfg
    return None
