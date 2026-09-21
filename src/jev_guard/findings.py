from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> Severity:
        return cls[name.strip().upper()]


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    file: str
    line: int
    message: str
    remediation: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d
