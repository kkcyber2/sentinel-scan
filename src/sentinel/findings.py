"""Finding model and severity weighting."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# How much each severity subtracts from a perfect score.
WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 18,
    Severity.MEDIUM: 9,
    Severity.LOW: 4,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    check: str
    severity: Severity
    title: str
    detail: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }


def score_findings(findings: list[Finding]) -> int:
    """Start at 100 and subtract each finding's weight, floored at 0."""
    total = 100
    for finding in findings:
        total -= WEIGHTS[finding.severity]
    return max(0, total)


def grade_for(score: int) -> str:
    if score >= 95:
        return "A"
    if score >= 85:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    if score >= 40:
        return "E"
    return "F"
