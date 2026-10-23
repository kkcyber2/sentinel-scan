"""Fetch a target and run every check against the response."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from .checks import (
    check_cookies,
    check_cors,
    check_disclosure,
    check_headers,
    check_transport,
)
from .findings import Finding, grade_for, score_findings

USER_AGENT = "sentinel-scan/1.0 (+posture check)"


@dataclass
class Report:
    url: str
    status_code: int
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    @property
    def score(self) -> int:
        return score_findings(self.findings)

    @property
    def grade(self) -> str:
        return grade_for(self.score)

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    def public(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "score": self.score,
            "grade": self.grade,
            "by_severity": self.by_severity(),
            "findings": [f.public() for f in self.findings],
            "error": self.error,
        }


def analyse(url: str, status_code: int, headers: dict[str, str], body: str) -> Report:
    """Run every check against an already-fetched response."""
    set_cookies = [
        v for k, v in headers.items() if k.lower() == "set-cookie"
    ]
    findings: list[Finding] = []
    findings += check_transport(url, headers)
    findings += check_headers(headers)
    findings += check_cookies(set_cookies)
    findings += check_disclosure(headers, body)
    findings += check_cors(headers)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order[f.severity.value])
    return Report(url=url, status_code=status_code, findings=findings)


def scan(url: str, *, timeout: float = 10.0, client: httpx.Client | None = None) -> Report:
    """Fetch `url` and analyse the response. Never raises on a network error."""
    owns_client = client is None
    client = client or httpx.Client(
        timeout=timeout, follow_redirects=True, headers={"user-agent": USER_AGENT}
    )
    try:
        response = client.get(url)
        return analyse(
            str(response.url), response.status_code, dict(response.headers), response.text
        )
    except httpx.HTTPError as exc:
        return Report(url=url, status_code=0, error=f"{type(exc).__name__}: {exc}")
    finally:
        if owns_client:
            client.close()
