"""Command line entry point."""
from __future__ import annotations

import argparse
import json
import sys

from .scanner import scan

SEVERITY_MARK = {
    "critical": "!!",
    "high": "! ",
    "medium": "~ ",
    "low": ". ",
    "info": "  ",
}


def render(report) -> str:
    lines = [f"Target : {report.url}", f"Status : {report.status_code}"]
    if report.error:
        lines.append(f"Error  : {report.error}")
        return "\n".join(lines)
    lines.append(f"Grade  : {report.grade}  (score {report.score}/100)")
    lines.append("")
    if not report.findings:
        lines.append("No findings. Every check passed.")
        return "\n".join(lines)
    for finding in report.findings:
        mark = SEVERITY_MARK[finding.severity.value]
        lines.append(f"{mark} [{finding.severity.value.upper()}] {finding.title}")
        lines.append(f"     {finding.detail}")
        lines.append(f"     fix: {finding.remediation}")
        lines.append("")
    return "\n".join(lines).rstrip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel-scan", description="Web security posture scanner")
    parser.add_argument("url", help="target URL (only scan sites you own)")
    parser.add_argument("--json", metavar="PATH", help="write the full report as JSON")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    report = scan(args.url, timeout=args.timeout)
    print(render(report))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(report.public(), handle, indent=2)
        print(f"\nJSON report written to {args.json}")
    if report.error:
        return 2
    return 1 if report.findings else 0


if __name__ == "__main__":
    sys.exit(main())
