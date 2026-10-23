# Sentinel Scan

A web security posture scanner. Point it at a site you own and it grades the things
that are cheap to get wrong and expensive to ignore: transport security, response
headers, cookie flags, information disclosure and CORS.

It is a **posture** tool, not a penetration test. It sends a small number of ordinary
GET requests, never attacks, and never touches anything outside the host you name.

## What it checks

| Area | Examples |
|---|---|
| Transport | HTTPS enforced, HSTS present and long enough, no mixed redirect |
| Headers | CSP, X-Content-Type-Options, X-Frame-Options / frame-ancestors, Referrer-Policy, Permissions-Policy |
| Cookies | `Secure`, `HttpOnly`, `SameSite`, over-broad `Domain` |
| Disclosure | `Server` / `X-Powered-By` version leakage, directory listing, stack traces |
| CORS | `Access-Control-Allow-Origin: *` combined with credentials |

Each finding carries a severity, the evidence that produced it, and a concrete
remediation. The overall grade is a weighted score, not a count.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
sentinel-scan https://example.com
sentinel-scan https://example.com --json report.json
```

## Using it as a library

```python
from sentinel.scanner import scan

report = scan("https://example.com")
print(report.grade, report.score)
for finding in report.findings:
    print(finding.severity, finding.title, "->", finding.remediation)
```

## Tests

```bash
pytest -q
```

The suite spins up a local HTTP server with deliberately bad headers, so the checks
are exercised against real responses rather than mocks.

## License

MIT — see `LICENSE`.
