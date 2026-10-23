"""Individual posture checks.

Every check is a pure function of a `Response`-like object, which is what makes the
suite testable without a network.
"""
from __future__ import annotations

from typing import Any

from .findings import Finding, Severity

MIN_HSTS_MAX_AGE = 15_552_000  # six months, the usual bar for preload eligibility


def _header(headers: dict[str, str], name: str) -> str | None:
    lowered = {k.lower(): v for k, v in headers.items()}
    return lowered.get(name.lower())


def check_transport(url: str, headers: dict[str, str]) -> list[Finding]:
    out: list[Finding] = []
    if not url.lower().startswith("https://"):
        out.append(
            Finding(
                check="transport.https",
                severity=Severity.CRITICAL,
                title="Site is served over plain HTTP",
                detail="The response came back over http://, so everything on the page can be read or altered in transit.",
                remediation="Serve the site over HTTPS and redirect all HTTP traffic to it.",
                evidence={"url": url},
            )
        )
        return out
    hsts = _header(headers, "strict-transport-security")
    if not hsts:
        out.append(
            Finding(
                check="transport.hsts",
                severity=Severity.HIGH,
                title="HSTS is not set",
                detail="Without Strict-Transport-Security a first visit can be downgraded to HTTP by an attacker on the network.",
                remediation="Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
            )
        )
    else:
        max_age = 0
        for part in hsts.split(";"):
            part = part.strip()
            if part.lower().startswith("max-age="):
                try:
                    max_age = int(part.split("=", 1)[1])
                except ValueError:
                    max_age = 0
        if max_age < MIN_HSTS_MAX_AGE:
            out.append(
                Finding(
                    check="transport.hsts_max_age",
                    severity=Severity.MEDIUM,
                    title="HSTS max-age is short",
                    detail=f"max-age is {max_age}s; browsers only honour HSTS for that long.",
                    remediation=f"Raise max-age to at least {MIN_HSTS_MAX_AGE} (six months).",
                    evidence={"max_age": max_age},
                )
            )
    return out


def check_headers(headers: dict[str, str]) -> list[Finding]:
    out: list[Finding] = []
    csp = _header(headers, "content-security-policy")
    if not csp:
        out.append(
            Finding(
                check="headers.csp",
                severity=Severity.HIGH,
                title="No Content-Security-Policy",
                detail="CSP is the main defence-in-depth control against cross-site scripting.",
                remediation="Add a CSP that starts restrictive, e.g. `default-src 'self'`.",
            )
        )
    elif "'unsafe-inline'" in csp and "'unsafe-eval'" in csp:
        out.append(
            Finding(
                check="headers.csp_weak",
                severity=Severity.MEDIUM,
                title="CSP allows both unsafe-inline and unsafe-eval",
                detail="A policy that permits inline and eval'd script blocks very little.",
                remediation="Move inline script to files and remove 'unsafe-eval'.",
                evidence={"csp": csp},
            )
        )
    if not _header(headers, "x-content-type-options"):
        out.append(
            Finding(
                check="headers.nosniff",
                severity=Severity.MEDIUM,
                title="X-Content-Type-Options is missing",
                detail="Browsers may sniff a response into a type you did not intend.",
                remediation="Send `X-Content-Type-Options: nosniff`.",
            )
        )
    if not _header(headers, "x-frame-options") and "frame-ancestors" not in (csp or ""):
        out.append(
            Finding(
                check="headers.framing",
                severity=Severity.MEDIUM,
                title="Clickjacking protection is missing",
                detail="Neither X-Frame-Options nor a CSP frame-ancestors directive is present.",
                remediation="Send `X-Frame-Options: DENY` or add `frame-ancestors 'none'` to the CSP.",
            )
        )
    if not _header(headers, "referrer-policy"):
        out.append(
            Finding(
                check="headers.referrer",
                severity=Severity.LOW,
                title="No Referrer-Policy",
                detail="Full URLs may leak to third parties in the Referer header.",
                remediation="Send `Referrer-Policy: strict-origin-when-cross-origin`.",
            )
        )
    if not _header(headers, "permissions-policy"):
        out.append(
            Finding(
                check="headers.permissions",
                severity=Severity.LOW,
                title="No Permissions-Policy",
                detail="Powerful browser features are not explicitly restricted.",
                remediation="Send a Permissions-Policy that disables features you do not use.",
            )
        )
    return out


def check_cookies(set_cookie_headers: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip()
        lowered = raw.lower()
        if "secure" not in lowered:
            out.append(
                Finding(
                    check="cookies.secure",
                    severity=Severity.HIGH,
                    title=f"Cookie {name!r} is missing Secure",
                    detail="The cookie can be sent over plain HTTP and intercepted.",
                    remediation="Add the Secure attribute.",
                    evidence={"cookie": name},
                )
            )
        if "httponly" not in lowered:
            out.append(
                Finding(
                    check="cookies.httponly",
                    severity=Severity.MEDIUM,
                    title=f"Cookie {name!r} is missing HttpOnly",
                    detail="Script on the page can read the cookie, so one XSS steals the session.",
                    remediation="Add the HttpOnly attribute.",
                    evidence={"cookie": name},
                )
            )
        if "samesite" not in lowered:
            out.append(
                Finding(
                    check="cookies.samesite",
                    severity=Severity.MEDIUM,
                    title=f"Cookie {name!r} has no SameSite",
                    detail="The cookie is attached to cross-site requests, which enables CSRF.",
                    remediation="Add `SameSite=Lax` (or Strict where it works).",
                    evidence={"cookie": name},
                )
            )
        elif "samesite=none" in lowered and "secure" not in lowered:
            out.append(
                Finding(
                    check="cookies.samesite_none",
                    severity=Severity.HIGH,
                    title=f"Cookie {name!r} is SameSite=None without Secure",
                    detail="Browsers reject this combination, and where they do not it is cross-site readable.",
                    remediation="Either add Secure or use SameSite=Lax.",
                    evidence={"cookie": name},
                )
            )
    return out


def check_disclosure(headers: dict[str, str], body: str) -> list[Finding]:
    out: list[Finding] = []
    for header_name in ("server", "x-powered-by", "x-aspnet-version"):
        value = _header(headers, header_name)
        if value and any(ch.isdigit() for ch in value):
            out.append(
                Finding(
                    check="disclosure.version",
                    severity=Severity.LOW,
                    title=f"{header_name} reveals a version",
                    detail=f"The header advertises {value!r}, which narrows an attacker's search.",
                    remediation=f"Remove or genericise the {header_name} header.",
                    evidence={"header": header_name, "value": value},
                )
            )
    lowered = body.lower()
    for marker, label in (
        ("traceback (most recent call last)", "a Python traceback"),
        ("stack trace", "a stack trace"),
        ("index of /", "a directory listing"),
    ):
        if marker in lowered:
            out.append(
                Finding(
                    check="disclosure.body",
                    severity=Severity.MEDIUM,
                    title=f"Response body contains {label}",
                    detail="Internal detail is being shown to the public.",
                    remediation="Return a generic error page and log the detail server-side.",
                    evidence={"marker": marker},
                )
            )
    return out


def check_cors(headers: dict[str, str]) -> list[Finding]:
    origin = _header(headers, "access-control-allow-origin")
    credentials = (_header(headers, "access-control-allow-credentials") or "").lower()
    if origin == "*" and credentials == "true":
        return [
            Finding(
                check="cors.wildcard_credentials",
                severity=Severity.HIGH,
                title="CORS allows any origin with credentials",
                detail="Any site can make authenticated requests and read the responses.",
                remediation="Echo only an allowlisted origin, never `*`, when credentials are allowed.",
                evidence={"origin": origin, "credentials": credentials},
            )
        ]
    if origin == "*":
        return [
            Finding(
                check="cors.wildcard",
                severity=Severity.LOW,
                title="CORS allows any origin",
                detail="Fine for a public read-only API, risky if any endpoint is authenticated.",
                remediation="Restrict Access-Control-Allow-Origin to the origins you actually serve.",
                evidence={"origin": origin},
            )
        ]
    return []
