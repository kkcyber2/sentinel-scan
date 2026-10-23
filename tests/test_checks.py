from sentinel.checks import (
    check_cookies,
    check_cors,
    check_disclosure,
    check_headers,
    check_transport,
)
from sentinel.findings import Finding, Severity, grade_for, score_findings


def checks(findings):
    return {f.check for f in findings}


def test_plain_http_is_critical():
    findings = check_transport("http://example.com", {})
    assert findings[0].severity is Severity.CRITICAL


def test_https_without_hsts_is_high():
    assert "transport.hsts" in checks(check_transport("https://example.com", {}))


def test_short_hsts_max_age_is_flagged():
    findings = check_transport(
        "https://example.com", {"Strict-Transport-Security": "max-age=600"}
    )
    assert "transport.hsts_max_age" in checks(findings)


def test_long_hsts_max_age_passes():
    findings = check_transport(
        "https://example.com",
        {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"},
    )
    assert findings == []


def test_missing_csp_is_high():
    assert "headers.csp" in checks(check_headers({}))


def test_weak_csp_is_medium():
    findings = check_headers(
        {"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'"}
    )
    assert "headers.csp_weak" in checks(findings)


def test_frame_ancestors_satisfies_framing():
    findings = check_headers(
        {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
    )
    assert "headers.framing" not in checks(findings)


def test_cookie_missing_all_flags_produces_three_findings():
    findings = check_cookies(["session=abc123"])
    assert checks(findings) == {"cookies.secure", "cookies.httponly", "cookies.samesite"}


def test_fully_flagged_cookie_passes():
    assert check_cookies(["session=abc; Secure; HttpOnly; SameSite=Lax"]) == []


def test_samesite_none_without_secure_is_high():
    findings = check_cookies(["s=1; SameSite=None"])
    assert "cookies.samesite_none" in checks(findings)


def test_version_disclosure_is_flagged():
    findings = check_disclosure({"Server": "nginx/1.18.0"}, "")
    assert "disclosure.version" in checks(findings)


def test_generic_server_header_is_not_flagged():
    assert check_disclosure({"Server": "nginx"}, "") == []


def test_traceback_in_body_is_flagged():
    findings = check_disclosure({}, "Traceback (most recent call last):")
    assert "disclosure.body" in checks(findings)


def test_wildcard_cors_with_credentials_is_high():
    findings = check_cors(
        {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
    )
    assert findings[0].severity is Severity.HIGH


def test_scoring_subtracts_weights_and_floors_at_zero():
    many = [Finding("x", Severity.CRITICAL, "t", "d", "r") for _ in range(5)]
    assert score_findings(many) == 0
    assert score_findings([]) == 100


def test_grade_boundaries():
    assert grade_for(100) == "A"
    assert grade_for(85) == "B"
    assert grade_for(70) == "C"
    assert grade_for(55) == "D"
    assert grade_for(40) == "E"
    assert grade_for(39) == "F"
