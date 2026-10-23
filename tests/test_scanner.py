from sentinel.scanner import analyse, scan


def test_analyse_sorts_by_severity():
    report = analyse("http://example.com", 200, {}, "")
    severities = [f.severity.value for f in report.findings]
    assert severities == sorted(severities, key=lambda s: ["critical", "high", "medium", "low", "info"].index(s))


def test_analyse_reports_grade_and_score():
    report = analyse("https://example.com", 200, {}, "")
    assert report.grade in "ABCDEF"
    assert 0 <= report.score <= 100


def test_scan_against_a_real_server(serve):
    url = serve({"X-Content-Type-Options": "nosniff"})
    report = scan(url)
    assert report.status_code == 200
    assert report.error is None
    # plain http -> critical transport finding
    assert any(f.check == "transport.https" for f in report.findings)


def test_scan_reports_network_errors_without_raising():
    report = scan("http://127.0.0.1:1/", timeout=1.0)
    assert report.error is not None
    assert report.status_code == 0


def test_scan_detects_a_well_configured_server(serve):
    url = serve(
        {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
    )
    report = scan(url)
    # only the plain-http transport finding should remain
    assert [f.check for f in report.findings] == ["transport.https"]


def test_public_dict_is_json_serialisable(serve):
    import json

    report = scan(serve({}))
    json.dumps(report.public())
