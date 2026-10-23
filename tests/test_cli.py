from sentinel.cli import main, render
from sentinel.scanner import analyse


def test_render_lists_findings():
    report = analyse("http://example.com", 200, {}, "")
    text = render(report)
    assert "Grade" in text
    assert "CRITICAL" in text


def test_render_clean_report():
    report = analyse(
        "https://example.com",
        200,
        {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        },
        "",
    )
    assert "No findings" in render(report)


def test_cli_writes_json(tmp_path, serve):
    out = tmp_path / "report.json"
    code = main([serve({}), "--json", str(out)])
    assert out.exists()
    assert code in (0, 1)


def test_cli_returns_2_on_network_error():
    assert main(["http://127.0.0.1:1/", "--timeout", "1"]) == 2
