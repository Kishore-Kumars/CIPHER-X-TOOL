from app.email_engine.authentication import (
    parse_authentication_results,
    analyze_authentication,
)


def test_authentication_results_pass():
    headers = [
        (
            "mx.company.com; "
            "spf=pass; "
            "dkim=pass; "
            "dmarc=pass"
        )
    ]

    result = parse_authentication_results(headers)

    assert result["spf"]["status"] == "pass"
    assert result["dkim"]["status"] == "pass"
    assert result["dmarc"]["status"] == "pass"


def test_authentication_results_fail():
    headers = [
        (
            "mx.company.com; "
            "spf=fail; "
            "dkim=fail; "
            "dmarc=fail"
        )
    ]

    result = parse_authentication_results(headers)

    assert result["spf"]["status"] == "fail"
    assert result["dkim"]["status"] == "fail"
    assert result["dmarc"]["status"] == "fail"


def test_missing_authentication_results():
    result = parse_authentication_results([])

    assert result["spf"]["status"] == "not_available"
    assert result["dkim"]["status"] == "not_available"
    assert result["dmarc"]["status"] == "not_available"


def test_authentication_analysis():
    headers = [
        (
            "mx.company.com; "
            "spf=pass; "
            "dkim=pass; "
            "dmarc=fail"
        )
    ]

    result = analyze_authentication(headers)

    assert result["spf"]["status"] == "pass"
    assert result["dkim"]["status"] == "pass"
    assert result["dmarc"]["status"] == "fail"

    assert any(
        finding["type"] == "dmarc_failure"
        for finding in result["findings"]
    )


def test_authentication_conflict():
    headers = [
        (
            "mx.company.com; "
            "spf=pass; "
            "dkim=pass; "
            "dmarc=fail"
        )
    ]

    result = analyze_authentication(headers)

    assert any(
        finding["type"] == "authentication_conflict"
        for finding in result["findings"]
    )