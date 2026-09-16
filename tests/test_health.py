from email import policy
from email.parser import BytesParser

from app.email_engine.headers import (
    extract_headers,
    analyze_header_relationships,
)


SAMPLE_EMAIL = b"""From: CEO <ceo@company.com>
To: employee@company.com
Reply-To: finance@external-example.com
Return-Path: <mailer@external-example.com>
Subject: Urgent Payment Request
Message-ID: <12345@company.com>
Date: Tue, 15 Sep 2026 10:00:00 +0530
Received: from mail.example.com (203.0.113.10) by mx.company.com
Received: from relay.example.net (198.51.100.20) by mail.example.com
Authentication-Results: mx.company.com; spf=pass; dkim=fail; dmarc=fail

Hello,

This is an urgent request.

Please process the payment immediately.
"""


def test_extract_headers():
    message = BytesParser(
        policy=policy.default
    ).parsebytes(
        SAMPLE_EMAIL
    )

    headers = extract_headers(
        message
    )

    assert headers["from_email"] == (
        "ceo@company.com"
    )

    assert headers["from_domain"] == (
        "company.com"
    )

    assert headers["reply_to_domain"] == (
        "external-example.com"
    )

    assert headers["return_path_domain"] == (
        "external-example.com"
    )

    assert headers["received_header_count"] == 2

    assert (
        headers["authentication_results_count"]
        == 1
    )


def test_header_relationships():
    message = BytesParser(
        policy=policy.default
    ).parsebytes(
        SAMPLE_EMAIL
    )

    headers = extract_headers(
        message
    )

    analysis = analyze_header_relationships(
        headers
    )

    assert analysis["reply_to_mismatch"] is True

    assert (
        analysis["return_path_mismatch"]
        is True
    )

    assert analysis["finding_count"] == 2