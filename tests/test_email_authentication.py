from app.email_engine.parser import parse_email

from app.intelligence.email_authentication import (
    EmailAuthenticationService,
)


def test_email_authentication():

    email_content = b"""\
From: attacker@example.com
To: victim@company.com
Subject: Urgent Payment Request
Message-ID: <test@example.com>
Authentication-Results: mx.company.com; spf=pass dkim=pass dmarc=fail

This is a test email.
"""

    # --------------------------------------------------
    # Parse email
    # --------------------------------------------------

    message = parse_email(
        email_content
    )

    # --------------------------------------------------
    # Analyze authentication
    # --------------------------------------------------

    service = EmailAuthenticationService()

    result = service.analyze(
        message
    )

    # --------------------------------------------------
    # Verify
    # --------------------------------------------------

    assert result["status"] == "analyzed"

    authentication = result[
        "authentication"
    ]

    assert (
        authentication["spf"]["status"]
        == "pass"
    )

    assert (
        authentication["dkim"]["status"]
        == "pass"
    )

    assert (
        authentication["dmarc"]["status"]
        == "fail"
    )

    assert (
        authentication["evidence_available"]
        is True
    )