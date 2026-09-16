from app.email_engine.parser import parse_email
from app.intelligence.email_ip_analysis import (
    EmailIPAnalysisService,
)


def test_email_ip_analysis():

    email_content = b"""\
From: attacker@example.com
To: victim@company.com
Subject: Urgent Payment Request
Message-ID: <test@example.com>
Reply-To: attacker@example.com
Return-Path: <attacker@example.com>
Received: from mail.example.com (8.8.8.8) by mx.company.com
Received: from relay.example.net (1.1.1.1) by mail.example.com

This is a test email.
"""

    # --------------------------------------------------
    # Parse .EML
    # --------------------------------------------------

    message = parse_email(
        email_content
    )

    # --------------------------------------------------
    # Run complete IP analysis
    # --------------------------------------------------

    service = EmailIPAnalysisService()

    result = service.analyze(
        message
    )

    # --------------------------------------------------
    # Verify result
    # --------------------------------------------------

    assert result["status"] == "analyzed"

    assert (
        result["received_chain"]["hop_count"]
        == 2
    )

    assert (
        result["earliest_public_ip"]
        == "1.1.1.1"
    )

    assert (
        result["candidate_ip_count"]
        == 2
    )

    assert len(
        result["ip_intelligence"]
    ) == 2