from app.ai.detector import ThreatDetector
from app.ai.features import (
    extract_email_features,
)


def test_feature_extraction():

    features = extract_email_features(
        subject="URGENT PAYMENT REQUIRED",
        body=(
            "Please transfer the funds immediately "
            "and confirm the transaction."
        ),
        from_address="ceo@example.com",
        reply_to="finance@external-example.com",
        return_path="ceo@example.com",
        attachment_count=1,
        spf_result="fail",
        dkim_result="fail",
        dmarc_result="fail",
    )

    assert features.subject_length > 0

    assert features.body_length > 0

    assert features.has_urgent_language is True

    assert features.has_financial_language is True

    assert features.reply_to_mismatch is True

    assert features.spf_fail is True

    assert features.dkim_fail is True

    assert features.dmarc_fail is True


def test_detector_identifies_bec():

    features = extract_email_features(
        subject="URGENT PAYMENT REQUIRED",
        body=(
            "Transfer the payment immediately."
        ),
        from_address="ceo@example.com",
        reply_to="finance@external-example.com",
        spf_result="fail",
        dkim_result="fail",
        dmarc_result="fail",
    )

    detector = ThreatDetector()

    result = detector.predict(
        features
    )

    assert result.label == "BEC"

    assert result.probability > 0

    assert len(
        result.explanations
    ) > 0


def test_detector_identifies_credential_harvesting():

    features = extract_email_features(
        subject="Verify your account",
        body=(
            "Please login and verify your password."
        ),
    )

    detector = ThreatDetector()

    result = detector.predict(
        features
    )

    assert (
        result.label
        == "CREDENTIAL_HARVESTING"
    )


def test_detector_handles_benign_email():

    features = extract_email_features(
        subject="Meeting tomorrow",
        body=(
            "Let's meet tomorrow at 10 AM."
        ),
    )

    detector = ThreatDetector()

    result = detector.predict(
        features
    )

    assert result.label == "BENIGN"

    assert result.probability >= 0