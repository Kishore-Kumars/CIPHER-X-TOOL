from dataclasses import dataclass
from typing import Any

from app.ai.features import EmailFeatures


@dataclass
class ThreatDetectionResult:
    """
    Standardized CIPHER-X AI threat-detection result.

    The current implementation is an interpretable
    rule-based baseline. A trained ML model can later
    replace or augment this detector.
    """

    label: str
    probability: float
    model: str
    features: dict[str, Any]
    explanations: list[str]
    is_model_trained: bool = False


class ThreatDetector:
    """
    CIPHER-X threat detector.

    Current:
        Interpretable rule-based baseline.

    Future:
        Trained ML model can replace or augment
        this baseline.
    """

    name = "cipherx_baseline"

    def predict(
        self,
        features: EmailFeatures,
    ) -> ThreatDetectionResult:
        """
        Analyze extracted email features and produce
        a standardized threat-detection result.
        """

        score = 0.0
        explanations: list[str] = []

        # ========================================================
        # AUTHENTICATION SIGNALS
        # ========================================================

        if features.spf_fail:
            score += 0.15
            explanations.append(
                "SPF authentication failure."
            )

        if features.dkim_fail:
            score += 0.15
            explanations.append(
                "DKIM authentication failure."
            )

        if features.dmarc_fail:
            score += 0.20
            explanations.append(
                "DMARC authentication failure."
            )

        # ========================================================
        # SENDER IDENTITY SIGNALS
        # ========================================================

        if features.reply_to_mismatch:
            score += 0.20
            explanations.append(
                "From and Reply-To domains do not match."
            )

        if features.sender_domain_mismatch:
            score += 0.10
            explanations.append(
                "Sender domain relationship appears inconsistent."
            )

        # ========================================================
        # LANGUAGE SIGNALS
        # ========================================================

        if features.has_urgent_language:
            score += 0.10
            explanations.append(
                "Urgency-related language detected."
            )

        if features.has_financial_language:
            score += 0.10
            explanations.append(
                "Financial or payment-related language detected."
            )

        if features.has_credential_language:
            score += 0.15
            explanations.append(
                "Credential or account-related language detected."
            )

        # ========================================================
        # URL SIGNALS
        # ========================================================

        if features.has_suspicious_url:
            score += 0.15
            explanations.append(
                "Potentially suspicious URL pattern detected."
            )

        if features.url_count > 0:
            explanations.append(
                f"{features.url_count} URL(s) detected in the email."
            )

        # ========================================================
        # ATTACHMENT SIGNAL
        # ========================================================

        if features.attachment_count > 0:
            score += 0.05
            explanations.append(
                "Email contains attachment(s)."
            )

        # ========================================================
        # NORMALIZE SCORE
        # ========================================================

        score = min(
            max(score, 0.0),
            1.0,
        )

        # ========================================================
        # THREAT CLASSIFICATION
        # ========================================================

        # Business Email Compromise
        if (
            features.has_financial_language
            and features.has_urgent_language
            and (
                features.reply_to_mismatch
                or features.sender_domain_mismatch
                or features.dmarc_fail
            )
        ):
            label = "BEC"

        # Credential harvesting
        elif (
            features.has_credential_language
            and (
                features.has_suspicious_url
                or features.dmarc_fail
                or features.reply_to_mismatch
            )
        ):
            label = "CREDENTIAL_HARVESTING"

        # General phishing
        elif (
            features.dmarc_fail
            or features.spf_fail
            or features.dkim_fail
            or features.has_suspicious_url
            or features.reply_to_mismatch
        ):
            label = "PHISHING"

        # Suspicious but not enough evidence for a
        # specific threat category
        elif score >= 0.30:
            label = "SUSPICIOUS"

        # No strong indicators
        else:
            label = "BENIGN"

        # ========================================================
        # DEFAULT EXPLANATION
        # ========================================================

        if not explanations:
            explanations.append(
                "No strong threat indicators were detected "
                "by the current baseline detector."
            )

        # ========================================================
        # RETURN RESULT
        # ========================================================

        return ThreatDetectionResult(
            label=label,
            probability=round(score, 4),
            model=self.name,
            features=features.to_dict(),
            explanations=explanations,
            is_model_trained=False,
        )