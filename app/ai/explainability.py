from app.ai.detector import ThreatDetectionResult


def explain_detection(
    result: ThreatDetectionResult,
) -> dict:
    """
    Convert the detector result into an
    investigator-friendly explanation.
    """

    if result.label == "BENIGN":

        summary = (
            "No strong threat indicators were detected "
            "by the current detection model."
        )

    elif result.label == "BEC":

        summary = (
            "The email exhibits characteristics associated "
            "with business email compromise."
        )

    elif result.label == "CREDENTIAL_HARVESTING":

        summary = (
            "The email contains indicators associated "
            "with credential or account harvesting."
        )

    elif result.label == "PHISHING":

        summary = (
            "The email contains indicators associated "
            "with phishing activity."
        )

    else:

        summary = (
            "The email requires additional investigation."
        )

    return {
        "summary": summary,

        "label": result.label,

        "probability": result.probability,

        "model": result.model,

        "supporting_signals": result.explanations,

        "features": result.features,

        "model_trained": result.is_model_trained,

        "limitations": [
            (
                "This result is an AI/model signal and "
                "should be combined with forensic and "
                "threat-intelligence evidence."
            )
        ],
    }