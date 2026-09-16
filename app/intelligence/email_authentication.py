from typing import Any
from email.message import Message

from app.email_engine.headers import extract_headers
from app.email_engine.authentication import analyze_authentication


class EmailAuthenticationService:
    """
    Connects parsed email headers with the existing
    authentication analysis engine.

    This analyzes Authentication-Results evidence
    already present in the email.
    """

    def analyze(
        self,
        message: Message,
    ) -> dict[str, Any]:
        """
        Analyze SPF, DKIM and DMARC evidence
        from a parsed email.
        """

        # --------------------------------------------------
        # 1. Extract headers
        # --------------------------------------------------

        headers = extract_headers(message)

        # --------------------------------------------------
        # 2. Get Authentication-Results
        # --------------------------------------------------

        authentication_headers = headers.get(
            "authentication_results",
            [],
        )

        # --------------------------------------------------
        # 3. Analyze authentication
        # --------------------------------------------------

        authentication_result = analyze_authentication(
            authentication_headers
        )

        # --------------------------------------------------
        # 4. Return combined result
        # --------------------------------------------------

        return {
            "status": "analyzed",
            "authentication": authentication_result,
            "authentication_header_count": len(
                authentication_headers
            ),
        }