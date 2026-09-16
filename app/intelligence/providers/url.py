from urllib.parse import urlparse

from app.intelligence.providers.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
)


class URLProvider(ThreatIntelProvider):
    """
    URL intelligence provider.

    Current responsibilities:
        - Validate URL structure
        - Extract URL components
        - Generate forensic evidence

    Future responsibilities:
        - URL reputation
        - Redirect analysis
        - URLhaus
        - VirusTotal
        - PhishTank
    """

    name = "url_analysis"

    supported_indicator_types = {
        "url",
    }

    def lookup(
        self,
        indicator: str,
        indicator_type: str,
    ) -> ThreatIntelResult:
        """
        Analyze a URL and extract its structural components.
        """

        # ---------------------------------------------------------
        # Validate indicator type
        # ---------------------------------------------------------

        if not self.supports(indicator_type):

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status="unsupported",
            )

        # ---------------------------------------------------------
        # Clean input
        # ---------------------------------------------------------

        indicator = indicator.strip()

        if not indicator:

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="url",
                provider=self.name,
                status="error",
                errors=[
                    "URL cannot be empty."
                ],
            )

        # ---------------------------------------------------------
        # Parse URL
        # ---------------------------------------------------------

        try:

            parsed = urlparse(indicator)

            # -----------------------------------------------------
            # Validate scheme
            # -----------------------------------------------------

            if not parsed.scheme:

                raise ValueError(
                    "URL is missing a scheme."
                )

            # -----------------------------------------------------
            # Validate hostname
            # -----------------------------------------------------

            if not parsed.netloc:

                raise ValueError(
                    "URL is missing a hostname."
                )

            hostname = parsed.hostname

            if not hostname:

                raise ValueError(
                    "URL hostname could not be determined."
                )

            # -----------------------------------------------------
            # Extract URL components
            # -----------------------------------------------------

            data = {
                "scheme": parsed.scheme,
                "hostname": hostname,
                "port": parsed.port,
                "path": parsed.path,
                "query": parsed.query,
                "fragment": parsed.fragment,
            }

            # -----------------------------------------------------
            # Create forensic evidence
            # -----------------------------------------------------

            evidence = [
                {
                    "type": "url_structure",
                    "source": self.name,
                    "value": data,
                }
            ]

            # -----------------------------------------------------
            # Return result
            # -----------------------------------------------------

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="url",
                provider=self.name,
                status="success",
                reputation="unknown",
                confidence=0.95,
                data=data,
                evidence=evidence,
            )

        # ---------------------------------------------------------
        # URL parsing error
        # ---------------------------------------------------------

        except ValueError as exc:

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="url",
                provider=self.name,
                status="error",
                errors=[
                    f"URL analysis failed: {exc}"
                ],
            )

        # ---------------------------------------------------------
        # Unexpected error
        # ---------------------------------------------------------

        except Exception as exc:

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="url",
                provider=self.name,
                status="error",
                errors=[
                    f"Unexpected URL analysis error: {exc}"
                ],
            )