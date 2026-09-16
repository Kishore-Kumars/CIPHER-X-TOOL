import httpx

from app.core.config import get_settings
from app.intelligence.providers.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
)


class AbuseIPDBProvider(ThreatIntelProvider):
    """
    AbuseIPDB provider.

    Used for IP reputation and abuse history.
    """

    name = "abuseipdb"

    supported_indicator_types = {
        "ip",
    }

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def lookup(
        self,
        indicator: str,
        indicator_type: str,
    ) -> ThreatIntelResult:

        indicator = indicator.strip()
        indicator_type = indicator_type.lower().strip()

        settings = get_settings()

        # ---------------------------------------------------------
        # Validate provider support
        # ---------------------------------------------------------

        if not self.supports(indicator_type):
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status="unsupported",
                reputation="unknown",
                confidence=0.0,
                errors=[
                    f"AbuseIPDB does not support "
                    f"{indicator_type} indicators."
                ],
            )

        # ---------------------------------------------------------
        # Check API key
        # ---------------------------------------------------------

        if not settings.abuseipdb_api_key:
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status="unavailable",
                reputation="unknown",
                confidence=0.0,
                data={
                    "reason": (
                        "AbuseIPDB API key is not configured."
                    )
                },
            )

        # ---------------------------------------------------------
        # API request
        # ---------------------------------------------------------

        headers = {
            "Accept": "application/json",
            "Key": settings.abuseipdb_api_key,
        }

        params = {
            "ipAddress": indicator,
            "maxAgeInDays": settings.abuseipdb_max_age_days,
        }

        try:

            response = httpx.get(
                self.BASE_URL,
                headers=headers,
                params=params,
                timeout=settings.threat_intel_timeout_seconds,
            )

            response.raise_for_status()

            payload = response.json()

            data = payload.get("data", {})

            # -----------------------------------------------------
            # Abuse score
            # -----------------------------------------------------

            abuse_score = data.get(
                "abuseConfidenceScore"
            )

            if abuse_score is None:

                reputation = "unknown"

            elif abuse_score >= 75:

                reputation = "high_abuse"

            elif abuse_score >= 25:

                reputation = "suspicious"

            else:

                reputation = "low_abuse"

            # -----------------------------------------------------
            # Return standardized result
            # -----------------------------------------------------

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="ip",
                provider=self.name,
                status="success",
                reputation=reputation,

                # Provider-data confidence,
                # NOT threat probability.
                confidence=0.90,

                data={
                    "abuse_confidence_score": abuse_score,
                    "country_code": data.get(
                        "countryCode"
                    ),
                    "usage_type": data.get(
                        "usageType"
                    ),
                    "isp": data.get(
                        "isp"
                    ),
                    "domain": data.get(
                        "domain"
                    ),
                    "total_reports": data.get(
                        "totalReports"
                    ),
                    "last_reported_at": data.get(
                        "lastReportedAt"
                    ),
                    "is_whitelisted": data.get(
                        "isWhitelisted"
                    ),
                },

                evidence=[
                    {
                        "type": "abuse_reputation",
                        "source": "AbuseIPDB",
                        "value": abuse_score,
                    },
                    {
                        "type": "usage_type",
                        "source": "AbuseIPDB",
                        "value": data.get(
                            "usageType"
                        ),
                    },
                    {
                        "type": "total_reports",
                        "source": "AbuseIPDB",
                        "value": data.get(
                            "totalReports"
                        ),
                    },
                ],
            )

        # ---------------------------------------------------------
        # HTTP errors
        # ---------------------------------------------------------

        except httpx.HTTPStatusError as exc:

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="ip",
                provider=self.name,
                status="error",
                reputation="unknown",
                confidence=0.0,
                errors=[
                    f"AbuseIPDB HTTP error: "
                    f"{exc.response.status_code}"
                ],
            )

        # ---------------------------------------------------------
        # Network errors
        # ---------------------------------------------------------

        except httpx.RequestError as exc:

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="ip",
                provider=self.name,
                status="error",
                reputation="unknown",
                confidence=0.0,
                errors=[
                    f"AbuseIPDB request error: "
                    f"{str(exc)}"
                ],
            )

        # ---------------------------------------------------------
        # Invalid JSON
        # ---------------------------------------------------------

        except ValueError:

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="ip",
                provider=self.name,
                status="error",
                reputation="unknown",
                confidence=0.0,
                errors=[
                    "AbuseIPDB returned invalid JSON."
                ],
            )