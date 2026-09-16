from ipaddress import ip_address
from typing import Any

import httpx

from app.core.config import get_settings
from app.intelligence.providers.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
)


class IPInfoProvider(ThreatIntelProvider):
    """
    IPinfo Lite provider.

    Provides basic country, continent, ASN,
    and network-owner information for an IP address.
    """

    name = "ipinfo_lite"

    supported_indicator_types = {
        "ip",
    }

    BASE_URL = "https://api.ipinfo.io/lite"

    def lookup(
        self,
        indicator: str,
        indicator_type: str,
    ) -> ThreatIntelResult:

        # ---------------------------------------------------------
        # Normalize input
        # ---------------------------------------------------------

        indicator = indicator.strip()
        indicator_type = indicator_type.lower().strip()

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
                    f"IPinfo provider does not support "
                    f"{indicator_type} indicators."
                ],
            )

        # ---------------------------------------------------------
        # Validate IP address
        # ---------------------------------------------------------

        try:
            parsed_ip = ip_address(indicator)

        except ValueError:
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status="invalid",
                reputation="unknown",
                confidence=0.0,
                errors=[
                    "Invalid IP address."
                ],
            )

        # Normalize IP representation
        indicator = str(parsed_ip)

        # ---------------------------------------------------------
        # Load application settings
        # ---------------------------------------------------------

        settings = get_settings()

        # ---------------------------------------------------------
        # Check API token
        # ---------------------------------------------------------

        if not settings.ipinfo_token:

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="ip",
                provider=self.name,
                status="unavailable",
                reputation="unknown",
                confidence=0.0,
                data={
                    "reason": (
                        "IPinfo API token is not configured."
                    )
                },
            )

        # ---------------------------------------------------------
        # Clean API token
        # ---------------------------------------------------------

        token = settings.ipinfo_token.strip()

        # ---------------------------------------------------------
        # Build API endpoint
        # ---------------------------------------------------------

        url = f"{self.BASE_URL}/{indicator}"

        # ---------------------------------------------------------
        # Perform IPinfo API lookup
        # ---------------------------------------------------------

        try:

            response = httpx.get(
                url,
                params={
                    "token": token,
                },
                headers={
                    "Accept": "application/json",
                    "User-Agent": "CIPHER-X/1.0",
                },
                timeout=settings.threat_intel_timeout_seconds,
                follow_redirects=True,
            )

            # -----------------------------------------------------
            # Raise exception for HTTP errors
            # -----------------------------------------------------

            response.raise_for_status()

            # -----------------------------------------------------
            # Parse JSON response
            # -----------------------------------------------------

            payload: dict[str, Any] = response.json()

            # -----------------------------------------------------
            # Extract IP intelligence
            # -----------------------------------------------------

            country = payload.get("country")
            country_code = payload.get("country_code")

            continent_code = payload.get("continent_code")
            continent = payload.get("continent")

            asn = payload.get("asn")
            as_name = payload.get("as_name")
            as_domain = payload.get("as_domain")

            # -----------------------------------------------------
            # Build evidence
            # -----------------------------------------------------

            evidence: list[dict[str, Any]] = []

            if country:
                evidence.append(
                    {
                        "type": "geolocation",
                        "source": "IPinfo Lite",
                        "value": country,
                    }
                )

            if country_code:
                evidence.append(
                    {
                        "type": "country_code",
                        "source": "IPinfo Lite",
                        "value": country_code,
                    }
                )

            if continent:
                evidence.append(
                    {
                        "type": "continent",
                        "source": "IPinfo Lite",
                        "value": continent,
                    }
                )

            if asn:
                evidence.append(
                    {
                        "type": "asn",
                        "source": "IPinfo Lite",
                        "value": asn,
                    }
                )

            if as_name:
                evidence.append(
                    {
                        "type": "network_owner",
                        "source": "IPinfo Lite",
                        "value": as_name,
                    }
                )

            if as_domain:
                evidence.append(
                    {
                        "type": "network_domain",
                        "source": "IPinfo Lite",
                        "value": as_domain,
                    }
                )

            # -----------------------------------------------------
            # Return successful result
            # -----------------------------------------------------

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="ip",
                provider=self.name,
                status="success",

                # IPinfo provides geolocation/network data.
                # It does NOT determine maliciousness.
                reputation="unknown",

                # Confidence in the returned provider data.
                # This is NOT a maliciousness probability.
                confidence=0.90,

                data={
                    "country_code": country_code,
                    "country": country,
                    "continent_code": continent_code,
                    "continent": continent,
                    "asn": asn,
                    "as_name": as_name,
                    "as_domain": as_domain,
                },

                evidence=evidence,

                errors=[],

                is_mock=False,
            )

        # ---------------------------------------------------------
        # HTTP/API errors
        # ---------------------------------------------------------

        except httpx.HTTPStatusError as exc:

            status_code = (
                exc.response.status_code
                if exc.response is not None
                else 0
            )

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="ip",
                provider=self.name,
                status="error",
                reputation="unknown",
                confidence=0.0,
                data={
                    "http_status": status_code,
                },
                errors=[
                    f"IPinfo HTTP error: {status_code}"
                ],
                is_mock=False,
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
                    f"IPinfo request error: {str(exc)}"
                ],
                is_mock=False,
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
                    "IPinfo returned invalid JSON."
                ],
                is_mock=False,
            )