"""
CIPHER-X IP Intelligence Service

Coordinates IP classification and geolocation.

This layer does not claim that an IP address identifies
the physical location or identity of an attacker.
"""

from typing import Any

from app.intelligence.ip import IPIntelligence
from app.intelligence.geolocation import GeoLocation


class IPIntelligenceService:
    """
    Coordinates:

        1. IP validation
        2. IP classification
        3. Geolocation

    External threat-intelligence providers can be added later.
    """

    def __init__(
        self,
        geolocation_provider: Any | None = None,
    ):
        self.geolocation_provider = geolocation_provider

    def analyze(self, ip: str) -> dict[str, Any]:
        """
        Perform complete IP intelligence analysis.
        """

        ip = ip.strip()

        # ---------------------------------------------------------
        # Validate and classify IP
        # ---------------------------------------------------------

        classification = IPIntelligence.classify(ip)

        classification_data = {
            "ip": classification.ip,
            "version": classification.version,
            "valid": classification.valid,
            "is_private": classification.is_private,
            "is_global": classification.is_global,
            "is_loopback": classification.is_loopback,
            "is_reserved": classification.is_reserved,
            "is_multicast": classification.is_multicast,
            "is_unspecified": classification.is_unspecified,
            "classification": classification.classification,
        }

        # ---------------------------------------------------------
        # Invalid IP
        # ---------------------------------------------------------

        if not classification.valid:
            return {
                "status": "invalid",
                "ip": classification.ip,
                "classification": classification_data,
                "geolocation": GeoLocation.to_dict(
                    GeoLocation.unavailable(
                        classification.ip,
                        "Invalid IP address.",
                    )
                ),
            }

        # ---------------------------------------------------------
        # Private / special IP
        # ---------------------------------------------------------

        if not classification.is_global:
            return {
                "status": "not_global",
                "ip": classification.ip,
                "classification": classification_data,
                "geolocation": GeoLocation.to_dict(
                    GeoLocation.unavailable(
                        classification.ip,
                        (
                            "Geolocation is not performed for "
                            "non-global IP addresses."
                        ),
                    )
                ),
            }

        # ---------------------------------------------------------
        # Global/public IP
        # ---------------------------------------------------------

        geolocation = GeoLocation.lookup(
            ip=classification.ip,
            provider=self.geolocation_provider,
        )

        return {
            "status": "success",
            "ip": classification.ip,
            "classification": classification_data,
            "geolocation": geolocation,
        }