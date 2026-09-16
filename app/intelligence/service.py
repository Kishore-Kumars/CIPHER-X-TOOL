from app.intelligence.providers.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
)

from app.intelligence.providers.dns import (
    DNSProvider,
)

from app.intelligence.providers.rdap import (
    RDAPProvider,
)

from app.intelligence.providers.url import (
    URLProvider,
)


class ThreatIntelligenceService:
    """
    Central service responsible for coordinating
    multiple threat-intelligence providers.

    The service itself is provider-agnostic.

    Providers are explicitly registered when creating
    the service instance.
    """

    def __init__(
        self,
        providers: list[ThreatIntelProvider] | None = None,
    ):
        # Do NOT automatically register providers here.
        #
        # This keeps the service generic and preserves
        # predictable unit-test behavior.

        self.providers = providers or []

    # =============================================================
    # Provider Management
    # =============================================================

    def add_provider(
        self,
        provider: ThreatIntelProvider,
    ) -> None:
        """
        Add a threat-intelligence provider.
        """

        self.providers.append(provider)

    # =============================================================
    # Provider Selection
    # =============================================================

    def get_providers_for_indicator(
        self,
        indicator_type: str,
    ) -> list[ThreatIntelProvider]:
        """
        Return all providers capable of handling
        the supplied indicator type.
        """

        indicator_type = (
            indicator_type.lower().strip()
        )

        return [
            provider
            for provider in self.providers
            if provider.supports(indicator_type)
        ]

    # =============================================================
    # Single IOC Lookup
    # =============================================================

    def lookup(
        self,
        indicator: str,
        indicator_type: str,
    ) -> dict:
        """
        Query all providers that support the supplied IOC type.

        Supported types:

            ip
            domain
            url
        """

        indicator = indicator.strip()
        indicator_type = (
            indicator_type.lower().strip()
        )

        # ---------------------------------------------------------
        # Validate input
        # ---------------------------------------------------------

        if not indicator:
            return {
                "status": "invalid",
                "indicator": indicator,
                "indicator_type": indicator_type,
                "provider_count": 0,
                "successful_results": 0,
                "results": [],
                "errors": [
                    "Indicator cannot be empty."
                ],
            }

        # ---------------------------------------------------------
        # Find compatible providers
        # ---------------------------------------------------------

        matching_providers = (
            self.get_providers_for_indicator(
                indicator_type
            )
        )

        # ---------------------------------------------------------
        # No provider available
        # ---------------------------------------------------------

        if not matching_providers:
            return {
                "status": "no_provider",
                "indicator": indicator,
                "indicator_type": indicator_type,
                "provider_count": 0,
                "successful_results": 0,
                "results": [],
                "errors": [],
            }

        # ---------------------------------------------------------
        # Query providers
        # ---------------------------------------------------------

        results: list[ThreatIntelResult] = []
        errors: list[str] = []

        for provider in matching_providers:

            try:

                result = provider.lookup(
                    indicator=indicator,
                    indicator_type=indicator_type,
                )

                results.append(result)

                # Collect provider errors without
                # stopping the remaining providers.

                if result.errors:

                    errors.extend(
                        [
                            f"{provider.name}: {error}"
                            for error in result.errors
                        ]
                    )

            except Exception as exc:

                errors.append(
                    f"{provider.name}: "
                    f"unexpected provider error: {str(exc)}"
                )

        # ---------------------------------------------------------
        # Count actual successful provider results
        # ---------------------------------------------------------

        successful_results = [
            result
            for result in results
            if result.status == "success"
        ]

        # ---------------------------------------------------------
        # Determine overall status
        # ---------------------------------------------------------

        if successful_results:

            if len(successful_results) == len(
                matching_providers
            ):
                overall_status = "complete"

            else:
                overall_status = "partial"

        else:

            # Providers exist, but none returned
            # usable intelligence.

            configured_results = [
                result
                for result in results
                if result.status != "not_configured"
            ]

            if not configured_results:
                overall_status = "not_configured"

            else:
                overall_status = "error"

        # ---------------------------------------------------------
        # Return standardized response
        # ---------------------------------------------------------

        return {
            "status": overall_status,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "provider_count": len(
                matching_providers
            ),
            "successful_results": len(
                successful_results
            ),
            "results": [
                self._serialize_result(result)
                for result in results
            ],
            "errors": errors,
        }

    # =============================================================
    # Serialization
    # =============================================================

    @staticmethod
    def _serialize_result(
        result: ThreatIntelResult,
    ) -> dict:
        """
        Convert a ThreatIntelResult dataclass
        into a JSON-compatible dictionary.
        """

        return {
            "indicator": result.indicator,
            "indicator_type": result.indicator_type,
            "provider": result.provider,
            "status": result.status,
            "reputation": result.reputation,
            "confidence": result.confidence,
            "data": result.data,
            "evidence": result.evidence,
            "errors": result.errors,
            "is_mock": result.is_mock,
        }

    # =============================================================
    # IOC Enrichment
    # =============================================================

    def enrich_iocs(
        self,
        iocs: dict,
    ) -> dict:
        """
        Enrich all extracted IOCs.

        Expected input:

            {
                "ips": [],
                "domains": [],
                "urls": []
            }
        """

        results = {
            "ips": [],
            "domains": [],
            "urls": [],
        }

        # ---------------------------------------------------------
        # IP addresses
        # ---------------------------------------------------------

        for ip in iocs.get("ips", []):

            results["ips"].append(
                self.lookup(
                    indicator=ip,
                    indicator_type="ip",
                )
            )

        # ---------------------------------------------------------
        # Domains
        # ---------------------------------------------------------

        for domain in iocs.get("domains", []):

            results["domains"].append(
                self.lookup(
                    indicator=domain,
                    indicator_type="domain",
                )
            )

        # ---------------------------------------------------------
        # URLs
        # ---------------------------------------------------------

        for url in iocs.get("urls", []):

            results["urls"].append(
                self.lookup(
                    indicator=url,
                    indicator_type="url",
                )
            )

        return {
            "status": "complete",
            "results": results,
        }


# =================================================================
# Default CIPHER-X Threat Intelligence Service
# =================================================================

def create_default_threat_intelligence_service() -> (
    ThreatIntelligenceService
):
    """
    Create the standard CIPHER-X
    threat-intelligence service.

    Current providers:

        Domain Intelligence
            - RDAP
            - DNS

        URL Intelligence
            - URL structural analysis

    Deferred / optional providers:

        IP Intelligence
            - IPinfo Lite
            - AbuseIPDB

    Future providers:

        - VirusTotal
        - URLhaus
        - OTX
        - GreyNoise
        - MISP
    """

    return ThreatIntelligenceService(
        providers=[
            # -----------------------------------------------------
            # Domain Intelligence
            # -----------------------------------------------------

            RDAPProvider(),
            DNSProvider(),

            # -----------------------------------------------------
            # URL Intelligence
            # -----------------------------------------------------

            URLProvider(),
        ]
    )