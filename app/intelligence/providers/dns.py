from typing import Any

import dns.exception
import dns.resolver

from app.intelligence.providers.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
)


class DNSProvider(ThreatIntelProvider):
    """
    DNS intelligence provider.

    Retrieves DNS records associated with a domain.

    Supported records:

        A
        AAAA
        MX
        NS
        CNAME
    """

    name = "dns"

    supported_indicator_types = {
        "domain",
    }

    RECORD_TYPES = (
        "A",
        "AAAA",
        "MX",
        "NS",
        "CNAME",
    )

    def lookup(
        self,
        indicator: str,
        indicator_type: str,
    ) -> ThreatIntelResult:

        indicator = indicator.strip().lower()
        indicator_type = indicator_type.lower().strip()

        if not self.supports(indicator_type):

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status="unsupported",
                reputation="unknown",
                confidence=0.0,
                errors=[
                    f"DNS provider does not support "
                    f"{indicator_type} indicators."
                ],
            )

        if not indicator:

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="domain",
                provider=self.name,
                status="invalid",
                reputation="unknown",
                confidence=0.0,
                errors=[
                    "Domain cannot be empty."
                ],
            )

        records: dict[str, list[str]] = {}

        errors: list[str] = []

        # ---------------------------------------------------------
        # Query DNS
        # ---------------------------------------------------------

        for record_type in self.RECORD_TYPES:

            try:

                answers = dns.resolver.resolve(
                    indicator,
                    record_type,
                    lifetime=5,
                )

                values = []

                for answer in answers:

                    values.append(
                        str(answer).rstrip(".")
                    )

                records[record_type] = values

            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):

                # Absence of a particular record is not necessarily
                # an error.
                records[record_type] = []

            except Exception as exc:

                errors.append(
                    f"{record_type}: {str(exc)}"
                )

        # ---------------------------------------------------------
        # Evidence
        # ---------------------------------------------------------

        evidence: list[dict[str, Any]] = []

        for record_type, values in records.items():

            for value in values:

                evidence.append(
                    {
                        "type": f"dns_{record_type.lower()}",
                        "source": "DNS",
                        "value": value,
                    }
                )

        # ---------------------------------------------------------
        # Return result
        # ---------------------------------------------------------

        status = (
            "success"
            if records or not errors
            else "error"
        )

        return ThreatIntelResult(
            indicator=indicator,
            indicator_type="domain",
            provider=self.name,
            status=status,
            reputation="unknown",

            # Successful DNS observation.
            # NOT maliciousness confidence.
            confidence=0.90,

            data={
                "records": records,
            },

            evidence=evidence,

            errors=errors,
        )