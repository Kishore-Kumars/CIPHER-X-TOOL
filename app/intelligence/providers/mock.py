from app.intelligence.providers.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
)


class MockThreatIntelProvider(ThreatIntelProvider):
    name = "mock"

    supported_indicator_types = {
        "ip",
        "domain",
        "url",
    }

    def lookup(
        self,
        indicator: str,
        indicator_type: str,
    ) -> ThreatIntelResult:

        indicator = indicator.strip()
        indicator_type = indicator_type.lower().strip()

        # ---------------------------------------------------------
        # Unsupported indicator type
        # ---------------------------------------------------------

        if not self.supports(indicator_type):
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status="unsupported",
                reputation="unknown",
                confidence=0.0,
                data={},
                evidence=[],
                errors=[
                    f"Unsupported indicator type: {indicator_type}"
                ],
                is_mock=True,
            )

        # ---------------------------------------------------------
        # Simulated successful result
        # ---------------------------------------------------------

        return ThreatIntelResult(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=self.name,
            status="success",
            reputation="unknown",
            confidence=1.0,
            data={
                "source": "mock",
                "message": "Synthetic threat-intelligence result",
            },
            evidence=[
                {
                    "type": "mock_lookup",
                    "source": "MockThreatIntelProvider",
                    "value": indicator,
                }
            ],
            errors=[],
            is_mock=True,
        )