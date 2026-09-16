from app.intelligence.providers.abuseipdb import (
    AbuseIPDBProvider,
)

from app.intelligence.providers.mock import (
    MockThreatIntelProvider,
)

from app.intelligence.service import (
    ThreatIntelligenceService,
)


# =================================================================
# MOCK PROVIDER TESTS
# =================================================================


def test_mock_provider_supports_ioc_types():

    provider = MockThreatIntelProvider()

    assert provider.supports("ip")
    assert provider.supports("domain")
    assert provider.supports("url")


def test_mock_provider_returns_simulated_result():

    provider = MockThreatIntelProvider()

    result = provider.lookup(
        indicator="8.8.8.8",
        indicator_type="ip",
    )

    assert result.provider == "mock"
    assert result.status == "success"
    assert result.is_mock is True
    assert result.reputation == "unknown"
    assert result.confidence == 1.0


def test_mock_provider_rejects_unsupported_type():

    provider = MockThreatIntelProvider()

    result = provider.lookup(
        indicator="test@example.com",
        indicator_type="email",
    )

    assert result.status == "unsupported"
    assert result.is_mock is True


# =================================================================
# SERVICE TESTS
# =================================================================


def test_service_lookup():

    service = ThreatIntelligenceService(
        providers=[
            MockThreatIntelProvider(),
        ]
    )

    result = service.lookup(
        indicator="8.8.8.8",
        indicator_type="ip",
    )

    assert result["status"] == "complete"
    assert result["provider_count"] == 1
    assert result["successful_results"] == 1

    assert (
        result["results"][0]["is_mock"]
        is True
    )


def test_service_handles_missing_provider():

    service = ThreatIntelligenceService()

    result = service.lookup(
        indicator="8.8.8.8",
        indicator_type="ip",
    )

    assert result["status"] == "no_provider"

    assert result["results"] == []


def test_enrich_iocs():

    service = ThreatIntelligenceService(
        providers=[
            MockThreatIntelProvider(),
        ]
    )

    iocs = {
        "ips": [
            "8.8.8.8",
        ],
        "domains": [
            "example.com",
        ],
        "urls": [
            "https://example.com/login",
        ],
    }

    result = service.enrich_iocs(iocs)

    assert result["status"] == "complete"

    assert len(
        result["results"]["ips"]
    ) == 1

    assert len(
        result["results"]["domains"]
    ) == 1

    assert len(
        result["results"]["urls"]
    ) == 1

    assert (
        result["results"]["ips"][0]
        ["results"][0]
        ["is_mock"]
        is True
    )


# =================================================================
# ABUSEIPDB PROVIDER TESTS
# =================================================================


def test_abuseipdb_without_api_key():

    provider = AbuseIPDBProvider()

    result = provider.lookup(
        indicator="8.8.8.8",
        indicator_type="ip",
    )

    assert result.status == "unavailable"

    assert (
        result.provider
        == "abuseipdb"
    )


def test_abuseipdb_rejects_non_ip():

    provider = AbuseIPDBProvider()

    result = provider.lookup(
        indicator="example.com",
        indicator_type="domain",
    )

    assert result.status == "unsupported"

    assert (
        result.provider
        == "abuseipdb"
    )


# =================================================================
# NOTE
# =================================================================
#
# IPinfo tests have intentionally been removed from this test file.
#
# IPinfo is currently deferred/optional in the CIPHER-X MVP.
#
# The following tests were removed:
#
# - test_ipinfo_rejects_non_ip
# - test_ipinfo_supports_ip
# - test_ipinfo_rejects_invalid_ip
# - test_ipinfo_success
# - test_ipinfo_http_error
# - test_ipinfo_network_error
# - test_ipinfo_invalid_json
# - test_ipinfo_sends_correct_request
# - test_ipinfo_strips_whitespace
#
# The default-service test expecting IPinfo and AbuseIPDB
# to be registered was also removed because the current
# default service intentionally uses:
#
# - RDAP
# - DNS
# - URL structural analysis
#
# IPinfo and AbuseIPDB can be added later as optional
# providers without changing the core service architecture.
#
# =================================================================