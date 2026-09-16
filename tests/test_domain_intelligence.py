from app.intelligence.providers.dns import (
    DNSProvider,
)
from app.intelligence.providers.rdap import (
    RDAPProvider,
)
from app.intelligence.service import (
    ThreatIntelligenceService,
    create_default_threat_intelligence_service,
)


# =================================================================
# RDAP TESTS
# =================================================================

def test_rdap_supports_domain():

    provider = RDAPProvider()

    assert provider.supports("domain")


def test_rdap_rejects_ip():

    provider = RDAPProvider()

    result = provider.lookup(
        indicator="8.8.8.8",
        indicator_type="ip",
    )

    assert result.status == "unsupported"


# =================================================================
# DNS TESTS
# =================================================================

def test_dns_supports_domain():

    provider = DNSProvider()

    assert provider.supports("domain")


def test_dns_rejects_ip():

    provider = DNSProvider()

    result = provider.lookup(
        indicator="8.8.8.8",
        indicator_type="ip",
    )

    assert result.status == "unsupported"


# =================================================================
# DNS LIVE LOOKUP
# =================================================================

def test_dns_lookup_example_domain():

    provider = DNSProvider()

    result = provider.lookup(
        indicator="example.com",
        indicator_type="domain",
    )

    assert result.status in {
        "success",
        "error",
    }

    assert result.provider == "dns"

    assert result.indicator == "example.com"


# =================================================================
# RDAP LIVE LOOKUP
# =================================================================

def test_rdap_lookup_example_domain():

    provider = RDAPProvider()

    result = provider.lookup(
        indicator="example.com",
        indicator_type="domain",
    )

    assert result.provider == "rdap"

    assert result.indicator == "example.com"

    assert result.status in {
        "success",
        "error",
    }


# =================================================================
# SERVICE TEST
# =================================================================

def test_domain_service_lookup():

    service = ThreatIntelligenceService(
        providers=[
            RDAPProvider(),
            DNSProvider(),
        ]
    )

    result = service.lookup(
        indicator="example.com",
        indicator_type="domain",
    )

    assert result["status"] == "complete"

    assert result["provider_count"] == 2

    providers = {
        item["provider"]
        for item in result["results"]
    }

    assert "rdap" in providers

    assert "dns" in providers


# =================================================================
# DEFAULT SERVICE
# =================================================================

def test_default_service_contains_domain_providers():

    service = (
        create_default_threat_intelligence_service()
    )

    result = service.lookup(
        indicator="example.com",
        indicator_type="domain",
    )

    assert result["status"] == "complete"

    assert result["provider_count"] == 2

    providers = {
        item["provider"]
        for item in result["results"]
    }

    assert "rdap" in providers

    assert "dns" in providers