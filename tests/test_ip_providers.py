from app.intelligence.providers.abuseipdb import (
    AbuseIPDBProvider,
)
from app.intelligence.providers.ipinfo import (
    IPInfoProvider,
)


def test_ipinfo_without_api_key():
    provider = IPInfoProvider()

    result = provider.lookup(
        indicator="8.8.8.8",
        indicator_type="ip",
    )

    assert result.status == "unavailable"
    assert result.provider == "ipinfo_lite"


def test_abuseipdb_without_api_key():
    provider = AbuseIPDBProvider()

    result = provider.lookup(
        indicator="8.8.8.8",
        indicator_type="ip",
    )

    assert result.status == "unavailable"
    assert result.provider == "abuseipdb"