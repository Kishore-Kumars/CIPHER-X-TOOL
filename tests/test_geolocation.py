from app.intelligence.geolocation import (
    GeoLocation,
)


# =================================================================
# UNAVAILABLE GEOLOCATION
# =================================================================


def test_geolocation_unavailable():

    result = GeoLocation.unavailable(
        ip="8.8.8.8"
    )

    assert result.ip == "8.8.8.8"

    assert result.status == "unavailable"

    assert result.country is None
    assert result.country_code is None

    assert result.region is None
    assert result.city is None

    assert result.latitude is None
    assert result.longitude is None

    assert result.asn is None
    assert result.organization is None

    assert result.source is None
    assert result.confidence == 0.0


# =================================================================
# EMPTY IP
# =================================================================


def test_geolocation_empty_ip():

    result = GeoLocation.lookup("")

    assert result["status"] == "unavailable"

    assert (
        result["message"]
        == "IP address cannot be empty."
    )


# =================================================================
# NO PROVIDER
# =================================================================


def test_geolocation_without_provider():

    result = GeoLocation.lookup(
        "8.8.8.8"
    )

    assert result["status"] == "unavailable"

    assert result["ip"] == "8.8.8.8"

    assert result["country"] is None

    assert result["city"] is None

    assert result["confidence"] == 0.0


# =================================================================
# NORMALIZATION
# =================================================================


def test_geolocation_normalization():

    data = {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "Mountain View",
        "latitude": 37.4056,
        "longitude": -122.0775,
        "timezone": "America/Los_Angeles",
        "asn": "AS15169",
        "organization": "Google LLC",
    }

    result = GeoLocation.normalize(
        ip="8.8.8.8",
        data=data,
        source="test-provider",
        confidence=0.90,
    )

    assert result.ip == "8.8.8.8"

    assert result.status == "success"

    assert result.country == "United States"
    assert result.country_code == "US"

    assert result.region == "California"
    assert result.city == "Mountain View"

    assert result.latitude == 37.4056
    assert result.longitude == -122.0775

    assert (
        result.timezone
        == "America/Los_Angeles"
    )

    assert result.asn == "AS15169"

    assert (
        result.organization
        == "Google LLC"
    )

    assert (
        result.source
        == "test-provider"
    )

    assert result.confidence == 0.90


# =================================================================
# PROVIDER LOOKUP
# =================================================================


class MockGeoProvider:

    def lookup(self, ip):

        return {
            "country": "India",
            "country_code": "IN",
            "region": "Karnataka",
            "city": "Bengaluru",
            "latitude": 12.9716,
            "longitude": 77.5946,
            "timezone": "Asia/Kolkata",
            "asn": "AS12345",
            "organization": "Example Network",
            "source": "mock-geolocation",
            "confidence": 0.85,
        }


def test_geolocation_provider_lookup():

    provider = MockGeoProvider()

    result = GeoLocation.lookup(
        "1.2.3.4",
        provider=provider,
    )

    assert result["status"] == "success"

    assert result["ip"] == "1.2.3.4"

    assert result["country"] == "India"

    assert result["country_code"] == "IN"

    assert result["region"] == "Karnataka"

    assert result["city"] == "Bengaluru"

    assert result["latitude"] == 12.9716

    assert result["longitude"] == 77.5946

    assert result["asn"] == "AS12345"

    assert (
        result["organization"]
        == "Example Network"
    )

    assert (
        result["source"]
        == "mock-geolocation"
    )

    assert result["confidence"] == 0.85


# =================================================================
# INVALID PROVIDER RESPONSE
# =================================================================


class InvalidGeoProvider:

    def lookup(self, ip):

        return "invalid-response"


def test_invalid_provider_response():

    provider = InvalidGeoProvider()

    result = GeoLocation.lookup(
        "8.8.8.8",
        provider=provider,
    )

    assert result["status"] == "unavailable"

    assert (
        result["message"]
        == "Geolocation provider returned invalid data."
    )


# =================================================================
# PROVIDER ERROR
# =================================================================


class ErrorGeoProvider:

    def lookup(self, ip):

        raise RuntimeError(
            "Provider unavailable"
        )


def test_geolocation_provider_error():

    provider = ErrorGeoProvider()

    result = GeoLocation.lookup(
        "8.8.8.8",
        provider=provider,
    )

    assert result["status"] == "unavailable"

    assert (
        result["message"]
        == "Geolocation provider error."
    )

    assert (
        result["error"]
        == "Provider unavailable"
    )


# =================================================================
# DICTIONARY SERIALIZATION
# =================================================================


def test_geolocation_to_dict():

    result = GeoLocation.normalize(
        ip="8.8.8.8",
        data={
            "country": "United States",
            "country_code": "US",
            "city": "Mountain View",
            "latitude": 37.4056,
            "longitude": -122.0775,
        },
        source="test-provider",
        confidence=0.90,
    )

    output = GeoLocation.to_dict(
        result
    )

    assert isinstance(output, dict)

    assert output["ip"] == "8.8.8.8"

    assert output["country"] == "United States"

    assert output["country_code"] == "US"

    assert output["city"] == "Mountain View"

    assert output["confidence"] == 0.90