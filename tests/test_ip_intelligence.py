from app.intelligence.ip import IPIntelligence


def test_valid_ipv4():

    result = IPIntelligence.classify(
        "8.8.8.8"
    )

    assert result.valid is True
    assert result.version == 4
    assert result.is_global is True
    assert result.classification == "public"


def test_valid_ipv6():

    result = IPIntelligence.classify(
        "2001:4860:4860::8888"
    )

    assert result.valid is True
    assert result.version == 6


def test_private_ipv4():

    result = IPIntelligence.classify(
        "192.168.1.10"
    )

    assert result.valid is True
    assert result.is_private is True
    assert result.classification == "private"


def test_loopback_ipv4():

    result = IPIntelligence.classify(
        "127.0.0.1"
    )

    assert result.valid is True
    assert result.is_loopback is True
    assert result.classification == "loopback"


def test_invalid_ip():

    result = IPIntelligence.classify(
        "999.999.999.999"
    )

    assert result.valid is False
    assert result.classification == "invalid"


def test_multicast_ip():

    result = IPIntelligence.classify(
        "224.0.0.1"
    )

    assert result.valid is True
    assert result.is_multicast is True
    assert result.classification == "multicast"


def test_unspecified_ipv4():

    result = IPIntelligence.classify(
        "0.0.0.0"
    )

    assert result.valid is True
    assert result.is_unspecified is True
    assert result.classification == "unspecified"