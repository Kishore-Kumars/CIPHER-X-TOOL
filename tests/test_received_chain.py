from app.email_engine.received_chain import (
    classify_ip,
    extract_ip_addresses,
    reconstruct_received_chain,
)


def test_extract_ip_addresses():
    header = (
        "from mail.example.com "
        "(203.0.113.10) "
        "by mx.company.com"
    )

    ips = extract_ip_addresses(header)

    assert ips == [
        "203.0.113.10"
    ]


def test_classify_private_ip():
    assert (
        classify_ip("192.168.1.10")
        == "private"
    )


def test_classify_public_ip():
    assert (
        classify_ip("8.8.8.8")
        == "public"
    )


def test_received_chain():
    received_headers = [
        (
            "from mail.example.com "
            "(8.8.8.8) "
            "by mx.company.com"
        ),
        (
            "from relay.example.net "
            "(1.1.1.1) "
            "by mail.example.com"
        ),
    ]

    result = reconstruct_received_chain(
        received_headers
    )

    assert result["status"] == "analyzed"

    assert result["hop_count"] == 2

    assert len(
        result["public_ip_candidates"]
    ) == 2

    assert (
        result["earliest_public_ip"]
        == "1.1.1.1"
    )