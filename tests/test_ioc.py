from app.email_engine.ioc import (
    classify_ip,
    extract_domains,
    extract_email_addresses,
    extract_hashes,
    extract_ips,
    extract_iocs,
    extract_urls,
)


def test_extract_ips():

    text = (
        "Connection observed from "
        "8.8.8.8 and 1.1.1.1"
    )

    ips = extract_ips(text)

    assert ips == [
        "8.8.8.8",
        "1.1.1.1",
    ]


def test_extract_domains():

    text = (
        "Visit evil-example.com or "
        "login.example.org"
    )

    domains = extract_domains(text)

    assert "evil-example.com" in domains
    assert "login.example.org" in domains


def test_extract_urls():

    text = (
        "Click here: "
        "https://evil-example.com/login"
    )

    urls = extract_urls(text)

    assert urls == [
        "https://evil-example.com/login"
    ]


def test_extract_email_addresses():

    text = (
        "Contact attacker@evil-example.com "
        "or finance@company.com"
    )

    addresses = extract_email_addresses(text)

    assert addresses == [
        "attacker@evil-example.com",
        "finance@company.com",
    ]


def test_extract_hashes():

    text = (
        "MD5 "
        "d41d8cd98f00b204e9800998ecf8427e "
        "and SHA256 "
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )

    hashes = extract_hashes(text)

    assert (
        "d41d8cd98f00b204e9800998ecf8427e"
        in hashes["md5"]
    )

    assert (
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        in hashes["sha256"]
    )


def test_classify_ip():

    assert classify_ip(
        "192.168.1.10"
    ) == "private"

    assert classify_ip(
        "8.8.8.8"
    ) == "public"


def test_extract_iocs():

    text = """
    From attacker@evil-example.com

    Visit:
    https://evil-example.com/login

    Infrastructure:
    8.8.8.8
    """

    result = extract_iocs(text)

    assert "8.8.8.8" in result["ips"]

    assert (
        "evil-example.com"
        in result["domains"]
    )

    assert (
        "https://evil-example.com/login"
        in result["urls"]
    )

    assert (
        "attacker@evil-example.com"
        in result["email_addresses"]
    )