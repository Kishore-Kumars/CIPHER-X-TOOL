import hashlib
import ipaddress
import re
from urllib.parse import urlparse


# ============================================================
# REGEX PATTERNS
# ============================================================

IP_PATTERN = re.compile(
    r"\b(?:"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"\\]+",
    re.IGNORECASE,
)


EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)


DOMAIN_PATTERN = re.compile(
    r"\b(?:"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"\.)+"
    r"[A-Za-z]{2,63}\b"
)


SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)


SHA1_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)


MD5_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)


# ============================================================
# IP EXTRACTION
# ============================================================

def extract_ips(text: str) -> list[str]:
    """
    Extract IPv4 addresses from text.

    Duplicate IP addresses are removed while preserving
    their original order.
    """

    if not text:
        return []

    found = IP_PATTERN.findall(text)

    result = []

    for ip in found:
        if ip not in result:
            result.append(ip)

    return result


def classify_ip(ip: str) -> str:
    """
    Classify an IPv4 address.
    """

    try:
        address = ipaddress.ip_address(ip)

    except ValueError:
        return "invalid"

    if address.is_loopback:
        return "loopback"

    if address.is_private:
        return "private"

    if address.is_reserved:
        return "reserved"

    if address.is_link_local:
        return "link_local"

    if address.is_multicast:
        return "multicast"

    if address.is_unspecified:
        return "unspecified"

    return "public"


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text: str) -> list[str]:
    """
    Extract HTTP/HTTPS URLs.

    Trailing punctuation commonly used in email sentences
    is removed.
    """

    if not text:
        return []

    found = URL_PATTERN.findall(text)

    result = []

    trailing_characters = ".,;:!?)]}>\"'"

    for url in found:
        url = url.rstrip(trailing_characters)

        if url and url not in result:
            result.append(url)

    return result


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domains(text: str) -> list[str]:
    """
    Extract domain names from text.

    Domains appearing as part of URLs are also detected.
    """

    if not text:
        return []

    found = DOMAIN_PATTERN.findall(text)

    result = []

    for domain in found:
        domain = domain.lower().rstrip(".")

        if domain not in result:
            result.append(domain)

    return result


# ============================================================
# EMAIL ADDRESS EXTRACTION
# ============================================================

def extract_email_addresses(text: str) -> list[str]:
    """
    Extract email addresses from text.
    """

    if not text:
        return []

    found = EMAIL_PATTERN.findall(text)

    result = []

    for address in found:
        address = address.lower()

        if address not in result:
            result.append(address)

    return result


# ============================================================
# HASH EXTRACTION
# ============================================================

def extract_hashes(text: str) -> dict:
    """
    Extract MD5, SHA-1 and SHA-256 hashes from text.
    """

    if not text:
        return {
            "md5": [],
            "sha1": [],
            "sha256": [],
        }

    return {
        "md5": list(
            dict.fromkeys(
                MD5_PATTERN.findall(text)
            )
        ),

        "sha1": list(
            dict.fromkeys(
                SHA1_PATTERN.findall(text)
            )
        ),

        "sha256": list(
            dict.fromkeys(
                SHA256_PATTERN.findall(text)
            )
        ),
    }


# ============================================================
# URL → DOMAIN
# ============================================================

def extract_url_domains(urls: list[str]) -> list[str]:
    """
    Extract hostnames from URLs.
    """

    result = []

    for url in urls:
        try:
            parsed = urlparse(url)

            hostname = parsed.hostname

            if hostname:
                hostname = hostname.lower()

                if hostname not in result:
                    result.append(hostname)

        except ValueError:
            continue

    return result


# ============================================================
# IOC NORMALIZATION
# ============================================================

def normalize_iocs(
    ips: list[str],
    domains: list[str],
    urls: list[str],
    email_addresses: list[str],
    hashes: dict,
) -> dict:
    """
    Normalize and deduplicate IOC collections.
    """

    normalized_ips = []

    for ip in ips:
        try:
            normalized = str(
                ipaddress.ip_address(ip)
            )

            if normalized not in normalized_ips:
                normalized_ips.append(normalized)

        except ValueError:
            continue

    normalized_domains = []

    for domain in domains:
        domain = domain.lower().strip().rstrip(".")

        if domain not in normalized_domains:
            normalized_domains.append(domain)

    normalized_urls = []

    for url in urls:
        url = url.strip()

        if url not in normalized_urls:
            normalized_urls.append(url)

    normalized_emails = []

    for address in email_addresses:
        address = address.lower().strip()

        if address not in normalized_emails:
            normalized_emails.append(address)

    return {
        "ips": normalized_ips,
        "domains": normalized_domains,
        "urls": normalized_urls,
        "email_addresses": normalized_emails,
        "hashes": {
            "md5": list(
                dict.fromkeys(
                    hashes.get("md5", [])
                )
            ),
            "sha1": list(
                dict.fromkeys(
                    hashes.get("sha1", [])
                )
            ),
            "sha256": list(
                dict.fromkeys(
                    hashes.get("sha256", [])
                )
            ),
        },
    }


# ============================================================
# COMPLETE IOC EXTRACTION
# ============================================================

def extract_iocs(text: str) -> dict:
    """
    Extract all supported Indicators of Compromise from
    supplied email text.
    """

    if not text:
        return {
            "ips": [],
            "domains": [],
            "urls": [],
            "email_addresses": [],
            "hashes": {
                "md5": [],
                "sha1": [],
                "sha256": [],
            },
            "ip_classification": [],
            "url_domains": [],
        }

    ips = extract_ips(text)

    urls = extract_urls(text)

    domains = extract_domains(text)

    email_addresses = extract_email_addresses(text)

    hashes = extract_hashes(text)

    url_domains = extract_url_domains(urls)

    # Add domains found inside URLs.
    domains = normalize_iocs(
        ips=ips,
        domains=domains + url_domains,
        urls=urls,
        email_addresses=email_addresses,
        hashes=hashes,
    )["domains"]

    normalized = normalize_iocs(
        ips=ips,
        domains=domains,
        urls=urls,
        email_addresses=email_addresses,
        hashes=hashes,
    )

    ip_classification = []

    for ip in normalized["ips"]:
        ip_classification.append(
            {
                "ip": ip,
                "classification": classify_ip(ip),
            }
        )

    return {
        "ips": normalized["ips"],
        "domains": normalized["domains"],
        "urls": normalized["urls"],
        "email_addresses": normalized[
            "email_addresses"
        ],
        "hashes": normalized["hashes"],
        "ip_classification": ip_classification,
        "url_domains": url_domains,
    }


# ============================================================
# EMAIL MESSAGE EXTRACTION
# ============================================================

def build_searchable_email_text(
    headers: dict,
    body: str,
) -> str:
    """
    Build a searchable text representation from
    extracted headers and email body.

    This is intentionally simple for Phase 08.
    """

    header_values = []

    for key, value in headers.items():

        if isinstance(value, list):

            header_values.extend(
                str(item)
                for item in value
            )

        elif value is not None:

            header_values.append(
                str(value)
            )

    header_text = "\n".join(
        header_values
    )

    return (
        header_text
        + "\n"
        + (body or "")
    )