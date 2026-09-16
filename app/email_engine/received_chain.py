import ipaddress
import re


IP_PATTERN = re.compile(
    r"\b(?:"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


def extract_ip_addresses(value: str) -> list[str]:
    """
    Extract IPv4 addresses from a Received header.
    """

    return IP_PATTERN.findall(value)


def classify_ip(ip: str) -> str:
    """
    Classify an IP address using Python's ipaddress module.
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


def parse_received_header(
    header: str,
    position: int,
) -> dict:
    """
    Convert one Received header into structured evidence.
    """

    ips = extract_ip_addresses(header)

    ip_records = []

    for ip in ips:
        ip_records.append(
            {
                "ip": ip,
                "classification": classify_ip(ip),
            }
        )

    return {
        "position": position,
        "raw": header,
        "ip_addresses": ip_records,
    }


def reconstruct_received_chain(
    received_headers: list[str],
) -> dict:
    """
    Reconstruct the observable SMTP relay chain.

    Important:
    Received headers are interpreted cautiously.
    They do not automatically establish attacker identity
    or physical location.
    """

    if not received_headers:
        return {
            "status": "insufficient_evidence",
            "hop_count": 0,
            "hops": [],
            "public_ip_candidates": [],
            "earliest_public_ip": None,
            "confidence": 0.0,
            "confidence_reasons": [
                "No Received headers were supplied."
            ],
            "limitations": [
                "SMTP origin cannot be reliably reconstructed "
                "from missing Received headers."
            ],
        }

    hops = []

    for index, header in enumerate(
        received_headers,
        start=1,
    ):
        hops.append(
            parse_received_header(
                header,
                index,
            )
        )

    public_ip_candidates = []

    for hop in hops:
        for record in hop["ip_addresses"]:
            if record["classification"] == "public":
                public_ip_candidates.append(
                    {
                        "ip": record["ip"],
                        "received_position": hop["position"],
                    }
                )

    # --------------------------------------------------
    # Confidence assessment
    # --------------------------------------------------

    confidence = 0.50

    confidence_reasons = [
        "Received headers were available."
    ]

    if len(received_headers) >= 2:
        confidence += 0.15

        confidence_reasons.append(
            "Multiple Received headers provide "
            "additional routing context."
        )

    if public_ip_candidates:
        confidence += 0.15

        confidence_reasons.append(
            "At least one public IP address was "
            "observed in the Received headers."
        )

    confidence = min(
        confidence,
        0.90,
    )

    earliest_public_ip = None

    if public_ip_candidates:
        earliest_public_ip = (
            public_ip_candidates[-1]["ip"]
        )

    limitations = [
        "Received headers can be incomplete or forged.",
        "The earliest observed public IP is an "
        "infrastructure candidate, not proof of attacker identity.",
        "IP geolocation does not establish the physical location "
        "of the person operating the infrastructure.",
    ]

    return {
        "status": "analyzed",

        "hop_count": len(hops),

        "hops": hops,

        "public_ip_candidates": public_ip_candidates,

        "earliest_public_ip": earliest_public_ip,

        "confidence": round(
            confidence,
            2,
        ),

        "confidence_reasons": confidence_reasons,

        "limitations": limitations,
    }