from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv6Address,
    ip_address,
)


@dataclass
class IPClassification:
    """
    Normalized classification of an IP address.
    """

    ip: str
    version: int
    valid: bool

    is_private: bool
    is_global: bool
    is_loopback: bool
    is_reserved: bool
    is_multicast: bool
    is_unspecified: bool

    classification: str


class IPIntelligence:
    """
    Core IP validation and classification engine.

    This layer does not perform external API lookups.

    It determines whether an IP is suitable for
    further threat-intelligence enrichment.
    """

    @staticmethod
    def classify(ip: str) -> IPClassification:
        """
        Validate and classify an IPv4 or IPv6 address.
        """

        ip = ip.strip()

        # ---------------------------------------------------------
        # Validate IP
        # ---------------------------------------------------------

        try:
            parsed_ip = ip_address(ip)

        except ValueError:

            return IPClassification(
                ip=ip,
                version=0,
                valid=False,
                is_private=False,
                is_global=False,
                is_loopback=False,
                is_reserved=False,
                is_multicast=False,
                is_unspecified=False,
                classification="invalid",
            )

        # ---------------------------------------------------------
        # Determine IP version
        # ---------------------------------------------------------

        if isinstance(parsed_ip, IPv4Address):
            version = 4
        else:
            version = 6

        # ---------------------------------------------------------
        # Determine classification
        # ---------------------------------------------------------

        if parsed_ip.is_unspecified:

            classification = "unspecified"

        elif parsed_ip.is_loopback:

            classification = "loopback"

        elif parsed_ip.is_multicast:

            classification = "multicast"

        elif parsed_ip.is_private:

            classification = "private"

        elif parsed_ip.is_reserved:

            classification = "reserved"

        elif parsed_ip.is_global:

            classification = "public"

        else:

            classification = "special"

        # ---------------------------------------------------------
        # Return normalized result
        # ---------------------------------------------------------

        return IPClassification(
            ip=str(parsed_ip),
            version=version,
            valid=True,
            is_private=parsed_ip.is_private,
            is_global=parsed_ip.is_global,
            is_loopback=parsed_ip.is_loopback,
            is_reserved=parsed_ip.is_reserved,
            is_multicast=parsed_ip.is_multicast,
            is_unspecified=parsed_ip.is_unspecified,
            classification=classification,
        )