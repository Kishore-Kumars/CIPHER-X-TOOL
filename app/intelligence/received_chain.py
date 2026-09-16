"""
CIPHER-X Received Header / SMTP Relay Chain Analysis

This module extracts and normalizes Received headers from
an email message.

Important:
A Received header can be forged or modified by an attacker.
Therefore, this module reconstructs the observed relay chain
but does NOT automatically declare the earliest IP to be the
attacker's physical location or identity.
"""

from dataclasses import dataclass
import re
from typing import Any


# ============================================================
# Data Model
# ============================================================

@dataclass
class ReceivedHop:
    """
    Represents one observed SMTP relay hop.
    """

    hop_number: int

    raw_header: str

    from_host: str | None
    from_ip: str | None

    by_host: str | None
    by_ip: str | None

    protocol: str | None
    timestamp: str | None

    private_ips: list[str]
    public_ips: list[str]

    reliability: str


# ============================================================
# Received Chain Analyzer
# ============================================================

class ReceivedChainAnalyzer:
    """
    Extracts and analyzes Received headers.

    The analyzer is intentionally conservative.

    It reports:
        - observed relay hops
        - extracted hostnames
        - extracted IP addresses
        - public/private classification
        - timestamps
        - basic reliability indicators

    It does not claim attacker identity.
    """

    # --------------------------------------------------------
    # IP pattern
    # --------------------------------------------------------

    IPV4_PATTERN = re.compile(
        r"\b(?:"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"\b"
    )

    # Basic IPv6 detection.
    IPV6_PATTERN = re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){2,7}"
        r"[0-9a-fA-F]{0,4}\b"
    )

    # --------------------------------------------------------
    # Public/private IP classification
    # --------------------------------------------------------

    @staticmethod
    def classify_ip(ip: str) -> str:
        """
        Classify an IP address.

        Returns:
            private
            public
            special
            invalid
        """

        from ipaddress import ip_address

        try:
            parsed = ip_address(ip)

        except ValueError:
            return "invalid"

        if parsed.is_private:
            return "private"

        if parsed.is_loopback:
            return "special"

        if parsed.is_reserved:
            return "special"

        if parsed.is_multicast:
            return "special"

        if parsed.is_unspecified:
            return "special"

        if parsed.is_global:
            return "public"

        return "special"

    # ========================================================
    # Extract IP addresses
    # ========================================================

    @classmethod
    def extract_ips(cls, text: str) -> list[str]:
        """
        Extract IPv4 and IPv6 addresses from a Received header.
        """

        if not text:
            return []

        ipv4 = cls.IPV4_PATTERN.findall(text)
        ipv6 = cls.IPV6_PATTERN.findall(text)

        # Preserve order while removing duplicates.
        result = []

        for ip in ipv4 + ipv6:
            if ip not in result:
                result.append(ip)

        return result

    # ========================================================
    # Extract hostname
    # ========================================================

    @staticmethod
    def extract_from_host(header: str) -> str | None:
        """
        Extract the host following 'from'.
        """

        match = re.search(
            r"\bfrom\s+([^\s(]+)",
            header,
            re.IGNORECASE,
        )

        if match:
            return match.group(1).strip()

        return None

    @staticmethod
    def extract_by_host(header: str) -> str | None:
        """
        Extract the host following 'by'.
        """

        match = re.search(
            r"\bby\s+([^\s(]+)",
            header,
            re.IGNORECASE,
        )

        if match:
            return match.group(1).strip()

        return None

    # ========================================================
    # Extract protocol
    # ========================================================

    @staticmethod
    def extract_protocol(header: str) -> str | None:
        """
        Extract protocol information such as:

            ESMTP
            SMTP
            ESMTPS
        """

        match = re.search(
            r"\bwith\s+([A-Za-z0-9._-]+)",
            header,
            re.IGNORECASE,
        )

        if match:
            return match.group(1).strip()

        return None

    # ========================================================
    # Extract timestamp
    # ========================================================

    @staticmethod
    def extract_timestamp(header: str) -> str | None:
        """
        Extract the timestamp portion of a Received header.

        This intentionally returns the raw timestamp rather
        than attempting to interpret timezone semantics here.
        """

        if ";" not in header:
            return None

        timestamp = header.rsplit(";", 1)[-1].strip()

        if not timestamp:
            return None

        return timestamp

    # ========================================================
    # Reliability
    # ========================================================

    @classmethod
    def determine_reliability(
        cls,
        header: str,
        ips: list[str],
    ) -> str:
        """
        Determine a conservative reliability level.

        This is NOT an attacker-attribution score.

        high:
            Structured Received header with useful routing
            information.

        medium:
            Some routing information exists but evidence is
            incomplete.

        low:
            Header is malformed or contains very little
            usable information.
        """

        if not header.strip():
            return "low"

        from_host = cls.extract_from_host(header)
        by_host = cls.extract_by_host(header)
        timestamp = cls.extract_timestamp(header)

        if from_host and by_host and ips and timestamp:
            return "high"

        if from_host or by_host or ips:
            return "medium"

        return "low"

    # ========================================================
    # Analyze Single Hop
    # ========================================================

    @classmethod
    def analyze_hop(
        cls,
        header: str,
        hop_number: int,
    ) -> ReceivedHop:
        """
        Analyze one Received header.
        """

        header = header.strip()

        ips = cls.extract_ips(header)

        private_ips = []
        public_ips = []

        for ip in ips:

            classification = cls.classify_ip(ip)

            if classification == "private":
                private_ips.append(ip)

            elif classification == "public":
                public_ips.append(ip)

        return ReceivedHop(
            hop_number=hop_number,

            raw_header=header,

            from_host=cls.extract_from_host(
                header
            ),

            from_ip=(
                public_ips[0]
                if public_ips
                else ips[0]
                if ips
                else None
            ),

            by_host=cls.extract_by_host(
                header
            ),

            by_ip=(
                public_ips[-1]
                if public_ips
                else None
            ),

            protocol=cls.extract_protocol(
                header
            ),

            timestamp=cls.extract_timestamp(
                header
            ),

            private_ips=private_ips,

            public_ips=public_ips,

            reliability=cls.determine_reliability(
                header,
                ips,
            ),
        )

    # ========================================================
    # Analyze Chain
    # ========================================================

    @classmethod
    def analyze(
        cls,
        received_headers: list[str],
    ) -> dict[str, Any]:
        """
        Analyze an entire Received header chain.

        Important:
        Received headers are generally stored newest-first
        in an email.

        Therefore, the observed chain is normalized into
        chronological order for investigation.
        """

        if not received_headers:
            return {
                "status": "no_received_headers",
                "hop_count": 0,
                "hops": [],
                "public_ips": [],
                "private_ips": [],
                "candidate_origin_ips": [],
                "warnings": [
                    "No Received headers were found."
                ],
            }

        # Analyze in original order first.
        analyzed = []

        for index, header in enumerate(
            received_headers,
            start=1,
        ):
            analyzed.append(
                cls.analyze_hop(
                    header=header,
                    hop_number=index,
                )
            )

        # ----------------------------------------------------
        # Aggregate IPs
        # ----------------------------------------------------

        public_ips = []
        private_ips = []

        for hop in analyzed:

            for ip in hop.public_ips:
                if ip not in public_ips:
                    public_ips.append(ip)

            for ip in hop.private_ips:
                if ip not in private_ips:
                    private_ips.append(ip)

        # ----------------------------------------------------
        # Candidate origin
        # ----------------------------------------------------

        candidate_origin_ips = []

        for hop in reversed(analyzed):

            for ip in hop.public_ips:

                if ip not in candidate_origin_ips:
                    candidate_origin_ips.append(ip)

        warnings = []

        if not candidate_origin_ips:
            warnings.append(
                "No globally routable IP was identified "
                "in the Received chain."
            )

        if any(
            hop.reliability == "low"
            for hop in analyzed
        ):
            warnings.append(
                "One or more Received headers contain "
                "limited routing evidence."
            )

        warnings.append(
            "Received headers may be forged or modified; "
            "candidate origin is not proof of attacker identity."
        )

        # ----------------------------------------------------
        # Return result
        # ----------------------------------------------------

        return {
            "status": "success",
            "hop_count": len(analyzed),

            "hops": [
                cls.hop_to_dict(hop)
                for hop in analyzed
            ],

            "public_ips": public_ips,
            "private_ips": private_ips,

            "candidate_origin_ips": candidate_origin_ips,

            "warnings": warnings,
        }

    # ========================================================
    # Serialization
    # ========================================================

    @staticmethod
    def hop_to_dict(
        hop: ReceivedHop,
    ) -> dict[str, Any]:
        """
        Convert ReceivedHop into JSON-compatible data.
        """

        return {
            "hop_number": hop.hop_number,

            "raw_header": hop.raw_header,

            "from_host": hop.from_host,
            "from_ip": hop.from_ip,

            "by_host": hop.by_host,
            "by_ip": hop.by_ip,

            "protocol": hop.protocol,

            "timestamp": hop.timestamp,

            "private_ips": hop.private_ips,
            "public_ips": hop.public_ips,

            "reliability": hop.reliability,
        }