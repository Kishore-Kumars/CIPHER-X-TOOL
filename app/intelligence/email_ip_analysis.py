from typing import Any

from email.message import Message

from app.email_engine.headers import extract_headers
from app.email_engine.received_chain import (
    reconstruct_received_chain,
)

from app.intelligence.ip import IPIntelligence
from app.intelligence.geolocation import GeoLocation


class EmailIPAnalysisService:
    """
    Connects:

        Parsed Email
            ↓
        Header Extraction
            ↓
        Received Chain Reconstruction
            ↓
        IP Intelligence
            ↓
        Geolocation
    """

    def analyze(
        self,
        message: Message,
    ) -> dict[str, Any]:
        """
        Analyze IP-related forensic evidence from
        a parsed email message.
        """

        # --------------------------------------------------
        # 1. Extract email headers
        # --------------------------------------------------

        headers = extract_headers(message)

        # --------------------------------------------------
        # 2. Get Received headers
        # --------------------------------------------------

        received_headers = headers.get(
            "received",
            [],
        )

        # --------------------------------------------------
        # 3. Reconstruct Received chain
        # --------------------------------------------------

        chain_result = reconstruct_received_chain(
            received_headers
        )

        # --------------------------------------------------
        # 4. Get candidate public IPs
        # --------------------------------------------------

        public_ip_candidates = chain_result.get(
            "public_ip_candidates",
            [],
        )

        ip_results = []

        # --------------------------------------------------
        # 5. Analyze candidate IPs
        # --------------------------------------------------

        for candidate in public_ip_candidates:

            if isinstance(candidate, dict):

                ip = candidate.get("ip")

                received_position = candidate.get(
                    "received_position"
                )

            else:

                ip = candidate

                received_position = None

            if not ip:
                continue

            # ----------------------------------------------
            # IP classification
            # ----------------------------------------------

            classification = IPIntelligence.classify(
                ip
            )

            # ----------------------------------------------
            # Geolocation
            # ----------------------------------------------

            geolocation = GeoLocation.lookup(
                ip=ip
            )

            ip_results.append(
                {
                    "ip": ip,

                    "received_position": (
                        received_position
                    ),

                    "classification": {
                        "valid": classification.valid,
                        "version": classification.version,

                        "is_private": (
                            classification.is_private
                        ),

                        "is_global": (
                            classification.is_global
                        ),

                        "is_loopback": (
                            classification.is_loopback
                        ),

                        "is_reserved": (
                            classification.is_reserved
                        ),

                        "is_multicast": (
                            classification.is_multicast
                        ),

                        "is_unspecified": (
                            classification.is_unspecified
                        ),

                        "classification": (
                            classification.classification
                        ),
                    },

                    "geolocation": geolocation,
                }
            )

        # --------------------------------------------------
        # 6. Final forensic result
        # --------------------------------------------------

        return {
            "status": "analyzed",

            "headers": headers,

            "received_chain": chain_result,

            "ip_intelligence": ip_results,

            "candidate_ip_count": len(
                ip_results
            ),

            "earliest_public_ip": (
                chain_result.get(
                    "earliest_public_ip"
                )
            ),
        }