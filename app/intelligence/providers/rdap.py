from datetime import datetime
from typing import Any

import httpx

from app.core.config import get_settings
from app.intelligence.providers.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
)


class RDAPProvider(ThreatIntelProvider):
    """
    RDAP domain intelligence provider.

    RDAP is used to retrieve structured registration information
    about a domain.

    This provider does NOT determine whether a domain is malicious.
    It only provides registration evidence.
    """

    name = "rdap"

    supported_indicator_types = {
        "domain",
    }

    BASE_URL = "https://rdap.org/domain"

    def lookup(
        self,
        indicator: str,
        indicator_type: str,
    ) -> ThreatIntelResult:

        indicator = indicator.strip().lower()
        indicator_type = indicator_type.lower().strip()

        settings = get_settings()

        # ---------------------------------------------------------
        # Provider support
        # ---------------------------------------------------------

        if not self.supports(indicator_type):
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                status="unsupported",
                reputation="unknown",
                confidence=0.0,
                errors=[
                    f"RDAP does not support "
                    f"{indicator_type} indicators."
                ],
            )

        # ---------------------------------------------------------
        # Validate domain
        # ---------------------------------------------------------

        if not indicator:
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="domain",
                provider=self.name,
                status="invalid",
                reputation="unknown",
                confidence=0.0,
                errors=[
                    "Domain cannot be empty."
                ],
            )

        url = f"{self.BASE_URL}/{indicator}"

        # ---------------------------------------------------------
        # RDAP request
        # ---------------------------------------------------------

        try:

            response = httpx.get(
                url,
                timeout=settings.threat_intel_timeout_seconds,
                headers={
                    "Accept": "application/rdap+json",
                },
                follow_redirects=True,
            )

            response.raise_for_status()

            payload: dict[str, Any] = response.json()

            # -----------------------------------------------------
            # Extract basic registration information
            # -----------------------------------------------------

            events = payload.get("events", [])

            registration_event = self._find_event(
                events,
                "registration",
            )

            last_changed_event = self._find_event(
                events,
                "last changed",
            )

            expiration_event = self._find_event(
                events,
                "expiration",
            )

            registration_date = (
                registration_event.get("eventDate")
                if registration_event
                else None
            )

            last_changed_date = (
                last_changed_event.get("eventDate")
                if last_changed_event
                else None
            )

            expiration_date = (
                expiration_event.get("eventDate")
                if expiration_event
                else None
            )

            # -----------------------------------------------------
            # Registrar
            # -----------------------------------------------------

            registrar = self._extract_registrar(
                payload
            )

            # -----------------------------------------------------
            # Nameservers
            # -----------------------------------------------------

            nameservers = self._extract_nameservers(
                payload
            )

            # -----------------------------------------------------
            # Entity / registration handle
            # -----------------------------------------------------

            domain_handle = payload.get(
                "handle"
            )

            # -----------------------------------------------------
            # Return result
            # -----------------------------------------------------

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="domain",
                provider=self.name,
                status="success",
                reputation="unknown",

                # This represents confidence in successful
                # structured registration retrieval,
                # NOT maliciousness.
                confidence=0.90,

                data={
                    "domain": payload.get(
                        "ldhName"
                    ),
                    "handle": domain_handle,
                    "registrar": registrar,
                    "registration_date": registration_date,
                    "last_changed_date": last_changed_date,
                    "expiration_date": expiration_date,
                    "nameservers": nameservers,
                    "status": payload.get(
                        "status",
                        [],
                    ),
                },

                evidence=[
                    {
                        "type": "domain_registration",
                        "source": "RDAP",
                        "value": registration_date,
                    },
                    {
                        "type": "registrar",
                        "source": "RDAP",
                        "value": registrar,
                    },
                    {
                        "type": "nameservers",
                        "source": "RDAP",
                        "value": nameservers,
                    },
                ],
            )

        # ---------------------------------------------------------
        # HTTP error
        # ---------------------------------------------------------

        except httpx.HTTPStatusError as exc:

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="domain",
                provider=self.name,
                status="error",
                reputation="unknown",
                confidence=0.0,
                errors=[
                    f"RDAP HTTP error: "
                    f"{exc.response.status_code}"
                ],
            )

        # ---------------------------------------------------------
        # Network error
        # ---------------------------------------------------------

        except httpx.RequestError as exc:

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="domain",
                provider=self.name,
                status="error",
                reputation="unknown",
                confidence=0.0,
                errors=[
                    f"RDAP request error: {str(exc)}"
                ],
            )

        # ---------------------------------------------------------
        # Invalid JSON
        # ---------------------------------------------------------

        except ValueError:

            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="domain",
                provider=self.name,
                status="error",
                reputation="unknown",
                confidence=0.0,
                errors=[
                    "RDAP returned invalid JSON."
                ],
            )

    # =============================================================
    # Helpers
    # =============================================================

    @staticmethod
    def _find_event(
        events: list[dict[str, Any]],
        action: str,
    ) -> dict[str, Any]:

        for event in events:

            if event.get("eventAction") == action:
                return event

        return {}

    @staticmethod
    def _extract_registrar(
        payload: dict[str, Any],
    ) -> str | None:

        entities = payload.get(
            "entities",
            [],
        )

        for entity in entities:

            roles = entity.get(
                "roles",
                [],
            )

            if "registrar" not in roles:
                continue

            vcard_array = entity.get(
                "vcardArray",
                [],
            )

            if len(vcard_array) < 2:
                continue

            properties = vcard_array[1]

            for prop in properties:

                if (
                    len(prop) >= 4
                    and prop[0] == "fn"
                ):
                    return prop[3]

        return None

    @staticmethod
    def _extract_nameservers(
        payload: dict[str, Any],
    ) -> list[str]:

        nameservers = []

        for nameserver in payload.get(
            "nameservers",
            [],
        ):

            ldh_name = nameserver.get(
                "ldhName"
            )

            if ldh_name:
                nameservers.append(
                    ldh_name.lower()
                )

        return nameservers