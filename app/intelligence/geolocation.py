"""
CIPHER-X Geolocation Intelligence

This module provides a provider-independent geolocation layer.

Important:
Geolocation describes the observed network infrastructure
associated with an IP address. It does NOT establish the
physical location or identity of an attacker.
"""

from dataclasses import dataclass
from typing import Any


@dataclass
class GeoLocationResult:
    """
    Normalized geolocation result for an IP address.
    """

    ip: str

    status: str

    country: str | None
    country_code: str | None

    region: str | None
    city: str | None

    latitude: float | None
    longitude: float | None

    timezone: str | None

    asn: str | None
    organization: str | None

    source: str | None
    confidence: float

    message: str | None


class GeoLocation:
    """
    Provider-independent geolocation engine.

    This class does not directly call external APIs.

    External providers such as IPinfo can be connected later
    through the provider layer.
    """

    @staticmethod
    def unavailable(
        ip: str,
        message: str = "No geolocation provider configured.",
    ) -> GeoLocationResult:
        """
        Return an explicit unavailable result.

        We never invent geographic information.
        """

        return GeoLocationResult(
            ip=ip.strip(),
            status="unavailable",

            country=None,
            country_code=None,

            region=None,
            city=None,

            latitude=None,
            longitude=None,

            timezone=None,

            asn=None,
            organization=None,

            source=None,
            confidence=0.0,

            message=message,
        )

    @staticmethod
    def normalize(
        ip: str,
        data: dict[str, Any],
        source: str,
        confidence: float = 0.0,
    ) -> GeoLocationResult:
        """
        Normalize provider-specific geolocation data.

        Different providers may use different field names.
        This method converts them into the CIPHER-X format.
        """

        return GeoLocationResult(
            ip=ip.strip(),

            status="success",

            country=data.get("country"),
            country_code=data.get(
                "country_code",
                data.get("countryCode"),
            ),

            region=data.get("region"),

            city=data.get("city"),

            latitude=GeoLocation._to_float(
                data.get("latitude")
            ),

            longitude=GeoLocation._to_float(
                data.get("longitude")
            ),

            timezone=data.get("timezone"),

            asn=data.get("asn"),

            organization=data.get(
                "organization",
                data.get(
                    "org",
                    data.get("as_name"),
                ),
            ),

            source=source,

            confidence=confidence,

            message=None,
        )

    @staticmethod
    def _to_float(
        value: Any,
    ) -> float | None:
        """
        Safely convert a value to float.
        """

        if value is None:
            return None

        try:
            return float(value)

        except (TypeError, ValueError):
            return None

    @staticmethod
    def to_dict(
        result: GeoLocationResult,
    ) -> dict[str, Any]:
        """
        Convert GeoLocationResult into a JSON-compatible dictionary.
        """

        return {
            "ip": result.ip,

            "status": result.status,

            "country": result.country,
            "country_code": result.country_code,

            "region": result.region,
            "city": result.city,

            "latitude": result.latitude,
            "longitude": result.longitude,

            "timezone": result.timezone,

            "asn": result.asn,
            "organization": result.organization,

            "source": result.source,
            "confidence": result.confidence,

            "message": result.message,
        }

    @staticmethod
    def lookup(
        ip: str,
        provider: Any | None = None,
    ) -> dict[str, Any]:
        """
        Perform geolocation lookup.

        If no provider is configured, return an explicit
        unavailable result.
        """

        ip = ip.strip()

        if not ip:
            result = GeoLocation.unavailable(
                ip=ip,
                message="IP address cannot be empty.",
            )

            return GeoLocation.to_dict(result)

        if provider is None:
            result = GeoLocation.unavailable(
                ip=ip,
            )

            return GeoLocation.to_dict(result)

        try:

            provider_result = provider.lookup(ip)

            if not isinstance(
                provider_result,
                dict,
            ):

                result = GeoLocation.unavailable(
                    ip=ip,
                    message=(
                        "Geolocation provider returned "
                        "invalid data."
                    ),
                )

                return GeoLocation.to_dict(result)

            result = GeoLocation.normalize(
                ip=ip,
                data=provider_result,
                source=provider_result.get(
                    "source",
                    provider.__class__.__name__,
                ),
                confidence=GeoLocation._to_float(
                    provider_result.get(
                        "confidence",
                        0.0,
                    )
                ) or 0.0,
            )

            return GeoLocation.to_dict(result)

        except Exception as exc:

            result = GeoLocation.unavailable(
                ip=ip,
                message="Geolocation provider error.",
            )

            output = GeoLocation.to_dict(result)

            output["error"] = str(exc)

            return output