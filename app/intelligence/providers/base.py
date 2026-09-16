from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ThreatIntelResult:
    """
    Standardized result returned by every threat-intelligence provider.
    """

    indicator: str
    indicator_type: str
    provider: str

    status: str = "unknown"
    reputation: str = "unknown"
    confidence: float = 0.0

    data: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)

    errors: list[str] = field(default_factory=list)

    # True only for simulated/mock providers.
    is_mock: bool = False


class ThreatIntelProvider(ABC):
    """
    Base interface for all CIPHER-X threat-intelligence providers.
    """

    name: str = "unknown"

    supported_indicator_types: set[str] = set()

    def supports(self, indicator_type: str) -> bool:
        """
        Check whether this provider supports a particular IOC type.
        """

        return indicator_type.lower().strip() in self.supported_indicator_types

    @abstractmethod
    def lookup(
        self,
        indicator: str,
        indicator_type: str,
    ) -> ThreatIntelResult:
        """
        Perform an intelligence lookup.
        """

        raise NotImplementedError