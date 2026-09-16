from typing import Any

from pydantic import BaseModel, Field


class IntelligenceLookupRequest(BaseModel):
    indicator: str = Field(
        ...,
        min_length=1,
        max_length=2048,
    )

    indicator_type: str = Field(
        ...,
        min_length=2,
        max_length=20,
    )


class IntelligenceLookupResponse(BaseModel):
    indicator: str
    indicator_type: str
    status: str
    provider_count: int
    results: list[dict[str, Any]]
    errors: list[str]