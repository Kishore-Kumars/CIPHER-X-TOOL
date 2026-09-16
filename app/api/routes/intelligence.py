from fastapi import APIRouter, HTTPException

from app.schemas.intelligence import (
    IntelligenceLookupRequest,
    IntelligenceLookupResponse,
)

from app.intelligence.service import (
    create_default_threat_intelligence_service,
)


router = APIRouter(
    prefix="/intelligence",
    tags=["Threat Intelligence"],
)


threat_intelligence_service = (
    create_default_threat_intelligence_service()
)


@router.post(
    "/lookup",
    response_model=IntelligenceLookupResponse,
)
def lookup_indicator(
    request: IntelligenceLookupRequest,
):

    indicator = request.indicator.strip()

    indicator_type = (
        request.indicator_type
        .strip()
        .lower()
    )

    supported_types = {
        "ip",
        "domain",
        "url",
    }

    if indicator_type not in supported_types:

        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported indicator type. "
                "Supported types: ip, domain, url."
            ),
        )

    if not indicator:

        raise HTTPException(
            status_code=400,
            detail="Indicator cannot be empty.",
        )

    result = threat_intelligence_service.lookup(
        indicator=indicator,
        indicator_type=indicator_type,
    )

    return result