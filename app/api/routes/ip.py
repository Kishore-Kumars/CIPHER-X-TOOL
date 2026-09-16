from fastapi import APIRouter, HTTPException

from app.intelligence.ip_service import IPIntelligenceService


router = APIRouter(
    prefix="/ip",
    tags=["IP Intelligence"],
)


ip_intelligence_service = IPIntelligenceService()


@router.get("/{ip_address}")
def analyze_ip(ip_address: str):
    """
    Analyze and classify an IP address.
    """

    if not ip_address.strip():
        raise HTTPException(
            status_code=400,
            detail="IP address cannot be empty.",
        )

    return ip_intelligence_service.analyze(
        ip_address
    )