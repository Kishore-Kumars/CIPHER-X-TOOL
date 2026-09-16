from pathlib import Path
from hashlib import sha256
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.email_engine.parser import parse_email

from app.email_engine.headers import (
    extract_headers,
    analyze_header_relationships,
)

from app.email_engine.received_chain import (
    reconstruct_received_chain,
)

from app.email_engine.authentication import (
    analyze_authentication,
)

from app.email_engine.ioc import (
    build_searchable_email_text,
    extract_iocs,
)

from app.intelligence.service import (
    create_default_threat_intelligence_service,
)

from app.ai.features import extract_email_features
from app.ai.detector import ThreatDetector
from app.ai.explainability import explain_detection


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/email",
    tags=["Email Evidence"],
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[3]

EVIDENCE_DIR = (
    BASE_DIR
    / "data"
    / "evidence"
)

EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# CONFIGURATION
# ============================================================

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB


# ============================================================
# THREAT INTELLIGENCE SERVICE
# ============================================================

threat_intelligence_service = (
    create_default_threat_intelligence_service()
)

# ============================================================
# AI THREAT DETECTOR
# ============================================================

threat_detector = ThreatDetector()


# ============================================================
# AI AUTHENTICATION RESULT HELPER
# ============================================================

def _get_auth_result(authentication: dict, name: str) -> str:
    """
    Safely extract SPF/DKIM/DMARC status from the
    authentication analysis structure.
    """
    value = authentication.get(name)

    if isinstance(value, str):
        return value.lower().strip()

    if isinstance(value, dict):
        status = value.get("status")

        if isinstance(status, str):
            return status.lower().strip()

        results = value.get("results", [])

        if isinstance(results, list) and results:
            first = results[0]

            if isinstance(first, str):
                return first.lower().strip()

    return ""


# ============================================================
# ROUTE
# ============================================================

@router.post("/upload")
async def upload_email(
    file: UploadFile = File(...)
):
    """
    Upload and perform forensic analysis
    on an .eml email.

    Current pipeline:

        Upload
          ↓
        Validation
          ↓
        SHA-256
          ↓
        Evidence Preservation
          ↓
        MIME Parsing
          ↓
        Header Extraction
          ↓
        Header Relationship Analysis
          ↓
        Received-Chain Reconstruction
          ↓
        SPF / DKIM / DMARC Analysis
          ↓
        IOC Extraction
          ↓
        Threat Intelligence Enrichment
          ↓
        AI Threat Detection
          ↓
        Explainable AI
          ↓
        Forensic Response
    """

    # ========================================================
    # 1. VALIDATE FILENAME
    # ========================================================

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Filename is required.",
        )

    original_filename = file.filename

    extension = Path(
        original_filename
    ).suffix.lower()

    if extension != ".eml":
        raise HTTPException(
            status_code=400,
            detail=(
                "Only .eml files are currently supported."
            ),
        )

    # ========================================================
    # 2. READ EMAIL EVIDENCE
    # ========================================================

    try:
        content = await file.read()

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unable to read email file: {exc}"
            ),
        )

    # ========================================================
    # 3. VALIDATE FILE
    # ========================================================

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Uploaded email file is empty.",
        )

    file_size = len(content)

    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=(
                "Email file exceeds the maximum "
                "allowed size of 25 MB."
            ),
        )

    # ========================================================
    # 4. CALCULATE SHA-256 EVIDENCE HASH
    # ========================================================

    evidence_hash = sha256(
        content
    ).hexdigest()

    # ========================================================
    # 5. GENERATE INVESTIGATION ID
    # ========================================================

    investigation_id = str(
        uuid4()
    )

    # ========================================================
    # 6. PRESERVE ORIGINAL EVIDENCE
    # ========================================================

    evidence_filename = (
        f"{investigation_id}.eml"
    )

    evidence_path = (
        EVIDENCE_DIR
        / evidence_filename
    )

    try:
        evidence_path.write_bytes(
            content
        )

    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Unable to preserve evidence: {exc}"
            ),
        )

    # ========================================================
    # 7. PARSE EMAIL
    # ========================================================

    try:
        message = parse_email(
            content
        )

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unable to parse email evidence: {exc}"
            ),
        )

    # ========================================================
    # 8. EXTRACT EMAIL HEADERS
    # ========================================================

    try:
        headers = extract_headers(
            message
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Header extraction failed: {exc}"
            ),
        )

    # ========================================================
    # 9. ANALYZE HEADER RELATIONSHIPS
    # ========================================================

    try:
        header_analysis = (
            analyze_header_relationships(
                headers
            )
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Header relationship analysis failed: "
                f"{exc}"
            ),
        )

    # ========================================================
    # 10. RECONSTRUCT RECEIVED / SMTP CHAIN
    # ========================================================

    try:
        received_chain = (
            reconstruct_received_chain(
                headers.get(
                    "received",
                    []
                )
            )
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Received-chain reconstruction failed: "
                f"{exc}"
            ),
        )

    # ========================================================
    # 11. AUTHENTICATION ANALYSIS
    # ========================================================

    try:
        authentication_analysis = (
            analyze_authentication(
                headers.get(
                    "authentication_results",
                    []
                )
            )
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Authentication analysis failed: "
                f"{exc}"
            ),
        )

    # ========================================================
    # 12. IOC EXTRACTION
    # ========================================================

    try:

        # ----------------------------------------------------
        # Extract email body
        # ----------------------------------------------------

        body = message.get_body(
            preferencelist=(
                "plain",
                "html",
            )
        )

        if body is not None:
            body_content = body.get_content()

        else:
            body_content = ""

        # ----------------------------------------------------
        # Combine headers + body
        # ----------------------------------------------------

        searchable_text = (
            build_searchable_email_text(
                headers=headers,
                body=body_content,
            )
        )

        # ----------------------------------------------------
        # Extract IOCs
        # ----------------------------------------------------

        ioc_analysis = extract_iocs(
            searchable_text
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "IOC extraction failed: "
                f"{exc}"
            ),
        )

    # ========================================================
    # 13. THREAT INTELLIGENCE ENRICHMENT
    # ========================================================

    try:

        threat_intelligence = (
            threat_intelligence_service.enrich_iocs(
                ioc_analysis
            )
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Threat intelligence enrichment failed: "
                f"{exc}"
            ),
        )

    # ========================================================
    # 14. AI THREAT DETECTION + EXPLAINABLE AI
    # ========================================================

    try:
        subject = message.get("Subject", "")
        from_address = message.get("From", "")
        reply_to = message.get("Reply-To", "")
        return_path = message.get("Return-Path", "")

        # Authentication analysis returns nested SPF/DKIM/DMARC
        # objects, so extract their actual status values first.
        spf_result = _get_auth_result(
            authentication_analysis,
            "spf",
        )
        dkim_result = _get_auth_result(
            authentication_analysis,
            "dkim",
        )
        dmarc_result = _get_auth_result(
            authentication_analysis,
            "dmarc",
        )

        attachment_count = sum(
            1
            for part in message.walk()
            if part.get_filename()
        )

        ai_features = extract_email_features(
            subject=subject,
            body=body_content,
            from_address=from_address,
            reply_to=reply_to,
            return_path=return_path,
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            attachment_count=attachment_count,
        )

        detection_result = threat_detector.predict(
            ai_features
        )

        ai_detection = explain_detection(
            detection_result
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "AI threat detection failed: "
                f"{exc}"
            ),
        )

    # ========================================================
    # 15. RETURN FORENSIC RESULT
    # ========================================================

    return {

        "status": "accepted",

        # ----------------------------------------------------
        # INVESTIGATION
        # ----------------------------------------------------

        "investigation_id": (
            investigation_id
        ),

        # ----------------------------------------------------
        # EVIDENCE
        # ----------------------------------------------------

        "evidence": {

            "original_filename": (
                original_filename
            ),

            "stored_filename": (
                evidence_filename
            ),

            "file_size_bytes": (
                file_size
            ),

            "sha256": (
                evidence_hash
            ),

            "evidence_type": (
                "email/eml"
            ),

            "preserved": True,
        },

        # ----------------------------------------------------
        # EMAIL HEADERS
        # ----------------------------------------------------

        "headers": headers,

        # ----------------------------------------------------
        # HEADER FORENSICS
        # ----------------------------------------------------

        "header_analysis": (
            header_analysis
        ),

        # ----------------------------------------------------
        # SMTP / RECEIVED CHAIN
        # ----------------------------------------------------

        "received_chain": (
            received_chain
        ),

        # ----------------------------------------------------
        # SPF / DKIM / DMARC
        # ----------------------------------------------------

        "authentication": (
            authentication_analysis
        ),

        # ----------------------------------------------------
        # INDICATORS OF COMPROMISE
        # ----------------------------------------------------

        "iocs": (
            ioc_analysis
        ),

        # ----------------------------------------------------
        # THREAT INTELLIGENCE
        # ----------------------------------------------------

        "threat_intelligence": (
            threat_intelligence
        ),

        # ----------------------------------------------------
        # AI THREAT DETECTION
        # ----------------------------------------------------

        "ai_detection": (
            ai_detection
        ),

        # ----------------------------------------------------
        # CURRENT PIPELINE STATE
        # ----------------------------------------------------

        "analysis_status": {

            "evidence_ingestion": (
                "complete"
            ),

            "mime_parsing": (
                "complete"
            ),

            "header_forensics": (
                "complete"
            ),

            "received_chain": (
                "complete"
            ),

            "authentication_analysis": (
                "complete"
            ),

            "ioc_extraction": (
                "complete"
            ),

            "threat_intelligence": (
                "complete"
            ),

            "ai_detection": (
                "complete"
            ),

            "explainable_ai": (
                "complete"
            ),

            "evidence_fusion": (
                "pending"
            ),

            "forensic_reasoning_engine": (
                "pending"
            ),

            "threat_dna": (
                "pending"
            ),

            "campaign_correlation": (
                "pending"
            ),

            "forensic_report": (
                "pending"
            ),
        },

        # ----------------------------------------------------
        # NEXT PHASE
        # ----------------------------------------------------

        "next_phase": (
            "Evidence Fusion Engine"
        ),
    }