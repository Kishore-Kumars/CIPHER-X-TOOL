import re
from email.message import Message
from email.utils import parseaddr


EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def _clean_header(value: str | None) -> str | None:
    """
    Normalize a header value.
    """
    if value is None:
        return None

    value = str(value).strip()

    return value if value else None


def _extract_email_address(value: str | None) -> str | None:
    """
    Extract an email address from a header.

    Example:
        CEO <ceo@example.com>
        -> ceo@example.com
    """

    value = _clean_header(value)

    if not value:
        return None

    _, address = parseaddr(value)

    address = address.strip().lower()

    if EMAIL_PATTERN.match(address):
        return address

    return None


def _extract_domain(email_address: str | None) -> str | None:
    """
    Extract domain from an email address.
    """

    if not email_address or "@" not in email_address:
        return None

    return email_address.rsplit("@", 1)[1].lower()


def extract_headers(message: Message) -> dict:
    """
    Extract important forensic headers from an email.
    """

    from_header = _clean_header(message.get("From"))
    to_header = _clean_header(message.get("To"))
    cc_header = _clean_header(message.get("Cc"))
    bcc_header = _clean_header(message.get("Bcc"))
    subject = _clean_header(message.get("Subject"))
    date = _clean_header(message.get("Date"))
    message_id = _clean_header(message.get("Message-ID"))
    reply_to = _clean_header(message.get("Reply-To"))
    return_path = _clean_header(message.get("Return-Path"))

    received_headers = [
        value.strip()
        for value in message.get_all("Received", [])
        if value
    ]

    authentication_results = [
        value.strip()
        for value in message.get_all(
            "Authentication-Results",
            []
        )
        if value
    ]

    from_email = _extract_email_address(from_header)
    reply_to_email = _extract_email_address(reply_to)

    return {
        "from": from_header,
        "from_email": from_email,
        "from_domain": _extract_domain(from_email),

        "to": to_header,
        "cc": cc_header,
        "bcc": bcc_header,

        "subject": subject,
        "date": date,
        "message_id": message_id,

        "reply_to": reply_to,
        "reply_to_email": reply_to_email,
        "reply_to_domain": _extract_domain(reply_to_email),

        "return_path": return_path,
        "return_path_email": _extract_email_address(return_path),
        "return_path_domain": _extract_domain(
            _extract_email_address(return_path)
        ),

        "received": received_headers,
        "authentication_results": authentication_results,

        "received_header_count": len(received_headers),
        "authentication_results_count": len(
            authentication_results
        ),
    }


def analyze_header_relationships(headers: dict) -> dict:
    """
    Analyze relationships between important email identities.

    Findings are signals, not automatic verdicts.
    """

    findings = []

    from_domain = headers.get("from_domain")
    reply_to_domain = headers.get("reply_to_domain")
    return_path_domain = headers.get("return_path_domain")

    # --------------------------------------------------
    # Reply-To relationship
    # --------------------------------------------------

    reply_to_mismatch = False

    if from_domain and reply_to_domain:
        reply_to_mismatch = (
            from_domain != reply_to_domain
        )

        if reply_to_mismatch:
            findings.append({
                "type": "reply_to_mismatch",
                "severity": "medium",
                "title": "Reply-To domain mismatch",
                "description": (
                    "The Reply-To domain differs from "
                    "the visible sender domain."
                ),
                "evidence": {
                    "from_domain": from_domain,
                    "reply_to_domain": reply_to_domain,
                },
            })

    # --------------------------------------------------
    # Return-Path relationship
    # --------------------------------------------------

    return_path_mismatch = False

    if from_domain and return_path_domain:
        return_path_mismatch = (
            from_domain != return_path_domain
        )

        if return_path_mismatch:
            findings.append({
                "type": "return_path_mismatch",
                "severity": "medium",
                "title": "Return-Path domain mismatch",
                "description": (
                    "The Return-Path domain differs from "
                    "the visible sender domain."
                ),
                "evidence": {
                    "from_domain": from_domain,
                    "return_path_domain": return_path_domain,
                },
            })

    # --------------------------------------------------
    # Missing Reply-To
    # --------------------------------------------------

    if not reply_to_domain:
        findings.append({
            "type": "missing_reply_to",
            "severity": "info",
            "title": "Reply-To header not present",
            "description": (
                "No Reply-To header was found."
            ),
        })

    # --------------------------------------------------
    # Missing Return-Path
    # --------------------------------------------------

    if not return_path_domain:
        findings.append({
            "type": "missing_return_path",
            "severity": "info",
            "title": "Return-Path not available",
            "description": (
                "No usable Return-Path address was found "
                "in the supplied evidence."
            ),
        })

    # --------------------------------------------------
    # Message-ID
    # --------------------------------------------------

    if not headers.get("message_id"):
        findings.append({
            "type": "missing_message_id",
            "severity": "low",
            "title": "Message-ID missing",
            "description": (
                "The email does not contain a Message-ID "
                "header."
            ),
        })

    # --------------------------------------------------
    # Received headers
    # --------------------------------------------------

    received_count = headers.get(
        "received_header_count",
        0,
    )

    if received_count == 0:
        findings.append({
            "type": "missing_received_headers",
            "severity": "high",
            "title": "No Received headers",
            "description": (
                "No SMTP Received headers were available. "
                "Reliable relay-path reconstruction may "
                "therefore be impossible."
            ),
        })

    # --------------------------------------------------
    # Authentication results
    # --------------------------------------------------

    auth_count = headers.get(
        "authentication_results_count",
        0,
    )

    if auth_count == 0:
        findings.append({
            "type": "missing_authentication_results",
            "severity": "medium",
            "title": "Authentication results unavailable",
            "description": (
                "No Authentication-Results header was "
                "found in the supplied evidence."
            ),
        })

    return {
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,

        "received_header_count": received_count,
        "authentication_results_count": auth_count,

        "finding_count": len(findings),
        "findings": findings,
    }