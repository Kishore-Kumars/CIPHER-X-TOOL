from dataclasses import dataclass
import re


@dataclass
class EmailFeatures:
    """
    Structured features extracted from an email.

    These features are deliberately interpretable.
    """

    subject_length: int = 0
    body_length: int = 0

    url_count: int = 0
    attachment_count: int = 0

    email_count: int = 0

    has_reply_to: bool = False
    reply_to_mismatch: bool = False

    has_return_path: bool = False

    has_urgent_language: bool = False
    has_financial_language: bool = False
    has_credential_language: bool = False

    has_suspicious_url: bool = False

    spf_fail: bool = False
    dkim_fail: bool = False
    dmarc_fail: bool = False

    sender_domain_mismatch: bool = False

    def to_dict(self) -> dict:
        """
        Convert features to a JSON-compatible dictionary.
        """

        return {
            "subject_length": self.subject_length,
            "body_length": self.body_length,
            "url_count": self.url_count,
            "attachment_count": self.attachment_count,
            "email_count": self.email_count,
            "has_reply_to": self.has_reply_to,
            "reply_to_mismatch": self.reply_to_mismatch,
            "has_return_path": self.has_return_path,
            "has_urgent_language": self.has_urgent_language,
            "has_financial_language": self.has_financial_language,
            "has_credential_language": self.has_credential_language,
            "has_suspicious_url": self.has_suspicious_url,
            "spf_fail": self.spf_fail,
            "dkim_fail": self.dkim_fail,
            "dmarc_fail": self.dmarc_fail,
            "sender_domain_mismatch": self.sender_domain_mismatch,
        }


URGENT_TERMS = {
    "urgent",
    "immediately",
    "asap",
    "immediate",
    "action required",
    "critical",
    "right away",
}

FINANCIAL_TERMS = {
    "payment",
    "invoice",
    "transfer",
    "bank",
    "wire",
    "account",
    "money",
    "funds",
    "transaction",
}

CREDENTIAL_TERMS = {
    "password",
    "login",
    "verify your account",
    "verification",
    "credentials",
    "sign in",
    "authenticate",
}


def _contains_any(
    text: str,
    terms: set[str],
) -> bool:

    text = text.lower()

    return any(
        term in text
        for term in terms
    )


def _extract_urls(text: str) -> list[str]:

    pattern = r"https?://[^\s<>\"]+"

    return re.findall(
        pattern,
        text,
        flags=re.IGNORECASE,
    )


def _extract_emails(text: str) -> list[str]:

    pattern = (
        r"[A-Za-z0-9._%+-]+"
        r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    )

    return re.findall(
        pattern,
        text,
    )


def extract_email_features(
    *,
    subject: str = "",
    body: str = "",
    from_address: str = "",
    reply_to: str = "",
    return_path: str = "",
    attachment_count: int = 0,
    spf_result: str = "",
    dkim_result: str = "",
    dmarc_result: str = "",
) -> EmailFeatures:

    subject = subject or ""
    body = body or ""

    combined_text = (
        f"{subject}\n{body}"
    )

    urls = _extract_urls(
        combined_text
    )

    emails = _extract_emails(
        combined_text
    )

    # -------------------------------------------------------------
    # Reply-To mismatch
    # -------------------------------------------------------------

    reply_to_mismatch = False

    if from_address and reply_to:

        from_domain = (
            from_address
            .split("@")[-1]
            .lower()
            .strip()
        )

        reply_domain = (
            reply_to
            .split("@")[-1]
            .lower()
            .strip()
        )

        if (
            from_domain
            and reply_domain
            and from_domain != reply_domain
        ):
            reply_to_mismatch = True

    # -------------------------------------------------------------
    # Authentication
    # -------------------------------------------------------------

    spf_fail = (
        spf_result.lower()
        in {
            "fail",
            "softfail",
        }
    )

    dkim_fail = (
        dkim_result.lower()
        in {
            "fail",
        }
    )

    dmarc_fail = (
        dmarc_result.lower()
        in {
            "fail",
        }
    )

    # -------------------------------------------------------------
    # Build features
    # -------------------------------------------------------------

    return EmailFeatures(
        subject_length=len(subject),
        body_length=len(body),

        url_count=len(urls),
        attachment_count=attachment_count,

        email_count=len(emails),

        has_reply_to=bool(reply_to),

        reply_to_mismatch=reply_to_mismatch,

        has_return_path=bool(return_path),

        has_urgent_language=_contains_any(
            combined_text,
            URGENT_TERMS,
        ),

        has_financial_language=_contains_any(
            combined_text,
            FINANCIAL_TERMS,
        ),

        has_credential_language=_contains_any(
            combined_text,
            CREDENTIAL_TERMS,
        ),

        has_suspicious_url=any(
            _looks_suspicious_url(url)
            for url in urls
        ),

        spf_fail=spf_fail,
        dkim_fail=dkim_fail,
        dmarc_fail=dmarc_fail,

        sender_domain_mismatch=reply_to_mismatch,
    )


def _looks_suspicious_url(
    url: str,
) -> bool:

    lowered = url.lower()

    suspicious_patterns = [
        "login",
        "verify",
        "secure",
        "account",
        "password",
        "signin",
        "confirm",
    ]

    return any(
        pattern in lowered
        for pattern in suspicious_patterns
    )