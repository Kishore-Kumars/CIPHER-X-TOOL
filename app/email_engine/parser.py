from email import policy
from email.message import Message
from email.parser import BytesParser


def parse_email(email_bytes: bytes) -> Message:
    """
    Parse raw .eml bytes into an email Message.

    The parser uses Python's standard email package with
    policy.default so headers and MIME parts are handled
    consistently.
    """

    if not isinstance(email_bytes, bytes):
        raise TypeError(
            "email_bytes must be bytes."
        )

    if not email_bytes:
        raise ValueError(
            "email_bytes cannot be empty."
        )

    return BytesParser(
        policy=policy.default
    ).parsebytes(email_bytes)