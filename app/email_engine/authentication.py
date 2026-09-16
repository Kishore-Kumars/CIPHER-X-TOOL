import re


AUTH_RESULT_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*"
    r"(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)


def _normalize_result(value: str) -> str:
    return value.strip().lower()


def parse_authentication_results(
    authentication_headers: list[str],
) -> dict:
    """
    Parse Authentication-Results headers.

    Reports authentication results already present
    in the supplied email headers.
    """

    result = {
        "spf": {
            "status": "not_available",
            "results": [],
        },
        "dkim": {
            "status": "not_available",
            "results": [],
        },
        "dmarc": {
            "status": "not_available",
            "results": [],
        },
        "raw_headers": authentication_headers,
        "evidence_available": bool(authentication_headers),
        "validation_mode": "header_reported_results",
    }

    if not authentication_headers:
        return result

    for header in authentication_headers:

        matches = AUTH_RESULT_PATTERN.findall(header)

        for method, value in matches:

            method = method.lower()
            value = _normalize_result(value)

            result[method]["results"].append(value)

    for method in ("spf", "dkim", "dmarc"):

        values = result[method]["results"]

        if values:
            result[method]["status"] = values[-1]

    return result


def analyze_authentication(
    authentication_headers: list[str],
) -> dict:
    """
    Convert authentication results into forensic signals.
    """

    parsed = parse_authentication_results(
        authentication_headers
    )

    findings = []
    warnings = []

    for method in ("spf", "dkim", "dmarc"):

        status = parsed[method]["status"]

        if status == "fail":

            findings.append({
                "type": f"{method}_failure",
                "severity": "high",
                "message": (
                    f"{method.upper()} authentication "
                    "reported failure."
                ),
            })

        elif status in (
            "softfail",
            "permerror",
            "temperror",
        ):

            findings.append({
                "type": f"{method}_{status}",
                "severity": "medium",
                "message": (
                    f"{method.upper()} authentication "
                    f"reported {status}."
                ),
            })

        elif status == "pass":

            findings.append({
                "type": f"{method}_pass",
                "severity": "info",
                "message": (
                    f"{method.upper()} authentication "
                    "reported pass."
                ),
            })

        elif status == "none":

            warnings.append(
                f"{method.upper()} authentication "
                "reported no applicable result."
            )

        elif status == "not_available":

            warnings.append(
                f"{method.upper()} authentication result "
                "was not available in the supplied "
                "Authentication-Results headers."
            )

    if (
        parsed["spf"]["status"] == "pass"
        and parsed["dkim"]["status"] == "pass"
        and parsed["dmarc"]["status"] == "fail"
    ):

        findings.append({
            "type": "authentication_conflict",
            "severity": "high",
            "message": (
                "SPF and DKIM passed, but DMARC reported "
                "failure. Further investigation of domain "
                "alignment and message identity is recommended."
            ),
        })

    return {
        "spf": parsed["spf"],
        "dkim": parsed["dkim"],
        "dmarc": parsed["dmarc"],
        "findings": findings,
        "warnings": warnings,
        "evidence_available": parsed[
            "evidence_available"
        ],
        "validation_mode": parsed[
            "validation_mode"
        ],
    }