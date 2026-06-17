"""Email authentication verification (SPF, DKIM, DMARC)."""

import re
from backend.models.schemas import Finding, EmailData


def analyze_auth(email_data: EmailData) -> list[Finding]:
    """
    Analyze email authentication headers (SPF, DKIM, DMARC).
    
    This analyzes the Authentication-Results header present in the email,
    which is typically added by the receiving mail server. We don't perform
    live DNS lookups here — instead we parse what the receiving MTA reported.
    """
    findings: list[Finding] = []

    auth_results = email_data.authentication_results
    headers = email_data.headers

    # Also check for individual auth headers
    spf_result = _extract_auth_result(auth_results, "spf") or headers.get("received-spf", "")
    dkim_result = _extract_auth_result(auth_results, "dkim") or ""
    dmarc_result = _extract_auth_result(auth_results, "dmarc") or ""

    has_any_auth = bool(auth_results or spf_result or email_data.dkim_signature)

    # SPF Check
    _check_spf(spf_result, findings)

    # DKIM Check
    _check_dkim(dkim_result, email_data.dkim_signature, findings)

    # DMARC Check
    _check_dmarc(dmarc_result, findings)

    # Overall auth assessment
    if not has_any_auth:
        findings.append(Finding(
            category="auth",
            severity="medium",
            title="No Authentication Headers",
            description=(
                "This email has no SPF, DKIM, or DMARC authentication results. "
                "While this can occur with forwarded or locally-sent emails, "
                "most legitimate mail servers add authentication headers."
            ),
            evidence=None,
        ))

    return findings


def _extract_auth_result(auth_header: str, mechanism: str) -> str:
    """Extract a specific mechanism result from Authentication-Results header."""
    if not auth_header:
        return ""
    
    # Pattern: mechanism=result
    pattern = rf"{mechanism}\s*=\s*(\S+)"
    match = re.search(pattern, auth_header, re.IGNORECASE)
    if match:
        return match.group(0)
    
    # Also try the longer form: mechanism result
    pattern2 = rf"{mechanism}\s+(?:result\s*=\s*)?(\w+)"
    match2 = re.search(pattern2, auth_header, re.IGNORECASE)
    if match2:
        return match2.group(0)
    
    return ""


def _check_spf(spf_result: str, findings: list[Finding]):
    """Analyze SPF result."""
    if not spf_result:
        findings.append(Finding(
            category="auth",
            severity="low",
            title="SPF Not Verified",
            description=(
                "No SPF (Sender Policy Framework) result was found. SPF helps "
                "verify that the sending server is authorized by the domain owner."
            ),
            evidence=None,
        ))
        return

    spf_lower = spf_result.lower()

    if "pass" in spf_lower:
        findings.append(Finding(
            category="auth",
            severity="info",
            title="SPF Passed",
            description="The SPF check passed — the sending server is authorized by the domain.",
            evidence=spf_result,
        ))
    elif "fail" in spf_lower and "softfail" not in spf_lower:
        findings.append(Finding(
            category="auth",
            severity="high",
            title="SPF Failed",
            description=(
                "The SPF check failed — the sending server is NOT authorized "
                "to send email on behalf of this domain. This is a strong "
                "indicator of email spoofing."
            ),
            evidence=spf_result,
        ))
    elif "softfail" in spf_lower:
        findings.append(Finding(
            category="auth",
            severity="medium",
            title="SPF Soft Fail",
            description=(
                "The SPF check resulted in a soft fail — the sending server "
                "is not explicitly authorized but the domain owner has not "
                "configured strict rejection."
            ),
            evidence=spf_result,
        ))
    elif "neutral" in spf_lower or "none" in spf_lower:
        findings.append(Finding(
            category="auth",
            severity="low",
            title="SPF Neutral/None",
            description=(
                "The SPF result is neutral or none — the domain does not have "
                "an SPF policy, so the sending server's authorization cannot be verified."
            ),
            evidence=spf_result,
        ))


def _check_dkim(dkim_result: str, dkim_signature: str, findings: list[Finding]):
    """Analyze DKIM result."""
    has_signature = bool(dkim_signature)

    if not dkim_result and not has_signature:
        findings.append(Finding(
            category="auth",
            severity="low",
            title="DKIM Not Present",
            description=(
                "No DKIM (DomainKeys Identified Mail) signature or result found. "
                "DKIM provides cryptographic verification that the email content "
                "has not been tampered with."
            ),
            evidence=None,
        ))
        return

    if dkim_result:
        dkim_lower = dkim_result.lower()
        if "pass" in dkim_lower:
            findings.append(Finding(
                category="auth",
                severity="info",
                title="DKIM Passed",
                description="The DKIM signature verification passed — email integrity is confirmed.",
                evidence=dkim_result,
            ))
        elif "fail" in dkim_lower:
            findings.append(Finding(
                category="auth",
                severity="high",
                title="DKIM Failed",
                description=(
                    "The DKIM signature verification failed — the email content "
                    "may have been modified in transit, or the signature is forged."
                ),
                evidence=dkim_result,
            ))
    elif has_signature:
        findings.append(Finding(
            category="auth",
            severity="low",
            title="DKIM Signature Present (Unverified)",
            description=(
                "A DKIM signature is present but no verification result was found "
                "in the authentication headers."
            ),
            evidence=dkim_signature[:100],
        ))


def _check_dmarc(dmarc_result: str, findings: list[Finding]):
    """Analyze DMARC result."""
    if not dmarc_result:
        findings.append(Finding(
            category="auth",
            severity="low",
            title="DMARC Not Verified",
            description=(
                "No DMARC (Domain-based Message Authentication, Reporting and "
                "Conformance) result found. DMARC ties SPF and DKIM together "
                "to prevent domain spoofing."
            ),
            evidence=None,
        ))
        return

    dmarc_lower = dmarc_result.lower()

    if "pass" in dmarc_lower:
        findings.append(Finding(
            category="auth",
            severity="info",
            title="DMARC Passed",
            description="The DMARC check passed — the domain's authentication policy is satisfied.",
            evidence=dmarc_result,
        ))
    elif "fail" in dmarc_lower:
        findings.append(Finding(
            category="auth",
            severity="high",
            title="DMARC Failed",
            description=(
                "The DMARC check failed — this email does not comply with the "
                "domain's authentication policy. This is a strong indicator "
                "of spoofing or phishing."
            ),
            evidence=dmarc_result,
        ))
    elif "none" in dmarc_lower:
        findings.append(Finding(
            category="auth",
            severity="low",
            title="DMARC Policy: None",
            description=(
                "The domain has a DMARC policy set to 'none', meaning it is "
                "monitoring but not enforcing email authentication."
            ),
            evidence=dmarc_result,
        ))
