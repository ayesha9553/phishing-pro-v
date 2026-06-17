"""NLP-based email body content analysis for phishing detection."""

import re
from backend.models.schemas import Finding, EmailData


# Urgency/pressure patterns with weights
URGENCY_PATTERNS = [
    (r"\bact\s+now\b", 3, "Act now"),
    (r"\bimmediately\b", 2, "Immediately"),
    (r"\burgent(?:ly)?\b", 3, "Urgent"),
    (r"\bexpir(?:e[sd]?|ing|ation)\b", 2, "Expiration language"),
    (r"\bsuspend(?:ed)?\b", 3, "Account suspension threat"),
    (r"\bdeactivat(?:e[sd]?|ing|ion)\b", 3, "Deactivation threat"),
    (r"\bverif(?:y|ication)\s+(?:your|the)\b", 2, "Verification request"),
    (r"\bconfirm\s+(?:your|the)\b", 2, "Confirmation request"),
    (r"\bwithin\s+\d+\s*(?:hour|minute|day)s?\b", 3, "Time-limited deadline"),
    (r"\blast\s+(?:chance|warning|notice)\b", 3, "Last chance pressure"),
    (r"\bfailure\s+to\b", 2, "Failure to comply threat"),
    (r"\bunauthori[sz]ed\s+(?:access|activity|transaction)\b", 3, "Unauthorized activity claim"),
    (r"\bimmediate\s+action\b", 3, "Immediate action required"),
    (r"\baccount\s+(?:will\s+be\s+)?(?:locked|closed|terminated|restricted)\b", 3, "Account lock threat"),
    (r"\blimited\s+time\b", 2, "Limited time pressure"),
    (r"\bdo\s+not\s+ignore\b", 2, "Do not ignore"),
    (r"\brequired\s+(?:immediately|urgently|now)\b", 3, "Urgent requirement"),
]

# Threat/fear patterns
THREAT_PATTERNS = [
    (r"\blegal\s+action\b", 3, "Legal action threat"),
    (r"\blaw\s+enforcement\b", 3, "Law enforcement mention"),
    (r"\bpenalt(?:y|ies)\b", 2, "Penalty threat"),
    (r"\bconsequences?\b", 2, "Consequences warning"),
    (r"\bfraud(?:ulent)?\b", 2, "Fraud mention"),
    (r"\bsecurity\s+(?:breach|alert|warning|incident)\b", 2, "Security alert claim"),
    (r"\bcompromised?\b", 2, "Compromised account claim"),
    (r"\bunusual\s+(?:activity|sign.?in|login)\b", 3, "Unusual activity claim"),
    (r"\bsuspicious\s+(?:activity|login|transaction)\b", 3, "Suspicious activity claim"),
    (r"\byour\s+account\s+(?:has\s+been|was)\b", 2, "Account action claim"),
]

# Credential/sensitive data request patterns
CREDENTIAL_PATTERNS = [
    (r"\b(?:enter|provide|confirm|verify|update)\s+(?:your\s+)?password\b", 4, "Password request"),
    (r"\b(?:social\s+security|ssn|ss\s*#)\b", 4, "SSN request"),
    (r"\b(?:credit\s+card|debit\s+card|card\s+number)\b", 3, "Card number request"),
    (r"\b(?:bank\s+account|account\s+number|routing\s+number)\b", 3, "Bank info request"),
    (r"\b(?:pin|cvv|cvc|security\s+code)\b", 3, "Security code request"),
    (r"\b(?:date\s+of\s+birth|birth\s*date|dob)\b", 2, "DOB request"),
    (r"\b(?:mother'?s?\s+maiden|maiden\s+name)\b", 3, "Security question info"),
    (r"\blogin\s+credentials?\b", 3, "Login credentials request"),
    (r"\b(?:username|user\s+name)\s+and\s+password\b", 4, "Username and password request"),
    (r"\btax\s+(?:id|identification|return)\b", 2, "Tax info request"),
]

# Suspicious action request patterns
ACTION_PATTERNS = [
    (r"\bclick\s+(?:the\s+)?(?:link|button|here|below)\b", 2, "Click link instruction"),
    (r"\bdownload\s+(?:the\s+)?(?:attached|attachment|file)\b", 2, "Download instruction"),
    (r"\b(?:wire|transfer)\s+(?:money|funds|payment)\b", 4, "Wire transfer request"),
    (r"\bbuy\s+gift\s+cards?\b", 4, "Gift card purchase request"),
    (r"\b(?:bitcoin|btc|cryptocurrency|crypto)\s+(?:payment|transfer|wallet)\b", 4, "Crypto payment request"),
    (r"\breply\s+with\s+(?:your|the)\b", 2, "Reply with info request"),
    (r"\bopen\s+(?:the\s+)?attach(?:ment|ed)\b", 2, "Open attachment instruction"),
    (r"\benable\s+(?:macros?|content|editing)\b", 4, "Enable macros instruction"),
    (r"\bdisable\s+(?:security|antivirus|protection)\b", 4, "Disable security instruction"),
]

# Authority impersonation patterns
AUTHORITY_PATTERNS = [
    (r"\b(?:IT|I\.T\.)\s+(?:department|support|team|helpdesk|admin)\b", 2, "IT department claim"),
    (r"\b(?:CEO|CFO|CTO|COO|president|director|manager)\b", 2, "Executive impersonation"),
    (r"\b(?:human\s+resources|HR\s+department)\b", 2, "HR impersonation"),
    (r"\btechnical\s+support\b", 2, "Technical support claim"),
    (r"\bcustomer\s+(?:support|service|care)\b", 1, "Customer support claim"),
    (r"\bsecurity\s+(?:team|department|division)\b", 2, "Security team claim"),
    (r"\b(?:IRS|FBI|CIA|police|government|federal)\b", 3, "Government impersonation"),
]

# Dangerous attachment extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".msi", ".msp", ".reg", ".rgs",
    ".ps1", ".ps2", ".psc1", ".psc2", ".lnk", ".inf", ".cpl",
    ".hta", ".jar", ".dll", ".sys", ".drv", ".ocx",
}

RISKY_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img",
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
    ".pdf", ".rtf",
}


def analyze_content(email_data: EmailData) -> list[Finding]:
    """Analyze email body content for phishing indicators."""
    findings: list[Finding] = []

    body = email_data.body_plain or ""
    # If no plain text, try to extract from HTML
    if not body and email_data.body_html:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(email_data.body_html, "html.parser")
            body = soup.get_text(separator=" ", strip=True)
        except Exception:
            body = re.sub(r"<[^>]+>", " ", email_data.body_html)

    if body:
        _check_patterns(body, URGENCY_PATTERNS, "Urgency/Pressure Language", findings)
        _check_patterns(body, THREAT_PATTERNS, "Threat/Fear Language", findings)
        _check_patterns(body, CREDENTIAL_PATTERNS, "Credential/Data Request", findings)
        _check_patterns(body, ACTION_PATTERNS, "Suspicious Action Request", findings)
        _check_patterns(body, AUTHORITY_PATTERNS, "Authority Impersonation", findings)
        _check_excessive_caps(body, findings)
        _check_greeting_patterns(body, findings)

    _check_attachments(email_data.attachment_names, email_data.attachment_hashes, findings)
    _check_html_tricks(email_data.body_html, findings)

    return findings


def _check_patterns(
    body: str,
    patterns: list[tuple[str, int, str]],
    category_name: str,
    findings: list[Finding],
):
    """Check text against a list of (pattern, weight, label) tuples."""
    matches = []
    total_weight = 0

    for pattern, weight, label in patterns:
        found = re.findall(pattern, body, re.IGNORECASE)
        if found:
            matches.append(label)
            total_weight += weight * len(found)

    if not matches:
        return

    # Determine severity based on cumulative weight
    if total_weight >= 10:
        severity = "high"
    elif total_weight >= 6:
        severity = "medium"
    else:
        severity = "low"

    findings.append(Finding(
        category="content",
        severity=severity,
        title=f"{category_name} Detected",
        description=(
            f"Found {len(matches)} indicator(s) of {category_name.lower()}: "
            f"{', '.join(matches[:5])}{'...' if len(matches) > 5 else ''}. "
            f"This type of language is commonly used in phishing emails to "
            f"manipulate recipients."
        ),
        evidence=", ".join(matches),
    ))


def _check_excessive_caps(body: str, findings: list[Finding]):
    """Check for excessive use of capital letters."""
    # Find words that are fully capitalized and at least 3 chars
    words = body.split()
    if len(words) < 10:
        return

    caps_words = [w for w in words if w.isupper() and len(w) >= 3 and w.isalpha()]
    ratio = len(caps_words) / len(words) if words else 0

    if ratio > 0.15 and len(caps_words) > 3:
        findings.append(Finding(
            category="content",
            severity="low",
            title="Excessive Capitalization",
            description=(
                f"About {ratio:.0%} of words are fully capitalized "
                f"({len(caps_words)} words). Excessive caps are used in phishing "
                f"to create urgency or draw attention."
            ),
            evidence=", ".join(caps_words[:8]),
        ))


def _check_greeting_patterns(body: str, findings: list[Finding]):
    """Check for generic/suspicious greeting patterns."""
    generic_greetings = [
        r"dear\s+(?:customer|user|client|member|valued\s+customer|sir|madam|account\s+holder)",
        r"dear\s+(?:email\s+user|webmail\s+user)",
        r"attention\s*[:\!]",
        r"to\s+whom\s+it\s+may\s+concern",
    ]

    first_200_chars = body[:200].lower()
    for pattern in generic_greetings:
        match = re.search(pattern, first_200_chars, re.IGNORECASE)
        if match:
            findings.append(Finding(
                category="content",
                severity="low",
                title="Generic Greeting",
                description=(
                    f"The email uses a generic greeting ('{match.group()}'). "
                    f"Phishing emails often use generic greetings because the "
                    f"attacker doesn't know the recipient's name."
                ),
                evidence=match.group(),
            ))
            break


def _check_attachments(attachment_names: list[str], attachment_hashes: dict[str, str], findings: list[Finding]):
    """Check attachment filenames for dangerous extensions and include hashes."""
    if not attachment_names:
        return

    for name in attachment_names:
        name_lower = name.lower()
        ext = "." + name_lower.rsplit(".", 1)[-1] if "." in name_lower else ""
        hash_val = attachment_hashes.get(name, "Unknown")

        if ext in DANGEROUS_EXTENSIONS:
            findings.append(Finding(
                category="content",
                severity="critical",
                title="Dangerous Attachment Type",
                description=(
                    f"The attachment '{name}' has a '{ext}' extension, which is "
                    f"an executable/script file type. These are commonly used to "
                    f"deliver malware."
                ),
                evidence=f"File: {name} | SHA256: {hash_val}",
            ))
        elif ext in RISKY_EXTENSIONS:
            # Check for double extensions (e.g., "document.pdf.exe")
            parts = name_lower.rsplit(".", 2)
            if len(parts) >= 3:
                second_ext = "." + parts[-2]
                if second_ext in DANGEROUS_EXTENSIONS:
                    findings.append(Finding(
                        category="content",
                        severity="critical",
                        title="Double Extension Attack",
                        description=(
                            f"The attachment '{name}' uses a double extension, "
                            f"hiding a dangerous '{second_ext}' extension behind "
                            f"a seemingly safe '{ext}' extension."
                        ),
                        evidence=f"File: {name} | SHA256: {hash_val}",
                    ))
                    continue

            findings.append(Finding(
                category="content",
                severity="low",
                title="Potentially Risky Attachment",
                description=(
                    f"The attachment '{name}' has a '{ext}' extension. While "
                    f"commonly used legitimately, these file types can contain "
                    f"malicious content (macros, embedded scripts)."
                ),
                evidence=f"File: {name} | SHA256: {hash_val}",
            ))


def _check_html_tricks(html: str, findings: list[Finding]):
    """Check for HTML-based deception techniques."""
    if not html:
        return

    # Hidden text (very small font, display:none, visibility:hidden)
    hidden_patterns = [
        r"display\s*:\s*none",
        r"visibility\s*:\s*hidden",
        r"font-size\s*:\s*[01]px",
        r"opacity\s*:\s*0(?:\.0+)?(?:\s*;|\s*})",
        r"color\s*:\s*(?:#fff(?:fff)?|white|#fefefe|rgb\(255\s*,\s*255\s*,\s*255\))",
    ]

    for pattern in hidden_patterns:
        if re.search(pattern, html, re.IGNORECASE):
            findings.append(Finding(
                category="content",
                severity="medium",
                title="Hidden Content in HTML",
                description=(
                    "The email HTML contains hidden content (via CSS). This technique "
                    "is used to bypass spam filters by hiding text or to confuse "
                    "users about the email's true content."
                ),
                evidence=f"Pattern: {pattern}",
            ))
            break

    # Forms inside emails
    if re.search(r"<form[\s>]", html, re.IGNORECASE):
        findings.append(Finding(
            category="content",
            severity="high",
            title="Embedded Form in Email",
            description=(
                "The email contains an embedded HTML form. Legitimate emails "
                "almost never include forms — this is used to harvest credentials "
                "directly within the email."
            ),
            evidence="<form> tag detected",
        ))

    # Iframes
    if re.search(r"<iframe[\s>]", html, re.IGNORECASE):
        findings.append(Finding(
            category="content",
            severity="high",
            title="Embedded Iframe in Email",
            description=(
                "The email contains an iframe element, which can load external "
                "content or phishing pages within the email body."
            ),
            evidence="<iframe> tag detected",
        ))

    # JavaScript
    if re.search(r"<script[\s>]|javascript:", html, re.IGNORECASE):
        findings.append(Finding(
            category="content",
            severity="critical",
            title="JavaScript in Email",
            description=(
                "The email contains JavaScript code. Legitimate emails should "
                "never include scripts — this can be used for malicious actions."
            ),
            evidence="<script> or javascript: detected",
        ))
