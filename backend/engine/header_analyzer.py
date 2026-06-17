"""Email header analysis for spoofing and anomaly detection."""

import re
from email.utils import parseaddr
from backend.models.schemas import Finding, EmailData


# Known suspicious X-Mailer values associated with phishing toolkits
SUSPICIOUS_MAILERS = [
    "king phisher", "gophish", "cobalt strike", "setoolkit",
    "swaks", "emkei", "anonymousemail",
]

# Free email providers commonly abused in phishing
FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "protonmail.com", "mail.com", "yandex.com", "zoho.com",
    "icloud.com", "gmx.com", "tutanota.com",
]


def analyze_headers(email_data: EmailData) -> list[Finding]:
    """Analyze email headers for spoofing indicators and anomalies."""
    findings: list[Finding] = []

    _check_sender_mismatch(email_data, findings)
    _check_reply_to_mismatch(email_data, findings)
    _check_received_chain(email_data, findings)
    _check_x_mailer(email_data, findings)
    _check_missing_headers(email_data, findings)
    _check_sender_domain(email_data, findings)

    return findings


def _check_sender_mismatch(email_data: EmailData, findings: list[Finding]):
    """Check if the display name doesn't match the actual email address."""
    display_name = email_data.sender_display_name.strip()
    email_addr = email_data.sender.strip().lower()

    if not display_name or not email_addr:
        return

    # Check if display name looks like an email address but differs from actual
    if "@" in display_name:
        display_email = display_name.lower().strip("<>")
        if display_email != email_addr:
            findings.append(Finding(
                category="header",
                severity="high",
                title="Sender Display Name Mismatch",
                description=(
                    f"The display name shows '{display_name}' but the actual "
                    f"sending address is '{email_addr}'. This is a common spoofing technique."
                ),
                evidence=f"Display: {display_name} | Actual: {email_addr}",
            ))

    # Check if display name impersonates a well-known company
    company_patterns = [
        (r"paypal", "PayPal"), (r"apple", "Apple"), (r"microsoft", "Microsoft"),
        (r"amazon", "Amazon"), (r"google", "Google"), (r"netflix", "Netflix"),
        (r"facebook|meta", "Facebook/Meta"), (r"instagram", "Instagram"),
        (r"bank\s*of\s*america", "Bank of America"), (r"wells?\s*fargo", "Wells Fargo"),
        (r"chase", "Chase"), (r"citi\s*bank", "Citibank"),
    ]

    for pattern, company in company_patterns:
        if re.search(pattern, display_name, re.IGNORECASE):
            # Check if the domain is NOT the company's official domain
            email_domain = email_addr.split("@")[-1] if "@" in email_addr else ""
            company_key = company.lower().replace(" ", "").replace("/", "")
            if company_key not in email_domain.lower().replace(".", ""):
                findings.append(Finding(
                    category="header",
                    severity="high",
                    title=f"Possible {company} Impersonation",
                    description=(
                        f"The sender claims to be '{display_name}' but the email "
                        f"originates from '{email_domain}', not an official {company} domain."
                    ),
                    evidence=f"Display: {display_name} | Domain: {email_domain}",
                ))
                break


def _check_reply_to_mismatch(email_data: EmailData, findings: list[Finding]):
    """Flag when Reply-To address differs from From address."""
    reply_to = email_data.reply_to.strip().lower()
    sender = email_data.sender.strip().lower()

    if not reply_to or not sender:
        return

    # Extract just the email part
    _, reply_email = parseaddr(reply_to)
    _, sender_email = parseaddr(sender)

    if reply_email and sender_email and reply_email != sender_email:
        # Check if even the domains differ
        reply_domain = reply_email.split("@")[-1] if "@" in reply_email else ""
        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

        severity = "high" if reply_domain != sender_domain else "medium"

        findings.append(Finding(
            category="header",
            severity=severity,
            title="Reply-To Mismatch",
            description=(
                f"Replies will go to '{reply_email}' instead of the sender "
                f"'{sender_email}'. This is often used to intercept responses."
            ),
            evidence=f"From: {sender_email} | Reply-To: {reply_email}",
        ))


def _check_received_chain(email_data: EmailData, findings: list[Finding]):
    """Analyze the Received header chain for anomalies."""
    chain = email_data.received_chain

    if not chain:
        findings.append(Finding(
            category="header",
            severity="medium",
            title="Missing Received Headers",
            description=(
                "No 'Received' headers found. Legitimate emails typically have "
                "multiple Received headers showing the delivery path."
            ),
            evidence=None,
        ))
        return

    if len(chain) == 1:
        findings.append(Finding(
            category="header",
            severity="low",
            title="Single Received Header",
            description=(
                "Only one 'Received' header found. Legitimate emails usually "
                "pass through multiple mail servers."
            ),
            evidence=chain[0][:200],
        ))

    # Check for IP addresses in the chain
    for hop in chain:
        # Look for private/internal IPs being exposed
        private_ip_match = re.search(
            r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
            hop,
        )
        if private_ip_match:
            # This is normal for internal relays, just info
            pass

        # Check for suspicious "localhost" patterns
        if "localhost" in hop.lower() and len(chain) <= 2:
            findings.append(Finding(
                category="header",
                severity="medium",
                title="Suspicious Localhost in Received Chain",
                description=(
                    "The email appears to have been sent from localhost with minimal "
                    "routing, which can indicate a phishing tool or script."
                ),
                evidence=hop[:200],
            ))
            break


def _check_x_mailer(email_data: EmailData, findings: list[Finding]):
    """Check X-Mailer header for known phishing toolkits."""
    x_mailer = email_data.headers.get("x-mailer", "").lower()
    if not x_mailer:
        return

    for toolkit in SUSPICIOUS_MAILERS:
        if toolkit in x_mailer:
            findings.append(Finding(
                category="header",
                severity="critical",
                title="Known Phishing Toolkit Detected",
                description=(
                    f"The X-Mailer header indicates this email was sent using "
                    f"'{x_mailer}', which is a known phishing/social engineering toolkit."
                ),
                evidence=f"X-Mailer: {x_mailer}",
            ))
            return


def _check_missing_headers(email_data: EmailData, findings: list[Finding]):
    """Flag emails missing standard headers."""
    if not email_data.message_id:
        findings.append(Finding(
            category="header",
            severity="low",
            title="Missing Message-ID",
            description=(
                "The email is missing a Message-ID header. While not always malicious, "
                "legitimate mail servers almost always generate this header."
            ),
            evidence=None,
        ))

    if not email_data.date:
        findings.append(Finding(
            category="header",
            severity="low",
            title="Missing Date Header",
            description=(
                "The email is missing a Date header, which is unusual for "
                "legitimate emails."
            ),
            evidence=None,
        ))


def _check_sender_domain(email_data: EmailData, findings: list[Finding]):
    """Check sender domain characteristics."""
    sender = email_data.sender.strip().lower()
    if "@" not in sender:
        return

    domain = sender.split("@")[-1]

    # Check for IP-based sender
    if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        findings.append(Finding(
            category="header",
            severity="high",
            title="IP-Based Sender Domain",
            description=(
                f"The sender domain is an IP address ({domain}) instead of a "
                f"domain name. This is highly unusual for legitimate emails."
            ),
            evidence=f"Sender: {sender}",
        ))

    # Check for very long domain names (possible DGA)
    if len(domain) > 40:
        findings.append(Finding(
            category="header",
            severity="medium",
            title="Unusually Long Sender Domain",
            description=(
                f"The sender domain '{domain}' is unusually long ({len(domain)} chars), "
                f"which can indicate a domain generated by an algorithm."
            ),
            evidence=f"Domain: {domain}",
        ))

    # Check for excessive subdomains
    parts = domain.split(".")
    if len(parts) > 4:
        findings.append(Finding(
            category="header",
            severity="medium",
            title="Excessive Subdomains in Sender",
            description=(
                f"The sender domain has {len(parts)} levels ({domain}). "
                f"Excessive subdomains are sometimes used to make domains appear legitimate."
            ),
            evidence=f"Domain: {domain}",
        ))

    # Check domain age via Whois
    try:
        import whois
        from datetime import datetime, timezone
        
        # Only check the root domain
        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        w = whois.whois(root_domain)
        creation_date = w.creation_date
        
        if creation_date:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            # Make naive datetime timezone-aware (assume UTC) for calculation
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
                
            age_days = (datetime.now(timezone.utc) - creation_date).days
            
            if age_days < 30:
                findings.append(Finding(
                    category="header",
                    severity="high",
                    title="Recently Registered Domain",
                    description=(
                        f"The sender domain '{root_domain}' was registered very recently "
                        f"({age_days} days ago). Newly registered domains are frequently "
                        f"used in phishing campaigns."
                    ),
                    evidence=f"Domain: {root_domain} | Age: {age_days} days",
                ))
    except Exception:
        # Whois lookup failed (timeout, blocked, etc.), just ignore
        pass
