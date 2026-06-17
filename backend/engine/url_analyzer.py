"""URL extraction and analysis for phishing detection."""

import re
import math
from urllib.parse import urlparse, unquote
from collections import Counter
from bs4 import BeautifulSoup

from backend.models.schemas import Finding, EmailData, URLAnalysis


# URL shortener services commonly used to hide phishing URLs
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr", "db.tt",
    "qr.ae", "cur.lv", "ity.im", "lnkd.in", "rebrand.ly",
    "bl.ink", "short.io", "tiny.cc", "cutt.ly", "rb.gy",
}

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
    ".click", ".link", ".info", ".online", ".site", ".website",
    ".space", ".win", ".bid", ".stream", ".download", ".racing",
    ".loan", ".date", ".faith", ".review", ".accountant",
    ".cricket", ".science", ".party", ".trade",
}

# Known brand domains for impersonation detection
BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com", "office365.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "aws.amazon.com"],
    "google": ["google.com", "gmail.com", "accounts.google.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "citibank": ["citibank.com", "citi.com"],
}

# Homograph character mappings (looks like → actual)
HOMOGRAPH_MAP = {
    "0": "o", "1": "l", "!": "i", "@": "a", "$": "s",
    "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
}


def analyze_urls(email_data: EmailData) -> tuple[list[Finding], list[URLAnalysis]]:
    """
    Extract and analyze all URLs in the email.
    Returns (findings, url_analyses).
    """
    findings: list[Finding] = []
    url_analyses: list[URLAnalysis] = []

    # Extract URLs from both plain text and HTML
    all_urls = set(email_data.urls)
    all_urls.update(_extract_urls_from_text(email_data.body_plain))

    # HTML-specific checks
    html_urls, mismatched = _extract_urls_from_html(email_data.body_html)
    all_urls.update(html_urls)

    # Report mismatched anchor text vs href
    for display_url, href_url in mismatched:
        findings.append(Finding(
            category="url",
            severity="high",
            title="Mismatched Link Text and URL",
            description=(
                f"A link displays '{_defang_url(display_url)}' but actually points to "
                f"'{_defang_url(href_url)}'. This is a common phishing technique to disguise "
                f"malicious URLs."
            ),
            evidence=f"Shown: {_defang_url(display_url)} | Actual: {_defang_url(href_url)}",
        ))

    if not all_urls:
        return findings, url_analyses

    # Analyze each URL
    for url in all_urls:
        url_finding_reasons = []
        is_suspicious = False

        parsed = _safe_parse_url(url)
        if not parsed or not parsed.netloc:
            continue

        domain = parsed.netloc.lower().split(":")[0]  # Remove port

        # 1. IP-based URL
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            is_suspicious = True
            url_finding_reasons.append("URL uses an IP address instead of a domain name")
            findings.append(Finding(
                category="url",
                severity="high",
                title="IP Address URL",
                description=(
                    f"The URL '{_defang_url(url)[:100]}' uses a raw IP address instead of a domain name. "
                    f"Legitimate services rarely use IP addresses in user-facing URLs."
                ),
                evidence=_defang_url(url)[:200],
            ))

        # 2. URL shortener
        if domain in URL_SHORTENERS:
            is_suspicious = True
            url_finding_reasons.append(f"Uses URL shortener service ({domain})")
            findings.append(Finding(
                category="url",
                severity="medium",
                title="URL Shortener Detected",
                description=(
                    f"The URL uses the shortener service '{domain}'. URL shorteners "
                    f"can hide the true destination and are commonly used in phishing."
                ),
                evidence=_defang_url(url)[:200],
            ))

        # 3. Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                is_suspicious = True
                url_finding_reasons.append(f"Uses suspicious TLD ({tld})")
                findings.append(Finding(
                    category="url",
                    severity="medium",
                    title="Suspicious Domain Extension",
                    description=(
                        f"The domain '{domain}' uses the '{tld}' extension, which "
                        f"is frequently associated with phishing campaigns."
                    ),
                    evidence=_defang_url(url)[:200],
                ))
                break

        # 4. Domain entropy (randomness check)
        entropy = _calculate_entropy(domain.split(".")[0])
        if entropy > 3.8 and len(domain.split(".")[0]) > 8:
            is_suspicious = True
            url_finding_reasons.append(f"High domain entropy ({entropy:.1f}) suggests random/generated domain")
            findings.append(Finding(
                category="url",
                severity="medium",
                title="Possibly Generated Domain",
                description=(
                    f"The domain '{domain}' has high character entropy ({entropy:.1f}), "
                    f"suggesting it may be algorithmically generated rather than human-chosen."
                ),
                evidence=_defang_url(url)[:200],
            ))

        # 5. Brand impersonation
        brand_hit = _check_brand_impersonation(domain)
        if brand_hit:
            is_suspicious = True
            url_finding_reasons.append(f"Possible {brand_hit} impersonation")
            findings.append(Finding(
                category="url",
                severity="high",
                title=f"Possible {brand_hit} URL Impersonation",
                description=(
                    f"The domain '{domain}' resembles '{brand_hit}' but is not an "
                    f"official domain. This may be an attempt to impersonate a trusted brand."
                ),
                evidence=_defang_url(url)[:200],
            ))

        # 6. Excessive subdomain depth
        parts = domain.split(".")
        if len(parts) > 4:
            is_suspicious = True
            url_finding_reasons.append(f"Excessive subdomain depth ({len(parts)} levels)")
            findings.append(Finding(
                category="url",
                severity="medium",
                title="Excessive Subdomains in URL",
                description=(
                    f"The URL has {len(parts)} subdomain levels ({domain}). "
                    f"Deep subdomains can be used to make malicious URLs look legitimate."
                ),
                evidence=_defang_url(url)[:200],
            ))

        # 7. Suspicious path keywords
        suspicious_paths = ["login", "signin", "verify", "secure", "account", "update",
                           "confirm", "banking", "password", "credential", "webscr"]
        path_lower = parsed.path.lower()
        for keyword in suspicious_paths:
            if keyword in path_lower:
                is_suspicious = True
                url_finding_reasons.append(f"Suspicious keyword '{keyword}' in URL path")
                findings.append(Finding(
                    category="url",
                    severity="medium",
                    title="Suspicious URL Path Keywords",
                    description=(
                        f"The URL path contains the keyword '{keyword}', commonly "
                        f"seen in credential-harvesting phishing pages."
                    ),
                    evidence=_defang_url(url)[:200],
                ))
                break  # Only report once per URL
                
        # 7b. Base64 encoded path/query detection
        import base64
        path_and_query = parsed.path + "?" + parsed.query
        # Look for base64 looking strings (length >= 16, valid b64 chars, often ends in =)
        b64_matches = re.findall(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', path_and_query)
        for match in b64_matches:
            # Try to decode and see if it looks like an email or sensitive data
            try:
                decoded = base64.b64decode(match).decode('utf-8')
                if '@' in decoded and '.' in decoded:  # Looks like an email
                    is_suspicious = True
                    url_finding_reasons.append("Base64 encoded email address in URL")
                    findings.append(Finding(
                        category="url",
                        severity="high",
                        title="Encoded Target Data in URL",
                        description="The URL contains a Base64 encoded email address, a common technique to pre-fill phishing forms.",
                        evidence=f"Decoded: {decoded[:100]}"
                    ))
                    break
            except Exception:
                pass

        # 8. Data URI or javascript: protocol
        if url.lower().startswith(("data:", "javascript:")):
            is_suspicious = True
            url_finding_reasons.append("Uses data: or javascript: URI scheme")
            findings.append(Finding(
                category="url",
                severity="critical",
                title="Dangerous URI Scheme",
                description=(
                    f"A link uses a '{url.split(':')[0]}:' URI scheme, which can "
                    f"execute code or embed malicious content directly."
                ),
                evidence=_defang_url(url)[:100],
            ))

        url_analyses.append(URLAnalysis(
            url=_defang_url(url)[:500],
            is_suspicious=is_suspicious,
            reasons=url_finding_reasons,
        ))

    # Summary finding if many suspicious URLs
    suspicious_count = sum(1 for ua in url_analyses if ua.is_suspicious)
    total_count = len(url_analyses)
    if suspicious_count > 2:
        findings.append(Finding(
            category="url",
            severity="high",
            title=f"Multiple Suspicious URLs ({suspicious_count}/{total_count})",
            description=(
                f"This email contains {suspicious_count} out of {total_count} "
                f"URLs that triggered suspicious indicators."
            ),
            evidence=None,
        ))

    return findings, url_analyses


def _extract_urls_from_text(text: str) -> set[str]:
    """Extract URLs from plain text using regex."""
    if not text:
        return set()
    pattern = r'https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:/[^\s<>"{}|\\^`\[\]]*)?'
    return set(re.findall(pattern, text))


def _extract_urls_from_html(html: str) -> tuple[set[str], list[tuple[str, str]]]:
    """
    Extract URLs from HTML content.
    Returns (all_urls, mismatched_pairs) where mismatched_pairs
    is a list of (display_text, href) where display looks like a different URL.
    """
    urls = set()
    mismatched = []

    if not html:
        return urls, mismatched

    try:
        soup = BeautifulSoup(html, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            if href.startswith(("http://", "https://")):
                urls.add(href)

            # Check for text/href mismatch
            text = a_tag.get_text(strip=True)
            if text and re.match(r"https?://", text):
                text_parsed = _safe_parse_url(text)
                href_parsed = _safe_parse_url(href)
                if (text_parsed and href_parsed and
                        text_parsed.netloc and href_parsed.netloc and
                        text_parsed.netloc.lower() != href_parsed.netloc.lower()):
                    mismatched.append((text[:100], href[:100]))
    except Exception:
        pass

    return urls, mismatched


def _safe_parse_url(url: str):
    """Safely parse a URL, returning None on failure."""
    try:
        return urlparse(unquote(url))
    except Exception:
        return None


def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counter = Counter(text.lower())
    length = len(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return entropy


def _check_brand_impersonation(domain: str) -> str | None:
    """
    Check if domain is impersonating a known brand.
    Returns the brand name if suspicious, None otherwise.
    """
    # Remove www. prefix
    clean_domain = domain.lstrip("www.")

    for brand, official_domains in BRAND_DOMAINS.items():
        # Skip if it IS an official domain
        if clean_domain in official_domains:
            continue
        # Check if domain contains brand name but isn't official
        if brand in clean_domain.replace(".", "").replace("-", ""):
            return brand.capitalize()

        # Homograph check: normalize domain and check
        normalized = _normalize_homographs(clean_domain.split(".")[0])
        if brand in normalized and clean_domain not in official_domains:
            return brand.capitalize()

    return None


def _normalize_homographs(text: str) -> str:
    """Replace common homograph characters with their lookalikes."""
    result = text.lower()
    for fake, real in HOMOGRAPH_MAP.items():
        result = result.replace(fake, real)
    return result


def _defang_url(url: str) -> str:
    """Defang a URL for safe display (e.g., http://example.com -> hxxp[://]example[.]com)."""
    if not url:
        return url
    defanged = url.replace("http://", "hxxp[://]").replace("https://", "hxxps[://]")
    defanged = defanged.replace(".", "[.]")
    return defanged
