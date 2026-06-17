"""Risk scoring and aggregation of all analyzer results."""

from backend.models.schemas import Finding, ScanResult, EmailData, URLAnalysis


# Severity weights for score calculation
SEVERITY_SCORES = {
    "info": 0,
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 50,
}

# Category weights (how much each analyzer contributes)
CATEGORY_WEIGHTS = {
    "header": 0.20,
    "url": 0.30,
    "content": 0.30,
    "auth": 0.20,
}

# Risk level thresholds
RISK_LEVELS = [
    (25, "safe"),
    (45, "low"),
    (65, "medium"),
    (85, "high"),
    (100, "critical"),
]


def calculate_risk(
    email_data: EmailData,
    header_findings: list[Finding],
    url_findings: list[Finding],
    content_findings: list[Finding],
    auth_findings: list[Finding],
    url_analyses: list[URLAnalysis],
    source: str = "upload",
) -> ScanResult:
    """
    Aggregate all findings into a final risk score and level.
    
    The scoring algorithm:
    1. Calculate a raw score per category based on severity weights
    2. Cap each category at 100
    3. Apply category weights
    4. Sum to get final score (0-100)
    """
    all_findings = header_findings + url_findings + content_findings + auth_findings

    # Calculate per-category scores
    category_scores = {"header": 0, "url": 0, "content": 0, "auth": 0}
    for finding in all_findings:
        score = SEVERITY_SCORES.get(finding.severity, 0)
        if finding.category in category_scores:
            category_scores[finding.category] += score

    # Cap each category at 100
    for cat in category_scores:
        category_scores[cat] = min(category_scores[cat], 100)

    # Weighted final score
    final_score = sum(
        category_scores[cat] * CATEGORY_WEIGHTS.get(cat, 0.25)
        for cat in category_scores
    )
    final_score = min(round(final_score, 1), 100)

    # Determine risk level
    risk_level = "critical"
    for threshold, level in RISK_LEVELS:
        if final_score <= threshold:
            risk_level = level
            break

    # Build body preview
    body_text = email_data.body_plain or ""
    if not body_text and email_data.body_html:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(email_data.body_html, "html.parser")
            body_text = soup.get_text(separator=" ", strip=True)
        except Exception:
            body_text = ""
    body_preview = body_text[:300] + "..." if len(body_text) > 300 else body_text

    return ScanResult(
        source=source,
        subject=email_data.subject,
        sender=email_data.sender,
        sender_display_name=email_data.sender_display_name,
        recipient=email_data.recipient,
        email_date=email_data.date,
        risk_score=final_score,
        risk_level=risk_level,
        findings=all_findings,
        urls_analyzed=url_analyses,
        body_preview=body_preview,
        attachment_names=email_data.attachment_names,
        attachment_hashes=email_data.attachment_hashes,
        raw_headers=email_data.raw_headers,
    )
