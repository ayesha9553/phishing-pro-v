"""Scanner service — orchestrates the full email analysis pipeline."""

import asyncio
from backend.models.schemas import EmailData, ScanResult
from backend.engine.header_analyzer import analyze_headers
from backend.engine.url_analyzer import analyze_urls
from backend.engine.content_analyzer import analyze_content
from backend.engine.auth_checker import analyze_auth
from backend.engine.risk_scorer import calculate_risk
from backend.engine.ml_analyzer import ml_analyzer
from backend import database


async def scan_email(email_data: EmailData, source: str = "upload") -> ScanResult:
    """
    Run the full detection pipeline on an email.
    
    Pipeline:
    1. Header Analysis (spoofing, anomalies)
    2. URL Analysis (phishing links, impersonation)
    3. Content Analysis (NLP patterns, attachments)
    4. Auth Verification (SPF, DKIM, DMARC)
    5. ML Analysis (Transformer sequence classification)
    6. Risk Scoring (weighted aggregation)
    7. Persist to database
    """
    # Run all analyzers concurrently
    loop = asyncio.get_running_loop()

    header_findings, (url_findings, url_analyses), content_findings, auth_findings, ml_findings = (
        await asyncio.gather(
            loop.run_in_executor(None, analyze_headers, email_data),
            loop.run_in_executor(None, analyze_urls, email_data),
            loop.run_in_executor(None, analyze_content, email_data),
            loop.run_in_executor(None, analyze_auth, email_data),
            ml_analyzer.analyze(email_data.body_plain or email_data.body_html or ""),
        )
    )

    # Combine content and ML findings (ML is essentially advanced content analysis)
    all_content_findings = content_findings + ml_findings

    # Calculate final risk score
    scan_result = calculate_risk(
        email_data=email_data,
        header_findings=header_findings,
        url_findings=url_findings,
        content_findings=all_content_findings,
        auth_findings=auth_findings,
        url_analyses=url_analyses,
        source=source,
    )

    # Persist to database
    scan_dict = scan_result.model_dump()
    scan_dict["findings"] = [f.model_dump() for f in scan_result.findings]
    scan_dict["urls_analyzed"] = [u.model_dump() for u in scan_result.urls_analyzed]

    scan_id = await database.save_scan(scan_dict)
    scan_result.id = scan_id

    return scan_result
