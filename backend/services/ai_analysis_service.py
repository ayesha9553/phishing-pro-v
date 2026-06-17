"""Generative AI Threat Analysis — LLM-powered plain-English phishing summaries."""

import logging
from typing import Optional

from backend.config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst specializing in email phishing threat analysis. 
Your job is to review phishing scan results and provide a clear, concise threat summary for security teams.

Guidelines:
- Write in plain English, accessible to both technical and non-technical stakeholders
- Be specific about WHAT indicators were found and WHY they're suspicious
- Include a clear recommendation (block, quarantine, or allow with caution)
- Keep the summary to 3-5 sentences maximum
- Do NOT use markdown formatting — plain text only
- Do NOT start with "I" or "As an AI"
- Lead with the threat level assessment"""


def _build_analysis_prompt(scan_data: dict) -> str:
    """Build the analysis prompt from scan data."""
    subject = scan_data.get("subject") or "(no subject)"
    sender = scan_data.get("sender") or "unknown"
    risk_score = scan_data.get("risk_score", 0)
    risk_level = scan_data.get("risk_level", "unknown")
    findings = scan_data.get("findings", [])
    urls_analyzed = scan_data.get("urls_analyzed", [])
    body_preview = (scan_data.get("body_preview") or "")[:500]

    # Format findings
    findings_text = ""
    if findings:
        finding_lines = []
        for f in findings[:10]:  # Cap at 10 findings
            severity = f.get("severity", "info").upper()
            title = f.get("title", "")
            desc = f.get("description", "")
            finding_lines.append(f"[{severity}] {title}: {desc}")
        findings_text = "\n".join(finding_lines)
    else:
        findings_text = "No specific findings detected."

    # Format URLs
    suspicious_urls = [u for u in urls_analyzed if u.get("is_suspicious")]
    url_text = ""
    if suspicious_urls:
        url_lines = [f"- {u['url']} ({', '.join(u.get('reasons', [])[:3])})" for u in suspicious_urls[:5]]
        url_text = "Suspicious URLs found:\n" + "\n".join(url_lines)
    else:
        url_text = "No suspicious URLs detected."

    prompt = f"""Analyze this email phishing scan result and provide a threat summary:

EMAIL DETAILS:
- Subject: {subject}
- Sender: {sender}
- Risk Score: {risk_score}/100
- Risk Level: {risk_level.upper()}

DETECTION FINDINGS:
{findings_text}

URL ANALYSIS:
{url_text}

EMAIL BODY PREVIEW:
{body_preview if body_preview else '(not available)'}

Provide a 3-5 sentence plain-English threat summary with your recommendation."""

    return prompt


async def _analyze_with_openai(prompt: str) -> str:
    """Use OpenAI GPT to analyze the threat."""
    try:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

        response = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            max_tokens=300,
            temperature=0.3,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"OpenAI analysis error: {e}")
        raise


async def _analyze_with_gemini(prompt: str) -> str:
    """Use Google Gemini to analyze the threat."""
    try:
        import google.generativeai as genai
        genai.configure(api_key=settings.GOOGLE_API_KEY)
        model = genai.GenerativeModel("gemini-1.5-flash")

        full_prompt = f"{SYSTEM_PROMPT}\n\n{prompt}"
        response = await model.generate_content_async(
            full_prompt,
            generation_config={"max_output_tokens": 300, "temperature": 0.3},
        )
        return response.text.strip()
    except Exception as e:
        logger.error(f"Gemini analysis error: {e}")
        raise


def _generate_rule_based_summary(scan_data: dict) -> str:
    """
    Generate a rule-based summary when no AI provider is configured.
    Produces a structured but readable analysis without an LLM.
    """
    risk_score = scan_data.get("risk_score", 0)
    risk_level = scan_data.get("risk_level", "safe")
    findings = scan_data.get("findings", [])
    sender = scan_data.get("sender") or "unknown sender"
    subject = scan_data.get("subject") or "no subject"
    urls_analyzed = scan_data.get("urls_analyzed", [])

    # Count findings by severity
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    critical_count = severity_counts.get("critical", 0)
    high_count = severity_counts.get("high", 0)
    suspicious_urls = sum(1 for u in urls_analyzed if u.get("is_suspicious"))

    # Determine threat assessment sentence
    if risk_level == "critical":
        assessment = f"This email is highly likely a phishing attack with a risk score of {risk_score}/100."
        recommendation = "Immediate action required — block this sender and quarantine the email."
    elif risk_level == "high":
        assessment = f"This email exhibits strong phishing indicators with a risk score of {risk_score}/100."
        recommendation = "Quarantine this email and investigate the sender domain before allowing delivery."
    elif risk_level == "medium":
        assessment = f"This email shows moderate phishing indicators with a risk score of {risk_score}/100."
        recommendation = "Flag for user review — exercise caution before opening links or attachments."
    elif risk_level == "low":
        assessment = f"This email shows minor suspicious signals with a risk score of {risk_score}/100."
        recommendation = "Email appears mostly safe, but monitor for similar patterns from this sender."
    else:
        assessment = f"This email appears safe with a risk score of {risk_score}/100."
        recommendation = "No action required — email passed all security checks."

    # Build finding details
    detail_parts = []
    if critical_count or high_count:
        detail_parts.append(
            f"Detected {critical_count} critical and {high_count} high-severity findings"
        )
    if suspicious_urls > 0:
        detail_parts.append(f"{suspicious_urls} suspicious URL{'s' if suspicious_urls > 1 else ''} identified")

    # Top findings
    top_findings = [f.get("title", "") for f in findings[:3] if f.get("title")]
    if top_findings:
        detail_parts.append(f"Key indicators: {', '.join(top_findings)}")

    details = ". ".join(detail_parts) + "." if detail_parts else ""

    summary = f"{assessment} {details} {recommendation}".strip()
    return summary


async def analyze_scan(scan_data: dict) -> str:
    """
    Generate an AI-powered threat analysis summary for a scan result.
    
    Falls back gracefully through: OpenAI → Gemini → Rule-based
    """
    provider = settings.AI_PROVIDER.lower()

    if provider == "openai" and settings.OPENAI_API_KEY:
        try:
            prompt = _build_analysis_prompt(scan_data)
            return await _analyze_with_openai(prompt)
        except Exception as e:
            logger.warning(f"OpenAI failed, falling back to rule-based: {e}")

    elif provider == "gemini" and settings.GOOGLE_API_KEY:
        try:
            prompt = _build_analysis_prompt(scan_data)
            return await _analyze_with_gemini(prompt)
        except Exception as e:
            logger.warning(f"Gemini failed, falling back to rule-based: {e}")

    # Rule-based fallback (always available)
    return _generate_rule_based_summary(scan_data)
