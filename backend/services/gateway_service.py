"""Email Gateway Service — processes incoming emails from external mail servers."""

import logging
from typing import Optional

from backend.config import settings
from backend.services.scanner_service import scan_email
from backend.services.email_parser import parse_raw_email
from backend import database

logger = logging.getLogger(__name__)


def _determine_action(risk_score: float, risk_level: str) -> str:
    """Determine gateway action based on risk score and configured thresholds."""
    if risk_score >= settings.GATEWAY_BLOCK_THRESHOLD:
        return "blocked"
    elif risk_score >= settings.GATEWAY_QUARANTINE_THRESHOLD:
        return "quarantined"
    else:
        return "allowed"


async def ingest_email(
    raw_email: str,
    source_ip: str = "",
    envelope_from: str = "",
    envelope_to: str = "",
) -> dict:
    """
    Process an incoming email through the phishing detection pipeline.
    
    This is called by the gateway API endpoint when an external mail server
    (Postfix, Exchange, Mailgun, etc.) forwards an email for inspection.
    
    Returns:
        {
            "action": "allowed" | "quarantined" | "blocked",
            "risk_score": float,
            "risk_level": str,
            "scan_id": int,
            "summary": str,
            "findings_count": int,
        }
    """
    # Parse the raw email
    try:
        email_data = parse_raw_email(raw_email)
    except Exception as e:
        logger.error(f"Gateway: failed to parse email from {envelope_from}: {e}")
        return {
            "action": "allowed",  # Fail open to avoid blocking legitimate emails
            "risk_score": 0,
            "risk_level": "safe",
            "scan_id": None,
            "summary": f"Parse error: {e}",
            "findings_count": 0,
            "error": str(e),
        }

    # Override sender/recipient from SMTP envelope if not in headers
    if envelope_from and not email_data.sender:
        email_data.sender = envelope_from
    if envelope_to and not email_data.recipient:
        email_data.recipient = envelope_to

    # Run scan
    try:
        scan_result = await scan_email(email_data, source="gateway")
    except Exception as e:
        logger.error(f"Gateway: scan failed for email from {envelope_from}: {e}")
        return {
            "action": "allowed",  # Fail open
            "risk_score": 0,
            "risk_level": "safe",
            "scan_id": None,
            "summary": f"Scan error: {e}",
            "findings_count": 0,
            "error": str(e),
        }

    risk_score = scan_result.risk_score
    risk_level = scan_result.risk_level
    action = _determine_action(risk_score, risk_level)

    # Log to gateway_emails table
    gateway_log_data = {
        "source_ip": source_ip,
        "envelope_from": envelope_from or scan_result.sender,
        "envelope_to": envelope_to or scan_result.recipient,
        "subject": scan_result.subject,
        "scan_id": scan_result.id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "action_taken": action,
    }

    try:
        await database.save_gateway_email(gateway_log_data)
    except Exception as e:
        logger.error(f"Gateway: failed to log email: {e}")

    logger.info(
        f"Gateway processed email from={envelope_from or scan_result.sender} "
        f"score={risk_score} level={risk_level} action={action}"
    )

    return {
        "action": action,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "scan_id": scan_result.id,
        "subject": scan_result.subject,
        "sender": scan_result.sender,
        "findings_count": len(scan_result.findings),
        "thresholds": {
            "quarantine": settings.GATEWAY_QUARANTINE_THRESHOLD,
            "block": settings.GATEWAY_BLOCK_THRESHOLD,
        },
    }


async def get_imap_emails() -> list[dict]:
    """
    Poll an IMAP mailbox for new emails and run them through the scanner.
    Returns a list of results for each processed email.
    
    Requires IMAP_HOST, IMAP_USER, IMAP_PASS to be configured.
    """
    if not settings.IMAP_ENABLED:
        return []

    import imaplib
    import email as email_lib

    results = []

    try:
        import ssl as ssl_lib

        # Connect to IMAP server
        ctx = ssl_lib.create_default_context()
        imap = imaplib.IMAP4_SSL(settings.IMAP_HOST, settings.IMAP_PORT, ssl_context=ctx)
        imap.login(settings.IMAP_USER, settings.IMAP_PASS)
        imap.select(settings.IMAP_FOLDER)

        # Search for unseen emails
        status, msg_ids = imap.search(None, "UNSEEN")
        if status != "OK":
            imap.logout()
            return []

        msg_id_list = msg_ids[0].split()[-20:]  # Cap at 20 emails per poll

        for msg_id in msg_id_list:
            try:
                status, msg_data = imap.fetch(msg_id, "(RFC822)")
                if status != "OK":
                    continue

                raw_bytes = msg_data[0][1]
                raw_email = raw_bytes.decode("utf-8", errors="replace")

                result = await ingest_email(
                    raw_email=raw_email,
                    source_ip=settings.IMAP_HOST,
                    envelope_from="",
                    envelope_to=settings.IMAP_USER,
                )
                results.append(result)

                # Mark as seen
                imap.store(msg_id, "+FLAGS", "\\Seen")

            except Exception as e:
                logger.error(f"IMAP: failed to process message {msg_id}: {e}")

        imap.logout()

    except Exception as e:
        logger.error(f"IMAP connection error: {e}")

    return results
