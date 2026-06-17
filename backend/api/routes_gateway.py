"""Email Gateway API routes — ingest and manage real-time email scanning."""

import logging
from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel
from typing import Optional

from backend.services.gateway_service import ingest_email
from backend.config import settings
from backend import database

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/gateway", tags=["gateway"])


class GatewayIngestRequest(BaseModel):
    """Request body for email gateway ingest."""
    raw_email: str
    source_ip: Optional[str] = ""
    envelope_from: Optional[str] = ""
    envelope_to: Optional[str] = ""


class GatewayConfigUpdate(BaseModel):
    """Gateway threshold configuration update."""
    quarantine_threshold: Optional[int] = None
    block_threshold: Optional[int] = None


@router.post("/ingest")
async def gateway_ingest(request: GatewayIngestRequest, req: Request):
    """
    Ingest an email from an external mail server for phishing analysis.
    
    This endpoint is designed to be called by:
    - Postfix content filters (milter)
    - Microsoft Exchange transport rules
    - Mailgun/SendGrid webhooks
    - Any SMTP relay that supports HTTP callbacks
    
    Returns the scan result and recommended action (allow/quarantine/block).
    """
    if not request.raw_email or not request.raw_email.strip():
        raise HTTPException(status_code=400, detail="raw_email is required")

    # Get client IP if not provided
    source_ip = request.source_ip or (req.client.host if req.client else "")

    result = await ingest_email(
        raw_email=request.raw_email,
        source_ip=source_ip,
        envelope_from=request.envelope_from or "",
        envelope_to=request.envelope_to or "",
    )

    return result


@router.get("/logs")
async def get_gateway_logs(limit: int = Query(default=100, le=500)):
    """Get the gateway email processing log."""
    logs = await database.get_gateway_logs(limit=limit)
    return {"logs": logs, "total": len(logs)}


@router.get("/stats")
async def get_gateway_stats():
    """Get gateway processing statistics."""
    stats = await database.get_gateway_stats()
    stats["thresholds"] = {
        "quarantine": settings.GATEWAY_QUARANTINE_THRESHOLD,
        "block": settings.GATEWAY_BLOCK_THRESHOLD,
    }
    return stats


@router.put("/config")
async def update_gateway_config(update: GatewayConfigUpdate):
    """Update gateway action thresholds."""
    updated = {}

    if update.quarantine_threshold is not None:
        if not (0 <= update.quarantine_threshold <= 100):
            raise HTTPException(
                status_code=400,
                detail="quarantine_threshold must be between 0 and 100",
            )
        # Store in DB settings for persistence
        await database.set_setting("gateway_quarantine_threshold", str(update.quarantine_threshold))
        settings.GATEWAY_QUARANTINE_THRESHOLD = update.quarantine_threshold
        updated["quarantine_threshold"] = update.quarantine_threshold

    if update.block_threshold is not None:
        if not (0 <= update.block_threshold <= 100):
            raise HTTPException(
                status_code=400,
                detail="block_threshold must be between 0 and 100",
            )
        await database.set_setting("gateway_block_threshold", str(update.block_threshold))
        settings.GATEWAY_BLOCK_THRESHOLD = update.block_threshold
        updated["block_threshold"] = update.block_threshold

    if not updated:
        raise HTTPException(status_code=400, detail="No valid fields to update")

    return {
        "success": True,
        "updated": updated,
        "current_thresholds": {
            "quarantine": settings.GATEWAY_QUARANTINE_THRESHOLD,
            "block": settings.GATEWAY_BLOCK_THRESHOLD,
        },
    }


@router.get("/config")
async def get_gateway_config():
    """Get current gateway configuration."""
    # Load from DB if overridden
    q_stored = await database.get_setting("gateway_quarantine_threshold")
    b_stored = await database.get_setting("gateway_block_threshold")

    quarantine = int(q_stored) if q_stored else settings.GATEWAY_QUARANTINE_THRESHOLD
    block = int(b_stored) if b_stored else settings.GATEWAY_BLOCK_THRESHOLD

    return {
        "thresholds": {
            "quarantine": quarantine,
            "block": block,
        },
        "imap_polling": {
            "enabled": settings.IMAP_ENABLED,
            "host": settings.IMAP_HOST,
            "folder": settings.IMAP_FOLDER,
            "interval_seconds": settings.IMAP_POLL_INTERVAL,
        },
    }
