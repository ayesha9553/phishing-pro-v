"""AI Threat Analysis API routes — LLM-powered phishing summaries."""

import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from backend.services.ai_analysis_service import analyze_scan
from backend.config import settings
from backend import database

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/ai", tags=["ai-analysis"])


class AIScanAnalysisRequest(BaseModel):
    """Request to analyze an existing scan by ID."""
    scan_id: int


class AICustomAnalysisRequest(BaseModel):
    """Request to summarize custom phishing indicators."""
    indicators: list[str]
    context: Optional[str] = ""


@router.post("/analyze")
async def analyze_scan_by_id(request: AIScanAnalysisRequest):
    """
    Generate an AI-powered threat analysis summary for an existing scan.
    
    The summary is cached in the database after generation for subsequent requests.
    """
    # Fetch the scan
    scan = await database.get_scan(request.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {request.scan_id} not found")

    # Return cached summary if available
    if scan.get("ai_summary"):
        return {
            "scan_id": request.scan_id,
            "summary": scan["ai_summary"],
            "provider": settings.AI_PROVIDER,
            "cached": True,
        }

    # Generate new summary
    try:
        summary = await analyze_scan(scan)
    except Exception as e:
        logger.error(f"AI analysis failed for scan {request.scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")

    # Cache the summary
    await database.update_scan_ai_summary(request.scan_id, summary)

    return {
        "scan_id": request.scan_id,
        "summary": summary,
        "provider": settings.AI_PROVIDER,
        "cached": False,
    }


@router.post("/summarize")
async def summarize_indicators(request: AICustomAnalysisRequest):
    """
    Generate an AI summary for a list of custom phishing indicators.
    Useful for quick threat briefings without a full email scan.
    """
    if not request.indicators:
        raise HTTPException(status_code=400, detail="At least one indicator is required")

    # Build a synthetic scan data structure
    synthetic_scan = {
        "risk_score": 75,
        "risk_level": "high",
        "findings": [
            {"severity": "high", "title": indicator, "description": indicator, "category": "manual"}
            for indicator in request.indicators[:10]
        ],
        "urls_analyzed": [],
        "subject": request.context or "Manual threat briefing",
        "sender": "",
        "body_preview": request.context or "",
    }

    try:
        summary = await analyze_scan(synthetic_scan)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    return {
        "summary": summary,
        "provider": settings.AI_PROVIDER,
        "indicators_analyzed": len(request.indicators),
    }


@router.get("/status")
async def get_ai_status():
    """Get the AI analysis service status and configuration."""
    provider = settings.AI_PROVIDER.lower()

    return {
        "provider": settings.AI_PROVIDER,
        "enabled": provider not in ("none", ""),
        "openai_configured": bool(settings.OPENAI_API_KEY),
        "gemini_configured": bool(settings.GOOGLE_API_KEY),
        "fallback_available": True,  # Rule-based always available
        "model": (
            "gpt-4o-mini" if provider == "openai"
            else "gemini-1.5-flash" if provider == "gemini"
            else "rule-based"
        ),
    }
