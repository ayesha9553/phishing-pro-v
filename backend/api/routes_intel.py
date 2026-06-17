"""Threat Intelligence API routes — URL/domain reputation and user reports."""

import logging
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel
from typing import Optional

from backend.services.openphish_service import openphish_service
from backend.services.phishtank_service import phishtank_service
from backend.services.domain_reputation_service import analyze_domain
from backend.services.virustotal_service import scan_url as vt_scan_url
from backend.config import settings
from backend import database

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/intel", tags=["threat-intelligence"])


class UserReportRequest(BaseModel):
    scan_id: Optional[int] = None
    reporter_email: Optional[str] = ""
    report_type: str = "general"  # 'false_positive' | 'missed_threat' | 'general'
    comment: str = ""


@router.get("/check")
async def check_url_intel(url: str = Query(..., description="URL to check against all threat intel sources")):
    """Check a URL against VirusTotal, OpenPhish, and PhishTank."""
    if not url or not url.strip():
        raise HTTPException(status_code=400, detail="URL parameter is required")

    url = url.strip()
    results: dict = {"url": url, "sources": {}, "overall_malicious": False}

    # OpenPhish (always available, free feed)
    try:
        op_result = await openphish_service.check_url(url)
        results["sources"]["openphish"] = op_result
        if op_result.get("is_malicious"):
            results["overall_malicious"] = True
    except Exception as e:
        logger.error(f"OpenPhish check failed: {e}")
        results["sources"]["openphish"] = {"error": str(e)}

    # PhishTank
    try:
        pt_result = await phishtank_service.check_url(url)
        results["sources"]["phishtank"] = pt_result
        if pt_result.get("is_malicious"):
            results["overall_malicious"] = True
    except Exception as e:
        logger.error(f"PhishTank check failed: {e}")
        results["sources"]["phishtank"] = {"error": str(e)}

    # VirusTotal (if configured)
    vt_api_key = await database.get_setting("virustotal_api_key") or settings.VIRUSTOTAL_API_KEY
    if vt_api_key:
        try:
            vt_result = await vt_scan_url(url, vt_api_key)
            if vt_result:
                vt_data = {
                    "is_malicious": vt_result.is_malicious,
                    "is_suspicious": vt_result.is_suspicious,
                    "malicious_count": vt_result.malicious,
                    "suspicious_count": vt_result.suspicious,
                    "total_vendors": vt_result.total,
                    "permalink": vt_result.permalink,
                    "source": "virustotal",
                }
                results["sources"]["virustotal"] = vt_data
                if vt_result.is_malicious:
                    results["overall_malicious"] = True
            else:
                results["sources"]["virustotal"] = {"error": "No result returned"}
        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
            results["sources"]["virustotal"] = {"error": str(e)}
    else:
        results["sources"]["virustotal"] = {"enabled": False, "message": "API key not configured"}

    # Cache combined result
    await database.set_threat_intel_cache(
        url, "combined",
        results["overall_malicious"],
        {"sources": list(results["sources"].keys())},
    )

    return results


@router.get("/domain")
async def check_domain_reputation(domain: str = Query(..., description="Domain or URL to analyze")):
    """Get full domain reputation report — WHOIS, domain age, SSL certificate."""
    if not domain or not domain.strip():
        raise HTTPException(status_code=400, detail="Domain parameter is required")

    try:
        result = await analyze_domain(domain.strip())
        return result
    except Exception as e:
        logger.error(f"Domain reputation check failed for {domain}: {e}")
        raise HTTPException(status_code=500, detail=f"Domain analysis failed: {str(e)}")


@router.get("/feed-status")
async def get_feed_status():
    """Get status of all threat intelligence feeds."""
    import time
    now = time.time()

    op_last = openphish_service.last_updated
    op_age = round((now - op_last) / 3600, 1) if op_last else None

    return {
        "openphish": {
            "feed_size": openphish_service.feed_size,
            "last_updated_hours_ago": op_age,
            "status": "ok" if openphish_service.feed_size > 0 else "not_loaded",
        },
        "phishtank": {
            "configured": bool(settings.PHISHTANK_APP_KEY),
            "status": "ok",
        },
        "virustotal": {
            "configured": bool(
                await database.get_setting("virustotal_api_key") or settings.VIRUSTOTAL_API_KEY
            ),
        },
    }


@router.post("/report")
async def submit_user_report(request: UserReportRequest):
    """Submit a user threat report (false positive, missed threat, etc.)."""
    valid_types = {"false_positive", "missed_threat", "general"}
    if request.report_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid report_type. Must be one of: {', '.join(valid_types)}",
        )

    report_id = await database.create_user_report(
        scan_id=request.scan_id,
        reporter_email=request.reporter_email or "",
        report_type=request.report_type,
        comment=request.comment,
    )

    return {"success": True, "report_id": report_id}


@router.get("/reports")
async def get_user_reports(limit: int = Query(default=50, le=200)):
    """Get recent user-submitted threat reports."""
    reports = await database.get_user_reports(limit=limit)
    return {"reports": reports, "total": len(reports)}
