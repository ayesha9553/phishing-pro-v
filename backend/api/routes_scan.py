"""Scan API routes — upload and analyze emails."""

import json
from datetime import datetime, timezone
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import Response
from backend.services.email_parser import parse_eml, parse_msg, parse_raw_email
from backend.services.scanner_service import scan_email
from backend.models.schemas import ScanResult, ScanTextRequest
from backend import database

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.post("/upload", response_model=ScanResult)
async def scan_upload(file: UploadFile = File(...)):
    """Upload an .eml or .msg file for phishing analysis."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    filename_lower = file.filename.lower()
    if not filename_lower.endswith((".eml", ".msg")):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Please upload .eml or .msg files.",
        )

    # Read file content
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file uploaded")

    # Size check (25MB max)
    if len(content) > 25 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 25MB)")

    try:
        if filename_lower.endswith(".eml"):
            email_data = parse_eml(content)
        else:
            email_data = parse_msg(content)
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail=f"Failed to parse email file: {str(e)}",
        )

    # Run the scan
    result = await scan_email(email_data, source="upload")
    return result


@router.post("/text", response_model=ScanResult)
async def scan_text(request: ScanTextRequest):
    """Scan raw email text (including headers) for phishing indicators."""
    if not request.raw_email.strip():
        raise HTTPException(status_code=400, detail="Empty email text provided")

    try:
        email_data = parse_raw_email(request.raw_email)
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail=f"Failed to parse email text: {str(e)}",
        )

    result = await scan_email(email_data, source="paste")
    return result


@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: int):
    """Get detailed results of a previous scan."""
    scan = await database.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/export")
async def export_scan(scan_id: int):
    """Export scan results as a downloadable JSON report."""
    scan = await database.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Build a structured report
    report = {
        "report_title": "PhishingPro — Email Analysis Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_id": scan.get("id"),
        "summary": {
            "risk_score": scan.get("risk_score", 0),
            "risk_level": scan.get("risk_level", "safe"),
            "total_findings": len(scan.get("findings", [])),
            "urls_analyzed": len(scan.get("urls_analyzed", [])),
        },
        "email_metadata": {
            "subject": scan.get("subject", ""),
            "sender": scan.get("sender", ""),
            "sender_display_name": scan.get("sender_display_name", ""),
            "recipient": scan.get("recipient", ""),
            "date": scan.get("email_date", ""),
            "source": scan.get("source", ""),
            "scanned_at": scan.get("created_at", ""),
        },
        "findings": scan.get("findings", []),
        "urls_analyzed": scan.get("urls_analyzed", []),
        "body_preview": scan.get("body_preview", ""),
        "attachment_names": scan.get("attachment_names", []),
    }

    report_json = json.dumps(report, indent=2, ensure_ascii=False)
    filename = f"phishingpro_report_{scan_id}.json"

    return Response(
        content=report_json,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
