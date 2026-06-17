"""History API routes — scan history and dashboard stats."""

from fastapi import APIRouter, HTTPException, Query
from backend import database

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("")
async def get_history(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    risk_level: str | None = Query(default=None),
    source: str | None = Query(default=None),
):
    """Get paginated scan history with optional filters."""
    scans, total = await database.get_scan_history(
        limit=limit, offset=offset, risk_level=risk_level, source=source
    )
    return {
        "scans": scans,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/stats")
async def get_stats():
    """Get dashboard statistics (totals, breakdowns, trends)."""
    return await database.get_dashboard_stats()


@router.get("/{scan_id}")
async def get_scan_detail(scan_id: int):
    """Get full details of a specific scan."""
    scan = await database.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.delete("/{scan_id}")
async def delete_scan(scan_id: int):
    """Delete a scan record."""
    deleted = await database.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"message": "Scan deleted successfully"}


@router.delete("")
async def clear_history():
    """Clear all scan history."""
    await database.clear_all_scans()
    return {"message": "All scan history cleared"}
