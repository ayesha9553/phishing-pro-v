"""Settings API routes."""

from fastapi import APIRouter
from backend import database
from backend.models.schemas import SettingsUpdate

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
async def get_settings():
    """Get current application settings."""
    vt_key = await database.get_setting("virustotal_api_key", "")
    return {
        "virustotal_api_key": "***" + vt_key[-4:] if len(vt_key) > 4 else "",
        "virustotal_configured": bool(vt_key),
    }


@router.put("")
async def update_settings(settings: SettingsUpdate):
    """Update application settings."""
    if settings.virustotal_api_key is not None:
        await database.set_setting("virustotal_api_key", settings.virustotal_api_key)

    return {"message": "Settings updated successfully"}
