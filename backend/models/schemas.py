"""Pydantic schemas for API request/response models."""

from pydantic import BaseModel, Field
from typing import Optional


class Finding(BaseModel):
    """A single finding from an analyzer."""

    category: str = Field(description="Analyzer category: header, url, content, auth")
    severity: str = Field(description="Severity: info, low, medium, high, critical")
    title: str = Field(description="Short finding title")
    description: str = Field(description="Detailed description of the finding")
    evidence: Optional[str] = Field(
        default=None, description="The specific evidence that triggered this finding"
    )


class URLAnalysis(BaseModel):
    """Analysis result for a single URL."""

    url: str
    is_suspicious: bool = False
    reasons: list[str] = Field(default_factory=list)


class EmailData(BaseModel):
    """Normalized parsed email representation."""

    subject: str = ""
    sender: str = ""
    sender_display_name: str = ""
    reply_to: str = ""
    recipient: str = ""
    date: str = ""
    message_id: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    raw_headers: str = ""
    body_plain: str = ""
    body_html: str = ""
    urls: list[str] = Field(default_factory=list)
    attachment_names: list[str] = Field(default_factory=list)
    attachment_hashes: dict[str, str] = Field(default_factory=dict)
    received_chain: list[str] = Field(default_factory=list)
    authentication_results: str = ""
    dkim_signature: str = ""
    spf_record: str = ""


class ScanResult(BaseModel):
    """Complete scan result with all findings."""

    id: Optional[int] = None
    source: str = "upload"
    subject: str = ""
    sender: str = ""
    sender_display_name: str = ""
    recipient: str = ""
    email_date: str = ""
    risk_score: float = 0.0
    risk_level: str = "safe"
    findings: list[Finding] = Field(default_factory=list)
    urls_analyzed: list[URLAnalysis] = Field(default_factory=list)
    body_preview: str = ""
    attachment_names: list[str] = Field(default_factory=list)
    attachment_hashes: dict[str, str] = Field(default_factory=dict)
    raw_headers: str = ""
    created_at: Optional[str] = None


class ScanHistoryItem(BaseModel):
    """Lightweight scan for history list."""

    id: int
    source: str
    subject: str = ""
    sender: str = ""
    risk_score: float
    risk_level: str
    created_at: str


class DashboardStats(BaseModel):
    """Dashboard aggregate statistics."""

    total_scans: int = 0
    threats_detected: int = 0
    safe_emails: int = 0
    avg_risk_score: float = 0.0
    risk_breakdown: dict[str, int] = Field(default_factory=dict)
    daily_trend: list[dict] = Field(default_factory=list)
    recent_scans: list[dict] = Field(default_factory=list)


class ScanTextRequest(BaseModel):
    """Request body for scanning raw email text."""

    raw_email: str = Field(description="Complete raw email content including headers")


class SettingsUpdate(BaseModel):
    """Settings update request."""

    virustotal_api_key: Optional[str] = None
