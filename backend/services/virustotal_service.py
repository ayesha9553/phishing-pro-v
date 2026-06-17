"""VirusTotal v3 API integration for URL reputation scanning."""

import asyncio
import hashlib
import logging
import base64
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = 15  # seconds per request
VT_POLL_DELAY = 3  # seconds between poll attempts
VT_MAX_POLLS = 3   # max times we poll before giving up


class VTResult:
    """Result from VirusTotal URL analysis."""

    def __init__(
        self,
        url: str,
        malicious: int = 0,
        suspicious: int = 0,
        harmless: int = 0,
        undetected: int = 0,
        total: int = 0,
        permalink: str = "",
        error: Optional[str] = None,
    ):
        self.url = url
        self.malicious = malicious
        self.suspicious = suspicious
        self.harmless = harmless
        self.undetected = undetected
        self.total = total
        self.permalink = permalink
        self.error = error

    @property
    def is_malicious(self) -> bool:
        return self.malicious >= 2

    @property
    def is_suspicious(self) -> bool:
        return self.suspicious >= 2 or self.malicious >= 1

    @property
    def summary(self) -> str:
        if self.error:
            return f"VT error: {self.error}"
        return f"{self.malicious} malicious, {self.suspicious} suspicious / {self.total} vendors"


def _url_id(url: str) -> str:
    """VirusTotal URL ID is the URL-safe base64 of the raw URL (no padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def scan_url(url: str, api_key: str) -> Optional[VTResult]:
    """
    Submit a URL to VirusTotal and return the analysis result.
    Returns None on any error so callers can safely ignore VT failures.
    """
    if not api_key or not url:
        return None

    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=VT_TIMEOUT) as client:
            # First, try to get existing analysis (avoids quota usage for known URLs)
            url_id = _url_id(url)
            resp = await client.get(f"{VT_BASE}/urls/{url_id}", headers=headers)

            if resp.status_code == 200:
                return _parse_vt_response(url, resp.json())

            if resp.status_code == 404:
                # URL not in VT cache — submit for analysis
                submit_resp = await client.post(
                    f"{VT_BASE}/urls",
                    headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                    data=f"url={url}",
                )
                if submit_resp.status_code not in (200, 201):
                    logger.warning(f"VT submit failed for {url}: {submit_resp.status_code}")
                    return None

                analysis_id = submit_resp.json().get("data", {}).get("id", "")
                if not analysis_id:
                    return None

                # Poll for result
                for _ in range(VT_MAX_POLLS):
                    await asyncio.sleep(VT_POLL_DELAY)
                    poll_resp = await client.get(
                        f"{VT_BASE}/analyses/{analysis_id}",
                        headers=headers,
                    )
                    if poll_resp.status_code == 200:
                        data = poll_resp.json()
                        status = data.get("data", {}).get("attributes", {}).get("status", "")
                        if status == "completed":
                            # Fetch the full URL object for the stats
                            url_resp = await client.get(
                                f"{VT_BASE}/urls/{url_id}", headers=headers
                            )
                            if url_resp.status_code == 200:
                                return _parse_vt_response(url, url_resp.json())
                            break

            elif resp.status_code == 429:
                logger.warning("VirusTotal rate limit hit — skipping VT scan")
                return None
            else:
                logger.warning(f"VT lookup returned {resp.status_code} for {url}")
                return None

    except httpx.TimeoutException:
        logger.warning(f"VirusTotal timeout for URL: {url[:80]}")
        return None
    except Exception as exc:
        logger.error(f"VirusTotal error for {url[:80]}: {exc}")
        return None

    return None


def _parse_vt_response(url: str, data: dict) -> VTResult:
    """Parse a VirusTotal URL object response into VTResult."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    url_id = _url_id(url)

    return VTResult(
        url=url,
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        total=sum(stats.values()),
        permalink=f"https://www.virustotal.com/gui/url/{url_id}",
    )


async def scan_urls_batch(
    urls: list[str],
    api_key: str,
    max_concurrent: int = 3,
) -> dict[str, Optional[VTResult]]:
    """
    Scan multiple URLs concurrently with a semaphore to respect rate limits.
    Returns dict mapping url → VTResult (or None if failed).
    """
    if not api_key or not urls:
        return {}

    sem = asyncio.Semaphore(max_concurrent)

    async def _limited_scan(url: str) -> tuple[str, Optional[VTResult]]:
        async with sem:
            result = await scan_url(url, api_key)
            return url, result

    tasks = [_limited_scan(url) for url in urls[:10]]  # Cap at 10 URLs per scan
    results = await asyncio.gather(*tasks, return_exceptions=True)

    output: dict[str, Optional[VTResult]] = {}
    for item in results:
        if isinstance(item, Exception):
            logger.error(f"VT batch scan error: {item}")
        else:
            url, result = item
            output[url] = result

    return output
