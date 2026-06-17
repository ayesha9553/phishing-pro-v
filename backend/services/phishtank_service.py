"""PhishTank API integration — community-verified phishing URL database."""

import asyncio
import logging
import time
import hashlib
from typing import Optional
from urllib.parse import urlparse

import httpx

from backend.config import settings
from backend import database

logger = logging.getLogger(__name__)

PHISHTANK_VERIFY_URL = "https://checkurl.phishtank.com/checkurl/"
PHISHTANK_FEED_URL = "https://data.phishtank.com/data/{key}/online-valid.json"
REQUEST_TIMEOUT = 15
CACHE_TTL_HOURS = 6


class PhishTankService:
    """PhishTank URL reputation checking with SQLite cache."""

    def __init__(self):
        self._app_key = settings.PHISHTANK_APP_KEY
        self._lock = asyncio.Lock()

    async def check_url(self, url: str) -> dict:
        """
        Check a URL against PhishTank.
        First checks local cache, then queries PhishTank API.

        Returns:
            {
                "is_malicious": bool,
                "source": "phishtank",
                "verified": bool,
                "phish_id": str | None,
                "phish_detail_url": str | None,
                "in_database": bool,
                "cached": bool,
            }
        """
        # Check cache first
        cached = await database.get_threat_intel_cache(url, "phishtank")
        if cached:
            return {
                "is_malicious": bool(cached["is_malicious"]),
                "source": "phishtank",
                "cached": True,
                **cached.get("details", {}),
            }

        # Query PhishTank API
        result = await self._query_phishtank(url)

        # Cache the result
        await database.set_threat_intel_cache(
            url, "phishtank",
            result.get("is_malicious", False),
            result,
        )

        return result

    async def _query_phishtank(self, url: str) -> dict:
        """Query PhishTank API for URL verification."""
        headers = {
            "User-Agent": "phishtank/PhishingPro",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        payload = {"url": url, "format": "json"}
        if self._app_key:
            payload["app_key"] = self._app_key

        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                resp = await client.post(
                    PHISHTANK_VERIFY_URL,
                    data=payload,
                    headers=headers,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", {})
                    in_db = results.get("in_database", False)
                    verified = results.get("verified", False)
                    phish_id = results.get("phish_id")
                    phish_detail = results.get("phish_detail_url", "")

                    is_malicious = in_db and verified

                    return {
                        "is_malicious": is_malicious,
                        "source": "phishtank",
                        "in_database": in_db,
                        "verified": verified,
                        "phish_id": phish_id,
                        "phish_detail_url": phish_detail,
                        "cached": False,
                    }

                elif resp.status_code == 429:
                    logger.warning("PhishTank rate limit hit")
                    return self._error_result("Rate limit exceeded")

                else:
                    logger.warning(f"PhishTank returned HTTP {resp.status_code}")
                    return self._error_result(f"HTTP {resp.status_code}")

        except httpx.TimeoutException:
            logger.warning(f"PhishTank timeout for URL: {url[:80]}")
            return self._error_result("Timeout")
        except Exception as e:
            logger.error(f"PhishTank error: {e}")
            return self._error_result(str(e))

    def _error_result(self, error: str) -> dict:
        return {
            "is_malicious": False,
            "source": "phishtank",
            "in_database": False,
            "verified": False,
            "phish_id": None,
            "phish_detail_url": None,
            "cached": False,
            "error": error,
        }

    async def check_urls_batch(self, urls: list[str], max_concurrent: int = 3) -> dict[str, dict]:
        """Check multiple URLs with concurrency control."""
        sem = asyncio.Semaphore(max_concurrent)

        async def _limited_check(url: str) -> tuple[str, dict]:
            async with sem:
                result = await self.check_url(url)
                return url, result

        tasks = [_limited_check(url) for url in urls[:10]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        output = {}
        for item in results:
            if isinstance(item, Exception):
                logger.error(f"PhishTank batch error: {item}")
            else:
                url, result = item
                output[url] = result

        return output


# Singleton instance
phishtank_service = PhishTankService()
