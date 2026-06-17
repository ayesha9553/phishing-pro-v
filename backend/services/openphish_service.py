"""OpenPhish feed integration — free phishing URL blacklist."""

import asyncio
import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# OpenPhish public feed (updated every ~6 hours)
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
FEED_REFRESH_INTERVAL = 6 * 3600  # 6 hours in seconds
REQUEST_TIMEOUT = 30


class OpenPhishService:
    """Manages a local in-memory copy of the OpenPhish phishing URL feed."""

    def __init__(self):
        self._feed: set[str] = set()
        self._last_refresh: float = 0.0
        self._lock = asyncio.Lock()
        self._initialized = False

    async def _refresh_feed(self) -> None:
        """Download and update the OpenPhish feed."""
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(OPENPHISH_FEED_URL)
                if resp.status_code == 200:
                    lines = resp.text.strip().splitlines()
                    new_feed = set()
                    for line in lines:
                        url = line.strip()
                        if url:
                            new_feed.add(url)
                            # Also add domain-only for partial matching
                            try:
                                from urllib.parse import urlparse
                                parsed = urlparse(url)
                                if parsed.netloc:
                                    new_feed.add(parsed.netloc.lower())
                            except Exception:
                                pass
                    self._feed = new_feed
                    self._last_refresh = time.time()
                    logger.info(f"OpenPhish feed refreshed: {len(self._feed)} entries")
                else:
                    logger.warning(f"OpenPhish feed returned HTTP {resp.status_code}")
        except Exception as e:
            logger.error(f"Failed to refresh OpenPhish feed: {e}")

    async def _ensure_fresh(self) -> None:
        """Ensure the feed is loaded and not stale."""
        now = time.time()
        if not self._initialized or (now - self._last_refresh) > FEED_REFRESH_INTERVAL:
            async with self._lock:
                # Double-check inside lock
                if not self._initialized or (now - self._last_refresh) > FEED_REFRESH_INTERVAL:
                    await self._refresh_feed()
                    self._initialized = True

    async def check_url(self, url: str) -> dict:
        """
        Check a URL against the OpenPhish feed.
        
        Returns:
            {
                "is_malicious": bool,
                "source": "openphish",
                "feed_size": int,
                "matched": str | None,
            }
        """
        await self._ensure_fresh()

        matched = None
        is_malicious = False

        # Exact URL match
        if url in self._feed:
            is_malicious = True
            matched = url
        else:
            # Domain match
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                if domain in self._feed:
                    is_malicious = True
                    matched = domain
                # Strip www.
                bare = domain.replace("www.", "")
                if bare in self._feed:
                    is_malicious = True
                    matched = bare
            except Exception:
                pass

        return {
            "is_malicious": is_malicious,
            "source": "openphish",
            "feed_size": len(self._feed),
            "matched": matched,
            "last_updated": self._last_refresh,
        }

    async def check_urls_batch(self, urls: list[str]) -> dict[str, dict]:
        """Check multiple URLs at once."""
        await self._ensure_fresh()
        return {url: await self.check_url(url) for url in urls}

    @property
    def feed_size(self) -> int:
        return len(self._feed)

    @property
    def last_updated(self) -> float:
        return self._last_refresh


# Singleton instance
openphish_service = OpenPhishService()
