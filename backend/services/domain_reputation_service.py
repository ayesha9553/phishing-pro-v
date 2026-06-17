"""Domain Reputation Engine — WHOIS analysis, domain age, SSL certificate validation."""

import asyncio
import logging
import ssl
import socket
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

from backend import database

logger = logging.getLogger(__name__)


def _extract_domain(url_or_domain: str) -> str:
    """Extract the bare domain from a URL or domain string."""
    if url_or_domain.startswith(("http://", "https://")):
        parsed = urlparse(url_or_domain)
        domain = parsed.netloc
    else:
        domain = url_or_domain

    # Strip port and www.
    domain = domain.split(":")[0].strip().lower()
    return domain


def _calculate_age_days(creation_date) -> Optional[int]:
    """Calculate domain age in days from a WHOIS creation date."""
    if not creation_date:
        return None

    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    if isinstance(creation_date, str):
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%d-%b-%Y", "%Y.%m.%d"):
            try:
                creation_date = datetime.strptime(creation_date, fmt)
                break
            except ValueError:
                continue
        else:
            return None

    if isinstance(creation_date, datetime):
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return max(0, (now - creation_date).days)

    return None


async def _get_whois_data(domain: str) -> dict:
    """Fetch WHOIS data for a domain."""
    result = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "age_days": None,
        "country": None,
        "name_servers": [],
        "raw": None,
        "error": None,
    }

    try:
        import whois as python_whois
        loop = asyncio.get_event_loop()

        def _do_whois():
            return python_whois.whois(domain)

        w = await asyncio.wait_for(
            loop.run_in_executor(None, _do_whois),
            timeout=15.0,
        )

        if w:
            creation = w.creation_date
            expiration = w.expiration_date

            result["registrar"] = w.registrar or None
            result["country"] = w.country or None
            result["name_servers"] = (
                [str(ns).lower() for ns in w.name_servers] if w.name_servers else []
            )

            if creation:
                d = creation[0] if isinstance(creation, list) else creation
                result["creation_date"] = str(d)
                result["age_days"] = _calculate_age_days(d)

            if expiration:
                d = expiration[0] if isinstance(expiration, list) else expiration
                result["expiration_date"] = str(d)

    except asyncio.TimeoutError:
        result["error"] = "WHOIS lookup timed out"
        logger.warning(f"WHOIS timeout for {domain}")
    except Exception as e:
        result["error"] = str(e)
        logger.debug(f"WHOIS error for {domain}: {e}")

    return result


async def _get_ssl_info(domain: str) -> dict:
    """Fetch SSL certificate info for a domain."""
    result = {
        "valid": False,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "is_expired": False,
        "is_self_signed": False,
        "san_domains": [],
        "error": None,
    }

    try:
        loop = asyncio.get_event_loop()

        def _fetch_cert():
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return cert

        cert = await asyncio.wait_for(
            loop.run_in_executor(None, _fetch_cert),
            timeout=12.0,
        )

        if cert:
            result["valid"] = True

            # Issuer
            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            result["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName")

            # Subject
            subject_dict = dict(x[0] for x in cert.get("subject", []))
            result["subject"] = subject_dict.get("commonName")

            # Dates
            not_after_str = cert.get("notAfter", "")
            not_before_str = cert.get("notBefore", "")

            result["not_before"] = not_before_str
            result["not_after"] = not_after_str

            if not_after_str:
                try:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    not_after = not_after.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    remaining = (not_after - now).days
                    result["days_remaining"] = remaining
                    result["is_expired"] = remaining < 0
                except ValueError:
                    pass

            # Self-signed check
            issuer_org = (result["issuer"] or "").lower()
            subject_cn = (result["subject"] or "").lower()
            result["is_self_signed"] = issuer_org == subject_cn or "self" in issuer_org

            # SANs (Subject Alternative Names)
            san_list = []
            for san_type, san_value in cert.get("subjectAltName", []):
                if san_type == "DNS":
                    san_list.append(san_value)
            result["san_domains"] = san_list

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"SSL verification failed: {e}"
        result["valid"] = False
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        result["error"] = f"Cannot connect: {e}"
    except asyncio.TimeoutError:
        result["error"] = "SSL fetch timed out"
    except Exception as e:
        result["error"] = str(e)
        logger.debug(f"SSL error for {domain}: {e}")

    return result


def _calculate_reputation_score(whois: dict, ssl: dict, domain: str) -> tuple[float, list[str]]:
    """
    Calculate a domain reputation score (0-100, higher = more suspicious).
    Returns (score, list_of_risk_factors).
    """
    score = 0.0
    flags = []

    # Domain age
    age_days = whois.get("age_days")
    if age_days is None:
        score += 15
        flags.append("No WHOIS creation date found")
    elif age_days < 30:
        score += 40
        flags.append(f"Very new domain: {age_days} days old")
    elif age_days < 90:
        score += 25
        flags.append(f"Recently registered domain: {age_days} days old")
    elif age_days < 365:
        score += 10
        flags.append(f"Domain less than 1 year old: {age_days} days")

    # SSL certificate
    if not ssl.get("valid"):
        score += 20
        flags.append("No valid SSL certificate")
    elif ssl.get("is_self_signed"):
        score += 15
        flags.append("Self-signed SSL certificate")
    elif ssl.get("is_expired"):
        score += 20
        flags.append("SSL certificate is expired")
    elif ssl.get("days_remaining") is not None and ssl.get("days_remaining", 999) < 14:
        score += 10
        flags.append(f"SSL certificate expires in {ssl['days_remaining']} days")

    # Suspicious domain patterns
    suspicious_tlds = {".xyz", ".top", ".club", ".work", ".info", ".biz", ".tk", ".ml", ".cf", ".gq", ".ga"}
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            score += 15
            flags.append(f"Suspicious TLD: {tld}")
            break

    # Long domain names (common in phishing)
    bare = domain.replace("www.", "")
    if len(bare) > 40:
        score += 10
        flags.append(f"Unusually long domain name ({len(bare)} chars)")

    # Numeric IP as domain
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if ip_pattern.match(domain):
        score += 25
        flags.append("IP address used as domain (no hostname)")

    # Hyphen abuse (common phishing technique)
    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        score += 10
        flags.append(f"Multiple hyphens in domain ({hyphen_count})")

    # Punycode / IDN homograph
    if "xn--" in domain:
        score += 20
        flags.append("Punycode/IDN domain — possible homograph attack")

    return min(score, 100.0), flags


async def analyze_domain(url_or_domain: str) -> dict:
    """
    Full domain reputation analysis.
    Returns cached result if available, otherwise runs all checks.
    """
    domain = _extract_domain(url_or_domain)

    if not domain:
        return {"error": "Could not extract domain", "domain": url_or_domain}

    # Check cache first
    cached = await database.get_domain_reputation(domain)
    if cached:
        cached["cached"] = True
        return cached

    # Run WHOIS and SSL checks concurrently
    whois_data, ssl_data = await asyncio.gather(
        _get_whois_data(domain),
        _get_ssl_info(domain),
    )

    reputation_score, risk_flags = _calculate_reputation_score(whois_data, ssl_data, domain)

    # Determine risk level
    if reputation_score >= 70:
        risk_level = "high"
    elif reputation_score >= 40:
        risk_level = "medium"
    elif reputation_score >= 20:
        risk_level = "low"
    else:
        risk_level = "safe"

    result = {
        "domain": domain,
        "whois_registrar": whois_data.get("registrar"),
        "creation_date": whois_data.get("creation_date"),
        "domain_age_days": whois_data.get("age_days"),
        "ssl_valid": ssl_data.get("valid", False),
        "ssl_issuer": ssl_data.get("issuer"),
        "ssl_expires": ssl_data.get("not_after"),
        "ssl_days_remaining": ssl_data.get("days_remaining"),
        "reputation_score": reputation_score,
        "risk_level": risk_level,
        "risk_flags": risk_flags,
        "details": {
            "whois": whois_data,
            "ssl": ssl_data,
        },
        "cached": False,
    }

    # Save to cache
    await database.save_domain_reputation(result)

    return result
