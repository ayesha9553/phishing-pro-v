"""Async SQLite database management."""

import json
import aiosqlite
from pathlib import Path
from backend.config import settings


_db_connection: aiosqlite.Connection | None = None

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL DEFAULT 'upload',
    subject TEXT,
    sender TEXT,
    sender_display_name TEXT,
    recipient TEXT,
    email_date TEXT,
    risk_score REAL NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'safe',
    findings_json TEXT NOT NULL DEFAULT '[]',
    raw_headers TEXT,
    body_preview TEXT,
    attachment_names TEXT,
    ai_summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS urls_analyzed (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    is_suspicious INTEGER NOT NULL DEFAULT 0,
    reasons TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    url_or_domain TEXT NOT NULL,
    source TEXT NOT NULL,
    is_malicious INTEGER DEFAULT 0,
    details_json TEXT DEFAULT '{}',
    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (url_or_domain, source)
);

CREATE TABLE IF NOT EXISTS domain_reputation (
    domain TEXT PRIMARY KEY,
    whois_registrar TEXT,
    creation_date TEXT,
    domain_age_days INTEGER,
    ssl_valid INTEGER DEFAULT 0,
    ssl_issuer TEXT,
    ssl_expires TEXT,
    reputation_score REAL DEFAULT 0,
    details_json TEXT DEFAULT '{}',
    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    reporter_email TEXT,
    report_type TEXT,
    comment TEXT,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gateway_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT,
    envelope_from TEXT,
    envelope_to TEXT,
    subject TEXT,
    scan_id INTEGER REFERENCES scans(id),
    risk_score REAL DEFAULT 0,
    risk_level TEXT DEFAULT 'safe',
    action_taken TEXT DEFAULT 'allowed',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


async def get_db() -> aiosqlite.Connection:
    """Get or create the database connection."""
    global _db_connection
    if _db_connection is None:
        settings.ensure_data_dir()
        _db_connection = await aiosqlite.connect(str(settings.DATABASE_PATH))
        _db_connection.row_factory = aiosqlite.Row
        await _db_connection.execute("PRAGMA journal_mode=WAL")
        await _db_connection.execute("PRAGMA foreign_keys=ON")
        await _db_connection.executescript(SCHEMA_SQL)
        # Add ai_summary column if upgrading from older schema
        try:
            await _db_connection.execute("ALTER TABLE scans ADD COLUMN ai_summary TEXT")
            await _db_connection.commit()
        except Exception:
            pass  # Column already exists
        await _db_connection.commit()
    return _db_connection


async def close_db():
    """Close the database connection."""
    global _db_connection
    if _db_connection:
        await _db_connection.close()
        _db_connection = None


async def save_scan(scan_data: dict) -> int:
    """Save a scan result to the database. Returns the scan ID."""
    db = await get_db()
    cursor = await db.execute(
        """INSERT INTO scans 
           (source, subject, sender, sender_display_name, recipient, email_date,
            risk_score, risk_level, findings_json, raw_headers, body_preview, attachment_names, ai_summary)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            scan_data.get("source", "upload"),
            scan_data.get("subject"),
            scan_data.get("sender"),
            scan_data.get("sender_display_name"),
            scan_data.get("recipient"),
            scan_data.get("email_date"),
            scan_data.get("risk_score", 0),
            scan_data.get("risk_level", "safe"),
            json.dumps(scan_data.get("findings", [])),
            scan_data.get("raw_headers"),
            scan_data.get("body_preview"),
            json.dumps(scan_data.get("attachment_names", [])),
            scan_data.get("ai_summary"),
        ),
    )
    scan_id = cursor.lastrowid

    # Save analyzed URLs
    urls = scan_data.get("urls_analyzed", [])
    for url_data in urls:
        await db.execute(
            """INSERT INTO urls_analyzed (scan_id, url, is_suspicious, reasons)
               VALUES (?, ?, ?, ?)""",
            (
                scan_id,
                url_data.get("url"),
                1 if url_data.get("is_suspicious") else 0,
                json.dumps(url_data.get("reasons", [])),
            ),
        )

    await db.commit()
    return scan_id


async def update_scan_ai_summary(scan_id: int, summary: str):
    """Update the AI summary for an existing scan."""
    db = await get_db()
    await db.execute(
        "UPDATE scans SET ai_summary = ? WHERE id = ?",
        (summary, scan_id),
    )
    await db.commit()


async def get_scan(scan_id: int) -> dict | None:
    """Get a scan by ID."""
    db = await get_db()
    cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = await cursor.fetchone()
    if row is None:
        return None

    scan = dict(row)
    scan["findings"] = json.loads(scan.pop("findings_json", "[]"))
    scan["attachment_names"] = json.loads(scan.get("attachment_names", "[]") or "[]")

    # Fetch associated URLs
    url_cursor = await db.execute(
        "SELECT * FROM urls_analyzed WHERE scan_id = ?", (scan_id,)
    )
    urls = await url_cursor.fetchall()
    scan["urls_analyzed"] = [
        {
            "url": u["url"],
            "is_suspicious": bool(u["is_suspicious"]),
            "reasons": json.loads(u["reasons"] or "[]"),
        }
        for u in urls
    ]

    return scan


async def get_scan_history(
    limit: int = 50,
    offset: int = 0,
    risk_level: str | None = None,
    source: str | None = None,
) -> tuple[list[dict], int]:
    """Get paginated scan history. Returns (scans, total_count)."""
    db = await get_db()

    where_clauses = []
    params = []

    if risk_level:
        where_clauses.append("risk_level = ?")
        params.append(risk_level)
    if source:
        where_clauses.append("source = ?")
        params.append(source)

    where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    # Get total count
    count_cursor = await db.execute(
        f"SELECT COUNT(*) as cnt FROM scans{where_sql}", params
    )
    count_row = await count_cursor.fetchone()
    total = count_row["cnt"]

    # Get paginated results
    cursor = await db.execute(
        f"SELECT * FROM scans{where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    )
    rows = await cursor.fetchall()

    scans = []
    for row in rows:
        scan = dict(row)
        scan["findings"] = json.loads(scan.pop("findings_json", "[]"))
        scan["attachment_names"] = json.loads(scan.get("attachment_names", "[]") or "[]")
        scans.append(scan)

    return scans, total


async def get_dashboard_stats() -> dict:
    """Get aggregated dashboard statistics — enhanced SOC view."""
    db = await get_db()

    # Total scans
    cursor = await db.execute("SELECT COUNT(*) as cnt FROM scans")
    row = await cursor.fetchone()
    total_scans = row["cnt"]

    # Risk level breakdown
    cursor = await db.execute(
        "SELECT risk_level, COUNT(*) as cnt FROM scans GROUP BY risk_level"
    )
    rows = await cursor.fetchall()
    risk_breakdown = {r["risk_level"]: r["cnt"] for r in rows}

    # Average risk score
    cursor = await db.execute("SELECT AVG(risk_score) as avg_score FROM scans")
    row = await cursor.fetchone()
    avg_score = round(row["avg_score"] or 0, 1)

    # Threats detected (medium + high + critical)
    threats = sum(
        risk_breakdown.get(level, 0) for level in ["medium", "high", "critical"]
    )

    # 30-day trend
    cursor = await db.execute(
        """SELECT DATE(created_at) as scan_date, COUNT(*) as cnt, 
           AVG(risk_score) as avg_score,
           SUM(CASE WHEN risk_level IN ('medium','high','critical') THEN 1 ELSE 0 END) as threat_cnt
           FROM scans 
           WHERE created_at >= datetime('now', '-30 days')
           GROUP BY DATE(created_at)
           ORDER BY scan_date"""
    )
    trend_rows = await cursor.fetchall()
    daily_trend = [
        {
            "date": r["scan_date"],
            "count": r["cnt"],
            "avg_score": round(r["avg_score"], 1),
            "threat_count": r["threat_cnt"],
        }
        for r in trend_rows
    ]

    # 7-day trend (for backward compat)
    daily_trend_7 = [d for d in daily_trend if True][-7:]

    # Attack sources (top 10 sender domains)
    cursor = await db.execute(
        """SELECT 
               CASE 
                   WHEN sender LIKE '%@%' THEN LOWER(TRIM(SUBSTR(sender, INSTR(sender, '@') + 1)))
                   ELSE COALESCE(sender, 'unknown')
               END as domain,
               COUNT(*) as cnt,
               AVG(risk_score) as avg_score,
               SUM(CASE WHEN risk_level IN ('medium','high','critical') THEN 1 ELSE 0 END) as threat_cnt
           FROM scans
           WHERE sender IS NOT NULL AND sender != ''
           GROUP BY domain
           ORDER BY threat_cnt DESC, cnt DESC
           LIMIT 10"""
    )
    rows = await cursor.fetchall()
    attack_sources = [
        {
            "domain": r["domain"],
            "count": r["cnt"],
            "avg_score": round(r["avg_score"], 1),
            "threat_count": r["threat_cnt"],
        }
        for r in rows
    ]

    # Top targeted recipients
    cursor = await db.execute(
        """SELECT recipient, COUNT(*) as cnt,
               SUM(CASE WHEN risk_level IN ('medium','high','critical') THEN 1 ELSE 0 END) as threat_cnt
           FROM scans
           WHERE recipient IS NOT NULL AND recipient != ''
           GROUP BY recipient
           ORDER BY cnt DESC
           LIMIT 5"""
    )
    rows = await cursor.fetchall()
    top_recipients = [
        {"recipient": r["recipient"], "count": r["cnt"], "threat_count": r["threat_cnt"]}
        for r in rows
    ]

    # User reports count
    cursor = await db.execute("SELECT COUNT(*) as cnt FROM user_reports")
    row = await cursor.fetchone()
    user_reports_count = row["cnt"]

    # User reports by type
    cursor = await db.execute(
        "SELECT report_type, COUNT(*) as cnt FROM user_reports GROUP BY report_type"
    )
    rows = await cursor.fetchall()
    reports_by_type = {r["report_type"]: r["cnt"] for r in rows}

    # Gateway stats
    cursor = await db.execute(
        """SELECT action_taken, COUNT(*) as cnt FROM gateway_emails GROUP BY action_taken"""
    )
    rows = await cursor.fetchall()
    gateway_stats = {r["action_taken"]: r["cnt"] for r in rows}

    # Threat category breakdown (from findings_json)
    cursor = await db.execute(
        "SELECT findings_json FROM scans WHERE findings_json != '[]' ORDER BY created_at DESC LIMIT 200"
    )
    rows = await cursor.fetchall()
    category_counts: dict[str, int] = {}
    for row in rows:
        try:
            findings = json.loads(row["findings_json"])
            for f in findings:
                cat = f.get("category", "unknown")
                category_counts[cat] = category_counts.get(cat, 0) + 1
        except Exception:
            pass

    # Risk score distribution buckets
    cursor = await db.execute(
        """SELECT 
            SUM(CASE WHEN risk_score < 20 THEN 1 ELSE 0 END) as s0_20,
            SUM(CASE WHEN risk_score >= 20 AND risk_score < 40 THEN 1 ELSE 0 END) as s20_40,
            SUM(CASE WHEN risk_score >= 40 AND risk_score < 60 THEN 1 ELSE 0 END) as s40_60,
            SUM(CASE WHEN risk_score >= 60 AND risk_score < 80 THEN 1 ELSE 0 END) as s60_80,
            SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as s80_100
           FROM scans"""
    )
    row = await cursor.fetchone()
    score_distribution = {
        "0-20": row["s0_20"] or 0,
        "20-40": row["s20_40"] or 0,
        "40-60": row["s40_60"] or 0,
        "60-80": row["s60_80"] or 0,
        "80-100": row["s80_100"] or 0,
    }

    # Recent scans
    cursor = await db.execute(
        "SELECT id, source, subject, sender, risk_score, risk_level, created_at FROM scans ORDER BY created_at DESC LIMIT 10"
    )
    recent = [dict(r) for r in await cursor.fetchall()]

    return {
        "total_scans": total_scans,
        "threats_detected": threats,
        "safe_emails": risk_breakdown.get("safe", 0) + risk_breakdown.get("low", 0),
        "avg_risk_score": avg_score,
        "risk_breakdown": risk_breakdown,
        "daily_trend": daily_trend_7,
        "daily_trend_30": daily_trend,
        "recent_scans": recent,
        "attack_sources": attack_sources,
        "top_recipients": top_recipients,
        "user_reports_count": user_reports_count,
        "reports_by_type": reports_by_type,
        "gateway_stats": gateway_stats,
        "category_breakdown": category_counts,
        "score_distribution": score_distribution,
    }


async def delete_scan(scan_id: int) -> bool:
    """Delete a scan and its associated URLs."""
    db = await get_db()
    cursor = await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    await db.commit()
    return cursor.rowcount > 0


async def clear_all_scans():
    """Delete all scan data."""
    db = await get_db()
    await db.execute("DELETE FROM urls_analyzed")
    await db.execute("DELETE FROM scans")
    await db.commit()


async def get_setting(key: str, default: str = "") -> str:
    """Get an app setting value."""
    db = await get_db()
    cursor = await db.execute(
        "SELECT value FROM app_settings WHERE key = ?", (key,)
    )
    row = await cursor.fetchone()
    return row["value"] if row else default


async def set_setting(key: str, value: str):
    """Set an app setting value."""
    db = await get_db()
    await db.execute(
        "INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)",
        (key, value),
    )
    await db.commit()


# ── Threat Intel Cache ────────────────────────────────────────────────────────

async def get_threat_intel_cache(url_or_domain: str, source: str) -> dict | None:
    """Get a cached threat intel result (max 6h TTL)."""
    db = await get_db()
    cursor = await db.execute(
        """SELECT * FROM threat_intel_cache 
           WHERE url_or_domain = ? AND source = ?
           AND cached_at >= datetime('now', '-6 hours')""",
        (url_or_domain, source),
    )
    row = await cursor.fetchone()
    if row:
        result = dict(row)
        result["details"] = json.loads(result.get("details_json", "{}"))
        return result
    return None


async def set_threat_intel_cache(url_or_domain: str, source: str, is_malicious: bool, details: dict):
    """Cache a threat intel result."""
    db = await get_db()
    await db.execute(
        """INSERT OR REPLACE INTO threat_intel_cache 
           (url_or_domain, source, is_malicious, details_json, cached_at)
           VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)""",
        (url_or_domain, source, 1 if is_malicious else 0, json.dumps(details)),
    )
    await db.commit()


# ── Domain Reputation ─────────────────────────────────────────────────────────

async def get_domain_reputation(domain: str) -> dict | None:
    """Get cached domain reputation (24h TTL)."""
    db = await get_db()
    cursor = await db.execute(
        """SELECT * FROM domain_reputation 
           WHERE domain = ? AND cached_at >= datetime('now', '-24 hours')""",
        (domain,),
    )
    row = await cursor.fetchone()
    if row:
        result = dict(row)
        result["details"] = json.loads(result.get("details_json", "{}"))
        return result
    return None


async def save_domain_reputation(data: dict):
    """Save domain reputation data."""
    db = await get_db()
    await db.execute(
        """INSERT OR REPLACE INTO domain_reputation 
           (domain, whois_registrar, creation_date, domain_age_days,
            ssl_valid, ssl_issuer, ssl_expires, reputation_score, details_json, cached_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
        (
            data.get("domain"),
            data.get("whois_registrar"),
            data.get("creation_date"),
            data.get("domain_age_days"),
            1 if data.get("ssl_valid") else 0,
            data.get("ssl_issuer"),
            data.get("ssl_expires"),
            data.get("reputation_score", 0),
            json.dumps(data.get("details", {})),
        ),
    )
    await db.commit()


# ── User Reports ──────────────────────────────────────────────────────────────

async def create_user_report(scan_id: int | None, reporter_email: str, report_type: str, comment: str) -> int:
    """Create a user report."""
    db = await get_db()
    cursor = await db.execute(
        """INSERT INTO user_reports (scan_id, reporter_email, report_type, comment)
           VALUES (?, ?, ?, ?)""",
        (scan_id, reporter_email, report_type, comment),
    )
    await db.commit()
    return cursor.lastrowid


async def get_user_reports(limit: int = 50) -> list[dict]:
    """Get recent user reports."""
    db = await get_db()
    cursor = await db.execute(
        """SELECT ur.*, s.subject, s.risk_level 
           FROM user_reports ur
           LEFT JOIN scans s ON ur.scan_id = s.id
           ORDER BY ur.created_at DESC LIMIT ?""",
        (limit,),
    )
    return [dict(r) for r in await cursor.fetchall()]


# ── Gateway Emails ────────────────────────────────────────────────────────────

async def save_gateway_email(data: dict) -> int:
    """Log a gateway-processed email."""
    db = await get_db()
    cursor = await db.execute(
        """INSERT INTO gateway_emails 
           (source_ip, envelope_from, envelope_to, subject, scan_id, risk_score, risk_level, action_taken)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            data.get("source_ip"),
            data.get("envelope_from"),
            data.get("envelope_to"),
            data.get("subject"),
            data.get("scan_id"),
            data.get("risk_score", 0),
            data.get("risk_level", "safe"),
            data.get("action_taken", "allowed"),
        ),
    )
    await db.commit()
    return cursor.lastrowid


async def get_gateway_logs(limit: int = 100) -> list[dict]:
    """Get gateway email logs."""
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM gateway_emails ORDER BY created_at DESC LIMIT ?",
        (limit,),
    )
    return [dict(r) for r in await cursor.fetchall()]


async def get_gateway_stats() -> dict:
    """Get gateway statistics."""
    db = await get_db()

    cursor = await db.execute("SELECT COUNT(*) as cnt FROM gateway_emails")
    row = await cursor.fetchone()
    total = row["cnt"]

    cursor = await db.execute(
        "SELECT action_taken, COUNT(*) as cnt FROM gateway_emails GROUP BY action_taken"
    )
    rows = await cursor.fetchall()
    by_action = {r["action_taken"]: r["cnt"] for r in rows}

    cursor = await db.execute(
        """SELECT DATE(created_at) as day, COUNT(*) as cnt
           FROM gateway_emails WHERE created_at >= datetime('now', '-7 days')
           GROUP BY day ORDER BY day"""
    )
    trend = [{"date": r["day"], "count": r["cnt"]} for r in await cursor.fetchall()]

    return {
        "total_processed": total,
        "allowed": by_action.get("allowed", 0),
        "quarantined": by_action.get("quarantined", 0),
        "blocked": by_action.get("blocked", 0),
        "daily_trend": trend,
    }
