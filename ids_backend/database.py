"""
database.py
-----------
Async SQLite database layer for the IDS backend.

Tables
------
logs   : every record processed (including normal traffic)
alerts : attack detections only (excludes Normal)

Severity rules
--------------
DoS, Exploits          -> High
Reconnaissance, Generic -> Medium
Fuzzers, Other          -> Low
"""

import aiosqlite
from datetime import datetime, timezone
from typing import Optional

DB_PATH = "ids.db"

# Attack class -> severity mapping
SEVERITY_MAP: dict[str, str] = {
    "DoS": "High",
    "Exploits": "High",
    "Reconnaissance": "Medium",
    "Generic": "Medium",
    "Fuzzers": "Low",
    "Other": "Low",
}


async def init_db() -> None:
    """Create tables if they do not exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                src_ip          TEXT,
                dst_ip          TEXT,
                proto           TEXT,
                predicted_class TEXT    NOT NULL,
                confidence      REAL    NOT NULL,
                is_attack       INTEGER NOT NULL
            )
            """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                src_ip      TEXT,
                dst_ip      TEXT,
                attack_type TEXT NOT NULL,
                confidence  REAL NOT NULL,
                severity    TEXT NOT NULL
            )
            """
        )
        await db.commit()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_severity(attack_type: str) -> str:
    return SEVERITY_MAP.get(attack_type, "Low")


async def insert_log(
    *,
    src_ip: str,
    dst_ip: str,
    proto: str,
    predicted_class: str,
    confidence: float,
    is_attack: bool,
    timestamp: Optional[str] = None,
) -> int:
    """Insert a single log record. Returns the new row id."""
    ts = timestamp or _now_iso()
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO logs (timestamp, src_ip, dst_ip, proto, predicted_class, confidence, is_attack)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, src_ip, dst_ip, proto, predicted_class, float(confidence), int(is_attack)),
        )
        await db.commit()
        return cursor.lastrowid


async def insert_alert(
    *,
    src_ip: str,
    dst_ip: str,
    attack_type: str,
    confidence: float,
    timestamp: Optional[str] = None,
) -> int:
    """Insert an alert record. Returns the new row id."""
    ts = timestamp or _now_iso()
    severity = get_severity(attack_type)
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO alerts (timestamp, src_ip, dst_ip, attack_type, confidence, severity)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (ts, src_ip, dst_ip, attack_type, float(confidence), severity),
        )
        await db.commit()
        return cursor.lastrowid


async def get_logs(
    limit: int = 100,
    from_time: Optional[str] = None,
) -> list[dict]:
    """Retrieve log records, newest first."""
    query = "SELECT * FROM logs"
    params: list = []
    if from_time:
        query += " WHERE timestamp >= ?"
        params.append(from_time)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_alerts(
    limit: int = 100,
    severity: Optional[str] = None,
) -> list[dict]:
    """Retrieve alert records, newest first."""
    query = "SELECT * FROM alerts"
    params: list = []
    if severity:
        query += " WHERE severity = ?"
        params.append(severity)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_stats() -> dict:
    """Return summary statistics."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Total traffic
        async with db.execute("SELECT COUNT(*) AS total FROM logs") as cur:
            total_row = await cur.fetchone()
        total_traffic = total_row["total"] if total_row else 0

        # Attacks breakdown by class
        async with db.execute(
            "SELECT predicted_class, COUNT(*) AS cnt FROM logs WHERE is_attack = 1 GROUP BY predicted_class"
        ) as cur:
            attack_rows = await cur.fetchall()
        attacks_by_class = {r["predicted_class"]: r["cnt"] for r in attack_rows}

        # Alerts today
        async with db.execute(
            "SELECT COUNT(*) AS cnt FROM alerts WHERE timestamp LIKE ?",
            (f"{today}%",),
        ) as cur:
            today_row = await cur.fetchone()
        alerts_today = today_row["cnt"] if today_row else 0

    return {
        "total_traffic": total_traffic,
        "attacks_by_class": attacks_by_class,
        "alerts_today": alerts_today,
    }
