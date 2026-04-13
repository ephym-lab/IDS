"""
database.py
-----------
Async SQLite database layer for the IDS backend.

Tables
------
logs   : every record processed (including normal traffic)
alerts : attack detections only (excludes Normal)
users  : registered users for auth and email notifications

Severity rules
--------------
DoS, Exploits          -> High
Reconnaissance, Generic -> Medium
Fuzzers, Other          -> Low

User isolation
--------------
Both `logs` and `alerts` carry a `user_id` foreign key so each user
sees only their own data on the dashboard.  Existing rows (pre-migration)
will have user_id = NULL and will not appear on any user's dashboard.
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


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

async def _column_exists(db: aiosqlite.Connection, table: str, column: str) -> bool:
    """Return True if *column* already exists in *table*."""
    async with db.execute(f"PRAGMA table_info({table})") as cur:
        rows = await cur.fetchall()
    return any(row[1] == column for row in rows)


async def init_db() -> None:
    """Create tables if they do not exist and run idempotent migrations."""
    async with aiosqlite.connect(DB_PATH) as db:
        # --- logs ---
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
                is_attack       INTEGER NOT NULL,
                user_id         INTEGER REFERENCES users(id)
            )
            """
        )
        # Migration: add user_id if upgrading from an older schema
        if not await _column_exists(db, "logs", "user_id"):
            await db.execute(
                "ALTER TABLE logs ADD COLUMN user_id INTEGER REFERENCES users(id)"
            )

        # --- alerts ---
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                src_ip      TEXT,
                dst_ip      TEXT,
                attack_type TEXT NOT NULL,
                confidence  REAL NOT NULL,
                severity    TEXT NOT NULL,
                user_id     INTEGER REFERENCES users(id)
            )
            """
        )
        if not await _column_exists(db, "alerts", "user_id"):
            await db.execute(
                "ALTER TABLE alerts ADD COLUMN user_id INTEGER REFERENCES users(id)"
            )

        # --- users ---
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name       TEXT    NOT NULL,
                email           TEXT    NOT NULL UNIQUE,
                hashed_password TEXT    NOT NULL,
                created_at      TEXT    NOT NULL
            )
            """
        )

        await db.commit()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_severity(attack_type: str) -> str:
    return SEVERITY_MAP.get(attack_type, "Low")


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

async def insert_log(
    *,
    src_ip: str,
    dst_ip: str,
    proto: str,
    predicted_class: str,
    confidence: float,
    is_attack: bool,
    user_id: Optional[int] = None,
    timestamp: Optional[str] = None,
) -> int:
    """Insert a single log record. Returns the new row id."""
    ts = timestamp or _now_iso()
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO logs
                (timestamp, src_ip, dst_ip, proto, predicted_class, confidence, is_attack, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, src_ip, dst_ip, proto, predicted_class, float(confidence), int(is_attack), user_id),
        )
        await db.commit()
        return cursor.lastrowid


async def get_logs(
    limit: int = 100,
    from_time: Optional[str] = None,
    user_id: Optional[int] = None,
) -> list[dict]:
    """Retrieve log records for a specific user, newest first.

    When *user_id* is None the function returns all records (admin / backward-compat).
    """
    conditions: list[str] = []
    params: list = []

    if user_id is not None:
        conditions.append("user_id = ?")
        params.append(user_id)

    if from_time:
        conditions.append("timestamp >= ?")
        params.append(from_time)

    query = "SELECT * FROM logs"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

async def insert_alert(
    *,
    src_ip: str,
    dst_ip: str,
    attack_type: str,
    confidence: float,
    user_id: Optional[int] = None,
    timestamp: Optional[str] = None,
) -> int:
    """Insert an alert record. Returns the new row id."""
    ts = timestamp or _now_iso()
    severity = get_severity(attack_type)
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO alerts (timestamp, src_ip, dst_ip, attack_type, confidence, severity, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, src_ip, dst_ip, attack_type, float(confidence), severity, user_id),
        )
        await db.commit()
        return cursor.lastrowid


async def get_alerts(
    limit: int = 100,
    severity: Optional[str] = None,
    user_id: Optional[int] = None,
) -> list[dict]:
    """Retrieve alert records for a specific user, newest first.

    When *user_id* is None the function returns all records (admin / backward-compat).
    """
    conditions: list[str] = []
    params: list = []

    if user_id is not None:
        conditions.append("user_id = ?")
        params.append(user_id)

    if severity:
        conditions.append("severity = ?")
        params.append(severity)

    query = "SELECT * FROM alerts"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

async def get_stats(user_id: Optional[int] = None) -> dict:
    """Return summary statistics scoped to *user_id*.

    When *user_id* is None the function returns global stats (admin).
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Build user filter clause
    user_filter = "user_id = ?" if user_id is not None else ""
    user_params: list = [user_id] if user_id is not None else []

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Total traffic
        q_total = "SELECT COUNT(*) AS total FROM logs"
        if user_filter:
            q_total += f" WHERE {user_filter}"
        async with db.execute(q_total, user_params) as cur:
            total_row = await cur.fetchone()
        total_traffic = total_row["total"] if total_row else 0

        # Attacks breakdown by class
        if user_filter:
            q_attacks = (
                "SELECT predicted_class, COUNT(*) AS cnt FROM logs "
                f"WHERE is_attack = 1 AND {user_filter} GROUP BY predicted_class"
            )
            attacks_params = [user_id]
        else:
            q_attacks = (
                "SELECT predicted_class, COUNT(*) AS cnt FROM logs "
                "WHERE is_attack = 1 GROUP BY predicted_class"
            )
            attacks_params = []
        async with db.execute(q_attacks, attacks_params) as cur:
            attack_rows = await cur.fetchall()
        attacks_by_class = {r["predicted_class"]: r["cnt"] for r in attack_rows}

        # Alerts today
        if user_filter:
            q_today = (
                "SELECT COUNT(*) AS cnt FROM alerts "
                f"WHERE timestamp LIKE ? AND {user_filter}"
            )
            today_params = [f"{today}%", user_id]
        else:
            q_today = "SELECT COUNT(*) AS cnt FROM alerts WHERE timestamp LIKE ?"
            today_params = [f"{today}%"]
        async with db.execute(q_today, today_params) as cur:
            today_row = await cur.fetchone()
        alerts_today = today_row["cnt"] if today_row else 0

    return {
        "total_traffic": total_traffic,
        "attacks_by_class": attacks_by_class,
        "alerts_today": alerts_today,
    }


# ---------------------------------------------------------------------------
# Users — Auth & Email Notifications
# ---------------------------------------------------------------------------

async def create_user(
    *,
    full_name: str,
    email: str,
    hashed_password: str,
) -> dict:
    """Insert a new user. Raises ValueError on duplicate email."""
    ts = _now_iso()
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                INSERT INTO users (full_name, email, hashed_password, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (full_name, email.lower(), hashed_password, ts),
            )
            await db.commit()
            user_id = cursor.lastrowid
            async with db.execute(
                "SELECT id, full_name, email, created_at FROM users WHERE id = ?",
                (user_id,),
            ) as cur:
                row = await cur.fetchone()
            return dict(row)
    except aiosqlite.IntegrityError:
        raise ValueError(f"A user with email '{email}' already exists.")


async def get_user_by_email(email: str) -> Optional[dict]:
    """Fetch a user record (including hashed_password) by email. Returns None if not found."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email.lower(),),
        ) as cursor:
            row = await cursor.fetchone()
    return dict(row) if row else None


async def get_all_user_emails() -> list[str]:
    """Return all registered user email addresses (for broadcast notifications)."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT email FROM users") as cursor:
            rows = await cursor.fetchall()
    return [r["email"] for r in rows]
