"""
database.py
-----------
Async SQLite database layer for the IDS backend.

Tables
------
logs      : every record processed (including normal traffic)
alerts    : attack detections only (excludes Normal)
users     : registered users for auth and email notifications
otps      : hashed one-time passwords for 2-step auth
feedbacks : user-submitted feedback entries (CRUD by user, read/triage by admin)

Severity rules
--------------
DoS, Exploits          -> High
Reconnaissance, Generic -> Medium
Fuzzers, Other          -> Low

Feedback categories  : bug | suggestion | general
Feedback statuses    : open | reviewed | resolved | dismissed
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
        # Migration: safely add user_id to existing DB (no-op if already present)
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
                is_verified     INTEGER NOT NULL DEFAULT 0,
                admin_verified  INTEGER NOT NULL DEFAULT 0,
                role            TEXT    NOT NULL DEFAULT 'user',
                created_at      TEXT    NOT NULL
            )
            """
        )
        # Migrations: safely add new columns to existing DB
        if not await _column_exists(db, "users", "is_verified"):
            await db.execute(
                "ALTER TABLE users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 0"
            )
        if not await _column_exists(db, "users", "admin_verified"):
            await db.execute(
                "ALTER TABLE users ADD COLUMN admin_verified INTEGER NOT NULL DEFAULT 0"
            )
        if not await _column_exists(db, "users", "role"):
            await db.execute(
                "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'"
            )

        # --- otps ---
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS otps (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                email       TEXT    NOT NULL UNIQUE,
                otp_hash    TEXT    NOT NULL,
                expires_at  TEXT    NOT NULL,
                created_at  TEXT    NOT NULL
            )
            """
        )

        # --- feedbacks ---
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS feedbacks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title       TEXT    NOT NULL,
                message     TEXT    NOT NULL,
                category    TEXT    NOT NULL DEFAULT 'general',
                status      TEXT    NOT NULL DEFAULT 'open',
                created_at  TEXT    NOT NULL,
                updated_at  TEXT    NOT NULL
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
    user_id: Optional[int] = None,
    timestamp: Optional[str] = None,
) -> int:
    """Insert a single log record tagged with *user_id*. Returns the new row id."""
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


async def insert_alert(
    *,
    src_ip: str,
    dst_ip: str,
    attack_type: str,
    confidence: float,
    user_id: Optional[int] = None,
    timestamp: Optional[str] = None,
) -> int:
    """Insert an alert record tagged with *user_id*. Returns the new row id."""
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


async def get_logs(
    limit: int = 100,
    from_time: Optional[str] = None,
    user_id: Optional[int] = None,
) -> list[dict]:
    """Retrieve log records for *user_id*, newest first.

    When *user_id* is None all records are returned (admin use).
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


async def get_alerts(
    limit: int = 100,
    severity: Optional[str] = None,
    user_id: Optional[int] = None,
) -> list[dict]:
    """Retrieve alert records for *user_id*, newest first.

    When *user_id* is None all records are returned (admin use).
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


async def get_stats(user_id: Optional[int] = None) -> dict:
    """Return summary statistics scoped to *user_id*.

    When *user_id* is None global stats are returned (admin use).
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    user_filter = "user_id = ?" if user_id is not None else ""
    user_params: list = [user_id] if user_id is not None else []

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Total traffic for this user
        q_total = "SELECT COUNT(*) AS total FROM logs"
        if user_filter:
            q_total += f" WHERE {user_filter}"
        async with db.execute(q_total, user_params) as cur:
            total_row = await cur.fetchone()
        total_traffic = total_row["total"] if total_row else 0

        # Attacks breakdown by class for this user
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

        # Alerts today for this user
        if user_filter:
            q_today = (
                "SELECT COUNT(*) AS cnt FROM alerts "
                f"WHERE timestamp LIKE ? AND {user_filter}"
            )
            today_params: list = [f"{today}%", user_id]
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
    is_verified: bool = False,
    admin_verified: bool = False,
    role: str = "user",
) -> dict:
    """Insert a new user. Raises ValueError on duplicate email."""
    ts = _now_iso()
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                INSERT INTO users (full_name, email, hashed_password, is_verified, admin_verified, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (full_name, email.lower(), hashed_password, int(is_verified), int(admin_verified), role, ts),
            )
            await db.commit()
            user_id = cursor.lastrowid
            async with db.execute(
                "SELECT id, full_name, email, is_verified, admin_verified, role, created_at FROM users WHERE id = ?",
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


async def mark_user_verified(email: str) -> None:
    """Set is_verified = 1 for the given email."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE users SET is_verified = 1 WHERE email = ?",
            (email.lower(),),
        )
        await db.commit()


async def approve_user(user_id: int) -> None:
    """Grant system access to a user (admin_verified = 1)."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE users SET admin_verified = 1 WHERE id = ?",
            (user_id,),
        )
        await db.commit()


async def revoke_user(user_id: int) -> None:
    """Revoke system access from a user (admin_verified = 0)."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE users SET admin_verified = 0 WHERE id = ?",
            (user_id,),
        )
        await db.commit()


async def get_all_users() -> list[dict]:
    """Return all user records (for admin dashboard), newest first."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, full_name, email, is_verified, admin_verified, role, created_at "
            "FROM users ORDER BY id DESC"
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_pending_users() -> list[dict]:
    """Return users who passed OTP but are awaiting admin approval."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, full_name, email, is_verified, admin_verified, role, created_at "
            "FROM users WHERE is_verified = 1 AND admin_verified = 0 AND role = 'user' "
            "ORDER BY id DESC"
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_all_user_emails() -> list[str]:
    """Return all registered user email addresses (for broadcast notifications)."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT email FROM users") as cursor:
            rows = await cursor.fetchall()
    return [r["email"] for r in rows]


# ---------------------------------------------------------------------------
# OTPs — one-time password store
# ---------------------------------------------------------------------------

async def upsert_otp(email: str, otp_hash: str, expires_at: str) -> None:
    """Insert or replace the OTP record for *email*."""
    ts = _now_iso()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO otps (email, otp_hash, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                otp_hash   = excluded.otp_hash,
                expires_at = excluded.expires_at,
                created_at = excluded.created_at
            """,
            (email.lower(), otp_hash, expires_at, ts),
        )
        await db.commit()


async def get_otp(email: str) -> Optional[dict]:
    """Fetch the OTP record for *email*. Returns None if not found."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM otps WHERE email = ?",
            (email.lower(),),
        ) as cursor:
            row = await cursor.fetchone()
    return dict(row) if row else None


async def delete_otp(email: str) -> None:
    """Remove the OTP record for *email* (called after successful verification)."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM otps WHERE email = ?",
            (email.lower(),),
        )
        await db.commit()


# ---------------------------------------------------------------------------
# Feedbacks — user CRUD + admin triage
# ---------------------------------------------------------------------------

VALID_FEEDBACK_CATEGORIES = {"bug", "suggestion", "general"}
VALID_FEEDBACK_STATUSES = {"open", "reviewed", "resolved", "dismissed"}


async def create_feedback(
    *,
    user_id: int,
    title: str,
    message: str,
    category: str = "general",
) -> dict:
    """Insert a new feedback entry for *user_id*. Returns the created row."""
    ts = _now_iso()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            INSERT INTO feedbacks (user_id, title, message, category, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'open', ?, ?)
            """,
            (user_id, title, message, category, ts, ts),
        )
        await db.commit()
        async with db.execute(
            "SELECT * FROM feedbacks WHERE id = ?", (cursor.lastrowid,)
        ) as cur:
            row = await cur.fetchone()
        return dict(row)


async def get_feedback_by_id(feedback_id: int) -> Optional[dict]:
    """Fetch a single feedback row by its primary key. Returns None if not found."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM feedbacks WHERE id = ?", (feedback_id,)
        ) as cursor:
            row = await cursor.fetchone()
    return dict(row) if row else None


async def get_feedbacks_by_user(
    user_id: int,
    limit: int = 100,
) -> list[dict]:
    """Return all feedbacks submitted by *user_id*, newest first."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM feedbacks WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, limit),
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_all_feedbacks(
    limit: int = 200,
    status: Optional[str] = None,
    category: Optional[str] = None,
) -> list[dict]:
    """Admin function — return all feedback rows with optional filters, newest first."""
    conditions: list[str] = []
    params: list = []

    if status:
        conditions.append("status = ?")
        params.append(status)
    if category:
        conditions.append("category = ?")
        params.append(category)

    query = "SELECT * FROM feedbacks"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def update_feedback(
    feedback_id: int,
    *,
    title: Optional[str] = None,
    message: Optional[str] = None,
    category: Optional[str] = None,
) -> Optional[dict]:
    """Update editable fields of a feedback row. Returns the updated row, or None if not found."""
    row = await get_feedback_by_id(feedback_id)
    if row is None:
        return None

    new_title = title if title is not None else row["title"]
    new_message = message if message is not None else row["message"]
    new_category = category if category is not None else row["category"]
    ts = _now_iso()

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute(
            """
            UPDATE feedbacks
            SET title = ?, message = ?, category = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_title, new_message, new_category, ts, feedback_id),
        )
        await db.commit()
        async with db.execute(
            "SELECT * FROM feedbacks WHERE id = ?", (feedback_id,)
        ) as cur:
            updated = await cur.fetchone()
        return dict(updated)


async def delete_feedback(feedback_id: int) -> bool:
    """Delete a feedback row by ID. Returns True if a row was deleted, False otherwise."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "DELETE FROM feedbacks WHERE id = ?", (feedback_id,)
        )
        await db.commit()
    return cursor.rowcount > 0


async def update_feedback_status(feedback_id: int, status: str) -> Optional[dict]:
    """Admin function — update only the status field of a feedback row."""
    row = await get_feedback_by_id(feedback_id)
    if row is None:
        return None
    ts = _now_iso()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute(
            "UPDATE feedbacks SET status = ?, updated_at = ? WHERE id = ?",
            (status, ts, feedback_id),
        )
        await db.commit()
        async with db.execute(
            "SELECT * FROM feedbacks WHERE id = ?", (feedback_id,)
        ) as cur:
            updated = await cur.fetchone()
        return dict(updated)
