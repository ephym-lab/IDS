"""
main.py
-------
FastAPI application for the Network Intrusion Detection System (IDS).

Endpoints
---------
POST /predict                      — single JSON record prediction
POST /upload                       — CSV batch prediction
GET  /alerts                       — query alert history (scoped to authenticated user)
GET  /logs                         — query full traffic log (scoped to authenticated user)
GET  /stats                        — summary statistics (scoped to authenticated user)
POST /capture/start                — start live packet capture
POST /capture/stop                 — stop live packet capture
GET  /capture/status               — capture thread status
POST /auth/signup                  — register a new user, send OTP
POST /auth/signup/verify-otp       — verify signup OTP, issue JWT
POST /auth/login                   — authenticate (admin: direct JWT; user: send OTP)
POST /auth/login/verify-otp        — verify login OTP, issue JWT (regular users only)
POST /auth/resend-otp              — resend OTP for an email address
GET  /auth/me                      — get current authenticated user
GET  /admin/users                  — list all users (admin only)
GET  /admin/users/pending          — list users awaiting approval (admin only)
POST /admin/users/{id}/approve     — approve a user (admin only)
POST /admin/users/{id}/revoke      — revoke a user's access (admin only)
GET  /admin/feedbacks              — list all feedbacks (admin only, filterable)
PATCH /admin/feedbacks/{id}/status — update feedback status (admin only)
POST /feedback                     — submit feedback (authenticated user)
GET  /feedback                     — list own feedbacks
PUT  /feedback/{id}                — update own feedback
DELETE /feedback/{id}              — delete own feedback

Roles
-----
admin : bypasses OTP, bypasses admin_verified gate, can manage users and triage feedback
user  : must pass OTP + wait for admin approval before accessing the system

Email notification rules
------------------------
Emails are sent only to the logged-in user who triggered the prediction.
An email is sent when:
  - Severity is High   (any confidence)
  - Severity is Medium AND confidence > 60%
"""

import asyncio
import io
import logging
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler
from typing import Literal, Optional

import numpy as np
import pandas as pd
from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

import auth
import capture
import database
import email_service
import model as mdl
import preprocessor


# ---------------------------------------------------------------------------
# Logging — console + rotating file
# ---------------------------------------------------------------------------

_file_handler = RotatingFileHandler(
    "ids.log", maxBytes=5_000_000, backupCount=3
)
_file_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[_file_handler, logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan — load all ML artefacts and initialise DB once at startup
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting IDS backend — loading artefacts…")
    await database.init_db()
    mdl.load_model()
    logger.info("All artefacts loaded. Ready.")
    yield
    logger.info("Shutting down IDS backend.")
    capture.stop_capture()


# ---------------------------------------------------------------------------
# Security — bearer token extractor
# ---------------------------------------------------------------------------

_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """Dependency: validates JWT, checks is_verified and admin_verified.

    Admins skip the admin_verified gate (they are always trusted).
    """
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    try:
        email = auth.decode_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    user = await database.get_user_by_email(email)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found.")
    if not user.get("is_verified"):
        raise HTTPException(
            status_code=403,
            detail="Account not verified. Please complete OTP verification.",
        )
    # Admins bypass the admin_verified gate
    if user.get("role") != "admin" and not user.get("admin_verified"):
        raise HTTPException(
            status_code=403,
            detail="Your account is pending admin approval. Please wait for an administrator to activate it.",
        )
    return user


async def get_current_admin(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Dependency: requires the current user to have role='admin'."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Administrator access required.",
        )
    return current_user


# ---------------------------------------------------------------------------
# App & middleware
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Network IDS API",
    description="FastAPI backend for UNSW-NB15 multi-class network intrusion detection.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class PredictRequest(BaseModel):
    # Numerical features
    dur: float = Field(default=0.0)
    spkts: float = Field(default=0.0)
    dpkts: float = Field(default=0.0)
    sbytes: float = Field(default=0.0)
    dbytes: float = Field(default=0.0)
    rate: float = Field(default=0.0)
    sttl: float = Field(default=0.0)
    dttl: float = Field(default=0.0)
    sload: float = Field(default=0.0)
    dload: float = Field(default=0.0)
    sinpkt: float = Field(default=0.0)
    dinpkt: float = Field(default=0.0)
    sjit: float = Field(default=0.0)
    djit: float = Field(default=0.0)
    swin: float = Field(default=0.0)
    stcpb: float = Field(default=0.0)
    dtcpb: float = Field(default=0.0)
    dwin: float = Field(default=0.0)
    smean: float = Field(default=0.0)
    dmean: float = Field(default=0.0)
    ct_srv_src: float = Field(default=0.0)
    ct_state_ttl: float = Field(default=0.0)
    ct_dst_ltm: float = Field(default=0.0)
    ct_src_dport_ltm: float = Field(default=0.0)
    ct_dst_sport_ltm: float = Field(default=0.0)
    ct_dst_src_ltm: float = Field(default=0.0)
    is_ftp_login: float = Field(default=0.0)
    ct_ftp_cmd: float = Field(default=0.0)
    ct_flw_http_mthd: float = Field(default=0.0)
    ct_src_ltm: float = Field(default=0.0)
    ct_srv_dst: float = Field(default=0.0)
    is_sm_ips_ports: float = Field(default=0.0)
    # Categorical features
    proto: str = Field(default="-")
    service: str = Field(default="-")
    state: str = Field(default="INT")
    # Metadata (stored in DB, not used for inference)
    src_ip: str = Field(default="0.0.0.0")
    dst_ip: str = Field(default="0.0.0.0")


class PredictResponse(BaseModel):
    predicted_class: str
    confidence: float
    is_attack: bool
    severity: Optional[str]


# ---------------------------------------------------------------------------
# Feedback schemas
# ---------------------------------------------------------------------------


class FeedbackCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=200, description="Short summary of the feedback")
    message: str = Field(..., min_length=10, description="Full feedback body")
    category: Literal["bug", "suggestion", "general"] = Field(
        default="general", description="Feedback category"
    )


class FeedbackUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=200)
    message: Optional[str] = Field(default=None, min_length=10)
    category: Optional[Literal["bug", "suggestion", "general"]] = None


class FeedbackStatusUpdate(BaseModel):
    status: Literal["open", "reviewed", "resolved", "dismissed"] = Field(
        ..., description="New status for the feedback entry"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_predict_response(class_label: str, confidence: float) -> dict:
    is_attack = class_label != "Normal"
    severity = database.get_severity(class_label) if is_attack else None
    return {
        "predicted_class": class_label,
        "confidence": round(confidence, 6),
        "is_attack": is_attack,
        "severity": severity,
    }


def _should_email(severity: str, confidence: float) -> bool:
    """
    Return True if this prediction warrants an email notification.

    Rules:
      - High severity   → always notify (regardless of confidence)
      - Medium severity → notify only when confidence > 60%
      - Low severity    → never notify
    """
    if severity == "High":
        return True
    if severity == "Medium" and confidence > 0.60:
        return True
    return False


# ---------------------------------------------------------------------------
# Prediction endpoints
# ---------------------------------------------------------------------------

@app.post("/predict", response_model=PredictResponse, summary="Single record prediction")
async def predict(
    req: PredictRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
):
    """
    Accept a single JSON network record and return the prediction.
    Persists the result to logs (and alerts if applicable), scoped to the
    authenticated user.

    Email notification is sent to the logged-in user when:
      - Severity is High (any confidence), or
      - Severity is Medium and confidence > 60%
    """
    try:
        record = req.model_dump()
        features = preprocessor.preprocess(record)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Preprocessing failed: {exc}") from exc

    try:
        class_label, confidence = mdl.predict(features)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Model inference failed: {exc}") from exc

    is_attack = class_label != "Normal"
    severity = database.get_severity(class_label) if is_attack else None
    user_id = current_user["id"]

    await database.insert_log(
        src_ip=req.src_ip,
        dst_ip=req.dst_ip,
        proto=req.proto,
        predicted_class=class_label,
        confidence=confidence,
        is_attack=is_attack,
        user_id=user_id,
    )

    if is_attack:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()

        await database.insert_alert(
            src_ip=req.src_ip,
            dst_ip=req.dst_ip,
            attack_type=class_label,
            confidence=confidence,
            user_id=user_id,
        )

        if severity and _should_email(severity, confidence):
            background_tasks.add_task(
                email_service.notify_alert,
                attack_type=class_label,
                severity=severity,
                src_ip=req.src_ip,
                dst_ip=req.dst_ip,
                confidence=confidence,
                timestamp=ts,
                recipients=[current_user["email"]],
            )

    return _build_predict_response(class_label, confidence)


@app.post("/upload", summary="Batch CSV prediction")
async def upload(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    """
    Upload a CSV file with raw network features.
    Runs batch prediction, stores all results scoped to the authenticated user,
    and returns a summary.

    At most one email notification is sent per batch upload (to avoid flooding
    the user's inbox). The first row that meets the notification rules triggers it.
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are accepted.")

    content = await file.read()
    try:
        df = pd.read_csv(io.StringIO(content.decode("utf-8")))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {exc}") from exc

    user_id = current_user["id"]
    results = []
    attack_counts: dict[str, int] = {}
    total = 0
    errors = 0
    email_sent = False  # send at most one email per batch upload

    for _, row in df.iterrows():
        total += 1
        record = row.to_dict()
        try:
            features = preprocessor.preprocess(record)
            class_label, confidence = mdl.predict(features)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Batch row %d processing error: %s", total, exc)
            errors += 1
            continue

        is_attack = class_label != "Normal"
        row_severity = database.get_severity(class_label) if is_attack else None
        src_ip = str(record.get("src_ip", "0.0.0.0"))
        dst_ip = str(record.get("dst_ip", "0.0.0.0"))
        proto = str(record.get("proto", "-"))

        await database.insert_log(
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=proto,
            predicted_class=class_label,
            confidence=confidence,
            is_attack=is_attack,
            user_id=user_id,
        )

        if is_attack:
            from datetime import datetime, timezone
            ts = datetime.now(timezone.utc).isoformat()
            attack_counts[class_label] = attack_counts.get(class_label, 0) + 1

            await database.insert_alert(
                src_ip=src_ip,
                dst_ip=dst_ip,
                attack_type=class_label,
                confidence=confidence,
                user_id=user_id,
            )

            if row_severity and _should_email(row_severity, confidence) and not email_sent:
                asyncio.create_task(
                    email_service.notify_alert(
                        attack_type=class_label,
                        severity=row_severity,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        confidence=confidence,
                        timestamp=ts,
                        recipients=[current_user["email"]],
                    )
                )
                email_sent = True

        results.append(_build_predict_response(class_label, confidence))

    return JSONResponse({
        "total_records": total,
        "processed": total - errors,
        "errors": errors,
        "attack_counts": attack_counts,
        "results": results,
    })


# ---------------------------------------------------------------------------
# Auth endpoints  (2-step OTP flow)
# ---------------------------------------------------------------------------

@app.post("/auth/signup", status_code=202, summary="Register a new user (step 1 — sends OTP)")
async def signup(
    req: auth.SignupRequest,
    background_tasks: BackgroundTasks,
):
    """
    **Step 1 of signup.**
    Validates the request, creates a *pending* (unverified) user account,
    generates a 6-digit OTP and emails it to the supplied address.

    The client must then call `POST /auth/signup/verify-otp` with the code.
    """
    hashed = auth.hash_password(req.password)
    try:
        await database.create_user(
            full_name=req.full_name,
            email=req.email,
            hashed_password=hashed,
            is_verified=False,
        )
    except ValueError as exc:
        # User already exists — allow re-sending OTP if they never verified
        existing = await database.get_user_by_email(req.email)
        if existing and existing.get("is_verified"):
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        # Fall through to resend OTP for the existing unverified account

    otp = auth.generate_otp()
    otp_hash = auth.hash_otp(otp)
    expires_at = auth.otp_expiry_iso()
    await database.upsert_otp(req.email, otp_hash, expires_at)

    background_tasks.add_task(
        email_service.send_otp_email,
        email=req.email,
        otp=otp,
        purpose="signup",
        expire_minutes=auth.OTP_EXPIRE_MINUTES,
    )
    return {"message": f"OTP sent to {req.email}. Enter it to complete signup."}


@app.post("/auth/signup/verify-otp", status_code=201, summary="Verify signup OTP (step 2 — issues JWT)")
async def signup_verify_otp(req: auth.OtpVerifyRequest):
    """
    **Step 2 of signup.**
    Accepts `{email, otp}`. If the OTP is valid and not expired, marks the user
    as verified and returns a JWT access token.
    """
    from datetime import datetime, timezone

    user = await database.get_user_by_email(req.email)
    if user is None:
        raise HTTPException(status_code=404, detail="No pending signup for this email.")

    otp_record = await database.get_otp(req.email)
    if otp_record is None:
        raise HTTPException(status_code=400, detail="No OTP was issued for this email.")

    # Expiry check
    if datetime.fromisoformat(otp_record["expires_at"]) <= datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="OTP has expired. Request a new one.")

    # Value check
    if not auth.verify_otp(req.otp, otp_record["otp_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect OTP.")

    # Mark verified & clean up OTP
    await database.mark_user_verified(req.email)
    await database.delete_otp(req.email)

    # Fetch updated user record
    user = await database.get_user_by_email(req.email)
    token = auth.create_access_token(subject=user["email"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "full_name": user["full_name"],
            "email": user["email"],
            "role": user.get("role", "user"),
            "created_at": user["created_at"],
        },
    }


@app.post("/auth/login", summary="Authenticate (step 1 — sends OTP or issues JWT for admin)")
async def login(
    req: auth.LoginRequest,
    background_tasks: BackgroundTasks,
):
    """
    **Step 1 of login.**

    - **Admin accounts** (`role = 'admin'`): credentials are verified and a JWT
      is returned immediately — no OTP step.
    - **Regular users**: credentials are verified, a 6-digit OTP is emailed,
      and the client must call `POST /auth/login/verify-otp` to receive a JWT.
    """
    user = await database.get_user_by_email(req.email)
    if user is None or not auth.verify_password(req.password, user["hashed_password"]):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.get("is_verified"):
        raise HTTPException(
            status_code=403,
            detail="Account not verified. Complete signup OTP verification first.",
        )

    # --- Admin fast-path: bypass OTP entirely ---
    if user.get("role") == "admin":
        token = auth.create_access_token(subject=user["email"])
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "full_name": user["full_name"],
                "email": user["email"],
                "role": user["role"],
                "created_at": user["created_at"],
            },
        }

    # --- Regular user: check admin_verified then send OTP ---
    if not user.get("admin_verified"):
        raise HTTPException(
            status_code=403,
            detail="Your account is pending admin approval. Please wait for an administrator to activate it.",
        )

    otp = auth.generate_otp()
    otp_hash = auth.hash_otp(otp)
    expires_at = auth.otp_expiry_iso()
    await database.upsert_otp(req.email, otp_hash, expires_at)

    background_tasks.add_task(
        email_service.send_otp_email,
        email=req.email,
        otp=otp,
        purpose="login",
        expire_minutes=auth.OTP_EXPIRE_MINUTES,
    )
    return {"message": f"OTP sent to {req.email}. Enter it to complete login."}


@app.post("/auth/login/verify-otp", summary="Verify login OTP (step 2 — issues JWT)")
async def login_verify_otp(req: auth.OtpVerifyRequest):
    """
    **Step 2 of login.**
    Accepts `{email, otp}`. If valid and not expired, returns a JWT access token.
    """
    from datetime import datetime, timezone

    user = await database.get_user_by_email(req.email)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    otp_record = await database.get_otp(req.email)
    if otp_record is None:
        raise HTTPException(status_code=400, detail="No active OTP for this email. Please login again.")

    # Expiry check
    if datetime.fromisoformat(otp_record["expires_at"]) <= datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="OTP has expired. Please login again.")

    # Value check
    if not auth.verify_otp(req.otp, otp_record["otp_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect OTP.")

    # Clear OTP — single use
    await database.delete_otp(req.email)

    token = auth.create_access_token(subject=user["email"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "full_name": user["full_name"],
            "email": user["email"],
            "role": user.get("role", "user"),
            "created_at": user["created_at"],
        },
    }


@app.post("/auth/resend-otp", summary="Resend OTP for an email address")
async def resend_otp(
    req: auth.ResendOtpRequest,
    background_tasks: BackgroundTasks,
):
    """
    Regenerates and re-sends the OTP for the given email.
    Works for both unverified signup accounts and verified users who need
    to complete a login flow.
    """
    user = await database.get_user_by_email(req.email)
    if user is None:
        # Don't reveal whether the email exists
        return {"message": f"If {req.email} is registered, a new OTP has been sent."}

    purpose = "signup" if not user.get("is_verified") else "login"
    otp = auth.generate_otp()
    otp_hash = auth.hash_otp(otp)
    expires_at = auth.otp_expiry_iso()
    await database.upsert_otp(req.email, otp_hash, expires_at)

    background_tasks.add_task(
        email_service.send_otp_email,
        email=req.email,
        otp=otp,
        purpose=purpose,
        expire_minutes=auth.OTP_EXPIRE_MINUTES,
    )
    return {"message": f"If {req.email} is registered, a new OTP has been sent."}


@app.get("/auth/me", summary="Get current authenticated user")
async def me(current_user: dict = Depends(get_current_user)):
    """
    Returns the profile of the currently authenticated user.
    Requires: Authorization: Bearer <token>
    """
    return {
        "id": current_user["id"],
        "full_name": current_user["full_name"],
        "email": current_user["email"],
        "role": current_user.get("role", "user"),
        "created_at": current_user["created_at"],
    }


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

@app.get("/admin/users", summary="List all users (admin only)")
async def admin_list_users(admin: dict = Depends(get_current_admin)):
    """Return every user record — id, name, email, OTP status, admin approval, role."""
    users = await database.get_all_users()
    return {"count": len(users), "users": users}


@app.get("/admin/users/pending", summary="List users awaiting admin approval (admin only)")
async def admin_pending_users(admin: dict = Depends(get_current_admin)):
    """Return users who completed OTP verification but haven't been approved yet."""
    users = await database.get_pending_users()
    return {"count": len(users), "users": users}


@app.post("/admin/users/{user_id}/approve", summary="Approve a user (admin only)")
async def admin_approve_user(
    user_id: int,
    admin: dict = Depends(get_current_admin),
):
    """Set admin_verified = 1 for the given user, granting them system access."""
    await database.approve_user(user_id)
    logger.info("Admin %s approved user id=%d", admin["email"], user_id)
    return {"message": f"User {user_id} approved successfully."}


@app.post("/admin/users/{user_id}/revoke", summary="Revoke a user's access (admin only)")
async def admin_revoke_user(
    user_id: int,
    admin: dict = Depends(get_current_admin),
):
    """Set admin_verified = 0 for the given user, suspending their system access."""
    await database.revoke_user(user_id)
    logger.info("Admin %s revoked user id=%d", admin["email"], user_id)
    return {"message": f"User {user_id} access revoked."}


# ---------------------------------------------------------------------------
# Admin feedback endpoints
# ---------------------------------------------------------------------------

@app.get("/admin/feedbacks", summary="List all feedbacks (admin only)")
async def admin_list_feedbacks(
    limit: int = Query(default=200, ge=1, le=1000),
    status: Optional[str] = Query(default=None, description="Filter by status: open, reviewed, resolved, dismissed"),
    category: Optional[str] = Query(default=None, description="Filter by category: bug, suggestion, general"),
    admin: dict = Depends(get_current_admin),
):
    """
    Return all feedback entries across all users.
    Optionally filter by *status* and/or *category*.
    Admin only.
    """
    if status and status not in database.VALID_FEEDBACK_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {sorted(database.VALID_FEEDBACK_STATUSES)}",
        )
    if category and category not in database.VALID_FEEDBACK_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category. Must be one of: {sorted(database.VALID_FEEDBACK_CATEGORIES)}",
        )
    rows = await database.get_all_feedbacks(limit=limit, status=status, category=category)
    return {"count": len(rows), "feedbacks": rows}


@app.patch("/admin/feedbacks/{feedback_id}/status", summary="Update feedback status (admin only)")
async def admin_update_feedback_status(
    feedback_id: int,
    req: FeedbackStatusUpdate,
    admin: dict = Depends(get_current_admin),
):
    """
    Update the *status* field of a feedback entry (open → reviewed → resolved / dismissed).
    Admin only.
    """
    updated = await database.update_feedback_status(feedback_id, req.status)
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Feedback {feedback_id} not found.")
    logger.info(
        "Admin %s set feedback id=%d status to '%s'",
        admin["email"], feedback_id, req.status,
    )
    return {"message": f"Feedback {feedback_id} status updated to '{req.status}'.", "feedback": updated}


# ---------------------------------------------------------------------------
# Data endpoints — all scoped to the authenticated user
# ---------------------------------------------------------------------------

@app.get("/alerts", summary="Query alert history")
async def alerts(
    limit: int = Query(default=100, ge=1, le=10000),
    severity: Optional[str] = Query(default=None, description="Filter by severity: High, Medium, Low"),
    current_user: dict = Depends(get_current_user),
):
    """Return alerts for the authenticated user, newest first."""
    if severity and severity not in ("High", "Medium", "Low"):
        raise HTTPException(status_code=400, detail="severity must be 'High', 'Medium', or 'Low'.")
    rows = await database.get_alerts(limit=limit, severity=severity, user_id=current_user["id"])
    return {"count": len(rows), "alerts": rows}


@app.get("/logs", summary="Query traffic logs history")
async def logs(
    limit: int = Query(default=100, ge=1, le=10000),
    from_time: Optional[str] = Query(default=None, description="ISO-8601 timestamp lower bound (inclusive)"),
    current_user: dict = Depends(get_current_user),
):
    """Return log records for the authenticated user, newest first."""
    rows = await database.get_logs(limit=limit, from_time=from_time, user_id=current_user["id"])
    return {"count": len(rows), "logs": rows}


@app.get("/stats", summary="Summary statistics")
async def stats(current_user: dict = Depends(get_current_user)):
    """Return summary counts scoped to the authenticated user."""
    return await database.get_stats(user_id=current_user["id"])


# ---------------------------------------------------------------------------
# Feedback endpoints — authenticated users (CRUD on own entries)
# ---------------------------------------------------------------------------

@app.post("/feedback", status_code=201, summary="Submit feedback")
async def create_feedback(
    req: FeedbackCreate,
    current_user: dict = Depends(get_current_user),
):
    """
    Create a new feedback entry for the currently authenticated user.
    Category must be one of: `bug`, `suggestion`, `general`.
    """
    feedback = await database.create_feedback(
        user_id=current_user["id"],
        title=req.title,
        message=req.message,
        category=req.category,
    )
    logger.info("User %s submitted feedback id=%d", current_user["email"], feedback["id"])
    return {"message": "Feedback submitted successfully.", "feedback": feedback}


@app.get("/feedback", summary="List own feedbacks")
async def list_my_feedbacks(
    limit: int = Query(default=100, ge=1, le=1000),
    current_user: dict = Depends(get_current_user),
):
    """Return all feedback entries submitted by the currently authenticated user, newest first."""
    rows = await database.get_feedbacks_by_user(user_id=current_user["id"], limit=limit)
    return {"count": len(rows), "feedbacks": rows}


@app.put("/feedback/{feedback_id}", summary="Update own feedback")
async def update_feedback(
    feedback_id: int,
    req: FeedbackUpdate,
    current_user: dict = Depends(get_current_user),
):
    """
    Update the title, message, and/or category of a feedback entry.
    Only the owner of the feedback can edit it.
    """
    existing = await database.get_feedback_by_id(feedback_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Feedback {feedback_id} not found.")
    if existing["user_id"] != current_user["id"]:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to edit this feedback.",
        )
    updated = await database.update_feedback(
        feedback_id,
        title=req.title,
        message=req.message,
        category=req.category,
    )
    return {"message": "Feedback updated successfully.", "feedback": updated}


@app.delete("/feedback/{feedback_id}", status_code=200, summary="Delete own feedback")
async def delete_feedback(
    feedback_id: int,
    current_user: dict = Depends(get_current_user),
):
    """
    Permanently delete a feedback entry.
    Only the owner of the feedback can delete it.
    """
    existing = await database.get_feedback_by_id(feedback_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Feedback {feedback_id} not found.")
    if existing["user_id"] != current_user["id"]:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to delete this feedback.",
        )
    await database.delete_feedback(feedback_id)
    logger.info("User %s deleted feedback id=%d", current_user["email"], feedback_id)
    return {"message": f"Feedback {feedback_id} deleted successfully."}


# ---------------------------------------------------------------------------
# Capture endpoints — all require authentication
# ---------------------------------------------------------------------------

@app.post("/capture/start", summary="Start live packet capture")
async def capture_start(current_user: dict = Depends(get_current_user)):
    """
    Start the background Scapy packet capture thread.
    Requires root/CAP_NET_RAW privileges to capture packets.
    """
    loop = asyncio.get_event_loop()
    started = capture.start_capture(loop=loop)
    if started:
        logger.info("Capture started by user: %s", current_user["email"])
        return {"status": "started", "capturing": True}
    return {"status": "already_running", "capturing": True}


@app.post("/capture/stop", summary="Stop live packet capture")
async def capture_stop(current_user: dict = Depends(get_current_user)):
    """Stop the background Scapy packet capture thread."""
    stopped = capture.stop_capture()
    if stopped:
        logger.info("Capture stopped by user: %s", current_user["email"])
        return {"status": "stopped", "capturing": False}
    return {"status": "not_running", "capturing": False}


@app.get("/capture/status", summary="Capture thread status")
async def capture_status(current_user: dict = Depends(get_current_user)):
    """Returns whether the live capture thread is currently running."""
    return {"capturing": capture.is_capturing()}


# ---------------------------------------------------------------------------
# Dev entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)