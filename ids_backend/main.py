"""
main.py
-------
FastAPI application for the Network Intrusion Detection System (IDS).

Endpoints
---------
POST /predict          — single JSON record prediction
POST /upload           — CSV batch prediction
GET  /alerts           — query alert history (scoped to authenticated user)
GET  /logs             — query full traffic log (scoped to authenticated user)
GET  /stats            — summary statistics (scoped to authenticated user)
POST /capture/start    — start live packet capture
POST /capture/stop     — stop live packet capture
GET  /capture/status   — capture thread status
POST /auth/signup      — register a new user
POST /auth/login       — authenticate and get a JWT token
GET  /auth/me          — get current authenticated user

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
from typing import Optional

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
    """Dependency: validates JWT and returns the user dict."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    try:
        email = auth.decode_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    user = await database.get_user_by_email(email)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found.")
    return user


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
# Auth endpoints
# ---------------------------------------------------------------------------

@app.post("/auth/signup", status_code=201, summary="Register a new user")
async def signup(req: auth.SignupRequest):
    """
    Create a new user account.
    Requires: full_name, email, password (min 8 chars).
    Returns the user profile and a JWT access token.
    """
    hashed = auth.hash_password(req.password)
    try:
        user = await database.create_user(
            full_name=req.full_name,
            email=req.email,
            hashed_password=hashed,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    token = auth.create_access_token(subject=user["email"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "full_name": user["full_name"],
            "email": user["email"],
            "created_at": user["created_at"],
        },
    }


@app.post("/auth/login", summary="Authenticate and get a JWT token")
async def login(req: auth.LoginRequest):
    """
    Authenticate with email and password.
    Returns a JWT access token on success.
    """
    user = await database.get_user_by_email(req.email)
    if user is None or not auth.verify_password(req.password, user["hashed_password"]):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth.create_access_token(subject=user["email"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "full_name": user["full_name"],
            "email": user["email"],
            "created_at": user["created_at"],
        },
    }


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
        "created_at": current_user["created_at"],
    }


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