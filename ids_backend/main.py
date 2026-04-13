"""
main.py
-------
FastAPI application for the Network Intrusion Detection System (IDS).

Endpoints
---------
POST /auth/signup      — register a new user, returns JWT
POST /auth/login       — authenticate, returns JWT
GET  /auth/me          — current user profile
POST /predict          — single JSON record prediction  (auth required)
POST /upload           — CSV batch prediction           (auth required)
GET  /alerts           — query user's alert history     (auth required)
GET  /logs             — query user's traffic log       (auth required)
GET  /stats            — user's summary statistics      (auth required)
POST /capture/start    — start live packet capture      (auth required)
POST /capture/stop     — stop live packet capture       (auth required)
GET  /capture/status   — capture thread status          (auth required)
"""

import asyncio
import io
import logging
from contextlib import asynccontextmanager
from typing import Optional

import numpy as np
import pandas as pd
from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

import auth
import capture
import database
import model as mdl
import preprocessor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

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
# App & middleware
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Network IDS API",
    description="FastAPI backend for UNSW-NB15 multi-class network intrusion detection.",
    version="2.0.0",
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
# Auth dependency
# ---------------------------------------------------------------------------

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Decode the JWT from the Authorization header and return the user row.
    Raises HTTP 401 if the token is missing, invalid, or the user is gone.
    """
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        email = auth.decode_token(token)  # raises ValueError if invalid
    except ValueError:
        raise credentials_exc

    user = await database.get_user_by_email(email)
    if user is None:
        raise credentials_exc
    return user


# ---------------------------------------------------------------------------
# Prediction helper
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


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.post("/auth/signup", response_model=auth.TokenResponse, summary="Register a new user")
async def signup(req: auth.SignupRequest):
    """Create a new user account and return a JWT access token."""
    try:
        user = await database.create_user(
            full_name=req.full_name,
            email=req.email,
            hashed_password=auth.hash_password(req.password),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))

    token = auth.create_access_token(subject=user["email"])
    return auth.TokenResponse(access_token=token, user=user)


@app.post("/auth/login", response_model=auth.TokenResponse, summary="Login and get JWT")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate with email + password (OAuth2 password flow).
    The *username* field should contain the user's email address.
    """
    user = await database.get_user_by_email(form_data.username)
    if user is None or not auth.verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth.create_access_token(subject=user["email"])
    return auth.TokenResponse(access_token=token, user={
        "id": user["id"],
        "full_name": user["full_name"],
        "email": user["email"],
        "created_at": user["created_at"],
    })


@app.post("/auth/login/json", response_model=auth.TokenResponse, summary="Login with JSON body")
async def login_json(req: auth.LoginRequest):
    """
    Alternative login endpoint accepting a JSON body instead of form data.
    Useful for frontend clients that prefer JSON over multipart/form-data.
    """
    user = await database.get_user_by_email(req.email)
    if user is None or not auth.verify_password(req.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth.create_access_token(subject=user["email"])
    return auth.TokenResponse(access_token=token, user={
        "id": user["id"],
        "full_name": user["full_name"],
        "email": user["email"],
        "created_at": user["created_at"],
    })


@app.get("/auth/me", response_model=auth.UserOut, summary="Get current user profile")
async def me(current_user: dict = Depends(get_current_user)):
    """Return the authenticated user's profile."""
    return auth.UserOut(**{k: current_user[k] for k in ("id", "full_name", "email", "created_at")})


# ---------------------------------------------------------------------------
# Prediction endpoints
# ---------------------------------------------------------------------------

@app.post("/predict", response_model=PredictResponse, summary="Single record prediction")
async def predict(
    req: PredictRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Accept a single JSON network record and return the prediction.
    Results are stored under the authenticated user's account.
    """
    user_id: int = current_user["id"]

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
        await database.insert_alert(
            src_ip=req.src_ip,
            dst_ip=req.dst_ip,
            attack_type=class_label,
            confidence=confidence,
            user_id=user_id,
        )

    return _build_predict_response(class_label, confidence)


@app.post("/upload", summary="Batch CSV prediction")
async def upload(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    """
    Upload a CSV file with raw network features.
    All results are stored under the authenticated user's account.
    """
    user_id: int = current_user["id"]

    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are accepted.")

    content = await file.read()
    try:
        df = pd.read_csv(io.StringIO(content.decode("utf-8")))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {exc}") from exc

    results = []
    attack_counts: dict[str, int] = {}
    total = 0
    errors = 0

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
            attack_counts[class_label] = attack_counts.get(class_label, 0) + 1
            await database.insert_alert(
                src_ip=src_ip,
                dst_ip=dst_ip,
                attack_type=class_label,
                confidence=confidence,
                user_id=user_id,
            )

        results.append(_build_predict_response(class_label, confidence))

    return JSONResponse({
        "total_records": total,
        "processed": total - errors,
        "errors": errors,
        "attack_counts": attack_counts,
        "results": results,
    })


# ---------------------------------------------------------------------------
# Data query endpoints (user-scoped)
# ---------------------------------------------------------------------------

@app.get("/alerts", summary="Query user's alert history")
async def alerts(
    limit: int = Query(default=100, ge=1, le=10000),
    severity: Optional[str] = Query(default=None, description="Filter: High, Medium, Low"),
    current_user: dict = Depends(get_current_user),
):
    """Return alerts belonging to the authenticated user, newest first."""
    if severity and severity not in ("High", "Medium", "Low"):
        raise HTTPException(status_code=400, detail="severity must be 'High', 'Medium', or 'Low'.")
    rows = await database.get_alerts(limit=limit, severity=severity, user_id=current_user["id"])
    return {"count": len(rows), "alerts": rows}


@app.get("/logs", summary="Query user's traffic log")
async def logs(
    limit: int = Query(default=100, ge=1, le=10000),
    from_time: Optional[str] = Query(default=None, description="ISO-8601 timestamp lower bound"),
    current_user: dict = Depends(get_current_user),
):
    """Return log records belonging to the authenticated user, newest first."""
    rows = await database.get_logs(limit=limit, from_time=from_time, user_id=current_user["id"])
    return {"count": len(rows), "logs": rows}


@app.get("/stats", summary="User's summary statistics")
async def stats(current_user: dict = Depends(get_current_user)):
    """Return summary counts scoped to the authenticated user's data."""
    return await database.get_stats(user_id=current_user["id"])


# ---------------------------------------------------------------------------
# Capture endpoints
# ---------------------------------------------------------------------------

@app.post("/capture/start", summary="Start live packet capture")
async def capture_start(current_user: dict = Depends(get_current_user)):
    """
    Start the background Scapy packet capture thread.
    All captured traffic is attributed to the user who starts the session.
    Requires root/CAP_NET_RAW privileges.
    """
    loop = asyncio.get_event_loop()
    started = capture.start_capture(loop=loop, user_id=current_user["id"])
    if started:
        return {"status": "started", "capturing": True, "owner_id": current_user["id"]}
    return {"status": "already_running", "capturing": True}


@app.post("/capture/stop", summary="Stop live packet capture")
async def capture_stop(current_user: dict = Depends(get_current_user)):
    """Stop the background Scapy packet capture thread."""
    stopped = capture.stop_capture()
    if stopped:
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
