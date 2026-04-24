"""
auth.py
-------
Authentication helpers for the IDS backend.

Responsibilities
----------------
- Password hashing & verification  (bcrypt — used directly, not via passlib)
- OTP generation, hashing & verification
- JWT access token generation       (python-jose)
- JWT token verification & decoding
- Pydantic request/response schemas for auth endpoints

Note: passlib is intentionally NOT used here because passlib's bcrypt backend
breaks on bcrypt >= 4.0 (the `__about__` attribute was removed in that release).
Calling bcrypt directly keeps things simple and compatible.
"""

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from dotenv import load_dotenv
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field

load_dotenv()

# ---------------------------------------------------------------------------
# Config — loaded from .env
# ---------------------------------------------------------------------------

SECRET_KEY: str = os.getenv("SECRET_KEY", "change-me-in-production-please")
ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# ---------------------------------------------------------------------------
# Password hashing  (direct bcrypt — no passlib wrapper)
# ---------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    """Return the bcrypt hash of *plain* as a UTF-8 string."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches the stored *hashed* value."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ---------------------------------------------------------------------------
# OTP helpers
# ---------------------------------------------------------------------------

OTP_EXPIRE_MINUTES: int = int(os.getenv("OTP_EXPIRE_MINUTES", "10"))


def generate_otp() -> str:
    """Return a cryptographically-random 6-digit OTP string (zero-padded)."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(plain_otp: str) -> str:
    """Return the bcrypt hash of *plain_otp* as a UTF-8 string."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(plain_otp.encode("utf-8"), salt).decode("utf-8")


def verify_otp(plain_otp: str, hashed_otp: str) -> bool:
    """Return True if *plain_otp* matches the stored *hashed_otp*."""
    return bcrypt.checkpw(plain_otp.encode("utf-8"), hashed_otp.encode("utf-8"))


def otp_expiry_iso() -> str:
    """Return an ISO-8601 timestamp *OTP_EXPIRE_MINUTES* from now (UTC)."""
    return (datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES)).isoformat()


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(subject: str, expire_minutes: Optional[int] = None) -> str:
    """
    Create a signed JWT access token.

    Parameters
    ----------
    subject : str
        The value to embed as the ``sub`` claim (typically the user's email).
    expire_minutes : int, optional
        Override the default expiry from the environment.
    """
    minutes = expire_minutes or ACCESS_TOKEN_EXPIRE_MINUTES
    expire = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> str:
    """
    Decode and verify a JWT token.

    Returns
    -------
    str
        The ``sub`` claim (user email).

    Raises
    ------
    ValueError
        If the token is invalid or expired.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        subject: Optional[str] = payload.get("sub")
        if subject is None:
            raise ValueError("Token has no subject claim.")
        return subject
    except JWTError as exc:
        raise ValueError(f"Invalid or expired token: {exc}") from exc


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class SignupRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100, examples=["Jane Doe"])
    email: EmailStr = Field(..., examples=["jane@example.com"])
    password: str = Field(..., min_length=8, examples=["s3cur3P@ss"])


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., examples=["jane@example.com"])
    password: str = Field(..., examples=["s3cur3P@ss"])


class OtpVerifyRequest(BaseModel):
    email: EmailStr = Field(..., examples=["jane@example.com"])
    otp: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$", examples=["123456"])


class ResendOtpRequest(BaseModel):
    email: EmailStr = Field(..., examples=["jane@example.com"])


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict  # { id, full_name, email, created_at }


class UserOut(BaseModel):
    id: int
    full_name: str
    email: str
    created_at: str
