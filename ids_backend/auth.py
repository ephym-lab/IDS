"""
auth.py
-------
Authentication helpers for the IDS backend.

Responsibilities
----------------
- Password hashing & verification  (passlib / bcrypt)
- JWT access token generation       (python-jose)
- JWT token verification & decoding
- Pydantic request/response schemas for auth endpoints
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from dotenv import load_dotenv
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

load_dotenv()

# ---------------------------------------------------------------------------
# Config — loaded from .env
# ---------------------------------------------------------------------------

SECRET_KEY: str = os.getenv("SECRET_KEY", "change-me-in-production-please")
ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    """Return the bcrypt hash of *plain*."""
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches *hashed*."""
    return _pwd_context.verify(plain, hashed)


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


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict  # { id, full_name, email, created_at }


class UserOut(BaseModel):
    id: int
    full_name: str
    email: str
    created_at: str
