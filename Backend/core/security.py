import logging
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional
from uuid import uuid4

from jose import JWTError, jwt
from passlib.context import CryptContext

from config import settings

logger = logging.getLogger(__name__)

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.BCRYPT_ROUNDS,
)


class TokenExpiredError(Exception):
    """Raised when a JWT token has passed its expiry time."""

    pass


class TokenInvalidError(Exception):
    """Raised when a JWT token is malformed, tampered, or wrong type."""

    pass


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as exc:
        logger.warning("Password verification failed: %s", exc)
        return False


def create_access_token(
    subject: str,
    email: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {
        "sub": subject,
        "email": email,
        "type": "access",
        "jti": str(uuid4()),
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_refresh_token(
    subject: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        or timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    )
    payload = {
        "sub": subject,
        "type": "refresh",
        "jti": str(uuid4()),
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except JWTError as exc:
        message = str(exc).lower()
        if "expired" in message:
            raise TokenExpiredError("Token has expired") from exc
        raise TokenInvalidError("Token is invalid or malformed") from exc


def _verify_token_type(payload: dict, expected_type: Literal["access", "refresh"]) -> dict:
    if payload.get("type") != expected_type:
        if expected_type == "access":
            raise TokenInvalidError("Not an access token")
        raise TokenInvalidError("Not a refresh token")
    return payload


def verify_access_token(token: str) -> dict:
    payload = decode_token(token)
    return _verify_token_type(payload, "access")


def verify_refresh_token(token: str) -> dict:
    payload = decode_token(token)
    return _verify_token_type(payload, "refresh")


def extract_token_from_header(authorization: Optional[str]) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise TokenInvalidError("Missing or malformed Authorization header")

    token = authorization[len("Bearer ") :].strip()
    if not token:
        raise TokenInvalidError("Missing or malformed Authorization header")

    return token
