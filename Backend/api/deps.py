import logging
from datetime import datetime, timezone
from typing import Annotated, Optional, TypeAlias
from urllib.parse import urlparse
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from core.database import get_db
from core.neo4j_client import neo4j_client
from core.security import (
    TokenExpiredError,
    TokenInvalidError,
    extract_token_from_header,
    verify_access_token,
)
from models.consent import ConsentRecord
from models.scan import Scan
from models.user import User

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

DBSession = Annotated[AsyncSession, Depends(get_db)]


def _normalized_oauth_token(token: str) -> str:
    return extract_token_from_header(f"Bearer {token}")


def _extract_domain(target_url: str) -> str:
    parsed = urlparse(target_url)
    domain = parsed.hostname or parsed.netloc
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan target URL is invalid and has no domain",
        )
    return domain.lower()


async def get_current_user(
    token: Annotated[Optional[str], Depends(oauth2_scheme)],
    db: DBSession,
) -> User:
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = verify_access_token(_normalized_oauth_token(token))
    except TokenExpiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired — please log in again",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except TokenInvalidError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_uuid = UUID(str(user_id))
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def get_current_user_optional(
    token: Annotated[Optional[str], Depends(oauth2_scheme)],
    db: DBSession,
) -> Optional[User]:
    if token is None:
        return None

    try:
        payload = verify_access_token(_normalized_oauth_token(token))
        user_id = payload.get("sub")
        if not user_id:
            return None
        user_uuid = UUID(str(user_id))
    except (TokenExpiredError, TokenInvalidError, TypeError, ValueError):
        return None

    result = await db.execute(select(User).where(User.id == user_uuid))
    return result.scalar_one_or_none()


CurrentUser: TypeAlias = Annotated[User, Depends(get_current_user)]


async def get_scan_or_404(
    scan_id: UUID,
    current_user: CurrentUser,
    db: DBSession,
) -> Scan:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    if scan.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this scan",
        )

    return scan


async def require_hardcore_consent(
    scan_id: UUID,
    current_user: CurrentUser,
    db: DBSession,
) -> ConsentRecord:
    scan = await get_scan_or_404(scan_id=scan_id, current_user=current_user, db=db)
    target_domain = _extract_domain(scan.target_url)

    consent_result = await db.execute(
        select(ConsentRecord).where(
            ConsentRecord.user_id == current_user.id,
            ConsentRecord.target_domain == target_domain,
        )
    )
    consent_record = consent_result.scalar_one_or_none()

    if consent_record is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Hardcore Mode requires domain ownership verification. "
                "Complete consent flow at /api/consent/initiate first."
            ),
        )

    if not consent_record.domain_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Domain ownership not verified. Add DNS TXT record and "
                "call /api/consent/verify-domain."
            ),
        )

    if consent_record.tc_version != settings.TC_CURRENT_VERSION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Terms & Conditions version mismatch. Please re-accept "
                f"the latest T&C at version {settings.TC_CURRENT_VERSION}."
            ),
        )

    now = datetime.now(timezone.utc)
    expires_at = consent_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Consent has expired. Please re-initiate the consent flow.",
        )

    if not consent_record.scope_config:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No scan scope defined. Specify allowed paths in consent config.",
        )

    return consent_record


async def get_neo4j():
    return neo4j_client


Neo4jClient = Annotated[neo4j_client.__class__, Depends(get_neo4j)]
