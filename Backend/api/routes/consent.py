import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from api.deps import get_current_user
from core.database import get_db_context
from models.consent import ConsentRecord
from services.consent_service import ConsentService, _build_record_candidates

router = APIRouter(prefix="/consent", tags=["Consent"])
logger = logging.getLogger(__name__)


class ConsentInitRequest(BaseModel):
    target_url: str
    agreed_to_tc: bool


class VerifyDomainRequest(BaseModel):
    consent_id: str
    domain: str


class LockScopeRequest(BaseModel):
    consent_id: str


async def _get_owned_consent(consent_id: str, current_user) -> ConsentRecord:
    try:
        consent_uuid = UUID(consent_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid consent ID") from exc

    async with get_db_context() as db:
        consent = await db.get(ConsentRecord, consent_uuid)
    if not consent:
        raise HTTPException(status_code=404, detail="Consent record not found")
    if str(consent.user_id) != str(current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    return consent


@router.post("/init")
async def init_consent(
    payload: ConsentInitRequest,
    current_user=Depends(get_current_user),
) -> dict:
    if not payload.agreed_to_tc:
        raise HTTPException(status_code=400, detail="Must agree to terms and conditions")

    consent = await ConsentService.create_consent_record(
        user_id=str(current_user.id),
        target_url=payload.target_url,
    )

    return {
        "consent_id": str(consent.id),
        "domain": consent.target_domain,
        "dns_txt_record": str(consent.dns_txt_token),
        "dns_record_name": f"_asre-verify.{consent.target_domain}",
        "expires_at": consent.expires_at.isoformat() if consent.expires_at is not None else None,
        "next_step": "dns_verification",
    }


@router.post("/verify-domain")
async def verify_domain(
    payload: VerifyDomainRequest,
    current_user=Depends(get_current_user),
) -> dict:
    consent = await _get_owned_consent(payload.consent_id, current_user)
    requested_domain = payload.domain.strip().lower()
    if requested_domain and requested_domain != str(consent.target_domain).lower():
        raise HTTPException(status_code=400, detail="Domain does not match consent target")

    verified = await ConsentService.verify_domain_ownership(consent_id=payload.consent_id)

    if verified:
        return {
            "verified": True,
            "consent_id": payload.consent_id,
            "domain": consent.target_domain,
            "next_step": "lock_scope",
        }

    return {
        "verified": False,
        "consent_id": payload.consent_id,
        "message": (
            "DNS TXT record not found yet. DNS propagation can take up to 5 minutes. "
            "Try again shortly."
        ),
        "expected_record": str(consent.dns_txt_token),
        "record_name": f"_asre-verify.{consent.target_domain}",
        "checked_record_names": _build_record_candidates(str(consent.target_domain)),
    }


@router.post("/lock-scope")
async def lock_scope(
    payload: LockScopeRequest,
    current_user=Depends(get_current_user),
) -> dict:
    consent = await _get_owned_consent(payload.consent_id, current_user)
    if not bool(consent.domain_verified):
        raise HTTPException(
            status_code=400,
            detail=(
                "Domain must be verified before locking scope. "
                "Complete DNS verification first."
            ),
        )

    locked = await ConsentService.lock_scope(consent_id=payload.consent_id)
    if not locked:
        raise HTTPException(status_code=400, detail="Unable to lock consent scope")

    async with get_db_context() as db:
        refreshed = await db.get(ConsentRecord, payload.consent_id)

    if not refreshed:
        raise HTTPException(status_code=404, detail="Consent record not found")

    return {
        "scope_locked": True,
        "consent_id": str(refreshed.id),
        "target_domain": refreshed.target_domain,
        "valid_until": refreshed.expires_at.isoformat() if refreshed.expires_at is not None else None,
        "message": (
            "Scope locked. Hardcore Mode is now enabled for this target. "
            "Consent expires in 24 hours."
        ),
        "ready_for_scan": True,
    }


@router.get("/{consent_id}")
async def get_consent_status(
    consent_id: str,
    current_user=Depends(get_current_user),
) -> dict:
    consent = await _get_owned_consent(consent_id, current_user)
    now = datetime.now(timezone.utc)
    expires_at = consent.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    is_expired = bool(expires_at and now > expires_at)

    next_step = (
        "lock_scope"
        if bool(consent.domain_verified) and not bool(consent.scope_config)
        else "verify_domain"
        if not bool(consent.domain_verified)
        else "complete"
    )

    return {
        "consent_id": str(consent.id),
        "target_domain": consent.target_domain,
        "tc_agreed": bool(consent.tc_accepted_at),
        "domain_verified": bool(consent.domain_verified),
        "scope_locked": bool(consent.scope_config),
        "expires_at": consent.expires_at.isoformat() if consent.expires_at is not None else None,
        "is_expired": is_expired,
        "next_step": next_step,
    }


@router.get("/active")
async def get_active_consents(current_user=Depends(get_current_user)) -> dict:
    now = datetime.now(timezone.utc)
    async with get_db_context() as db:
        consents = (
            await db.execute(
                select(ConsentRecord)
                .where(
                    ConsentRecord.user_id == current_user.id,
                    ConsentRecord.expires_at.is_not(None),
                    ConsentRecord.expires_at > now,
                )
                .order_by(ConsentRecord.expires_at.desc())
            )
        ).scalars().all()

    items = [
        {
            "consent_id": str(consent.id),
            "target_domain": consent.target_domain,
            "domain_verified": bool(consent.domain_verified),
            "scope_locked": bool(consent.scope_config),
            "expires_at": consent.expires_at.isoformat() if consent.expires_at is not None else None,
        }
        for consent in consents
        if bool(consent.domain_verified)
    ]

    return {
        "consents": items,
        "total": len(items),
    }
