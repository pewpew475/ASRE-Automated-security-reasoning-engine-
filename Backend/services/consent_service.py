import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Tuple
from urllib.parse import urlparse
from uuid import UUID, uuid4

import dns.exception
import dns.resolver
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from core.database import get_db_context
from models.consent import ConsentRecord

logger = logging.getLogger(__name__)


async def verify_dns_txt_record(domain: str, expected_token: str) -> bool:
    def _resolve() -> bool:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10

        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            text_chunks = [chunk.decode("utf-8") for chunk in getattr(rdata, "strings", [])]
            if text_chunks and "".join(text_chunks) == expected_token:
                return True

            text_value = str(rdata).strip('"')
            if text_value == expected_token:
                return True
        return False

    try:
        return await asyncio.to_thread(_resolve)
    except dns.resolver.NXDOMAIN as exc:
        raise ValueError(f"Domain {domain} does not exist") from exc
    except dns.resolver.NoAnswer:
        return False
    except dns.exception.Timeout as exc:
        raise TimeoutError(f"DNS lookup timed out for {domain}") from exc


def generate_dns_token() -> Tuple[str, str]:
    token_uuid = str(uuid4())
    dns_value = f"{settings.DNS_VERIFICATION_PREFIX}={token_uuid}"
    return token_uuid, dns_value


async def verify_and_update_consent(consent_record: ConsentRecord, db: AsyncSession) -> bool:
    try:
        verified = await verify_dns_txt_record(
            str(consent_record.target_domain),
            str(consent_record.dns_txt_token),
        )
        if not verified:
            return False

        now = datetime.now(timezone.utc)
        consent_record.domain_verified = True
        consent_record.verified_at = now
        consent_record.expires_at = now + timedelta(days=settings.CONSENT_EXPIRY_DAYS)

        db.add(consent_record)
        await db.flush()
        return True
    except Exception as exc:
        logger.error(
            "Consent verification failed for domain %s: %s",
            str(consent_record.target_domain),
            exc,
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc


class ConsentService:
    @staticmethod
    def _extract_domain(target_url: str) -> str:
        parsed = urlparse(target_url)
        domain = parsed.hostname or parsed.netloc
        if not domain:
            raise HTTPException(status_code=400, detail="Invalid target URL")
        return domain.lower()

    @staticmethod
    async def create_consent_record(user_id: str, target_url: str) -> ConsentRecord:
        target_domain = ConsentService._extract_domain(target_url)
        _, dns_value = generate_dns_token()
        now = datetime.now(timezone.utc)

        try:
            user_uuid = UUID(user_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid user ID") from exc

        async with get_db_context() as db:
            existing = (
                await db.execute(
                    select(ConsentRecord).where(
                        ConsentRecord.user_id == user_uuid,
                        ConsentRecord.target_domain == target_domain,
                    )
                )
            ).scalar_one_or_none()

            if existing is not None:
                existing.dns_txt_token = dns_value
                existing.domain_verified = False
                existing.verified_at = None
                existing.scope_config = {}
                existing.expires_at = None
                existing.tc_version = settings.TC_CURRENT_VERSION
                existing.tc_accepted_at = now
                existing.ip_address = "127.0.0.1"
                db.add(existing)
                await db.flush()
                return existing

            consent = ConsentRecord(
                id=uuid4(),
                user_id=user_uuid,
                target_domain=target_domain,
                dns_txt_token=dns_value,
                domain_verified=False,
                tc_version=settings.TC_CURRENT_VERSION,
                tc_accepted_at=now,
                ip_address="127.0.0.1",
                scope_config={},
                expires_at=None,
            )
            db.add(consent)
            await db.flush()
            return consent

    @staticmethod
    async def verify_domain_ownership(consent_id: str) -> bool:
        try:
            consent_uuid = UUID(consent_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid consent ID") from exc

        async with get_db_context() as db:
            consent = await db.get(ConsentRecord, consent_uuid)
            if consent is None:
                raise HTTPException(status_code=404, detail="Consent record not found")

            return await verify_and_update_consent(consent_record=consent, db=db)

    @staticmethod
    async def lock_scope(consent_id: str) -> bool:
        try:
            consent_uuid = UUID(consent_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid consent ID") from exc

        async with get_db_context() as db:
            consent = await db.get(ConsentRecord, consent_uuid)
            if consent is None:
                raise HTTPException(status_code=404, detail="Consent record not found")

            if not bool(consent.domain_verified):
                return False

            now = datetime.now(timezone.utc)
            consent.scope_config = {
                "scope_locked": True,
                "target_domain": str(consent.target_domain),
                "locked_at": now.isoformat(),
            }
            consent.expires_at = now + timedelta(days=settings.CONSENT_EXPIRY_DAYS)
            db.add(consent)
            await db.flush()
            return True
