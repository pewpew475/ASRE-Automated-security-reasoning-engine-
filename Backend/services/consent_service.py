import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Tuple
from uuid import uuid4

import dns.exception
import dns.resolver
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models.consent import ConsentRecord

logger = logging.getLogger(__name__)


async def verify_dns_txt_record(domain: str, expected_token: str) -> bool:
    def _resolve() -> bool:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10

        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode("utf-8")
                if decoded == expected_token:
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
            consent_record.target_domain,
            consent_record.dns_txt_token,
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
        logger.error("Consent verification failed for domain %s: %s", consent_record.target_domain, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
