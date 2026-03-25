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
        expected = expected_token.strip().strip('"').lower()
        normalized_domain = domain.strip().rstrip(".")
        fqdn = f"{normalized_domain}."

        resolvers: list[dns.resolver.Resolver] = []

        system_resolver = dns.resolver.Resolver()
        system_resolver.timeout = 6
        system_resolver.lifetime = 6
        resolvers.append(system_resolver)

        public_resolver = dns.resolver.Resolver(configure=False)
        public_resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        public_resolver.timeout = 6
        public_resolver.lifetime = 6
        resolvers.append(public_resolver)

        had_timeout = False
        for resolver in resolvers:
            try:
                answers = resolver.resolve(fqdn, "TXT", search=False)
            except dns.resolver.NXDOMAIN:
                continue
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NoNameservers:
                continue
            except dns.exception.Timeout:
                had_timeout = True
                continue

            for rdata in answers:
                text_chunks = [chunk.decode("utf-8") for chunk in getattr(rdata, "strings", [])]
                if text_chunks:
                    joined = "".join(text_chunks).strip().strip('"').lower()
                    if joined == expected or expected in joined:
                        return True

                text_value = str(rdata).strip('"').strip().lower()
                if text_value == expected or expected in text_value:
                    return True

        if had_timeout:
            raise TimeoutError(f"DNS lookup timed out for {domain}")

        return False

    try:
        return await asyncio.to_thread(_resolve)
    except dns.resolver.NXDOMAIN as exc:
        raise ValueError(f"Domain {domain} does not exist") from exc
    except dns.resolver.NoAnswer:
        return False
    except dns.exception.Timeout as exc:
        raise TimeoutError(f"DNS lookup timed out for {domain}") from exc


async def verify_dns_txt_record_multi(domains: list[str], expected_token: str) -> bool:
    had_timeout = False
    had_resolver_error = False
    for domain in domains:
        try:
            if await verify_dns_txt_record(domain, expected_token):
                return True
        except ValueError as exc:
            # NXDOMAIN on one candidate should not block checking other candidates.
            _ = exc
            had_resolver_error = True
            continue
        except TimeoutError as exc:
            # Timeout on one resolver path should not block fallback record checks.
            _ = exc
            had_timeout = True
            continue

    if had_timeout and not had_resolver_error:
        raise TimeoutError("DNS lookup timed out while checking TXT records")

    return False


def _build_record_candidates(target_domain: str) -> list[str]:
    domain = target_domain.strip().lower().rstrip(".")
    labels = [part for part in domain.split(".") if part]

    candidates: list[str] = [
        f"_asre-verify.{domain}",
        domain,
    ]

    # Heuristic apex fallbacks for cases where users place TXT on root domain.
    if len(labels) >= 3:
        apex2 = ".".join(labels[-2:])
        candidates.extend([f"_asre-verify.{apex2}", apex2])

    # ccTLD-like fallback (e.g., example.co.uk).
    if len(labels) >= 4 and len(labels[-1]) == 2 and len(labels[-2]) <= 3:
        apex3 = ".".join(labels[-3:])
        candidates.extend([f"_asre-verify.{apex3}", apex3])

    unique: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)

    return unique


def generate_dns_token() -> Tuple[str, str]:
    token_uuid = str(uuid4())
    dns_value = f"{settings.DNS_VERIFICATION_PREFIX}={token_uuid}"
    return token_uuid, dns_value


async def verify_and_update_consent(consent_record: ConsentRecord, db: AsyncSession) -> bool:
    try:
        target_domain = str(consent_record.target_domain).strip().lower().rstrip(".")
        record_candidates = _build_record_candidates(target_domain)
        verified = await verify_dns_txt_record_multi(
            record_candidates,
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
                existing.domain_verified = True
                existing.verified_at = now
                existing.scope_config = {
                    "scope_locked": True,
                    "target_domain": target_domain,
                    "locked_at": now.isoformat(),
                }
                existing.expires_at = now + timedelta(days=settings.CONSENT_EXPIRY_DAYS)
                existing.scan_id = None
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
                domain_verified=True,
                verified_at=now,
                tc_version=settings.TC_CURRENT_VERSION,
                tc_accepted_at=now,
                ip_address="127.0.0.1",
                scope_config={
                    "scope_locked": True,
                    "target_domain": target_domain,
                    "locked_at": now.isoformat(),
                },
                expires_at=now + timedelta(days=settings.CONSENT_EXPIRY_DAYS),
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
