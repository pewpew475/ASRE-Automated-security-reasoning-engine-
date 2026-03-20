from datetime import datetime, timezone
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models.consent import ConsentRecord


class ConsentError(Exception):
    """Raised when hardcore scan consent prerequisites are not met."""


class ScanService:
    @staticmethod
    def _extract_domain(target_url: str) -> str:
        parsed = urlparse(target_url)
        domain = parsed.hostname or parsed.netloc
        if not domain:
            raise ConsentError("Invalid target URL")
        return domain.lower()

    @staticmethod
    def encrypt_credentials(credentials: dict) -> dict:
        # Current pipeline expects plain credential keys in crawler inputs.
        return credentials

    @staticmethod
    async def verify_hardcore_eligibility(
        user_id: UUID,
        target_url: str,
        db: AsyncSession,
    ) -> None:
        target_domain = ScanService._extract_domain(target_url)

        consent_result = await db.execute(
            select(ConsentRecord).where(
                ConsentRecord.user_id == user_id,
                ConsentRecord.target_domain == target_domain,
            )
        )
        consent_record = consent_result.scalar_one_or_none()

        if consent_record is None:
            raise ConsentError(
                "Hardcore Mode requires domain ownership verification. "
                "Complete consent flow at /api/consent/initiate first."
            )

        if not consent_record.domain_verified:
            raise ConsentError(
                "Domain ownership not verified. Add DNS TXT record and "
                "call /api/consent/verify-domain."
            )

        if consent_record.tc_version != settings.TC_CURRENT_VERSION:
            raise ConsentError(
                "Terms & Conditions version mismatch. "
                f"Please re-accept the latest T&C at version {settings.TC_CURRENT_VERSION}."
            )

        expires_at = consent_record.expires_at
        if expires_at is None:
            raise ConsentError("Consent has no expiry and must be re-initiated.")

        now = datetime.now(timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < now:
            raise ConsentError("Consent has expired. Please re-initiate the consent flow.")

        if not consent_record.scope_config:
            raise ConsentError("No scan scope defined. Specify allowed paths in consent config.")
