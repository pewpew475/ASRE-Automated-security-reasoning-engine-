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
    ) -> ConsentRecord:
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
                "Hardcore Mode requires consent before scanning. "
                "Click 'Give Consent and Continue' first."
            )

        if consent_record.tc_version != settings.TC_CURRENT_VERSION:
            raise ConsentError(
                "Terms & Conditions version mismatch. "
                f"Please re-accept the latest T&C at version {settings.TC_CURRENT_VERSION}."
            )

        expires_at = consent_record.expires_at
        if expires_at is None:
            # Consent is considered active when T&C has been accepted in the simplified flow.
            return consent_record

        now = datetime.now(timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < now:
            raise ConsentError("Consent has expired. Please re-initiate the consent flow.")

        return consent_record
