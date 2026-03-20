from datetime import datetime, timezone
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import relationship

from core.database import Base


class ConsentRecord(Base):
    __tablename__ = "consent_records"
    __table_args__ = (
        Index("idx_consent_user_domain", "user_id", "target_domain"),
        Index("idx_consent_domain_verified", "domain_verified"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    target_domain = Column(String(255), nullable=False)
    dns_txt_token = Column(String(255), nullable=False)
    domain_verified = Column(Boolean, nullable=False, default=False)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    tc_version = Column(String(20), nullable=False)
    tc_accepted_at = Column(DateTime(timezone=True), nullable=False)
    ip_address = Column(INET, nullable=False)
    scope_config = Column(JSONB, nullable=False, default=dict)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="consent_records")
    scan = relationship("Scan", back_populates="consent_record")
