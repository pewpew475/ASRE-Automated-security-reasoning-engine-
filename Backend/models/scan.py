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


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("mode IN ('normal', 'hardcore')", name="ck_scans_mode"),
        CheckConstraint(
            "status IN ('pending', 'crawling', 'scanning', 'chaining', 'analyzing', 'generating_poc', 'reporting', 'completed', 'failed', 'cancelled')",
            name="ck_scans_status",
        ),
        Index("idx_scans_user_id", "user_id"),
        Index("idx_scans_status", "status"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    target_url = Column(String(2048), nullable=False)
    mode = Column(String(20), nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    config = Column(JSONB, nullable=False, default=dict)
    credentials = Column(JSONB, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    endpoints_found = Column(Integer, nullable=False, default=0)
    vulns_found = Column(Integer, nullable=False, default=0)
    chains_found = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    celery_task_id = Column(String(255), nullable=True)

    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    consent_record = relationship("ConsentRecord", back_populates="scan", uselist=False)
