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


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        Index("idx_audit_log_scan_id", "scan_id"),
        Index("idx_audit_log_timestamp", "timestamp"),
    )

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    request_method = Column(String(10), nullable=True)
    request_url = Column(String(2048), nullable=True)
    request_headers = Column(JSONB, nullable=True)
    request_body = Column(Text, nullable=True)
    response_code = Column(Integer, nullable=True)
    response_size = Column(Integer, nullable=True)
    module = Column(String(50), nullable=True)
    notes = Column(Text, nullable=True)
