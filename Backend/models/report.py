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


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (Index("idx_reports_scan_id", "scan_id"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    format = Column(String(10), nullable=False, default="pdf")
    file_path = Column(String(500), nullable=True)
    generated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    total_findings = Column(Integer, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    info_count = Column(Integer, nullable=False, default=0)
    executive_summary = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="reports")
