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


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (Index("idx_endpoints_scan_id", "scan_id"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    url = Column(String(2048), nullable=False)
    method = Column(String(10), nullable=False)
    params = Column(JSONB, nullable=False, default=list)
    body_params = Column(JSONB, nullable=False, default=list)
    headers = Column(JSONB, nullable=False, default=dict)
    auth_required = Column(Boolean, nullable=False, default=False)
    content_type = Column(String(255), nullable=True)
    status_code = Column(Integer, nullable=True)
    discovered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scan = relationship("Scan", back_populates="endpoints")
    findings = relationship("Finding", back_populates="endpoint")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_findings_severity",
        ),
        Index("idx_findings_scan_id", "scan_id"),
        Index("idx_findings_endpoint_id", "endpoint_id"),
        Index("idx_findings_vuln_type", "vuln_type"),
        Index("idx_findings_severity", "severity"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    endpoint_id = Column(UUID(as_uuid=True), ForeignKey("endpoints.id"), nullable=True)
    vuln_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    evidence = Column(JSONB, nullable=False, default=dict)
    parameter = Column(String(255), nullable=True)
    payload_used = Column(Text, nullable=True)
    confidence = Column(Float, nullable=False, default=0.0)
    is_confirmed = Column(Boolean, nullable=False, default=False)
    poc_curl = Column(Text, nullable=True)
    llm_impact = Column(Text, nullable=True)
    fix_suggestion = Column(Text, nullable=True)
    mitre_id = Column(String(20), nullable=True)
    owasp_category = Column(String(50), nullable=True)
    detected_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scan = relationship("Scan", back_populates="findings")
    endpoint = relationship("Endpoint", back_populates="findings")
