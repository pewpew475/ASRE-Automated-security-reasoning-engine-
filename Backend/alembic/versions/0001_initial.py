"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-03-20
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=False)

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column("mode", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("credentials", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("endpoints_found", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("vulns_found", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("chains_found", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("celery_task_id", sa.String(length=255), nullable=True),
        sa.CheckConstraint("mode IN ('normal', 'hardcore')", name="ck_scans_mode"),
        sa.CheckConstraint(
            "status IN ('pending', 'crawling', 'scanning', 'chaining', 'analyzing', 'generating_poc', 'reporting', 'completed', 'failed', 'cancelled')",
            name="ck_scans_status",
        ),
    )
    op.create_index("idx_scans_user_id", "scans", ["user_id"], unique=False)
    op.create_index("idx_scans_status", "scans", ["status"], unique=False)

    op.create_table(
        "endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("params", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("body_params", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("headers", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("auth_required", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("idx_endpoints_scan_id", "endpoints", ["scan_id"], unique=False)

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("endpoint_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("endpoints.id"), nullable=True),
        sa.Column("vuln_type", sa.String(length=50), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("parameter", sa.String(length=255), nullable=True),
        sa.Column("payload_used", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default=sa.text("0")),
        sa.Column("is_confirmed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("poc_curl", sa.Text(), nullable=True),
        sa.Column("llm_impact", sa.Text(), nullable=True),
        sa.Column("fix_suggestion", sa.Text(), nullable=True),
        sa.Column("mitre_id", sa.String(length=20), nullable=True),
        sa.Column("owasp_category", sa.String(length=50), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.CheckConstraint("severity IN ('critical', 'high', 'medium', 'low', 'info')", name="ck_findings_severity"),
    )
    op.create_index("idx_findings_scan_id", "findings", ["scan_id"], unique=False)
    op.create_index("idx_findings_endpoint_id", "findings", ["endpoint_id"], unique=False)
    op.create_index("idx_findings_vuln_type", "findings", ["vuln_type"], unique=False)
    op.create_index("idx_findings_severity", "findings", ["severity"], unique=False)

    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("format", sa.String(length=10), nullable=False, server_default=sa.text("'pdf'")),
        sa.Column("file_path", sa.String(length=500), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("total_findings", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("critical_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("high_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("medium_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("low_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("info_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("executive_summary", sa.Text(), nullable=True),
    )
    op.create_index("idx_reports_scan_id", "reports", ["scan_id"], unique=False)

    op.create_table(
        "consent_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("target_domain", sa.String(length=255), nullable=False),
        sa.Column("dns_txt_token", sa.String(length=255), nullable=False),
        sa.Column("domain_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tc_version", sa.String(length=20), nullable=False),
        sa.Column("tc_accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip_address", postgresql.INET(), nullable=False),
        sa.Column("scope_config", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("idx_consent_user_domain", "consent_records", ["user_id", "target_domain"], unique=False)
    op.create_index("idx_consent_domain_verified", "consent_records", ["domain_verified"], unique=False)

    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("request_method", sa.String(length=10), nullable=True),
        sa.Column("request_url", sa.String(length=2048), nullable=True),
        sa.Column("request_headers", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("request_body", sa.Text(), nullable=True),
        sa.Column("response_code", sa.Integer(), nullable=True),
        sa.Column("response_size", sa.Integer(), nullable=True),
        sa.Column("module", sa.String(length=50), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_index("idx_audit_log_scan_id", "audit_log", ["scan_id"], unique=False)
    op.create_index("idx_audit_log_timestamp", "audit_log", ["timestamp"], unique=False)

    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_audit_modification()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION
                'audit_log is append-only - UPDATE and DELETE are forbidden';
        END;
        $$ LANGUAGE plpgsql;
        """
    )

    op.execute(
        """
        CREATE TRIGGER audit_log_immutable
        BEFORE UPDATE OR DELETE ON audit_log
        FOR EACH ROW
        EXECUTE FUNCTION prevent_audit_modification();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_immutable ON audit_log;")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_modification;")

    op.drop_index("idx_audit_log_timestamp", table_name="audit_log")
    op.drop_index("idx_audit_log_scan_id", table_name="audit_log")
    op.drop_table("audit_log")

    op.drop_index("idx_consent_domain_verified", table_name="consent_records")
    op.drop_index("idx_consent_user_domain", table_name="consent_records")
    op.drop_table("consent_records")

    op.drop_index("idx_reports_scan_id", table_name="reports")
    op.drop_table("reports")

    op.drop_index("idx_findings_severity", table_name="findings")
    op.drop_index("idx_findings_vuln_type", table_name="findings")
    op.drop_index("idx_findings_endpoint_id", table_name="findings")
    op.drop_index("idx_findings_scan_id", table_name="findings")
    op.drop_table("findings")

    op.drop_index("idx_endpoints_scan_id", table_name="endpoints")
    op.drop_table("endpoints")

    op.drop_index("idx_scans_status", table_name="scans")
    op.drop_index("idx_scans_user_id", table_name="scans")
    op.drop_table("scans")

    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
