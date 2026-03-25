from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from core.database import get_db_context
from models.audit_log import AuditLog


async def log_audit_entry(
    scan_id: str,
    module: str,
    request_method: Optional[str],
    request_url: Optional[str],
    response_code: Optional[int],
    notes: Optional[str] = None,
) -> None:
    async with get_db_context() as db:
        db.add(
            AuditLog(
                scan_id=UUID(scan_id),
                timestamp=datetime.now(timezone.utc),
                request_method=request_method,
                request_url=request_url,
                response_code=response_code,
                notes=notes,
                module=module,
            )
        )