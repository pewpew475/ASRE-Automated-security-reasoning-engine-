import logging
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select

from api.deps import get_current_user
from core.database import get_db_context
from models.report import Report
from models.scan import Scan
from tasks.scan_tasks import regenerate_report_task

router = APIRouter(prefix="/reports", tags=["Reports"])
logger = logging.getLogger(__name__)


async def _verify_scan_ownership(scan_id: str, current_user) -> Scan:
    try:
        scan_uuid = UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid scan ID") from exc

    async with get_db_context() as db:
        scan = await db.get(Scan, scan_uuid)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if str(scan.user_id) != str(current_user.id):
            raise HTTPException(status_code=403, detail="Access denied")
        return scan


@router.get("/{scan_id}")
async def get_report_metadata(
    scan_id: str,
    current_user=Depends(get_current_user),
) -> dict:
    await _verify_scan_ownership(scan_id=scan_id, current_user=current_user)

    async with get_db_context() as db:
        report = (
            await db.execute(select(Report).where(Report.scan_id == UUID(scan_id)))
        ).scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report not yet generated. Scan may still be in progress.",
        )

    file_size_bytes = getattr(report, "file_size_bytes", None)
    report_path = str(report.file_path) if getattr(report, "file_path", None) else ""
    if file_size_bytes is None and report_path:
        pdf_path = Path(report_path)
        file_size_bytes = pdf_path.stat().st_size if pdf_path.exists() else 0

    return {
        "scan_id": str(report.scan_id),
        "report_id": str(report.id),
        "generated_at": report.generated_at.isoformat(),
        "file_size_kb": int(file_size_bytes or 0) // 1024,
        "total_findings": report.total_findings,
        "critical_count": report.critical_count,
        "high_count": report.high_count,
        "medium_count": report.medium_count,
        "low_count": report.low_count,
        "info_count": report.info_count,
        "download_url": f"/api/reports/{scan_id}/download",
    }


@router.get("/{scan_id}/download")
async def download_report(
    scan_id: str,
    current_user=Depends(get_current_user),
) -> FileResponse:
    await _verify_scan_ownership(scan_id=scan_id, current_user=current_user)

    async with get_db_context() as db:
        report = (
            await db.execute(select(Report).where(Report.scan_id == UUID(scan_id)))
        ).scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report not yet generated. Scan may still be in progress.",
        )

    report_path = str(report.file_path) if getattr(report, "file_path", None) else ""
    if not report_path:
        raise HTTPException(
            status_code=404,
            detail="Report file path is missing. Try regenerating the report.",
        )

    pdf_path = Path(report_path)
    if not pdf_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Report file not found on disk. Try regenerating the report.",
        )

    short_id = scan_id[:8]
    filename = f"asre-report-{short_id}.pdf"
    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=filename,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Report-Generated": report.generated_at.isoformat(),
        },
    )


@router.post("/{scan_id}/regenerate")
async def regenerate_report(
    scan_id: str,
    current_user=Depends(get_current_user),
) -> dict:
    scan = await _verify_scan_ownership(scan_id=scan_id, current_user=current_user)
    if str(scan.status) != "completed":
        raise HTTPException(
            status_code=400,
            detail="Report regeneration is only available for completed scans",
        )

    task = cast(Any, regenerate_report_task).delay(scan_id)
    return {
        "message": "Report regeneration queued",
        "task_id": task.id,
    }


@router.delete("/{scan_id}")
async def delete_report(
    scan_id: str,
    current_user=Depends(get_current_user),
) -> dict:
    await _verify_scan_ownership(scan_id=scan_id, current_user=current_user)

    async with get_db_context() as db:
        report = (
            await db.execute(select(Report).where(Report.scan_id == UUID(scan_id)))
        ).scalar_one_or_none()

        if report:
            report_path = str(report.file_path) if getattr(report, "file_path", None) else ""
            pdf_path = Path(report_path) if report_path else None
            if pdf_path is not None and pdf_path.exists():
                pdf_path.unlink()
            await db.delete(report)
            await db.flush()

    return {"message": "Report deleted"}
