import logging
from json import dumps
from pathlib import Path
from typing import Any, Optional, Sequence, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, Field
from sqlalchemy import select

from api.deps import get_current_user
from core.llm_registry import LLMRegistry
from core.database import get_db_context
from models.finding import Finding
from models.report import Report
from models.scan import Scan
from scanner.chain_builder import ChainBuilder
from tasks.scan_tasks import regenerate_report_task

router = APIRouter(prefix="/reports", tags=["Reports"])
logger = logging.getLogger(__name__)


class ReportAssistantMessage(BaseModel):
    role: str = Field(description="chat role: user or assistant")
    content: str = Field(min_length=1, max_length=3000)


class ReportAssistantRequest(BaseModel):
    question: str = Field(min_length=3, max_length=4000)
    history: list[ReportAssistantMessage] = Field(default_factory=list)


def _truncate(value: str, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


def _build_report_context_block(scan: Scan, report: Optional[Report], findings: Sequence[Finding], chains: list[dict]) -> str:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda item: (
            severity_order.get(str(getattr(item, "severity", "info") or "info").lower(), 5),
            str(getattr(item, "title", "")),
        ),
    )

    top_findings = []
    for finding in sorted_findings[:25]:
        top_findings.append(
            {
                "severity": str(getattr(finding, "severity", "info") or "info").lower(),
                "type": str(getattr(finding, "vuln_type", "unknown") or "unknown"),
                "title": _truncate(str(getattr(finding, "title", "Untitled") or "Untitled"), 140),
                "endpoint": _truncate(
                    str(
                        (
                            getattr(getattr(finding, "endpoint", None), "url", "")
                            or (getattr(finding, "evidence", {}) or {}).get("request_url", "")
                            or "N/A"
                        )
                    ),
                    180,
                ),
                "impact": _truncate(str(getattr(finding, "llm_impact", "") or ""), 220),
                "fix": _truncate(str(getattr(finding, "fix_suggestion", "") or ""), 220),
            }
        )

    top_chains = []
    for chain in chains[:12]:
        top_chains.append(
            {
                "entry_point": _truncate(str(chain.get("entry_point", "")), 160),
                "final_impact": _truncate(str(chain.get("final_impact", "")), 160),
                "severity_score": float(chain.get("severity_score", 0.0) or 0.0),
                "length": int(chain.get("length", 0) or 0),
                "nodes": [
                    _truncate(str(node), 120)
                    for node in (chain.get("nodes", []) or [])[:8]
                ],
            }
        )

    report_summary = {
        "scan_id": str(getattr(scan, "id", "")),
        "target_url": str(getattr(scan, "target_url", "")),
        "mode": str(getattr(scan, "mode", "")),
        "status": str(getattr(scan, "status", "")),
        "counts": {
            "findings_total": len(findings),
            "critical": sum(1 for item in findings if str(getattr(item, "severity", "")).lower() == "critical"),
            "high": sum(1 for item in findings if str(getattr(item, "severity", "")).lower() == "high"),
            "medium": sum(1 for item in findings if str(getattr(item, "severity", "")).lower() == "medium"),
            "low": sum(1 for item in findings if str(getattr(item, "severity", "")).lower() == "low"),
            "info": sum(1 for item in findings if str(getattr(item, "severity", "")).lower() == "info"),
            "chains": len(chains),
        },
        "report_generated_at": str(getattr(report, "generated_at", "") or ""),
        "report_summary": _truncate(str(getattr(report, "executive_summary", "") or ""), 2400),
        "top_findings": top_findings,
        "top_chains": top_chains,
    }
    return dumps(report_summary, ensure_ascii=True)


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
    suffix = pdf_path.suffix.lower()
    media_type = "application/pdf"
    if suffix == ".html":
        media_type = "text/html"

    ext = suffix.lstrip(".") or "pdf"
    filename = f"asre-report-{short_id}.{ext}"
    return FileResponse(
        path=str(pdf_path),
        media_type=media_type,
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


@router.post("/{scan_id}/assistant")
async def ask_report_assistant(
    scan_id: str,
    payload: ReportAssistantRequest,
    current_user=Depends(get_current_user),
) -> dict:
    scan = await _verify_scan_ownership(scan_id=scan_id, current_user=current_user)

    if not payload.question.strip():
        raise HTTPException(status_code=400, detail="Question is required")

    async with get_db_context() as db:
        report = (
            await db.execute(select(Report).where(Report.scan_id == UUID(scan_id)))
        ).scalar_one_or_none()
        findings = (
            await db.execute(select(Finding).where(Finding.scan_id == UUID(scan_id)).order_by(Finding.detected_at.desc()))
        ).scalars().all()

    chains = await ChainBuilder.get_ranked_chains(scan_id=scan_id)

    if not findings and not report and not chains:
        raise HTTPException(status_code=404, detail="No report context available for this scan yet")

    if len(payload.history) > 12:
        payload.history = payload.history[-12:]

    context_block = _build_report_context_block(scan=scan, report=report, findings=findings, chains=chains)

    system_text = (
        "You are ASRE Report Assistant. Answer only with guidance relevant to this scan report context. "
        "If user asks beyond report scope, say that the report does not provide enough evidence and suggest the next scan/probe. "
        "Prioritize actionable remediation order, exploitability, business impact, and verification steps. "
        "Use concise sections and bullet points. Do not invent findings."
    )

    llm = None
    try:
        llm = LLMRegistry.get_client()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"LLM is not available: {exc}") from exc

    messages = [
        SystemMessage(content=system_text),
        HumanMessage(content=f"SCAN REPORT CONTEXT JSON:\n{context_block}"),
    ]

    for message in payload.history:
        role = message.role.strip().lower()
        content = _truncate(message.content, 3000)
        if role == "assistant":
            messages.append(AIMessage(content=content))
        elif role == "user":
            messages.append(HumanMessage(content=content))

    messages.append(HumanMessage(content=f"User question: {payload.question.strip()}"))

    try:
        response = await llm.ainvoke(messages)
        answer = _truncate(str(getattr(response, "content", "")).strip(), 12000)
    except Exception as exc:
        logger.exception("Report assistant failed for scan=%s", scan_id)
        raise HTTPException(status_code=500, detail=f"Assistant failed: {exc}") from exc

    return {
        "answer": answer or "I could not generate an answer from the report context.",
        "scan_id": scan_id,
    }
