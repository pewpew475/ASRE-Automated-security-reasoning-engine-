import logging
from datetime import datetime, timezone
from typing import Optional

from celery.result import AsyncResult
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import case, func, select, update

from api.deps import CurrentUser, DBSession, get_scan_or_404
from config import settings
from models.finding import Endpoint, Finding
from models.scan import Scan
from schemas.finding import EndpointResponse, FindingResponse, FindingsListResponse
from schemas.scan import (
    ScanCreateResponse,
    ScanListItem,
    ScanListResponse,
    ScanStatusResponse,
    StartScanRequest,
)
from services.scan_service import ScanService
from tasks.celery_app import celery_app
from tasks.scan_tasks import run_scan_pipeline

router = APIRouter()
logger = logging.getLogger(__name__)


PHASE_BY_STATUS = {
    "pending": "Waiting to start",
    "crawling": "Phase 1: Crawling endpoints",
    "scanning": "Phase 2: Running vulnerability probes",
    "chaining": "Phase 3: Building attack chains",
    "analyzing": "Phase 4: LLM impact analysis",
    "generating_poc": "Phase 5: Generating PoC evidence",
    "reporting": "Phase 6: Generating PDF report",
    "completed": "Scan complete",
    "failed": "Scan failed",
    "cancelled": "Scan cancelled",
}

VALID_STATUSES = {
    "pending",
    "crawling",
    "scanning",
    "chaining",
    "analyzing",
    "generating_poc",
    "reporting",
    "completed",
    "failed",
    "cancelled",
}
VALID_MODES = {"normal", "hardcore"}
VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"]
VALID_VULN_TYPES = {
    "xss",
    "idor",
    "csrf",
    "sqli",
    "auth",
    "cors",
    "business_logic",
    "header",
    "rate_limit",
    "user_enum",
    "jwt",
    "session",
    "cve",
}


def _raise_internal_scan_error(exc: Exception, context: str, scan_id: Optional[str] = None) -> None:
    logger.error(
        "Unexpected scan operation error | context=%s | scan_id=%s | error=%s",
        context,
        scan_id,
        exc,
        exc_info=True,
    )
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="An internal error occurred during scan operation.",
    ) from exc


def _is_consent_error(exc: Exception) -> bool:
    return exc.__class__.__name__ == "ConsentError"


@router.post(
    "/start",
    response_model=ScanCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a new security scan",
    description=(
        "Queues a new scan job. The scan runs asynchronously via Celery. "
        "Use GET /scan/{scan_id}/status to poll progress, "
        "or connect to WS /ws/scan/{scan_id} for real-time updates."
    ),
)
async def start_scan(
    payload: StartScanRequest,
    current_user: CurrentUser,
    db: DBSession,
) -> ScanCreateResponse:
    if payload.mode == "hardcore":
        try:
            await ScanService.verify_hardcore_eligibility(
                user_id=current_user.id,
                target_url=payload.target_url,
                db=db,
            )
        except HTTPException:
            raise
        except Exception as exc:
            if _is_consent_error(exc):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=str(exc),
                ) from exc
            _raise_internal_scan_error(exc, context="start_scan.hardcore_precheck")

    try:
        encrypted_creds = None
        if payload.credentials is not None:
            encrypted_creds = ScanService.encrypt_credentials(payload.credentials.model_dump())

        new_scan = Scan(
            user_id=current_user.id,
            target_url=str(payload.target_url),
            mode=payload.mode,
            status="pending",
            config=payload.config.model_dump(),
            credentials=encrypted_creds,
        )
        db.add(new_scan)
        await db.flush()

        try:
            task = run_scan_pipeline.apply_async(
                args=[str(new_scan.id)],
                queue="scans",
                task_id=str(new_scan.id),
            )
        except ConnectionError as exc:
            await db.execute(
                update(Scan)
                .where(Scan.id == new_scan.id)
                .values(
                    status="failed",
                    completed_at=datetime.now(timezone.utc),
                    error_message="Scan queue unavailable",
                )
            )
            await db.commit()
            logger.error("Celery queue unavailable while starting scan %s", new_scan.id, exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Scan queue is currently unavailable. Please try again shortly.",
            ) from exc

        new_scan.celery_task_id = task.id

        logger.info(
            "Scan queued: %s | mode=%s | target=%s | user=%s",
            new_scan.id,
            payload.mode,
            payload.target_url,
            current_user.email,
        )

        return ScanCreateResponse(
            scan_id=new_scan.id,
            status="pending",
            message=(
                "Scan queued successfully. "
                f"Track progress at /api/scan/{new_scan.id}/status"
            ),
        )
    except HTTPException:
        raise
    except Exception as exc:
        _raise_internal_scan_error(exc, context="start_scan", scan_id=None)


@router.get(
    "/{scan_id}/status",
    response_model=ScanStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get scan status and progress",
    description="Returns current status, phase, and progress counters.",
)
async def get_scan_status(
    scan: Scan = Depends(get_scan_or_404),
    db: DBSession = Depends(),
) -> ScanStatusResponse:
    _ = db
    try:
        elapsed = None
        if scan.started_at is not None:
            elapsed = (datetime.now(timezone.utc) - scan.started_at).total_seconds()

        phase = PHASE_BY_STATUS.get(scan.status, "Unknown phase")

        return ScanStatusResponse(
            scan_id=scan.id,
            status=scan.status,
            mode=scan.mode,
            target_url=scan.target_url,
            phase=phase,
            progress={
                "endpoints_found": scan.endpoints_found,
                "vulns_found": scan.vulns_found,
                "chains_found": scan.chains_found,
            },
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            elapsed_seconds=elapsed,
            error_message=scan.error_message,
        )
    except Exception as exc:
        _raise_internal_scan_error(exc, context="get_scan_status", scan_id=str(scan.id))


@router.get(
    "/history",
    response_model=ScanListResponse,
    status_code=status.HTTP_200_OK,
    summary="List all scans for current user",
    description="Returns paginated scan history with optional filters.",
)
async def get_scan_history(
    current_user: CurrentUser,
    db: DBSession,
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=20, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(
        default=None,
        description="Filter by status (e.g. completed, failed)",
    ),
    mode: Optional[str] = Query(
        default=None,
        description="Filter by mode: normal or hardcore",
    ),
) -> ScanListResponse:
    try:
        query = select(Scan).where(Scan.user_id == current_user.id)

        if status is not None and status in VALID_STATUSES:
            query = query.where(Scan.status == status)
        if mode is not None and mode in VALID_MODES:
            query = query.where(Scan.mode == mode)

        count_query = select(func.count()).select_from(query.subquery())
        total = await db.scalar(count_query)
        if total is None:
            total = 0

        query = query.order_by(Scan.created_at.desc())
        query = query.offset((page - 1) * limit).limit(limit)

        result = await db.execute(query)
        scans = result.scalars().all()

        return ScanListResponse(
            scans=[ScanListItem.model_validate(scan) for scan in scans],
            total=total,
            page=page,
            limit=limit,
        )
    except Exception as exc:
        _raise_internal_scan_error(exc, context="get_scan_history")


@router.post(
    "/{scan_id}/cancel",
    status_code=status.HTTP_200_OK,
    summary="Cancel a running scan",
    description="Terminates the Celery task and marks scan as cancelled.",
)
async def cancel_scan(
    scan: Scan = Depends(get_scan_or_404),
    db: DBSession = Depends(),
) -> dict[str, str]:
    cancellable_statuses = {
        "pending",
        "crawling",
        "scanning",
        "chaining",
        "analyzing",
        "generating_poc",
    }

    if scan.status not in cancellable_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot cancel scan with status '{scan.status}'. "
                "Only active scans can be cancelled."
            ),
        )

    try:
        task_id = scan.celery_task_id or AsyncResult(str(scan.id), app=celery_app).id
        celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")

        await db.execute(
            update(Scan)
            .where(Scan.id == scan.id)
            .values(
                status="cancelled",
                completed_at=datetime.now(timezone.utc),
                error_message="Cancelled by user",
            )
        )

        logger.info("Scan %s cancelled by user %s", scan.id, scan.user_id)

        return {
            "scan_id": str(scan.id),
            "status": "cancelled",
            "message": "Scan has been cancelled",
        }
    except HTTPException:
        raise
    except Exception as exc:
        _raise_internal_scan_error(exc, context="cancel_scan", scan_id=str(scan.id))


@router.get(
    "/{scan_id}/findings",
    response_model=FindingsListResponse,
    status_code=status.HTTP_200_OK,
    summary="Get all findings for a scan",
    description="Returns vulnerability findings with optional severity/type filters.",
)
async def get_scan_findings(
    scan: Scan = Depends(get_scan_or_404),
    db: DBSession = Depends(),
    severity: Optional[str] = Query(
        default=None,
        description="Comma-separated severities: critical,high,medium,low,info",
    ),
    vuln_type: Optional[str] = Query(
        default=None,
        description="Comma-separated types: xss,idor,csrf,sqli,auth,cors",
    ),
) -> FindingsListResponse:
    try:
        query = select(Finding).where(Finding.scan_id == scan.id)

        if severity:
            severity_list = [s.strip() for s in severity.split(",") if s.strip()]
            severity_list = [s for s in severity_list if s in VALID_SEVERITIES]
            if severity_list:
                query = query.where(Finding.severity.in_(severity_list))

        if vuln_type:
            vuln_type_list = [v.strip() for v in vuln_type.split(",") if v.strip()]
            vuln_type_list = [v for v in vuln_type_list if v in VALID_VULN_TYPES]
            if vuln_type_list:
                query = query.where(Finding.vuln_type.in_(vuln_type_list))

        severity_order = case(
            {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4,
            },
            value=Finding.severity,
            else_=5,
        )
        query = query.order_by(severity_order, Finding.detected_at.desc())

        result = await db.execute(query)
        findings = result.scalars().all()

        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            if finding.severity in by_severity:
                by_severity[finding.severity] += 1

        return FindingsListResponse(
            findings=[FindingResponse.model_validate(finding) for finding in findings],
            total=len(findings),
            by_severity=by_severity,
        )
    except Exception as exc:
        _raise_internal_scan_error(exc, context="get_scan_findings", scan_id=str(scan.id))


@router.get(
    "/{scan_id}/endpoints",
    status_code=status.HTTP_200_OK,
    summary="Get all discovered endpoints for a scan",
    description="Returns the list of crawled endpoints from Phase 1.",
)
async def get_scan_endpoints(
    scan: Scan = Depends(get_scan_or_404),
    db: DBSession = Depends(),
    auth_required: Optional[bool] = Query(
        default=None,
        description="Filter: only auth-required endpoints",
    ),
) -> dict[str, object]:
    try:
        query = select(Endpoint).where(Endpoint.scan_id == scan.id)
        if auth_required is not None:
            query = query.where(Endpoint.auth_required == auth_required)
        query = query.order_by(Endpoint.discovered_at.asc())

        result = await db.execute(query)
        endpoints = result.scalars().all()

        return {
            "endpoints": [EndpointResponse.model_validate(endpoint) for endpoint in endpoints],
            "total": len(endpoints),
        }
    except Exception as exc:
        _raise_internal_scan_error(exc, context="get_scan_endpoints", scan_id=str(scan.id))
