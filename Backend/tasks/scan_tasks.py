import asyncio
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Optional
from uuid import UUID

from celery.exceptions import SoftTimeLimitExceeded
from celery.utils.log import get_task_logger
from sqlalchemy import select, update

from api.routes.websocket import publish_scan_event
from config import settings
from core.database import get_db_context
from core.neo4j_client import neo4j_client
from models.audit_log import AuditLog
from models.consent import ConsentRecord
from models.finding import Endpoint, Finding
from models.scan import Scan
from scanner.chain_builder import ChainBuilder
from scanner.crawler import Crawler
from scanner.llm_analyzer import LLMAnalyzer
from scanner.poc_generator import PoCGenerator
from scanner.report_engine import ReportEngine
from scanner.rule_engine import RuleEngine
from tasks.celery_app import celery_app

logger = get_task_logger(__name__)

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


def _value(data: object, field: str, default: object = None) -> object:
    if isinstance(data, dict):
        return data.get(field, default)
    return getattr(data, field, default)


def _as_dict(data: object) -> dict:
    if isinstance(data, dict):
        return data
    if hasattr(data, "model_dump"):
        return data.model_dump()
    return data.__dict__ if hasattr(data, "__dict__") else {}


async def _is_cancelled(scan_id: str) -> bool:
    async with get_db_context() as db:
        scan = await db.get(Scan, UUID(scan_id))
        return scan is None or scan.status == "cancelled"


async def update_scan_status(scan_id: str, status: str, **kwargs) -> None:
    scan_uuid = UUID(scan_id)
    async with get_db_context() as db:
        await db.execute(
            update(Scan)
            .where(Scan.id == scan_uuid)
            .values(status=status, **kwargs)
        )

    await publish_scan_event(
        scan_id,
        "scan.phase_change",
        {
            "status": status,
            "phase": PHASE_BY_STATUS.get(status, "Unknown phase"),
        },
    )
    logger.info("Scan %s -> status: %s", scan_id, status)


async def log_audit_entry(
    scan_id: str,
    module: str,
    request_method: Optional[str],
    request_url: Optional[str],
    response_code: Optional[int],
    notes: Optional[str] = None,
) -> None:
    await log_audit_entry(scan_id, module, request_method, request_url, response_code, notes)


@celery_app.task(
    bind=True,
    name="tasks.scan_tasks.run_scan_pipeline",
    max_retries=1,
    soft_time_limit=3600,
    time_limit=3900,
)
def run_scan_pipeline(self, scan_id: str) -> dict:
    try:
        return asyncio.run(_run_pipeline_async(self, scan_id))
    except SoftTimeLimitExceeded:
        asyncio.run(
            update_scan_status(
                scan_id,
                "failed",
                error_message="Scan exceeded time limit (1 hour)",
                completed_at=datetime.now(timezone.utc),
            )
        )
        logger.error("Scan %s hit soft time limit", scan_id)
        return {"status": "failed", "reason": "time_limit"}
    except Exception as exc:
        logger.exception("Scan %s crashed: %s", scan_id, exc)
        asyncio.run(
            update_scan_status(
                scan_id,
                "failed",
                error_message=str(exc),
                completed_at=datetime.now(timezone.utc),
            )
        )
        raise self.retry(exc=exc, countdown=60)


async def _run_pipeline_async(task, scan_id: str) -> dict:
    scan_uuid = UUID(scan_id)

    async with get_db_context() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
        scan = result.scalar_one_or_none()

    if scan is None:
        raise ValueError(f"Scan not found: {scan_id}")

    if scan.status == "cancelled":
        return {"status": "cancelled", "scan_id": scan_id}

    started_at = datetime.now(timezone.utc)
    async with get_db_context() as db:
        await db.execute(
            update(Scan).where(Scan.id == scan_uuid).values(started_at=started_at)
        )

    target_url = scan.target_url
    mode = scan.mode
    scan_config = scan.config or {}
    decrypted_credentials = scan.credentials
    consent_scope = scan_config.get("consent_scope", {}) if isinstance(scan_config, dict) else {}

    findings_data: list = []
    finding_rows: list[Finding] = []
    chains: list = []
    summary = ""

    try:
        if await _is_cancelled(scan_id):
            return {"status": "cancelled", "scan_id": scan_id}

        await update_scan_status(scan_id, "crawling")

        crawler = Crawler(
            target_url=target_url,
            config=scan_config,
            credentials=decrypted_credentials,
            scan_id=scan_id,
        )
        endpoints_data = await crawler.crawl()

        endpoint_rows = [
            Endpoint(
                scan_id=scan_uuid,
                url=str(_value(ep, "url", "")),
                method=str(_value(ep, "method", "GET")),
                params=_value(ep, "params", []) or [],
                body_params=_value(ep, "body_params", []) or [],
                headers=_value(ep, "headers", {}) or {},
                auth_required=bool(_value(ep, "auth_required", False)),
                status_code=_value(ep, "status_code"),
            )
            for ep in endpoints_data
        ]

        async with get_db_context() as db:
            if endpoint_rows:
                db.add_all(endpoint_rows)
            await db.execute(
                update(Scan)
                .where(Scan.id == scan_uuid)
                .values(endpoints_found=len(endpoint_rows))
            )

        await publish_scan_event(
            scan_id,
            "scan.progress",
            {
                "endpoints_found": len(endpoint_rows),
                "vulns_found": 0,
                "chains_found": 0,
            },
        )

        if len(endpoint_rows) == 0:
            await update_scan_status(
                scan_id,
                "failed",
                error_message="Crawler found no endpoints. Check the target URL and credentials.",
                completed_at=datetime.now(timezone.utc),
            )
            await publish_scan_event(
                scan_id,
                "scan.failed",
                {
                    "reason": "Crawler found no endpoints. Check the target URL and credentials.",
                },
            )
            return {"status": "failed", "scan_id": scan_id, "reason": "no_endpoints"}

        if await _is_cancelled(scan_id):
            return {"status": "cancelled", "scan_id": scan_id}

        await update_scan_status(scan_id, "scanning")

        rule_engine = RuleEngine(
            scan_id=scan_id,
            mode=mode,
            endpoints=endpoints_data,
            config=scan_config,
        )
        findings_data = list(await rule_engine.run_all_probes())

        if mode == "hardcore":
            # Lazy import to avoid circular dependency
            from scanner.hardcore.hardcore_runner import HardcoreRunner

            consent_record: ConsentRecord | SimpleNamespace | None = None
            async with get_db_context() as db:
                consent_result = await db.execute(
                    select(ConsentRecord).where(ConsentRecord.scan_id == scan_uuid)
                )
                consent_record = consent_result.scalar_one_or_none()

            if consent_record is None:
                consent_record = SimpleNamespace(
                    id=consent_scope.get("id", "runtime-consent") if isinstance(consent_scope, dict) else "runtime-consent",
                    target_domain=consent_scope.get("target_domain", "") if isinstance(consent_scope, dict) else "",
                    domain_verified=bool(consent_scope.get("domain_verified", False)) if isinstance(consent_scope, dict) else False,
                    scope_locked=bool(consent_scope.get("scope_locked", False)) if isinstance(consent_scope, dict) else False,
                    scope_config=consent_scope if isinstance(consent_scope, dict) else {},
                )

            hardcore_runner = HardcoreRunner(
                scan_id=scan_id,
                endpoints=endpoints_data,
                scan_config=scan_config,
                consent_scope=consent_record,
                session_cookies=getattr(crawler, "session_cookies", {}) or {},
            )
            hardcore_findings = await hardcore_runner.run()
            findings_data.extend(hardcore_findings)

        finding_rows = [
            Finding(
                scan_id=scan_uuid,
                endpoint_id=_value(finding, "endpoint_id"),
                vuln_type=str(_value(finding, "vuln_type", "unknown")),
                severity=str(_value(finding, "severity", "info")),
                title=str(_value(finding, "title", "Untitled finding")),
                description=_value(finding, "description"),
                evidence=_value(finding, "evidence", {}) or {},
                parameter=_value(finding, "parameter"),
                payload_used=_value(finding, "payload_used"),
                confidence=float(_value(finding, "confidence", 0.0) or 0.0),
                is_confirmed=bool(_value(finding, "is_confirmed", False)),
            )
            for finding in findings_data
        ]

        async with get_db_context() as db:
            if finding_rows:
                db.add_all(finding_rows)
                await db.flush()
            await db.execute(
                update(Scan)
                .where(Scan.id == scan_uuid)
                .values(vulns_found=len(finding_rows))
            )

        for finding in findings_data:
            await publish_scan_event(
                scan_id,
                "scan.finding",
                {
                    "vuln_type": _value(finding, "vuln_type", "unknown"),
                    "severity": _value(finding, "severity", "info"),
                    "title": _value(finding, "title", "Untitled finding"),
                    "url": _value(finding, "url", ""),
                },
            )

        if await _is_cancelled(scan_id):
            return {"status": "cancelled", "scan_id": scan_id}

        await update_scan_status(scan_id, "chaining")

        await neo4j_client.connect()
        await neo4j_client.init_constraints()

        chain_builder = ChainBuilder(
            scan_id=scan_id,
            endpoints=endpoints_data,
            findings=findings_data,
        )
        chains = list(await chain_builder.build())

        async with get_db_context() as db:
            await db.execute(
                update(Scan)
                .where(Scan.id == scan_uuid)
                .values(chains_found=len(chains))
            )

        for chain in chains:
            await publish_scan_event(
                scan_id,
                "chain.built",
                {
                    "chain_id": _value(chain, "path_id", ""),
                    "entry_point": _value(chain, "entry_point", ""),
                    "final_impact": _value(chain, "final_impact", ""),
                    "severity": _value(chain, "severity_score", 0),
                    "length": _value(chain, "length", 0),
                },
            )

        if await _is_cancelled(scan_id):
            return {"status": "cancelled", "scan_id": scan_id}

        await update_scan_status(scan_id, "analyzing")

        llm_analyzer = LLMAnalyzer(scan_id=scan_id)
        for batch_start in range(0, len(finding_rows), 5):
            batch_rows = finding_rows[batch_start : batch_start + 5]
            batch_source = findings_data[batch_start : batch_start + 5]

            analyses = await asyncio.gather(
                *[llm_analyzer.analyze_finding(source) for source in batch_source],
                return_exceptions=True,
            )

            async with get_db_context() as db:
                for row, source, analysis in zip(batch_rows, batch_source, analyses):
                    if isinstance(analysis, Exception):
                        logger.warning(
                            "LLM analysis failed for scan=%s finding=%s: %s",
                            scan_id,
                            row.id,
                            analysis,
                        )
                        continue

                    analysis_dict = _as_dict(analysis)
                    await db.execute(
                        update(Finding)
                        .where(Finding.id == row.id)
                        .values(
                            llm_impact=analysis_dict.get("llm_impact"),
                            fix_suggestion=analysis_dict.get("fix_suggestion"),
                            owasp_category=analysis_dict.get("owasp_category"),
                            mitre_id=analysis_dict.get("mitre_id"),
                        )
                    )

                    impact_preview = (analysis_dict.get("llm_impact") or "")[:200]
                    await publish_scan_event(
                        scan_id,
                        "llm.analysis",
                        {
                            "finding_id": str(row.id),
                            "vuln_type": _value(source, "vuln_type", "unknown"),
                            "impact": impact_preview,
                        },
                    )

            await asyncio.sleep(1)

        summary = await llm_analyzer.generate_executive_summary(
            scan_id=scan_id,
            findings=findings_data,
            chains=chains,
        )

        if await _is_cancelled(scan_id):
            return {"status": "cancelled", "scan_id": scan_id}

        await update_scan_status(scan_id, "generating_poc")

        poc_generator = PoCGenerator(scan_id=scan_id)
        for row, source in zip(finding_rows, findings_data):
            try:
                poc_curl = await poc_generator.generate(source)
            except Exception as exc:
                logger.warning("PoC generation failed for finding=%s: %s", row.id, exc)
                continue

            async with get_db_context() as db:
                await db.execute(
                    update(Finding)
                    .where(Finding.id == row.id)
                    .values(poc_curl=poc_curl)
                )

            await publish_scan_event(
                scan_id,
                "poc.generated",
                {
                    "finding_id": str(row.id),
                    "vuln_type": _value(source, "vuln_type", "unknown"),
                },
            )

        if await _is_cancelled(scan_id):
            return {"status": "cancelled", "scan_id": scan_id}

        await update_scan_status(scan_id, "reporting")

        report_engine = ReportEngine(scan_id=scan_id)
        report = await report_engine.generate(
            findings=findings_data,
            chains=chains,
            executive_summary=summary,
        )

        completed_at = datetime.now(timezone.utc)
        await update_scan_status(
            scan_id,
            "completed",
            completed_at=completed_at,
        )

        duration_sec = (completed_at - started_at).total_seconds()
        await publish_scan_event(
            scan_id,
            "scan.completed",
            {
                "vulns_found": len(finding_rows),
                "chains_found": len(chains),
                "report_id": str(_value(report, "id", "")),
                "duration_sec": duration_sec,
            },
        )

        logger.info(
            "Scan %s completed | findings=%s chains=%s",
            scan_id,
            len(finding_rows),
            len(chains),
        )

        return {
            "status": "completed",
            "scan_id": scan_id,
            "vulns_found": len(finding_rows),
            "chains_found": len(chains),
            "report_id": str(_value(report, "id", "")),
        }
    except asyncio.CancelledError:
        await update_scan_status(
            scan_id,
            "cancelled",
            completed_at=datetime.now(timezone.utc),
            error_message="Scan cancelled during execution",
        )
        await publish_scan_event(scan_id, "scan.cancelled", {"reason": "cancelled"})
        return {"status": "cancelled", "scan_id": scan_id}
    finally:
        await neo4j_client.disconnect()


@celery_app.task(name="tasks.scan_tasks.cleanup_stale_scans")
def cleanup_stale_scans() -> dict:
    async def _cleanup_async() -> dict:
        stale_cutoff = datetime.now(timezone.utc) - timedelta(hours=2)
        terminal_statuses = ["completed", "failed", "cancelled"]

        async with get_db_context() as db:
            stale_query = select(Scan.id).where(
                Scan.status.notin_(terminal_statuses),
                Scan.started_at.is_not(None),
                Scan.started_at < stale_cutoff,
            )
            stale_result = await db.execute(stale_query)
            stale_ids = list(stale_result.scalars().all())

            if stale_ids:
                await db.execute(
                    update(Scan)
                    .where(Scan.id.in_(stale_ids))
                    .values(
                        status="failed",
                        error_message="Scan timed out — no progress for 2+ hours",
                        completed_at=datetime.now(timezone.utc),
                    )
                )

        cleaned_count = len(stale_ids)
        logger.info("Cleanup stale scans completed: %s updated", cleaned_count)
        return {"cleaned_up": cleaned_count}

    return asyncio.run(_cleanup_async())


@celery_app.task(name="tasks.scan_tasks.regenerate_report_task")
def regenerate_report_task(scan_id: str) -> dict:
    async def _regenerate_async() -> dict:
        scan_uuid = UUID(scan_id)

        async with get_db_context() as db:
            scan = await db.get(Scan, scan_uuid)
            if scan is None:
                raise ValueError(f"Scan not found: {scan_id}")
            if str(scan.status) != "completed":
                raise ValueError("Report regeneration is only available for completed scans")

        chain_rows = await ChainBuilder.get_ranked_chains(scan_id)
        chain_objects = [SimpleNamespace(**row) if isinstance(row, dict) else row for row in chain_rows]

        report_engine = ReportEngine(scan_id=scan_id)
        report = await report_engine.generate(
            findings=[],
            chains=chain_objects,
            executive_summary=None,
        )

        await publish_scan_event(
            scan_id,
            "report.regenerated",
            {
                "report_id": str(_value(report, "id", "")),
            },
        )

        return {
            "status": "completed",
            "scan_id": scan_id,
            "report_id": str(_value(report, "id", "")),
        }

    return asyncio.run(_regenerate_async())
