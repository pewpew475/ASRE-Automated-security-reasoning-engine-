import asyncio
import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from weasyprint import HTML as WeasyPrintHTML

from config import settings
from core.database import get_db_context
from core.neo4j_client import neo4j_client
from models.finding import Finding
from models.report import Report
from models.scan import Scan
from scanner.chain_builder import ChainBuilder, ChainData, GraphData, SEVERITY_COLORS

logger = logging.getLogger(__name__)


def _filter_severity_color(severity: str) -> str:
    mapping = {
        "critical": "#7F1D1D",
        "high": "#EF4444",
        "medium": "#F97316",
        "low": "#EAB308",
        "info": "#6B7280",
    }
    return mapping.get((severity or "").lower(), "#6B7280")


def _filter_format_timestamp(dt: datetime) -> str:
    if dt is None:
        return "N/A"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%B %d, %Y at %I:%M %p UTC")


def _filter_truncate_url(url: str, length: int = 60) -> str:
    url = url or ""
    if len(url) <= length:
        return url
    return "..." + url[-(length - 3) :]


def _filter_json_pretty(data: Any) -> str:
    try:
        if isinstance(data, str):
            parsed = json.loads(data)
            return json.dumps(parsed, indent=2)
        return json.dumps(data, indent=2)
    except Exception:
        return str(data)


jinja_env = Environment(
    loader=FileSystemLoader(settings.TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)
jinja_env.filters["severity_color"] = _filter_severity_color
jinja_env.filters["format_timestamp"] = _filter_format_timestamp
jinja_env.filters["truncate_url"] = _filter_truncate_url
jinja_env.filters["json_pretty"] = _filter_json_pretty


class ReportEngine:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.reports_dir = Path(settings.REPORTS_DIR)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

    async def generate(
        self,
        findings: List[Any],
        chains: List[ChainData],
        executive_summary: Optional[Dict[str, Any]] = None,
    ) -> Report:
        async with get_db_context() as db:
            scan = await db.get(Scan, UUID(self.scan_id))
            if scan is None:
                raise ValueError(f"Scan not found: {self.scan_id}")

            db_findings = (
                await db.execute(
                    select(Finding)
                    .where(Finding.scan_id == UUID(self.scan_id))
                    .order_by(Finding.detected_at.asc())
                )
            ).scalars().all()

        db_findings = sorted(
            db_findings,
            key=lambda f: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(str(f.severity), 5),
                f.detected_at or datetime.now(timezone.utc),
            ),
        )

        context = await self._build_report_context(
            scan=scan,
            findings=db_findings,
            chains=chains,
            executive_summary=executive_summary,
        )

        html_content = await asyncio.to_thread(self._render_html, context)

        pdf_path = self.reports_dir / f"{self.scan_id}.pdf"
        await asyncio.to_thread(self._render_pdf, html_content, str(pdf_path))

        async with get_db_context() as db:
            report_kwargs: Dict[str, Any] = {
                "id": uuid4(),
                "scan_id": UUID(self.scan_id),
                "file_path": str(pdf_path),
                "total_findings": len(db_findings),
                "critical_count": sum(1 for f in db_findings if str(f.severity) == "critical"),
                "high_count": sum(1 for f in db_findings if str(f.severity) == "high"),
                "medium_count": sum(1 for f in db_findings if str(f.severity) == "medium"),
                "low_count": sum(1 for f in db_findings if str(f.severity) == "low"),
                "info_count": sum(1 for f in db_findings if str(f.severity) == "info"),
                "generated_at": datetime.now(timezone.utc),
                "executive_summary": json.dumps(context["executive_summary"]),
            }

            if hasattr(Report, "file_size_bytes"):
                report_kwargs["file_size_bytes"] = pdf_path.stat().st_size

            report = Report(**report_kwargs)
            db.add(report)
            await db.flush()

        self.logger.info(
            "Report generated: %s (%s KB)",
            str(pdf_path),
            pdf_path.stat().st_size // 1024,
        )
        return report

    async def _build_report_context(
        self,
        scan: Scan,
        findings: List[Finding],
        chains: List[ChainData],
        executive_summary: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        duration_sec = 0.0
        started_at = getattr(scan, "started_at", None)
        completed_at = getattr(scan, "completed_at", None)
        if isinstance(started_at, datetime) and isinstance(completed_at, datetime):
            started = started_at if started_at.tzinfo else started_at.replace(tzinfo=timezone.utc)
            completed = completed_at if completed_at.tzinfo else completed_at.replace(tzinfo=timezone.utc)
            duration_sec = max(0.0, (completed - started).total_seconds())

        raw_endpoints_found = getattr(scan, "endpoints_found", 0)
        endpoints_found = int(raw_endpoints_found) if isinstance(raw_endpoints_found, int) else 0

        finding_rows = [self._finding_to_view_model(f) for f in findings]

        grouped = {
            "critical": [f for f in finding_rows if f["severity"] == "critical"],
            "high": [f for f in finding_rows if f["severity"] == "high"],
            "medium": [f for f in finding_rows if f["severity"] == "medium"],
            "low": [f for f in finding_rows if f["severity"] == "low"],
            "info": [f for f in finding_rows if f["severity"] == "info"],
        }

        stats = {
            "total": len(finding_rows),
            "critical": len(grouped["critical"]),
            "high": len(grouped["high"]),
            "medium": len(grouped["medium"]),
            "low": len(grouped["low"]),
            "info": len(grouped["info"]),
            "chains": len(chains),
                "endpoints_found": endpoints_found,
        }

        top_chains = sorted(chains, key=lambda c: c.severity_score, reverse=True)[:20]

        return {
            "scan_id": str(scan.id),
            "target_url": str(scan.target_url),
            "scan_mode": str(scan.mode).capitalize(),
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "duration_sec": duration_sec,
            "generated_at": now,
            "asre_version": settings.APP_VERSION,
            "executive_summary": executive_summary
            or {
                "headline": "Scan complete.",
                "summary": "See findings below.",
                "top_risks": [],
                "immediate_actions": [],
                "overall_risk_rating": self._calculate_overall_rating(findings),
                "compliance_flags": [],
            },
            "stats": stats,
            "findings_by_severity": grouped,
            "low_info_summary": grouped["low"] + grouped["info"],
            "chains": top_chains,
            "owasp_breakdown": self._group_by_owasp(findings),
            "vuln_type_breakdown": self._group_by_vuln_type(findings),
        }

    def _finding_to_view_model(self, finding: Finding) -> Dict[str, Any]:
        endpoint_url = ""
        try:
            if getattr(finding, "endpoint", None) is not None:
                endpoint_url = str(getattr(finding.endpoint, "url", "") or "")
        except Exception:
            endpoint_url = ""

        if not endpoint_url:
            evidence = getattr(finding, "evidence", {}) or {}
            if isinstance(evidence, dict):
                endpoint_url = str(evidence.get("request_url", ""))

        fix_suggestion = getattr(finding, "fix_suggestion", "")
        try:
            if isinstance(fix_suggestion, str) and fix_suggestion.strip().startswith("["):
                fix_suggestion = json.loads(fix_suggestion)
        except Exception:
            pass

        return {
            "id": str(finding.id),
            "severity": str(finding.severity or "info").lower(),
            "vuln_type": str(finding.vuln_type or "unknown"),
            "title": str(finding.title or "Untitled finding"),
            "endpoint_url": endpoint_url or "N/A",
            "parameter": str(finding.parameter or "N/A"),
            "llm_impact": str(finding.llm_impact or "Analysis not available"),
            "fix_suggestion": fix_suggestion or [],
            "owasp_category": str(finding.owasp_category or "N/A"),
            "mitre_id": str(finding.mitre_id or "N/A"),
            "poc_curl": str(finding.poc_curl or "PoC not available"),
        }

    def _render_html(self, context: Dict[str, Any]) -> str:
        template = jinja_env.get_template("report.html")
        return template.render(**context)

    def _render_pdf(self, html_content: str, output_path: str) -> None:
        WeasyPrintHTML(string=html_content).write_pdf(
            output_path,
            presentational_hints=True,
        )

    def _calculate_overall_rating(self, findings: List[Finding]) -> str:
        severities = [str(f.severity or "").lower() for f in findings]
        if "critical" in severities:
            return "critical"
        if "high" in severities:
            return "high"
        if severities.count("medium") > 5:
            return "high"
        if "medium" in severities:
            return "medium"
        if any(s in {"low", "info"} for s in severities):
            return "low"
        return "info"

    def _group_by_owasp(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        counts = Counter(str(f.owasp_category or "Unknown") for f in findings)
        return [
            {"category": category, "count": count}
            for category, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)
        ]

    def _group_by_vuln_type(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        counts = Counter(str(f.vuln_type or "unknown") for f in findings)
        severity_by_type: Dict[str, str] = {}
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        for f in findings:
            vuln_type = str(f.vuln_type or "unknown")
            sev = str(f.severity or "info").lower()
            current = severity_by_type.get(vuln_type)
            if current is None or rank.get(sev, 0) > rank.get(current, 0):
                severity_by_type[vuln_type] = sev

        rows = []
        for vuln_type, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            sev = severity_by_type.get(vuln_type, "info")
            rows.append(
                {
                    "type": vuln_type,
                    "count": count,
                    "color": SEVERITY_COLORS.get(sev, "#6B7280"),
                }
            )
        return rows
