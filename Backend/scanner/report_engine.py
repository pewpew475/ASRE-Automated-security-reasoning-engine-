import asyncio
import importlib
import json
import logging
import os
import textwrap
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


def _load_reportlab() -> tuple[Any, Any]:
    pagesizes = importlib.import_module("reportlab.lib.pagesizes")
    canvas_module = importlib.import_module("reportlab.pdfgen.canvas")
    return pagesizes.A4, canvas_module


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

        html_content = ""
        output_format = "pdf"
        output_path = self.reports_dir / f"{self.scan_id}.pdf"
        renderer = "reportlab"

        # Prefer ReportLab on Windows to avoid native rendering crashes in worker processes.
        if os.name == "nt":
            await asyncio.to_thread(self._render_pdf_reportlab, context, str(output_path))
        else:
            try:
                html_content = await asyncio.to_thread(self._render_html, context)
                await asyncio.to_thread(self._render_pdf, html_content, str(output_path))
                renderer = "weasyprint"
            except Exception as exc:
                self.logger.warning(
                    "WeasyPrint render failed for scan=%s, falling back to ReportLab: %s",
                    self.scan_id,
                    exc,
                )
                await asyncio.to_thread(self._render_pdf_reportlab, context, str(output_path))

        async with get_db_context() as db:
            report_kwargs: Dict[str, Any] = {
                "id": uuid4(),
                "scan_id": UUID(self.scan_id),
                "format": output_format,
                "file_path": str(output_path),
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
                report_kwargs["file_size_bytes"] = output_path.stat().st_size

            report = Report(**report_kwargs)
            db.add(report)
            await db.flush()

        self.logger.info(
            "Report generated: %s (%s KB) format=%s renderer=%s",
            str(output_path),
            output_path.stat().st_size // 1024,
            output_format,
            renderer,
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
        remediation_roadmap = self._build_remediation_roadmap(finding_rows)

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
            "remediation_roadmap": remediation_roadmap,
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

    def _render_pdf_reportlab(self, context: Dict[str, Any], output_path: str) -> None:
        page_size, canvas_module = _load_reportlab()
        pdf = canvas_module.Canvas(output_path, pagesize=page_size)
        width, height = page_size
        left = 36
        top = height - 36
        bottom = 36
        y = top

        def write_line(text: str, font: str = "Helvetica", size: int = 10) -> None:
            nonlocal y
            if y < bottom:
                pdf.showPage()
                y = top
            pdf.setFont(font, size)
            pdf.drawString(left, y, text)
            y -= size + 4

        def write_wrapped(text: str, width_chars: int = 110, font: str = "Helvetica", size: int = 10) -> None:
            lines = textwrap.wrap(text or "", width=width_chars) or [""]
            for line in lines:
                write_line(line, font=font, size=size)

        summary = context.get("executive_summary", {}) or {}
        stats = context.get("stats", {}) or {}

        write_line("ASRE Security Report", font="Helvetica-Bold", size=16)
        write_line(f"Scan ID: {context.get('scan_id', 'N/A')}")
        write_line(f"Target: {context.get('target_url', 'N/A')}")
        write_line(f"Generated: {context.get('generated_at', 'N/A')}")
        write_line(f"Overall Risk: {str(summary.get('overall_risk_rating', 'unknown')).upper()}")
        write_line("")

        write_line("Risk Statistics", font="Helvetica-Bold", size=12)
        write_line(
            "Critical={critical} High={high} Medium={medium} Low={low} Info={info} "
            "Endpoints={endpoints} Chains={chains}".format(
                critical=stats.get("critical", 0),
                high=stats.get("high", 0),
                medium=stats.get("medium", 0),
                low=stats.get("low", 0),
                info=stats.get("info", 0),
                endpoints=stats.get("endpoints_found", 0),
                chains=stats.get("chains", 0),
            )
        )
        write_line("")

        write_line("Executive Summary", font="Helvetica-Bold", size=12)
        write_wrapped(str(summary.get("headline", "")), width_chars=100, font="Helvetica-Bold", size=10)
        write_wrapped(str(summary.get("summary", "")), width_chars=110)
        top_risks = summary.get("top_risks", []) or []
        if top_risks:
            write_line("Top Risks", font="Helvetica-Bold", size=11)
            for risk in top_risks[:5]:
                write_wrapped(f"- {str(risk)}", width_chars=104)

        immediate_actions = summary.get("immediate_actions", []) or []
        if immediate_actions:
            write_line("Immediate Actions", font="Helvetica-Bold", size=11)
            for action in immediate_actions[:5]:
                write_wrapped(f"- {str(action)}", width_chars=104)
        write_line("")

        roadmap = context.get("remediation_roadmap", []) or []
        if roadmap:
            write_line("Remediation Roadmap", font="Helvetica-Bold", size=12)
            for item in roadmap[:8]:
                write_wrapped(
                    f"- Priority {item.get('priority')}: {item.get('title')} | "
                    f"Count={item.get('count')} | SLA={item.get('sla')}",
                    width_chars=102,
                )
                write_wrapped(f"  Why: {item.get('reason')}", width_chars=100)
            write_line("")

        chains = context.get("chains", []) or []
        if chains:
            write_line("Attack Chain Highlights", font="Helvetica-Bold", size=12)
            for chain in chains[:10]:
                narrative = str(getattr(chain, "llm_analysis", "") or "")
                write_wrapped(
                    f"- {str(getattr(chain, 'entry_point', 'Entry'))} -> {str(getattr(chain, 'final_impact', 'Impact'))}",
                    width_chars=102,
                )
                write_wrapped(
                    f"  Score={float(getattr(chain, 'severity_score', 0.0)):.1f}/10 | Length={int(getattr(chain, 'length', 0))} hops",
                    width_chars=102,
                )
                if narrative:
                    write_wrapped(f"  Narrative: {narrative[:260]}", width_chars=100)
            write_line("")

        write_line("Findings", font="Helvetica-Bold", size=12)
        findings_by_severity = context.get("findings_by_severity", {}) or {}
        order = ["critical", "high", "medium", "low", "info"]
        for severity in order:
            rows = findings_by_severity.get(severity, []) or []
            if not rows:
                continue
            write_line(f"{severity.upper()} ({len(rows)})", font="Helvetica-Bold", size=11)
            for finding in rows[:80]:
                title = str(finding.get("title") or "Untitled")
                url = str(finding.get("endpoint_url") or "N/A")
                vuln_type = str(finding.get("vuln_type") or "unknown")
                impact = str(finding.get("llm_impact") or "")
                write_wrapped(f"- [{vuln_type}] {title}", width_chars=105)
                write_wrapped(f"  URL: {url}", width_chars=100)
                if impact:
                    write_wrapped(f"  Impact: {impact[:300]}", width_chars=100)
                write_line("")

        pdf.save()

    def _build_remediation_roadmap(self, finding_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        buckets = {
            "critical": {"priority": 1, "sla": "24-48 hours"},
            "high": {"priority": 2, "sla": "3-7 days"},
            "medium": {"priority": 3, "sla": "2-4 weeks"},
            "low": {"priority": 4, "sla": "1-2 months"},
            "info": {"priority": 5, "sla": "backlog hardening"},
        }

        counts = Counter(str(item.get("severity", "info")).lower() for item in finding_rows)
        titles = {
            "critical": "Stop active exploit paths",
            "high": "Close privilege escalation vectors",
            "medium": "Reduce exploit preconditions",
            "low": "Harden baseline controls",
            "info": "Improve observability and policy coverage",
        }

        roadmap = []
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = int(counts.get(severity, 0))
            if count <= 0:
                continue
            roadmap.append(
                {
                    "priority": buckets[severity]["priority"],
                    "title": titles[severity],
                    "count": count,
                    "sla": buckets[severity]["sla"],
                    "reason": f"{count} {severity} findings contribute to attack-chain risk and should be handled in this order.",
                }
            )

        return sorted(roadmap, key=lambda item: int(item["priority"]))

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
