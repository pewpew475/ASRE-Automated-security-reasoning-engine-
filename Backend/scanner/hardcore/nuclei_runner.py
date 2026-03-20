import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from api.routes.websocket import publish_scan_event
from config import settings
from scanner.rule_engine import FindingData
from tasks.scan_tasks import log_audit_entry

SAFE_NUCLEI_TAGS = [
    "cve",
    "misconfig",
    "exposure",
    "takeover",
    "tech",
    "ssl",
    "headers",
    "cors",
]

BLOCKED_NUCLEI_TAGS = [
    "exploit",
    "rce",
    "sqli",
    "xss",
    "lfi",
    "ssrf",
    "dos",
    "fuzz",
]

NUCLEI_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


class NucleiRunner:
    def __init__(self, scan_id: str, target_url: str, cookies: Dict[str, str]):
        self.scan_id = scan_id
        self.target_url = target_url
        self.cookies = cookies or {}
        self.binary = settings.NUCLEI_BINARY_PATH
        self.logger = logging.getLogger(__name__)

    async def run(self) -> List[FindingData]:
        binary_path = Path(self.binary)
        if not binary_path.exists():
            self.logger.error("Nuclei binary not found at %s. Ensure Docker image was built correctly.", self.binary)
            return []

        await self._update_templates()

        output_file = Path(tempfile.mkstemp(prefix=f"asre-nuclei-{self.scan_id}-", suffix=".jsonl")[1])
        findings: List[FindingData] = []

        cmd = [
            self.binary,
            "-u",
            self.target_url,
            "-tags",
            ",".join(SAFE_NUCLEI_TAGS),
            "-etags",
            ",".join(BLOCKED_NUCLEI_TAGS),
            "-json",
            "-silent",
            "-no-color",
            "-rate-limit",
            "20",
            "-timeout",
            "10",
            "-retries",
            "1",
            "-output",
            str(output_file),
        ]

        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            cmd.extend(["-H", f"Cookie: {cookie_str}"])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
            except asyncio.TimeoutError:
                proc.kill()
                self.logger.warning("Nuclei timed out for %s", self.target_url)
                await log_audit_entry(
                    scan_id=self.scan_id,
                    module="nuclei",
                    request_method="GET",
                    request_url=self.target_url,
                    response_code=None,
                    notes="Nuclei timed out after 600s",
                )
                return []

            if proc.returncode not in (0, 1):
                self.logger.warning("Nuclei exited with code %s: %s", proc.returncode, stderr.decode(errors="ignore")[:300])

            if output_file.exists():
                for line in output_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if not line.strip():
                        continue
                    try:
                        result = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    finding = self._parse_nuclei_result(result)
                    if finding is not None:
                        findings.append(finding)

            await log_audit_entry(
                scan_id=self.scan_id,
                module="nuclei",
                request_method="GET",
                request_url=self.target_url,
                response_code=proc.returncode,
                notes=f"Nuclei scan complete: {len(findings)} findings",
            )

            if findings:
                await publish_scan_event(
                    self.scan_id,
                    "scan.progress",
                    {"nuclei_findings": len(findings)},
                )

            return findings
        finally:
            try:
                if output_file.exists():
                    output_file.unlink(missing_ok=True)
            except Exception:
                pass

    def _parse_nuclei_result(self, result: dict) -> Optional[FindingData]:
        template_id = str(result.get("template-id", ""))
        info = result.get("info", {}) if isinstance(result.get("info", {}), dict) else {}
        name = str(info.get("name", template_id or "Nuclei finding"))
        severity = str(info.get("severity", "info")).lower()
        classification = info.get("classification", {}) if isinstance(info.get("classification", {}), dict) else {}
        cve_list = classification.get("cve-id", [""])
        cve_id = cve_list[0] if isinstance(cve_list, list) and cve_list else ""
        matched_url = str(result.get("matched-at", self.target_url))
        description = str(info.get("description", ""))
        reference = info.get("reference", [])
        if not isinstance(reference, list):
            reference = [str(reference)]

        return FindingData(
            scan_id=self.scan_id,
            endpoint_url=matched_url,
            endpoint_id=None,
            vuln_type="cve" if cve_id else "misconfig",
            severity=NUCLEI_SEVERITY_MAP.get(severity, "info"),
            title=f"[Nuclei] {name}",
            description=description[:500],
            evidence={
                "template_id": template_id,
                "cve_id": cve_id,
                "matched_url": matched_url,
                "reference": reference[:3],
                "nuclei_raw": str(result)[:300],
            },
            parameter=None,
            payload_used=template_id,
            confidence=0.9,
            is_confirmed=True,
            mitre_id=None,
            owasp_category=(
                "A06:2021-Vulnerable and Outdated Components"
                if cve_id
                else "A05:2021-Security Misconfiguration"
            ),
        )

    async def _update_templates(self) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary,
                "-update-templates",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=60)
        except Exception as exc:
            self.logger.warning("Nuclei template update skipped: %s", exc)
