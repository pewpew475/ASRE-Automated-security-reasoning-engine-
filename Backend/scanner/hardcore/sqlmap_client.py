import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

import httpx

from api.routes.websocket import publish_scan_event
from config import settings
from scanner.crawler import EndpointData
from scanner.rule_engine import FindingData
from tasks.scan_tasks import log_audit_entry

SAFE_SQLMAP_OPTIONS: Dict[str, Any] = {
    "level": 1,
    "risk": 1,
    "technique": "BEUST",
    "batch": True,
    "forms": False,
    "crawl": 0,
    "getDbs": False,
    "getTables": False,
    "getColumns": False,
    "dump": False,
    "dumpAll": False,
    "os-shell": False,
    "os-cmd": False,
    "priv-esc": False,
    "file-read": False,
    "file-write": False,
    "timeout": 30,
    "retries": 2,
    "delay": 1,
    "randomAgent": True,
}


class SQLMapClient:
    def __init__(self, scan_id: str, endpoints: List[EndpointData], cookies: Dict[str, str]):
        self.scan_id = scan_id
        self.endpoints = endpoints
        self.cookies = cookies or {}
        self.sqlmap_api_url = settings.SQLMAP_API_URL.rstrip("/")
        self.logger = logging.getLogger(__name__)

    async def run(self) -> List[FindingData]:
        target_endpoints = [ep for ep in self.endpoints if ep.params or ep.body_params][:20]
        findings: List[FindingData] = []

        for endpoint in target_endpoints:
            finding = await self._scan_endpoint(endpoint)
            if finding is not None:
                findings.append(finding)
            await asyncio.sleep(2)

        return findings

    async def _audit(self, method: str, url: str, status_code: Optional[int], notes: str) -> None:
        await log_audit_entry(
            scan_id=self.scan_id,
            module="sqlmap",
            request_method=method,
            request_url=url,
            response_code=status_code,
            notes=notes,
        )

    async def _scan_endpoint(self, endpoint: EndpointData) -> Optional[FindingData]:
        task_id: Optional[str] = None
        base = self.sqlmap_api_url

        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            try:
                task_url = f"{base}/task/new"
                task_resp = await client.post(task_url)
                await self._audit("POST", task_url, task_resp.status_code, "Create SQLMap task")
                task_resp.raise_for_status()
                task_id = task_resp.json().get("taskid")
                if not task_id:
                    return None

                options = {**SAFE_SQLMAP_OPTIONS, "url": endpoint.url}
                if endpoint.method.upper() == "POST" and endpoint.body_params:
                    pairs = []
                    for p in endpoint.body_params:
                        if isinstance(p, dict) and p.get("name"):
                            pairs.append(f"{p['name']}=FUZZ")
                    if pairs:
                        options["data"] = "&".join(pairs)

                if self.cookies:
                    options["cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())

                start_url = f"{base}/scan/{task_id}/start"
                start_resp = await client.post(start_url, json=options)
                await self._audit("POST", start_url, start_resp.status_code, f"Start SQLMap on {endpoint.url}")
                start_resp.raise_for_status()

                status_url = f"{base}/scan/{task_id}/status"
                elapsed = 0
                while elapsed <= 120:
                    status_resp = await client.get(status_url)
                    await self._audit("GET", status_url, status_resp.status_code, "Poll SQLMap status")
                    status_resp.raise_for_status()
                    status_data = status_resp.json()
                    if status_data.get("status") == "terminated":
                        break
                    await asyncio.sleep(5)
                    elapsed += 5

                data_url = f"{base}/scan/{task_id}/data"
                data_resp = await client.get(data_url)
                await self._audit("GET", data_url, data_resp.status_code, "Fetch SQLMap data")
                data_resp.raise_for_status()
                findings = self._parse_results(endpoint, task_id, data_resp.json())

                await self._audit(
                    endpoint.method.upper(),
                    endpoint.url,
                    None,
                    f"SQLMap task {task_id}: {len(findings)} injections found",
                )

                if findings:
                    await publish_scan_event(
                        self.scan_id,
                        "scan.finding",
                        {
                            "vuln_type": "sqli",
                            "severity": "critical",
                            "title": findings[0].title,
                            "url": endpoint.url,
                            "source": "sqlmap",
                        },
                    )
                    return findings[0]
                return None
            except httpx.HTTPError as exc:
                self.logger.warning("SQLMap API unavailable for %s: %s", endpoint.url, exc)
                return None
            except Exception as exc:
                self.logger.error("SQLMap scan failed for %s: %s", endpoint.url, exc, exc_info=True)
                return None
            finally:
                if task_id:
                    delete_url = f"{base}/task/{task_id}/delete"
                    try:
                        delete_resp = await client.get(delete_url)
                        await self._audit("GET", delete_url, delete_resp.status_code, "Delete SQLMap task")
                    except Exception:
                        await self._audit("GET", delete_url, None, "Delete SQLMap task failed")

    def _parse_results(self, endpoint: EndpointData, task_id: str, payload: Dict[str, Any]) -> List[FindingData]:
        findings: List[FindingData] = []
        for item in payload.get("data", []):
            if not isinstance(item, dict):
                continue
            if int(item.get("type", 0)) != 1:
                continue

            value = item.get("value", [])
            if not isinstance(value, list) or not value:
                continue

            first = value[0] if isinstance(value[0], dict) else {}
            param = str(first.get("parameter", "unknown"))
            technique = str(first.get("title", first.get("technique", "unknown")))
            dbms = str(first.get("dbms", ""))
            payload_used = str(first.get("payload", ""))

            findings.append(
                FindingData(
                    scan_id=self.scan_id,
                    endpoint_url=endpoint.url,
                    endpoint_id=None,
                    vuln_type="sqli",
                    severity="critical",
                    title=f"SQL Injection confirmed by SQLMap: {param}",
                    description=(
                        f"SQLMap confirmed injectable parameter '{param}' "
                        f"at {endpoint.url} using {technique}."
                    ),
                    evidence={
                        "sqlmap_taskid": task_id,
                        "injectable_param": param,
                        "technique": technique,
                        "dbms": dbms,
                        "request_url": endpoint.url,
                    },
                    parameter=param,
                    payload_used=payload_used,
                    confidence=1.0,
                    is_confirmed=True,
                    mitre_id="T1190",
                    owasp_category="A03:2021-Injection",
                )
            )

        return findings
