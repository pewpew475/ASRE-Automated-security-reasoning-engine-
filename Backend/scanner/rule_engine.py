import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from config import settings
from scanner.crawler import EndpointData
from scanner.probes import (
    AuthProbe,
    BusinessLogicProbe,
    CORSProbe,
    CSRFProbe,
    HeaderProbe,
    IDORProbe,
    SQLiProbe,
    XSSProbe,
)

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


@dataclass
class FindingData:
    scan_id: str
    endpoint_url: str
    endpoint_id: Optional[str]
    vuln_type: str
    severity: str
    title: str
    description: str
    evidence: Dict[str, Any]
    parameter: Optional[str]
    payload_used: Optional[str]
    confidence: float = 0.8
    is_confirmed: bool = False
    mitre_id: Optional[str] = None
    owasp_category: Optional[str] = None


class RuleEngine:
    def __init__(self, scan_id: str, mode: str, endpoints: List[EndpointData], config: dict):
        self.scan_id = scan_id
        self.mode = mode
        self.endpoints = endpoints
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self._rule_cache: Dict[str, dict] = {}
        self.rules_dir = Path(__file__).resolve().parent / "rules"

        self.probes = [
            XSSProbe(scan_id=scan_id),
            IDORProbe(scan_id=scan_id),
            CSRFProbe(scan_id=scan_id),
            SQLiProbe(scan_id=scan_id),
            AuthProbe(scan_id=scan_id),
            CORSProbe(scan_id=scan_id),
            HeaderProbe(scan_id=scan_id),
            BusinessLogicProbe(scan_id=scan_id),
        ]

    def load_yaml_rules(self, vuln_type: str) -> dict:
        if vuln_type in self._rule_cache:
            return self._rule_cache[vuln_type]

        if yaml is None:
            self.logger.warning("PyYAML not installed; rules disabled for %s", vuln_type)
            self._rule_cache[vuln_type] = {}
            return {}

        file_path = self.rules_dir / f"{vuln_type}.yaml"
        try:
            with file_path.open("r", encoding="utf-8") as handle:
                parsed = yaml.safe_load(handle) or {}
                self._rule_cache[vuln_type] = parsed
                return parsed
        except FileNotFoundError:
            self.logger.warning("Rules file missing for %s: %s", vuln_type, file_path)
            self._rule_cache[vuln_type] = {}
            return {}
        except Exception as exc:
            self.logger.warning("Failed parsing rule file %s: %s", file_path, exc)
            self._rule_cache[vuln_type] = {}
            return {}

    async def run_all_probes(self) -> List[FindingData]:
        all_findings: List[FindingData] = []

        form_endpoints = [e for e in self.endpoints if e.body_params]
        api_endpoints = [e for e in self.endpoints if "json" in (e.content_type or "").lower()]
        page_endpoints = [e for e in self.endpoints if e not in api_endpoints]
        self.logger.debug(
            "Probe endpoint groups | forms=%s api=%s pages=%s",
            len(form_endpoints),
            len(api_endpoints),
            len(page_endpoints),
        )

        for probe in self.probes:
            rules = self.load_yaml_rules(probe.vuln_type)
            try:
                findings = await probe.run(endpoints=self.endpoints, rules=rules)
                all_findings.extend(findings)
            except Exception as exc:
                self.logger.error("Probe failed: %s | error=%s", probe.__class__.__name__, exc, exc_info=True)
            await asyncio.sleep(0.1)

        return self._deduplicate_findings(all_findings)

    def _deduplicate_findings(self, findings: List[FindingData]) -> List[FindingData]:
        best_by_key: Dict[tuple, FindingData] = {}
        for finding in findings:
            key = (finding.endpoint_url, finding.vuln_type, finding.parameter)
            existing = best_by_key.get(key)
            if existing is None or finding.confidence > existing.confidence:
                best_by_key[key] = finding
        return list(best_by_key.values())

    @staticmethod
    def _build_httpx_client(cookies: Optional[Dict] = None) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=settings.REQUEST_TIMEOUT_SECONDS,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "ASRE-Scanner/1.0 (Authorized Security Audit)"},
            cookies=cookies or {},
        )
