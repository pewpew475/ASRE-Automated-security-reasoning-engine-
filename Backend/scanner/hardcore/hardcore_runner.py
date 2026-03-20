import asyncio
import logging
from typing import Dict, List, Optional

from api.routes.websocket import publish_scan_event
from config import settings
from scanner.crawler import EndpointData
# Lazy import to avoid circular dependency
from scanner.hardcore.jwt_attacker import JWTAttacker
from scanner.hardcore.nuclei_runner import NucleiRunner
from scanner.hardcore.rate_limit_tester import RateLimitTester
from scanner.hardcore.session_tester import SessionTester
from scanner.hardcore.sqlmap_client import SQLMapClient
from scanner.hardcore.user_enumerator import UserEnumerator
from scanner.rule_engine import FindingData
from utils.audit_logger import log_audit_entry


class HardcoreRunner:
    def __init__(
        self,
        scan_id: str,
        endpoints: List[EndpointData],
        scan_config: Dict,
        consent_scope: object,
        session_cookies: Optional[Dict[str, str]] = None,
    ):
        self.scan_id = scan_id
        self.endpoints = endpoints
        self.scan_config = scan_config
        self.consent_scope = consent_scope
        self.cookies = session_cookies or {}
        self.logger = logging.getLogger(__name__)

    async def run(self) -> List[FindingData]:
        if not bool(getattr(self.consent_scope, "domain_verified", False)):
            self.logger.error("Hardcore aborted: domain not verified for scan %s", self.scan_id)
            raise PermissionError(
                "Hardcore Mode requires verified domain ownership. "
                "Complete DNS TXT verification first."
            )

        scope_locked = bool(getattr(self.consent_scope, "scope_locked", False))
        if not scope_locked:
            scope_cfg = getattr(self.consent_scope, "scope_config", {}) or {}
            if isinstance(scope_cfg, dict):
                scope_locked = bool(scope_cfg.get("scope_locked", False))

        if not scope_locked:
            raise PermissionError("Hardcore Mode requires a locked consent scope.")

        self.logger.warning(
            "[HARDCORE] Scan %s starting hardcore modules. Target: %s - Consent ID: %s",
            self.scan_id,
            getattr(self.consent_scope, "target_domain", "unknown"),
            getattr(self.consent_scope, "id", "unknown"),
        )

        sqli_findings = await self._run_module(
            SQLMapClient(
                scan_id=self.scan_id,
                endpoints=self.endpoints,
                cookies=self.cookies,
            ).run(),
            module_name="SQLMap",
        )

        cve_findings = await self._run_module(
            NucleiRunner(
                scan_id=self.scan_id,
                target_url=str(getattr(self.consent_scope, "target_domain", "")),
                cookies=self.cookies,
            ).run(),
            module_name="Nuclei",
        )

        results = await asyncio.gather(
            self._run_module(
                RateLimitTester(
                    scan_id=self.scan_id,
                    endpoints=self.endpoints,
                    cookies=self.cookies,
                ).run(),
                module_name="RateLimitTester",
            ),
            self._run_module(
                UserEnumerator(
                    scan_id=self.scan_id,
                    endpoints=self.endpoints,
                ).run(),
                module_name="UserEnumerator",
            ),
            self._run_module(
                JWTAttacker(
                    scan_id=self.scan_id,
                    endpoints=self.endpoints,
                    cookies=self.cookies,
                ).run(),
                module_name="JWTAttacker",
            ),
            self._run_module(
                SessionTester(
                    scan_id=self.scan_id,
                    endpoints=self.endpoints,
                    cookies=self.cookies,
                ).run(),
                module_name="SessionTester",
            ),
            return_exceptions=True,
        )

        all_findings: List[FindingData] = []
        all_findings.extend(sqli_findings)
        all_findings.extend(cve_findings)
        for item in results:
            if isinstance(item, Exception):
                self.logger.error("Hardcore module failed: %s", item)
            else:
                if isinstance(item, list):
                    all_findings.extend(item)

        await publish_scan_event(
            self.scan_id,
            "hardcore.complete",
            {
                "total_hardcore_findings": len(all_findings),
                "modules_run": ["sqlmap", "nuclei", "rate_limit", "user_enum", "jwt", "session"],
            },
        )

        self.logger.warning(
            "[HARDCORE] Complete: %s findings from hardcore modules for scan %s",
            len(all_findings),
            self.scan_id,
        )

        return all_findings

    async def _run_module(self, coro, module_name: str) -> List[FindingData]:
        try:
            self.logger.info("[HARDCORE] Starting module: %s", module_name)
            start = asyncio.get_running_loop().time()
            findings = await coro
            elapsed = asyncio.get_running_loop().time() - start

            self.logger.info(
                "[HARDCORE] %s complete: %s findings in %.1fs",
                module_name,
                len(findings),
                elapsed,
            )

            await log_audit_entry(
                scan_id=self.scan_id,
                module=module_name,
                request_method=None,
                request_url=None,
                response_code=None,
                notes=f"Module complete: {len(findings)} findings",
            )
            return findings
        except Exception as exc:
            self.logger.error("[HARDCORE] Module %s failed: %s", module_name, exc, exc_info=True)
            return []
