import asyncio
import logging
import time
from typing import Dict, List, Optional

import httpx

from config import settings
from scanner.crawler import EndpointData
from scanner.rule_engine import FindingData
from tasks.scan_tasks import log_audit_entry


class RateLimitTester:
    RATE_SENSITIVE_PATHS = [
        "/login",
        "/signin",
        "/auth/login",
        "/api/auth/login",
        "/forgot-password",
        "/reset-password",
        "/api/password-reset",
        "/register",
        "/signup",
        "/api/register",
        "/otp",
        "/verify",
        "/api/otp",
        "/api/token",
        "/oauth/token",
    ]

    BURST_SIZE = 25
    STOP_CODE = 429

    def __init__(self, scan_id: str, endpoints: List[EndpointData], cookies: Dict[str, str]):
        self.scan_id = scan_id
        self.endpoints = endpoints
        self.cookies = cookies or {}
        self.max_rate = max(1, int(getattr(settings, "HARDCORE_MAX_RATE_PER_SEC", 50)))
        self.logger = logging.getLogger(__name__)

    async def run(self) -> List[FindingData]:
        targets = [
            ep
            for ep in self.endpoints
            if any(path in ep.url.lower() for path in self.RATE_SENSITIVE_PATHS)
        ]

        findings: List[FindingData] = []
        for endpoint in targets:
            finding = await self._burst_test(endpoint)
            if finding is not None:
                findings.append(finding)
            await asyncio.sleep(3)
        return findings

    async def _burst_test(self, endpoint: EndpointData) -> Optional[FindingData]:
        status_codes: List[int] = []
        async with httpx.AsyncClient(verify=False, timeout=10, cookies=self.cookies) as client:
            for _ in range(self.BURST_SIZE):
                start = time.perf_counter()
                try:
                    response = await client.request(endpoint.method.upper(), endpoint.url)
                    status_codes.append(response.status_code)
                    elapsed = time.perf_counter() - start
                    await log_audit_entry(
                        scan_id=self.scan_id,
                        module="rate_limit_tester",
                        request_method=endpoint.method.upper(),
                        request_url=endpoint.url,
                        response_code=response.status_code,
                        notes=f"Burst probe in {elapsed * 1000:.1f} ms",
                    )
                    if response.status_code == self.STOP_CODE:
                        break
                except Exception as exc:
                    await log_audit_entry(
                        scan_id=self.scan_id,
                        module="rate_limit_tester",
                        request_method=endpoint.method.upper(),
                        request_url=endpoint.url,
                        response_code=None,
                        notes=f"Burst probe error: {exc}",
                    )
                await asyncio.sleep(1 / self.max_rate)

        hit_429 = self.STOP_CODE in status_codes
        all_200 = bool(status_codes) and all(s < 400 for s in status_codes)
        first_429 = next((i + 1 for i, s in enumerate(status_codes) if s == self.STOP_CODE), None)

        await log_audit_entry(
            scan_id=self.scan_id,
            module="rate_limit_tester",
            request_method=endpoint.method.upper(),
            request_url=endpoint.url,
            response_code=status_codes[0] if status_codes else None,
            notes=f"Burst test: {len(status_codes)} responses, 429 at position {first_429}",
        )

        if all_200:
            return FindingData(
                scan_id=self.scan_id,
                endpoint_url=endpoint.url,
                endpoint_id=None,
                vuln_type="rate_limit",
                severity="high",
                title=f"No rate limiting on {endpoint.url}",
                description=(
                    f"Sent {self.BURST_SIZE} requests in rapid succession. "
                    "All returned success status - no rate limiting detected."
                ),
                evidence={
                    "burst_size": self.BURST_SIZE,
                    "status_codes": status_codes[:10],
                    "hit_429": False,
                    "all_succeeded": True,
                },
                parameter=None,
                payload_used=f"{self.BURST_SIZE}-request burst",
                confidence=0.95,
                is_confirmed=True,
                mitre_id="T1110",
                owasp_category="A07:2021-Identification and Authentication Failures",
            )

        if hit_429 and first_429 is not None and first_429 > 20:
            return FindingData(
                scan_id=self.scan_id,
                endpoint_url=endpoint.url,
                endpoint_id=None,
                vuln_type="rate_limit",
                severity="medium",
                title=f"Weak rate limiting on {endpoint.url}",
                description=(
                    f"Rate limiting triggered after {first_429} requests. "
                    "Threshold is high and allows excessive attempts before block."
                ),
                evidence={
                    "burst_size": self.BURST_SIZE,
                    "first_429_at": first_429,
                },
                parameter=None,
                payload_used=f"{self.BURST_SIZE}-request burst",
                confidence=0.85,
                is_confirmed=True,
                mitre_id="T1110",
                owasp_category="A07:2021-Identification and Authentication Failures",
            )

        return None
