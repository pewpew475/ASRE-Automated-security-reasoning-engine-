import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

from scanner.crawler import EndpointData
from scanner.rule_engine import FindingData
from tasks.scan_tasks import log_audit_entry


class UserEnumerator:
    TEST_USERNAMES = [
        "admin",
        "test@example.com",
        "user@example.com",
        "nonexistent_xyz_asre_9874@nowhere.invalid",
    ]
    KNOWN_EMAIL_MARKER = "test@example.com"
    FAKE_EMAIL_MARKER = "nonexistent_xyz_asre_9874@nowhere.invalid"

    def __init__(self, scan_id: str, endpoints: List[EndpointData]):
        self.scan_id = scan_id
        self.endpoints = endpoints
        self.logger = logging.getLogger(__name__)

    async def run(self) -> List[FindingData]:
        auth_endpoints = [
            ep
            for ep in self.endpoints
            if any(path in ep.url.lower() for path in ["/login", "/signin", "/forgot", "/reset"])
            and ep.method.upper() == "POST"
        ]

        findings: List[FindingData] = []
        for endpoint in auth_endpoints:
            finding = await self._test_enumeration(endpoint)
            if finding:
                findings.append(finding)
        return findings

    def _pick_identity_field(self, endpoint: EndpointData) -> Optional[str]:
        for item in endpoint.body_params:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).lower()
            if any(key in name for key in ["email", "user", "username", "login"]):
                return str(item.get("name"))
        return None

    async def _request_once(self, client: httpx.AsyncClient, endpoint: EndpointData, field: str, value: str) -> Tuple[httpx.Response, float]:
        payload = {field: value, "password": "invalid-password-asre"}
        start = time.perf_counter()
        response = await client.post(endpoint.url, json=payload)
        elapsed = time.perf_counter() - start
        await log_audit_entry(
            scan_id=self.scan_id,
            module="user_enumerator",
            request_method="POST",
            request_url=endpoint.url,
            response_code=response.status_code,
            notes=f"Enumeration probe for {field}={value[:24]}",
        )
        return response, elapsed

    async def _test_enumeration(self, endpoint: EndpointData) -> Optional[FindingData]:
        field = self._pick_identity_field(endpoint)
        if not field:
            return None

        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            try:
                response_a, time_a = await self._request_once(client, endpoint, field, self.KNOWN_EMAIL_MARKER)
                response_b, time_b = await self._request_once(client, endpoint, field, self.FAKE_EMAIL_MARKER)
                response_c, time_c = await self._request_once(client, endpoint, field, self.FAKE_EMAIL_MARKER)
            except Exception as exc:
                await log_audit_entry(
                    scan_id=self.scan_id,
                    module="user_enumerator",
                    request_method="POST",
                    request_url=endpoint.url,
                    response_code=None,
                    notes=f"Enumeration test failed: {exc}",
                )
                return None

        body_a = response_a.text[:400]
        body_b = response_b.text[:400]
        message_diff = body_a != body_b
        timing_diff_ms = abs(time_a - time_b) * 1000
        timing_consistent = abs(time_b - time_c) * 1000 < 120
        timing_oracle = timing_diff_ms > 200 and timing_consistent
        status_diff = response_a.status_code != response_b.status_code

        await log_audit_entry(
            scan_id=self.scan_id,
            module="user_enumerator",
            request_method="POST",
            request_url=endpoint.url,
            response_code=response_a.status_code,
            notes=f"Enumeration test: message_diff={message_diff}, timing_diff_ms={timing_diff_ms:.1f}, status_diff={status_diff}",
        )

        if not (message_diff or timing_oracle or status_diff):
            return None

        if message_diff:
            detection_method = "response message differences"
            confidence = 0.8
            confirmed = True
        elif timing_oracle:
            detection_method = "timing oracle"
            confidence = 0.6
            confirmed = False
        else:
            detection_method = "status code differences"
            confidence = 0.65
            confirmed = False

        return FindingData(
            scan_id=self.scan_id,
            endpoint_url=endpoint.url,
            endpoint_id=None,
            vuln_type="user_enum",
            severity="medium",
            title=f"User enumeration via {detection_method} on {endpoint.url}",
            description=(
                "Authentication responses differ between likely-valid and invalid identities, "
                "enabling user/account existence probing."
            ),
            evidence={
                "known_email_response": body_a,
                "fake_email_response": body_b,
                "message_diff": message_diff,
                "timing_diff_ms": round(timing_diff_ms, 2),
                "status_diff": status_diff,
            },
            parameter=field,
            payload_used=self.FAKE_EMAIL_MARKER,
            confidence=confidence,
            is_confirmed=confirmed,
            mitre_id="T1589",
            owasp_category="A07:2021-Identification and Authentication Failures",
        )
