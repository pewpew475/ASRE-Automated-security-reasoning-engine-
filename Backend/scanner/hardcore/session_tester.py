import asyncio
import logging
import re
from typing import Dict, List, Optional

import httpx

from scanner.crawler import EndpointData
from scanner.rule_engine import FindingData
from tasks.scan_tasks import log_audit_entry


class SessionTester:
    def __init__(self, scan_id: str, endpoints: List[EndpointData], cookies: Dict[str, str]):
        self.scan_id = scan_id
        self.endpoints = endpoints
        self.cookies = cookies or {}
        self.logger = logging.getLogger(__name__)

    async def run(self) -> List[FindingData]:
        results = await asyncio.gather(
            self._check_session_fixation(),
            self._check_cookie_flags(),
            self._check_session_predictability(),
            self._check_concurrent_sessions(),
            return_exceptions=True,
        )

        findings: List[FindingData] = []
        for item in results:
            if isinstance(item, Exception):
                self.logger.error("Session tester module failed: %s", item)
                continue
            if isinstance(item, list) and item:
                findings.extend(item)
        return findings

    def _guess_login_url(self) -> Optional[str]:
        for ep in self.endpoints:
            if any(k in ep.url.lower() for k in ["/login", "/signin", "/auth/login"]):
                return ep.url
        return self.endpoints[0].url if self.endpoints else None

    async def _check_session_fixation(self) -> List[FindingData]:
        url = self._guess_login_url()
        if not url:
            return []

        fake_session = "ASRE_FIXED_SESSION_12345"
        findings: List[FindingData] = []

        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            try:
                resp = await client.get(url, headers={"Cookie": f"session={fake_session}"})
                await log_audit_entry(
                    scan_id=self.scan_id,
                    module="session_tester",
                    request_method="GET",
                    request_url=url,
                    response_code=resp.status_code,
                    notes="Session fixation probe",
                )
                set_cookie = " | ".join(resp.headers.get_list("set-cookie"))
                reflected = fake_session in set_cookie
                if reflected:
                    findings.append(
                        FindingData(
                            scan_id=self.scan_id,
                            endpoint_url=url,
                            endpoint_id=None,
                            vuln_type="auth",
                            severity="high",
                            title="Session fixation vulnerability detected",
                            description=(
                                "The server appears to accept and re-use an attacker-supplied session ID."
                            ),
                            evidence={"forced_session": fake_session, "set_cookie": set_cookie[:300]},
                            parameter="session",
                            payload_used=fake_session,
                            confidence=0.9,
                            is_confirmed=True,
                            mitre_id="T1539",
                            owasp_category="A07:2021-Identification and Authentication Failures",
                        )
                    )
            except Exception as exc:
                await log_audit_entry(
                    scan_id=self.scan_id,
                    module="session_tester",
                    request_method="GET",
                    request_url=url,
                    response_code=None,
                    notes=f"Session fixation probe failed: {exc}",
                )
        return findings

    async def _check_cookie_flags(self) -> List[FindingData]:
        findings: List[FindingData] = []
        targets = self.endpoints[:20]

        async with httpx.AsyncClient(verify=False, timeout=15, cookies=self.cookies) as client:
            for ep in targets:
                try:
                    resp = await client.get(ep.url)
                    await log_audit_entry(
                        scan_id=self.scan_id,
                        module="session_tester",
                        request_method="GET",
                        request_url=ep.url,
                        response_code=resp.status_code,
                        notes="Cookie flag probe",
                    )
                except Exception as exc:
                    await log_audit_entry(
                        scan_id=self.scan_id,
                        module="session_tester",
                        request_method="GET",
                        request_url=ep.url,
                        response_code=None,
                        notes=f"Cookie flag probe failed: {exc}",
                    )
                    continue

                for cookie in resp.headers.get_list("set-cookie"):
                    lower = cookie.lower()
                    if "httponly" not in lower:
                        findings.append(
                            self._cookie_finding(ep.url, "medium", "Session cookie missing HttpOnly flag", cookie)
                        )
                    if ep.url.lower().startswith("https://") and "secure" not in lower:
                        findings.append(
                            self._cookie_finding(ep.url, "medium", "Session cookie missing Secure flag", cookie)
                        )
                    if "samesite=none" in lower and "secure" not in lower:
                        findings.append(
                            self._cookie_finding(ep.url, "high", "SameSite=None without Secure allows cross-site requests", cookie)
                        )
                    if ep.url.lower().startswith("http://"):
                        findings.append(
                            self._cookie_finding(ep.url, "high", "Session cookie transmitted over unencrypted HTTP", cookie)
                        )
        return findings

    def _cookie_finding(self, url: str, severity: str, title: str, cookie: str) -> FindingData:
        return FindingData(
            scan_id=self.scan_id,
            endpoint_url=url,
            endpoint_id=None,
            vuln_type="auth",
            severity=severity,
            title=title,
            description="Cookie security attributes are insufficient for session protection.",
            evidence={"set_cookie": cookie[:300]},
            parameter="Set-Cookie",
            payload_used="cookie-attribute-check",
            confidence=0.85,
            is_confirmed=True,
            mitre_id="T1539",
            owasp_category="A07:2021-Identification and Authentication Failures",
        )

    async def _check_session_predictability(self) -> List[FindingData]:
        if not self.endpoints:
            return []
        url = self.endpoints[0].url
        ids: List[str] = []

        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            for _ in range(5):
                try:
                    resp = await client.get(url)
                    await log_audit_entry(
                        scan_id=self.scan_id,
                        module="session_tester",
                        request_method="GET",
                        request_url=url,
                        response_code=resp.status_code,
                        notes="Session predictability probe",
                    )
                    for header in resp.headers.get_list("set-cookie"):
                        m = re.search(r"(?:session|sid|sessionid)=([^;]+)", header, re.IGNORECASE)
                        if m:
                            ids.append(m.group(1))
                            break
                except Exception as exc:
                    await log_audit_entry(
                        scan_id=self.scan_id,
                        module="session_tester",
                        request_method="GET",
                        request_url=url,
                        response_code=None,
                        notes=f"Session predictability request failed: {exc}",
                    )

        if len(ids) < 3:
            return []

        findings: List[FindingData] = []

        if all(item.isdigit() for item in ids):
            findings.append(
                FindingData(
                    scan_id=self.scan_id,
                    endpoint_url=url,
                    endpoint_id=None,
                    vuln_type="auth",
                    severity="high",
                    title="Predictable session IDs detected (numeric only)",
                    description="Session identifiers appear low entropy and numeric-only.",
                    evidence={"sample": ids[:3]},
                    parameter="session",
                    payload_used="entropy-check",
                    confidence=0.85,
                    is_confirmed=True,
                    mitre_id="T1539",
                    owasp_category="A07:2021-Identification and Authentication Failures",
                )
            )

        try:
            numeric = [int(x) for x in ids]
            sequential = all(numeric[i + 1] == numeric[i] + 1 for i in range(len(numeric) - 1))
            if sequential:
                findings.append(
                    FindingData(
                        scan_id=self.scan_id,
                        endpoint_url=url,
                        endpoint_id=None,
                        vuln_type="auth",
                        severity="critical",
                        title="Predictable session IDs detected (sequential)",
                        description="Session IDs increment sequentially and can be predicted.",
                        evidence={"sample": ids[:5]},
                        parameter="session",
                        payload_used="sequence-check",
                        confidence=1.0,
                        is_confirmed=True,
                        mitre_id="T1539",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                    )
                )
        except Exception:
            pass

        short_ids = [sid for sid in ids if len(sid) < 16]
        if short_ids:
            findings.append(
                FindingData(
                    scan_id=self.scan_id,
                    endpoint_url=url,
                    endpoint_id=None,
                    vuln_type="auth",
                    severity="medium",
                    title="Session IDs are shorter than recommended",
                    description="Some session IDs are under 16 characters and may have low entropy.",
                    evidence={"short_sample": short_ids[:3]},
                    parameter="session",
                    payload_used="length-check",
                    confidence=0.7,
                    is_confirmed=False,
                    mitre_id="T1539",
                    owasp_category="A07:2021-Identification and Authentication Failures",
                )
            )

        if ids:
            prefix = ids[0]
            common_prefix_len = 0
            for i in range(min(len(s) for s in ids)):
                ch = ids[0][i]
                if all(s[i] == ch for s in ids):
                    common_prefix_len += 1
                else:
                    break
            if common_prefix_len > max(8, len(prefix) // 2):
                findings.append(
                    FindingData(
                        scan_id=self.scan_id,
                        endpoint_url=url,
                        endpoint_id=None,
                        vuln_type="auth",
                        severity="medium",
                        title="Session IDs share a large common prefix",
                        description="Generated session IDs exhibit high shared-prefix overlap.",
                        evidence={"common_prefix_len": common_prefix_len, "sample": ids[:3]},
                        parameter="session",
                        payload_used="prefix-check",
                        confidence=0.75,
                        is_confirmed=False,
                        mitre_id="T1539",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                    )
                )

        return findings

    async def _check_concurrent_sessions(self) -> List[FindingData]:
        protected = next((ep for ep in self.endpoints if ep.auth_required), None)
        if protected is None:
            return []

        findings: List[FindingData] = []
        real_cookie = self.cookies or {}
        fake_cookie = {**real_cookie, "session": "ASRE_FAKE_SESSION_98765"}

        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            try:
                a = await client.get(protected.url, cookies=real_cookie)
                await log_audit_entry(
                    scan_id=self.scan_id,
                    module="session_tester",
                    request_method="GET",
                    request_url=protected.url,
                    response_code=a.status_code,
                    notes="Concurrent session probe (real cookie)",
                )
                b = await client.get(protected.url, cookies=fake_cookie)
                await log_audit_entry(
                    scan_id=self.scan_id,
                    module="session_tester",
                    request_method="GET",
                    request_url=protected.url,
                    response_code=b.status_code,
                    notes="Concurrent session probe (fake cookie)",
                )
            except Exception as exc:
                await log_audit_entry(
                    scan_id=self.scan_id,
                    module="session_tester",
                    request_method="GET",
                    request_url=protected.url,
                    response_code=None,
                    notes=f"Concurrent session probe failed: {exc}",
                )
                return []

        if a.status_code == 200 and b.status_code == 200:
            findings.append(
                FindingData(
                    scan_id=self.scan_id,
                    endpoint_url=protected.url,
                    endpoint_id=None,
                    vuln_type="auth",
                    severity="info",
                    title="Concurrent sessions not limited",
                    description=(
                        "Protected endpoint accepted requests from multiple session contexts. "
                        "This is informational and may be acceptable by policy."
                    ),
                    evidence={"real_status": a.status_code, "fake_status": b.status_code},
                    parameter="session",
                    payload_used="concurrent-session-check",
                    confidence=0.6,
                    is_confirmed=False,
                    mitre_id="T1539",
                    owasp_category="A07:2021-Identification and Authentication Failures",
                )
            )

        return findings
