import re
from typing import List, TYPE_CHECKING
from urllib.parse import urlparse

from scanner.crawler import EndpointData

if TYPE_CHECKING:
    from scanner.rule_engine import FindingData


class BusinessLogicProbe:
    vuln_type = "business_logic"
    owasp_category = "A04:2021-Insecure Design"
    mitre_id = "T1565.001"

    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    async def run(self, endpoints: List[EndpointData], rules: dict) -> List["FindingData"]:
        from scanner.rule_engine import FindingData, RuleEngine

        findings: List[FindingData] = []
        price_params = {"price", "amount", "total", "cost", "qty", "quantity", "discount"}
        test_values = [-1, -100, 0, 99999999]

        async with RuleEngine._build_httpx_client() as client:
            for endpoint in endpoints:
                method = endpoint.method.upper()
                body_names = [str(p.get("name", "")).lower() for p in (endpoint.body_params or []) if p.get("name")]

                if method in {"POST", "PUT"} and any(name in price_params for name in body_names):
                    for name in body_names:
                        if name not in price_params:
                            continue
                        for val in test_values:
                            payload = {name: val}
                            try:
                                response = await client.request(method, endpoint.url, data=payload)
                            except Exception:
                                continue
                            if response.status_code == 200:
                                findings.append(
                                    FindingData(
                                        scan_id=self.scan_id,
                                        endpoint_url=endpoint.url,
                                        endpoint_id=None,
                                        vuln_type=self.vuln_type,
                                        severity="high",
                                        title=f"Business logic flaw: {name} accepts invalid value {val}",
                                        description=(
                                            "A transactional parameter accepted an abnormal value without validation. "
                                            "Server-side business constraints should reject impossible financial or quantity values."
                                        ),
                                        evidence={
                                            "request_method": method,
                                            "request_url": endpoint.url,
                                            "request_headers": {},
                                            "request_body": str(payload),
                                            "response_code": response.status_code,
                                            "response_body": (response.text or "")[:500],
                                            "matched_pattern": f"{name}={val}",
                                        },
                                        parameter=name,
                                        payload_used=str(val),
                                        confidence=0.85,
                                        is_confirmed=True,
                                        mitre_id=self.mitre_id,
                                        owasp_category=self.owasp_category,
                                    )
                                )
                                break

                if method in {"POST", "PUT"}:
                    try:
                        response = await client.request(
                            method,
                            endpoint.url,
                            json={"role": "admin", "is_admin": True, "permissions": ["all"]},
                        )
                        if response.status_code not in {400, 422}:
                            findings.append(
                                FindingData(
                                    scan_id=self.scan_id,
                                    endpoint_url=endpoint.url,
                                    endpoint_id=None,
                                    vuln_type=self.vuln_type,
                                    severity="medium",
                                    title=f"Potential mass assignment vulnerability at {endpoint.url}",
                                    description=(
                                        "The endpoint accepted undeclared privilege fields without obvious validation errors. "
                                        "Review server-side allowlists for writable attributes."
                                    ),
                                    evidence={
                                        "request_method": method,
                                        "request_url": endpoint.url,
                                        "request_headers": {},
                                        "request_body": '{"role":"admin","is_admin":true,"permissions":["all"]}',
                                        "response_code": response.status_code,
                                        "response_body": (response.text or "")[:500],
                                        "matched_pattern": "Unexpected privileged fields accepted",
                                    },
                                    parameter=None,
                                    payload_used='{"role":"admin"}',
                                    confidence=0.6,
                                    is_confirmed=False,
                                    mitre_id=self.mitre_id,
                                    owasp_category=self.owasp_category,
                                )
                            )
                    except Exception:
                        pass

                match = re.search(r"(checkout|step)(?:/|=)?step?(\d)", endpoint.url.lower())
                if match:
                    step = int(match.group(2))
                    if step >= 2:
                        bypass_url = endpoint.url.lower().replace(f"step{step}", f"step{step + 1}")
                        try:
                            bypass_response = await client.get(bypass_url)
                            if bypass_response.status_code == 200:
                                findings.append(
                                    FindingData(
                                        scan_id=self.scan_id,
                                        endpoint_url=endpoint.url,
                                        endpoint_id=None,
                                        vuln_type=self.vuln_type,
                                        severity="high",
                                        title=f"Workflow sequence can be bypassed at {endpoint.url}",
                                        description="A later workflow step was reachable directly without completing earlier steps.",
                                        evidence={
                                            "request_method": "GET",
                                            "request_url": bypass_url,
                                            "request_headers": {},
                                            "request_body": None,
                                            "response_code": bypass_response.status_code,
                                            "response_body": (bypass_response.text or "")[:500],
                                            "matched_pattern": "Direct access to later workflow step",
                                        },
                                        parameter=None,
                                        payload_used=None,
                                        confidence=0.75,
                                        is_confirmed=False,
                                        mitre_id=self.mitre_id,
                                        owasp_category=self.owasp_category,
                                    )
                                )
                        except Exception:
                            pass

                url_lower = endpoint.url.lower()
                if any(token in url_lower for token in ["/login", "/signin", "/forgot-password", "/reset-password", "/auth/login"]):
                    success_count = 0
                    for _ in range(5):
                        try:
                            rl_resp = await client.post(endpoint.url, data={})
                            if rl_resp.status_code == 200:
                                success_count += 1
                        except Exception:
                            pass
                    if success_count == 5:
                        findings.append(
                            FindingData(
                                scan_id=self.scan_id,
                                endpoint_url=endpoint.url,
                                endpoint_id=None,
                                vuln_type=self.vuln_type,
                                severity="medium",
                                title=f"No rate limiting detected on {endpoint.url}",
                                description=(
                                    "Five rapid identical requests were accepted without throttling indicators. "
                                    "Consider enforcing per-IP and per-account rate limits."
                                ),
                                evidence={
                                    "request_method": "POST",
                                    "request_url": endpoint.url,
                                    "request_headers": {},
                                    "request_body": "{} x5",
                                    "response_code": 200,
                                    "response_body": "",
                                    "matched_pattern": "5/5 rapid requests succeeded",
                                },
                                parameter=None,
                                payload_used=None,
                                confidence=0.7,
                                is_confirmed=False,
                                mitre_id=self.mitre_id,
                                owasp_category=self.owasp_category,
                            )
                        )

                malformed_payload = {"probe": "A" * 1000 + "\x00\n\r"}
                try:
                    malformed = await client.request(method if method in {"POST", "PUT", "PATCH"} else "GET", endpoint.url, data=malformed_payload)
                    text = (malformed.text or "")
                    low = text.lower()
                    if any(marker in low for marker in ["traceback", "stack trace", "/var/", "c:\\", "sqlstate", "syntax error"]):
                        findings.append(
                            FindingData(
                                scan_id=self.scan_id,
                                endpoint_url=endpoint.url,
                                endpoint_id=None,
                                vuln_type=self.vuln_type,
                                severity="medium",
                                title=f"Verbose error message exposes internal details at {endpoint.url}",
                                description="Malformed input triggered verbose diagnostics that may reveal internal implementation details.",
                                evidence={
                                    "request_method": method,
                                    "request_url": endpoint.url,
                                    "request_headers": {},
                                    "request_body": str(malformed_payload),
                                    "response_code": malformed.status_code,
                                    "response_body": text[:500],
                                    "matched_pattern": "Verbose error signature",
                                },
                                parameter="probe",
                                payload_used="oversized+control chars",
                                confidence=0.7,
                                is_confirmed=False,
                                mitre_id=self.mitre_id,
                                owasp_category=self.owasp_category,
                            )
                        )
                except Exception:
                    pass

        return findings
