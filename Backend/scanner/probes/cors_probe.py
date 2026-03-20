from typing import List, TYPE_CHECKING

from scanner.crawler import EndpointData

if TYPE_CHECKING:
    from scanner.rule_engine import FindingData


class CORSProbe:
    vuln_type = "cors"
    owasp_category = "A05:2021-Security Misconfiguration"
    mitre_id = "T1557"

    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    async def run(self, endpoints: List[EndpointData], rules: dict) -> List["FindingData"]:
        from scanner.rule_engine import FindingData, RuleEngine

        findings: List[FindingData] = []

        async with RuleEngine._build_httpx_client() as client:
            for endpoint in endpoints:
                try:
                    evil_response = await client.get(endpoint.url, headers={"Origin": "https://evil-attacker.com"})
                    null_response = await client.get(endpoint.url, headers={"Origin": "null"})
                except Exception:
                    continue

                allow_origin = (evil_response.headers.get("Access-Control-Allow-Origin") or "").strip()
                allow_creds = (evil_response.headers.get("Access-Control-Allow-Credentials") or "").lower()

                if allow_origin == "*":
                    severity = "high" if endpoint.auth_required else "low"
                    findings.append(
                        FindingData(
                            scan_id=self.scan_id,
                            endpoint_url=endpoint.url,
                            endpoint_id=None,
                            vuln_type=self.vuln_type,
                            severity=severity,
                            title=f"CORS allows wildcard origin at {endpoint.url}",
                            description="Wildcard CORS may expose endpoint responses to any origin. Risk is higher for authenticated resources.",
                            evidence={
                                "request_method": "GET",
                                "request_url": endpoint.url,
                                "request_headers": {"Origin": "https://evil-attacker.com"},
                                "request_body": None,
                                "response_code": evil_response.status_code,
                                "response_body": (evil_response.text or "")[:500],
                                "matched_pattern": "Access-Control-Allow-Origin: *",
                            },
                            parameter=None,
                            payload_used="Origin: https://evil-attacker.com",
                            confidence=0.8,
                            is_confirmed=False,
                            mitre_id=self.mitre_id,
                            owasp_category=self.owasp_category,
                        )
                    )

                if allow_origin == "https://evil-attacker.com":
                    severity = "critical" if allow_creds == "true" else "high"
                    findings.append(
                        FindingData(
                            scan_id=self.scan_id,
                            endpoint_url=endpoint.url,
                            endpoint_id=None,
                            vuln_type=self.vuln_type,
                            severity=severity,
                            title=f"CORS reflects arbitrary origin at {endpoint.url}",
                            description="The response mirrors an attacker-controlled Origin header, indicating potentially unsafe dynamic CORS policy.",
                            evidence={
                                "request_method": "GET",
                                "request_url": endpoint.url,
                                "request_headers": {"Origin": "https://evil-attacker.com"},
                                "request_body": None,
                                "response_code": evil_response.status_code,
                                "response_body": (evil_response.text or "")[:500],
                                "matched_pattern": f"Reflected Origin with credentials={allow_creds}",
                            },
                            parameter=None,
                            payload_used="Origin: https://evil-attacker.com",
                            confidence=0.9,
                            is_confirmed=True,
                            mitre_id=self.mitre_id,
                            owasp_category=self.owasp_category,
                        )
                    )

                null_allow_origin = (null_response.headers.get("Access-Control-Allow-Origin") or "").strip().lower()
                if null_allow_origin == "null":
                    findings.append(
                        FindingData(
                            scan_id=self.scan_id,
                            endpoint_url=endpoint.url,
                            endpoint_id=None,
                            vuln_type=self.vuln_type,
                            severity="high",
                            title=f"CORS accepts null origin at {endpoint.url}",
                            description="Accepting null origin can enable data access from sandboxed or file-based contexts.",
                            evidence={
                                "request_method": "GET",
                                "request_url": endpoint.url,
                                "request_headers": {"Origin": "null"},
                                "request_body": None,
                                "response_code": null_response.status_code,
                                "response_body": (null_response.text or "")[:500],
                                "matched_pattern": "Access-Control-Allow-Origin: null",
                            },
                            parameter=None,
                            payload_used="Origin: null",
                            confidence=0.8,
                            is_confirmed=False,
                            mitre_id=self.mitre_id,
                            owasp_category=self.owasp_category,
                        )
                    )

                if allow_origin == "*" and allow_creds == "true":
                    findings.append(
                        FindingData(
                            scan_id=self.scan_id,
                            endpoint_url=endpoint.url,
                            endpoint_id=None,
                            vuln_type=self.vuln_type,
                            severity="critical",
                            title=f"CORS returns wildcard origin with credentials at {endpoint.url}",
                            description="This CORS combination is invalid in modern browsers and indicates severe policy misconfiguration.",
                            evidence={
                                "request_method": "GET",
                                "request_url": endpoint.url,
                                "request_headers": {"Origin": "https://evil-attacker.com"},
                                "request_body": None,
                                "response_code": evil_response.status_code,
                                "response_body": (evil_response.text or "")[:500],
                                "matched_pattern": "ACAO=* with ACAC=true",
                            },
                            parameter=None,
                            payload_used="Origin: https://evil-attacker.com",
                            confidence=0.9,
                            is_confirmed=False,
                            mitre_id=self.mitre_id,
                            owasp_category=self.owasp_category,
                        )
                    )

        return findings
