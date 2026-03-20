from collections import defaultdict
from typing import Dict, List, TYPE_CHECKING
from urllib.parse import urlparse

from scanner.crawler import EndpointData

if TYPE_CHECKING:
    from scanner.rule_engine import FindingData


class HeaderProbe:
    vuln_type = "header"
    owasp_category = "A05:2021-Security Misconfiguration"
    mitre_id = "T1190"

    REQUIRED_HEADERS = {
        "Content-Security-Policy": {
            "severity": "medium",
            "description": "Missing Content-Security-Policy header allows XSS attacks.",
        },
        "X-Frame-Options": {
            "severity": "medium",
            "description": "Missing X-Frame-Options enables clickjacking attacks.",
        },
        "X-Content-Type-Options": {
            "severity": "low",
            "description": "Missing X-Content-Type-Options allows MIME-type sniffing.",
        },
        "Strict-Transport-Security": {
            "severity": "medium",
            "description": "Missing HSTS header allows protocol downgrade attacks.",
        },
        "Referrer-Policy": {
            "severity": "low",
            "description": "Missing Referrer-Policy leaks URL info to third parties.",
        },
        "Permissions-Policy": {
            "severity": "low",
            "description": "Missing Permissions-Policy allows unrestricted browser API access.",
        },
    }

    DANGEROUS_HEADERS = {
        "Server": {
            "severity": "info",
            "description": "Server header exposes technology stack to attackers.",
        },
        "X-Powered-By": {
            "severity": "info",
            "description": "X-Powered-By reveals framework/language version.",
        },
        "X-AspNet-Version": {
            "severity": "low",
            "description": "X-AspNet-Version reveals .NET framework version.",
        },
    }

    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    async def run(self, endpoints: List[EndpointData], rules: dict) -> List["FindingData"]:
        from scanner.rule_engine import FindingData, RuleEngine

        findings: List[FindingData] = []
        seen_missing: set = set()
        seen_dangerous: set = set()
        seen_csp_weak: set = set()

        async with RuleEngine._build_httpx_client() as client:
            for endpoint in endpoints:
                domain = urlparse(endpoint.url).netloc.lower()
                headers = dict(endpoint.headers or {})

                if not headers:
                    try:
                        fresh = await client.get(endpoint.url)
                        headers = dict(fresh.headers)
                    except Exception:
                        headers = {}

                lowered = {k.lower(): v for k, v in headers.items()}

                for header_name, meta in self.REQUIRED_HEADERS.items():
                    key = (domain, header_name)
                    if key in seen_missing:
                        continue
                    if header_name.lower() not in lowered:
                        seen_missing.add(key)
                        findings.append(
                            FindingData(
                                scan_id=self.scan_id,
                                endpoint_url=endpoint.url,
                                endpoint_id=None,
                                vuln_type=self.vuln_type,
                                severity=meta["severity"],
                                title=f"Missing {header_name} security header",
                                description=meta["description"],
                                evidence={
                                    "request_method": endpoint.method,
                                    "request_url": endpoint.url,
                                    "request_headers": {},
                                    "request_body": None,
                                    "response_code": endpoint.status_code,
                                    "response_body": "",
                                    "matched_pattern": f"{header_name} absent",
                                },
                                parameter=None,
                                payload_used=None,
                                confidence=0.75,
                                is_confirmed=True,
                                mitre_id=self.mitre_id,
                                owasp_category=self.owasp_category,
                            )
                        )

                for header_name, meta in self.DANGEROUS_HEADERS.items():
                    key = (domain, header_name)
                    if key in seen_dangerous:
                        continue
                    if header_name.lower() in lowered:
                        seen_dangerous.add(key)
                        findings.append(
                            FindingData(
                                scan_id=self.scan_id,
                                endpoint_url=endpoint.url,
                                endpoint_id=None,
                                vuln_type=self.vuln_type,
                                severity=meta["severity"],
                                title=f"Information disclosure via {header_name} header",
                                description=meta["description"],
                                evidence={
                                    "request_method": endpoint.method,
                                    "request_url": endpoint.url,
                                    "request_headers": {},
                                    "request_body": None,
                                    "response_code": endpoint.status_code,
                                    "response_body": "",
                                    "matched_pattern": str(lowered.get(header_name.lower(), ""))[:500],
                                },
                                parameter=None,
                                payload_used=None,
                                confidence=0.7,
                                is_confirmed=False,
                                mitre_id=self.mitre_id,
                                owasp_category=self.owasp_category,
                            )
                        )

                csp = lowered.get("content-security-policy")
                if csp:
                    csp_lower = csp.lower()
                    weak_checks = {
                        "unsafe-inline": "CSP allows unsafe-inline",
                        "unsafe-eval": "CSP allows unsafe-eval",
                        "*": "CSP contains wildcard source",
                    }
                    for token, message in weak_checks.items():
                        key = (domain, message)
                        if key in seen_csp_weak:
                            continue
                        if token in csp_lower:
                            seen_csp_weak.add(key)
                            findings.append(
                                FindingData(
                                    scan_id=self.scan_id,
                                    endpoint_url=endpoint.url,
                                    endpoint_id=None,
                                    vuln_type=self.vuln_type,
                                    severity="medium",
                                    title=message,
                                    description="The configured Content-Security-Policy includes weak directives.",
                                    evidence={
                                        "request_method": endpoint.method,
                                        "request_url": endpoint.url,
                                        "request_headers": {},
                                        "request_body": None,
                                        "response_code": endpoint.status_code,
                                        "response_body": "",
                                        "matched_pattern": token,
                                    },
                                    parameter=None,
                                    payload_used=None,
                                    confidence=0.8,
                                    is_confirmed=False,
                                    mitre_id=self.mitre_id,
                                    owasp_category=self.owasp_category,
                                )
                            )

                    key = (domain, "missing default-src")
                    if key not in seen_csp_weak and "default-src" not in csp_lower:
                        seen_csp_weak.add(key)
                        findings.append(
                            FindingData(
                                scan_id=self.scan_id,
                                endpoint_url=endpoint.url,
                                endpoint_id=None,
                                vuln_type=self.vuln_type,
                                severity="low",
                                title="CSP missing default-src directive",
                                description="The CSP header does not define a default-src policy fallback.",
                                evidence={
                                    "request_method": endpoint.method,
                                    "request_url": endpoint.url,
                                    "request_headers": {},
                                    "request_body": None,
                                    "response_code": endpoint.status_code,
                                    "response_body": "",
                                    "matched_pattern": "default-src missing",
                                },
                                parameter=None,
                                payload_used=None,
                                confidence=0.7,
                                is_confirmed=False,
                                mitre_id=self.mitre_id,
                                owasp_category=self.owasp_category,
                            )
                        )

        return findings
