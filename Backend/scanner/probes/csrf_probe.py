from typing import List, TYPE_CHECKING

from scanner.crawler import EndpointData

if TYPE_CHECKING:
    from scanner.rule_engine import FindingData


class CSRFProbe:
    vuln_type = "csrf"
    owasp_category = "A01:2021-Broken Access Control"
    mitre_id = "T1185"

    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    async def run(self, endpoints: List[EndpointData], rules: dict) -> List["FindingData"]:
        from scanner.rule_engine import FindingData, RuleEngine

        findings: List[FindingData] = []
        token_names = {
            "csrf",
            "csrf_token",
            "_token",
            "authenticity_token",
            "csrfmiddlewaretoken",
            "__requestverificationtoken",
            "_csrf",
        }
        methods = {"POST", "PUT", "PATCH", "DELETE"}

        async with RuleEngine._build_httpx_client() as client:
            for endpoint in endpoints:
                method = endpoint.method.upper()
                if method not in methods:
                    continue

                body_fields = {str(p.get("name", "")).lower() for p in endpoint.body_params or []}
                missing_token = not body_fields.intersection(token_names)

                try:
                    probe_response = await client.request(
                        method,
                        endpoint.url,
                        data={},
                        headers={
                            "Origin": "https://evil.com",
                            "Referer": "https://evil.com/attack.html",
                        },
                    )
                except Exception:
                    continue

                set_cookie = (probe_response.headers.get("set-cookie") or "").lower()
                missing_samesite = bool(set_cookie) and "samesite" not in set_cookie
                origin_not_validated = probe_response.status_code == 200

                no_custom_header_enforcement = False
                try:
                    no_header_resp = await client.request(method, endpoint.url, data={})
                    no_custom_header_enforcement = no_header_resp.status_code == 200
                except Exception:
                    pass

                triggered = []
                if missing_token:
                    triggered.append("Missing anti-CSRF token")
                if missing_samesite:
                    triggered.append("Missing SameSite cookie flag")
                if origin_not_validated:
                    triggered.append("Origin/Referer not validated")
                if no_custom_header_enforcement:
                    triggered.append("No custom header enforcement")

                if not triggered:
                    continue

                if missing_token and missing_samesite and origin_not_validated:
                    severity = "high"
                elif missing_token:
                    severity = "medium"
                elif missing_samesite:
                    severity = "low"
                elif origin_not_validated:
                    severity = "medium"
                else:
                    severity = "low"

                findings.append(
                    FindingData(
                        scan_id=self.scan_id,
                        endpoint_url=endpoint.url,
                        endpoint_id=None,
                        vuln_type=self.vuln_type,
                        severity=severity,
                        title=f"CSRF protection weakness at {endpoint.url}",
                        description=(
                            "The endpoint appears to accept state-changing requests without robust CSRF defenses. "
                            "Implement anti-CSRF tokens, enforce SameSite on session cookies, and validate Origin/Referer."
                        ),
                        evidence={
                            "request_method": method,
                            "request_url": endpoint.url,
                            "request_headers": {"Origin": "https://evil.com", "Referer": "https://evil.com/attack.html"},
                            "request_body": "{}",
                            "response_code": probe_response.status_code,
                            "response_body": (probe_response.text or "")[:500],
                            "matched_pattern": "; ".join(triggered),
                        },
                        parameter=None,
                        payload_used="Origin/Referer cross-site probe",
                        confidence=0.8,
                        is_confirmed=False,
                        mitre_id=self.mitre_id,
                        owasp_category=self.owasp_category,
                    )
                )

        return findings
