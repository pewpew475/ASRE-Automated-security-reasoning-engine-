import base64
import json
import re
from datetime import datetime, timezone
from typing import List, TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from scanner.crawler import EndpointData

if TYPE_CHECKING:
    from scanner.rule_engine import FindingData


class AuthProbe:
    vuln_type = "auth"
    owasp_category = "A07:2021-Identification and Authentication Failures"
    mitre_id = "T1078.001"

    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    async def run(self, endpoints: List[EndpointData], rules: dict) -> List["FindingData"]:
        from scanner.rule_engine import FindingData, RuleEngine

        findings: List[FindingData] = []
        admin_paths = [
            "/admin",
            "/admin/login",
            "/administrator",
            "/wp-admin",
            "/phpmyadmin",
            "/cpanel",
            "/manager",
            "/console",
        ]
        sensitive_params = {"password", "passwd", "pwd", "pass", "secret", "token", "key", "api_key"}

        async with RuleEngine._build_httpx_client() as client:
            for endpoint in endpoints:
                if endpoint.auth_required:
                    try:
                        response = await client.get(endpoint.url, headers={})
                        if response.status_code == 200:
                            findings.append(
                                FindingData(
                                    scan_id=self.scan_id,
                                    endpoint_url=endpoint.url,
                                    endpoint_id=None,
                                    vuln_type=self.vuln_type,
                                    severity="critical",
                                    title=f"Protected route accessible without authentication at {endpoint.url}",
                                    description=(
                                        "An endpoint marked as authentication-required returned success without credentials. "
                                        "This indicates a likely broken authentication/authorization control."
                                    ),
                                    evidence={
                                        "request_method": "GET",
                                        "request_url": endpoint.url,
                                        "request_headers": {},
                                        "request_body": None,
                                        "response_code": response.status_code,
                                        "response_body": (response.text or "")[:500],
                                        "matched_pattern": "Unauthenticated request returned 200",
                                    },
                                    parameter=None,
                                    payload_used=None,
                                    confidence=0.95,
                                    is_confirmed=True,
                                    mitre_id=self.mitre_id,
                                    owasp_category=self.owasp_category,
                                )
                            )
                    except Exception:
                        pass

                parsed = urlparse(endpoint.url)
                query = parse_qs(parsed.query, keep_blank_values=True)
                for key in query:
                    if key.lower() in sensitive_params:
                        findings.append(
                            FindingData(
                                scan_id=self.scan_id,
                                endpoint_url=endpoint.url,
                                endpoint_id=None,
                                vuln_type=self.vuln_type,
                                severity="high",
                                title=f"Sensitive parameter in URL at {endpoint.url}",
                                description=(
                                    "Sensitive values in query strings can leak via logs, browser history, and referrer headers. "
                                    "Move secrets and credentials to secure request bodies or authorization headers."
                                ),
                                evidence={
                                    "request_method": endpoint.method,
                                    "request_url": endpoint.url,
                                    "request_headers": {},
                                    "request_body": None,
                                    "response_code": endpoint.status_code,
                                    "response_body": "",
                                    "matched_pattern": key,
                                },
                                parameter=key,
                                payload_used=None,
                                confidence=0.85,
                                is_confirmed=True,
                                mitre_id=self.mitre_id,
                                owasp_category=self.owasp_category,
                            )
                        )

                set_cookie = endpoint.headers.get("Set-Cookie", "")
                if set_cookie:
                    cookie_lower = set_cookie.lower()
                    if "httponly" not in cookie_lower:
                        findings.append(self._cookie_flag_finding(endpoint, "HttpOnly", "medium"))
                    if "secure" not in cookie_lower and "localhost" not in endpoint.url:
                        findings.append(self._cookie_flag_finding(endpoint, "Secure", "low"))
                    if "samesite" not in cookie_lower:
                        findings.append(self._cookie_flag_finding(endpoint, "SameSite", "low"))

                if any(path in endpoint.url.lower() for path in admin_paths):
                    try:
                        admin_response = await client.get(endpoint.url)
                        if admin_response.status_code == 200:
                            findings.append(
                                FindingData(
                                    scan_id=self.scan_id,
                                    endpoint_url=endpoint.url,
                                    endpoint_id=None,
                                    vuln_type=self.vuln_type,
                                    severity="low",
                                    title=f"Admin panel exposed at {endpoint.url}",
                                    description=(
                                        "A common administration path is reachable and may increase attack surface. "
                                        "Verify access controls and restrict exposure as appropriate."
                                    ),
                                    evidence={
                                        "request_method": "GET",
                                        "request_url": endpoint.url,
                                        "request_headers": {},
                                        "request_body": None,
                                        "response_code": admin_response.status_code,
                                        "response_body": (admin_response.text or "")[:500],
                                        "matched_pattern": "Known admin path returned 200",
                                    },
                                    parameter=None,
                                    payload_used=None,
                                    confidence=0.6,
                                    is_confirmed=False,
                                    mitre_id=self.mitre_id,
                                    owasp_category=self.owasp_category,
                                )
                            )
                    except Exception:
                        pass

                jwt_candidates = self._extract_jwt_candidates(endpoint)
                for token in jwt_candidates:
                    jwt_finding = self._analyze_jwt(token, endpoint)
                    if jwt_finding:
                        findings.append(jwt_finding)

        return findings

    def _extract_jwt_candidates(self, endpoint: EndpointData) -> List[str]:
        candidates: List[str] = []
        set_cookie = endpoint.headers.get("Set-Cookie", "")
        candidates.extend(re.findall(r"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", set_cookie))
        return candidates

    def _analyze_jwt(self, token: str, endpoint: EndpointData):
        from scanner.rule_engine import FindingData

        parts = token.split(".")
        if len(parts) != 3:
            return None

        try:
            header_raw = base64.urlsafe_b64decode(parts[0] + "==")
            payload_raw = base64.urlsafe_b64decode(parts[1] + "==")
            header = json.loads(header_raw.decode("utf-8", errors="ignore"))
            payload = json.loads(payload_raw.decode("utf-8", errors="ignore"))
        except Exception:
            return None

        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            return FindingData(
                scan_id=self.scan_id,
                endpoint_url=endpoint.url,
                endpoint_id=None,
                vuln_type=self.vuln_type,
                severity="critical",
                title=f"JWT uses insecure none algorithm at {endpoint.url}",
                description="A token header indicates alg=none, enabling unsigned token abuse if accepted server-side.",
                evidence={
                    "request_method": endpoint.method,
                    "request_url": endpoint.url,
                    "request_headers": {},
                    "request_body": None,
                    "response_code": endpoint.status_code,
                    "response_body": "",
                    "matched_pattern": "alg=none",
                },
                parameter=None,
                payload_used=token[:60],
                confidence=0.9,
                is_confirmed=False,
                mitre_id=self.mitre_id,
                owasp_category=self.owasp_category,
            )

        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            expiry = datetime.fromtimestamp(exp, tz=timezone.utc)
            if (expiry - datetime.now(timezone.utc)).days > 365:
                return FindingData(
                    scan_id=self.scan_id,
                    endpoint_url=endpoint.url,
                    endpoint_id=None,
                    vuln_type=self.vuln_type,
                    severity="medium",
                    title=f"JWT token expiry is excessively long at {endpoint.url}",
                    description="A token appears valid for more than one year, increasing risk if compromised.",
                    evidence={
                        "request_method": endpoint.method,
                        "request_url": endpoint.url,
                        "request_headers": {},
                        "request_body": None,
                        "response_code": endpoint.status_code,
                        "response_body": "",
                        "matched_pattern": "exp > 1 year",
                    },
                    parameter=None,
                    payload_used=token[:60],
                    confidence=0.7,
                    is_confirmed=False,
                    mitre_id=self.mitre_id,
                    owasp_category=self.owasp_category,
                )

        return None

    def _cookie_flag_finding(self, endpoint: EndpointData, flag: str, severity: str):
        from scanner.rule_engine import FindingData

        return FindingData(
            scan_id=self.scan_id,
            endpoint_url=endpoint.url,
            endpoint_id=None,
            vuln_type=self.vuln_type,
            severity=severity,
            title=f"Session cookie missing {flag} flag at {endpoint.url}",
            description=(
                f"Session cookies should include the {flag} attribute to reduce client-side abuse and transport risks."
            ),
            evidence={
                "request_method": endpoint.method,
                "request_url": endpoint.url,
                "request_headers": {},
                "request_body": None,
                "response_code": endpoint.status_code,
                "response_body": "",
                "matched_pattern": f"Missing {flag}",
            },
            parameter=None,
            payload_used=None,
            confidence=0.75,
            is_confirmed=False,
            mitre_id=self.mitre_id,
            owasp_category=self.owasp_category,
        )
