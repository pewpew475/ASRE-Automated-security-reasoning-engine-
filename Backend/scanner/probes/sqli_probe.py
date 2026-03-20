import time
from typing import List, TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from scanner.crawler import EndpointData

if TYPE_CHECKING:
    from scanner.rule_engine import FindingData


class SQLiProbe:
    vuln_type = "sqli"
    owasp_category = "A03:2021-Injection"
    mitre_id = "T1190"

    SAFE_BOOLEAN_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='2",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND '1'='1",
        "' AND '1'='2",
    ]

    ERROR_PATTERNS = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "PostgreSQL",
        "SQLite3::",
        "SQLSTATE",
        "Unclosed quotation mark",
        "quoted string not properly terminated",
        "syntax error at or near",
        "Warning: mysql",
        "supplied argument is not a valid MySQL",
    ]

    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    async def run(self, endpoints: List[EndpointData], rules: dict) -> List["FindingData"]:
        from scanner.rule_engine import FindingData, RuleEngine

        findings: List[FindingData] = []
        error_patterns = [p.lower() for p in rules.get("error_patterns", self.ERROR_PATTERNS)]

        async with RuleEngine._build_httpx_client() as client:
            for endpoint in endpoints:
                param_names = [str(p.get("name")) for p in (endpoint.params or []) if p.get("name")]
                body_names = [str(p.get("name")) for p in (endpoint.body_params or []) if p.get("name")]
                if not param_names and not body_names:
                    continue

                for param in param_names + body_names:
                    error_url = self._inject_query(endpoint.url, param, "'")
                    try:
                        error_resp = await client.get(error_url)
                    except Exception:
                        continue

                    body_lower = (error_resp.text or "").lower()
                    matched_error = next((pat for pat in error_patterns if pat in body_lower), None)
                    if matched_error:
                        findings.append(
                            FindingData(
                                scan_id=self.scan_id,
                                endpoint_url=endpoint.url,
                                endpoint_id=None,
                                vuln_type=self.vuln_type,
                                severity="high",
                                title=f"Potential SQL injection error disclosure in {param} at {endpoint.url}",
                                description=(
                                    "Database error fragments were detected after injecting a safe marker payload. "
                                    "Detected using safe boolean payloads in Normal Mode. "
                                    "Use Hardcore Mode with SQLMap for confirmation and scope."
                                ),
                                evidence={
                                    "request_method": "GET",
                                    "request_url": error_url,
                                    "request_headers": {},
                                    "request_body": None,
                                    "response_code": error_resp.status_code,
                                    "response_body": (error_resp.text or "")[:500],
                                    "matched_pattern": matched_error,
                                },
                                parameter=param,
                                payload_used="'",
                                confidence=0.8,
                                is_confirmed=False,
                                mitre_id=self.mitre_id,
                                owasp_category=self.owasp_category,
                            )
                        )

                    true_payload = "1 AND 1=1"
                    false_payload = "1 AND 1=2"
                    true_url = self._inject_query(endpoint.url, param, true_payload)
                    false_url = self._inject_query(endpoint.url, param, false_payload)

                    try:
                        t0 = time.monotonic()
                        true_resp = await client.get(true_url)
                        t1 = time.monotonic()
                        false_resp = await client.get(false_url)
                        t2 = time.monotonic()
                    except Exception:
                        continue

                    true_len = len(true_resp.text or "")
                    false_len = len(false_resp.text or "")
                    boolean_diff = true_resp.status_code != false_resp.status_code or abs(true_len - false_len) > max(40, int(true_len * 0.1))

                    true_time = t1 - t0
                    false_time = t2 - t1
                    passive_timing_flag = false_time > true_time * 3 and false_time > 1.2

                    if boolean_diff or passive_timing_flag:
                        reason = "Boolean response divergence" if boolean_diff else "Passive timing anomaly"
                        findings.append(
                            FindingData(
                                scan_id=self.scan_id,
                                endpoint_url=endpoint.url,
                                endpoint_id=None,
                                vuln_type=self.vuln_type,
                                severity="high",
                                title=f"Potential SQL injection in {param} at {endpoint.url}",
                                description=(
                                    "Response behavior changed under safe boolean SQL expressions. "
                                    "Detected using safe boolean payloads in Normal Mode. "
                                    "Use Hardcore Mode with SQLMap for confirmation and scope."
                                ),
                                evidence={
                                    "request_method": "GET",
                                    "request_url": true_url,
                                    "request_headers": {},
                                    "request_body": None,
                                    "response_code": true_resp.status_code,
                                    "response_body": (true_resp.text or "")[:500],
                                    "matched_pattern": reason,
                                },
                                parameter=param,
                                payload_used=f"{true_payload} vs {false_payload}",
                                confidence=0.7,
                                is_confirmed=False,
                                mitre_id=self.mitre_id,
                                owasp_category=self.owasp_category,
                            )
                        )

        return findings

    def _inject_query(self, url: str, name: str, value: str) -> str:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        params[name] = value
        query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=query))
