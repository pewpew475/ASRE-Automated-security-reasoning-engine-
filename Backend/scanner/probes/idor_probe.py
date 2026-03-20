import re
from typing import List, TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from scanner.crawler import EndpointData

if TYPE_CHECKING:
    from scanner.rule_engine import FindingData


class IDORProbe:
    vuln_type = "idor"
    owasp_category = "A01:2021-Broken Access Control"
    mitre_id = "T1078"

    ID_PATTERNS = [
        r"/\d+",
        r"/[a-f0-9-]{36}",
        r"[?&]id=\d+",
        r"[?&]user_id=\d+",
        r"[?&]order_id=\d+",
        r"[?&]account=\w+",
    ]

    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    async def run(self, endpoints: List[EndpointData], rules: dict) -> List["FindingData"]:
        from scanner.rule_engine import FindingData, RuleEngine

        findings: List[FindingData] = []
        sensitive_patterns = ["/user/", "/users/", "/account/", "/profile/", "/order/"]

        async with RuleEngine._build_httpx_client() as client:
            for endpoint in endpoints:
                url = endpoint.url

                numeric_match = re.search(r"/(\d+)(?=/|$)", url)
                if numeric_match:
                    original_id = int(numeric_match.group(1))
                    variants = [str(max(0, original_id - 1)), str(original_id + 1)]
                    results = []
                    for variant in variants:
                        test_url = re.sub(r"/(\d+)(?=/|$)", f"/{variant}", url, count=1)
                        try:
                            resp = await client.get(test_url)
                            results.append((resp.status_code, len(resp.text or ""), test_url))
                        except Exception:
                            continue

                    if len(results) == 2:
                        both_ok = all(code == 200 for code, _, _ in results)
                        similar_len = abs(results[0][1] - results[1][1]) <= max(50, int(results[0][1] * 0.1))
                        if both_ok and similar_len:
                            findings.append(
                                FindingData(
                                    scan_id=self.scan_id,
                                    endpoint_url=url,
                                    endpoint_id=None,
                                    vuln_type=self.vuln_type,
                                    severity="critical",
                                    title=f"Potential IDOR via numeric object enumeration at {url}",
                                    description=(
                                        "Adjacent object identifiers returned successful responses with similar payload sizes. "
                                        "This suggests object access might rely on predictable identifiers without strict ownership checks."
                                    ),
                                    evidence={
                                        "request_method": "GET",
                                        "request_url": results[0][2],
                                        "request_headers": {},
                                        "request_body": None,
                                        "response_code": results[0][0],
                                        "response_body": "",
                                        "matched_pattern": "Adjacent numeric IDs both returned 200 with similar lengths",
                                    },
                                    parameter="id",
                                    payload_used=f"{variants[0]} | {variants[1]}",
                                    confidence=0.9,
                                    is_confirmed=True,
                                    mitre_id=self.mitre_id,
                                    owasp_category=self.owasp_category,
                                )
                            )

                if any(pattern in url.lower() for pattern in sensitive_patterns):
                    findings.append(
                        FindingData(
                            scan_id=self.scan_id,
                            endpoint_url=url,
                            endpoint_id=None,
                            vuln_type=self.vuln_type,
                            severity="medium",
                            title=f"Potential horizontal access control weakness at {url}",
                            description=(
                                "The endpoint path suggests direct user/account object access. "
                                "Manual verification with multiple identities is required to confirm IDOR exposure."
                            ),
                            evidence={
                                "request_method": endpoint.method,
                                "request_url": url,
                                "request_headers": {},
                                "request_body": None,
                                "response_code": endpoint.status_code,
                                "response_body": "",
                                "matched_pattern": "Sensitive path pattern",
                            },
                            parameter="id",
                            payload_used=None,
                            confidence=0.5,
                            is_confirmed=False,
                            mitre_id=self.mitre_id,
                            owasp_category=self.owasp_category,
                        )
                    )

                uuid_match = re.search(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", url.lower())
                if uuid_match:
                    uuid_value = uuid_match.group(0)
                    replacement = uuid_value[:-1] + ("f" if uuid_value[-1] != "f" else "e")
                    test_url = url.replace(uuid_value, replacement)
                    try:
                        response = await client.get(test_url)
                        if response.status_code == 200:
                            findings.append(
                                FindingData(
                                    scan_id=self.scan_id,
                                    endpoint_url=url,
                                    endpoint_id=None,
                                    vuln_type=self.vuln_type,
                                    severity="medium",
                                    title=f"Potential IDOR on UUID object reference at {url}",
                                    description=(
                                        "A modified UUID still returned a successful response. "
                                        "This may indicate missing object-level authorization controls."
                                    ),
                                    evidence={
                                        "request_method": "GET",
                                        "request_url": test_url,
                                        "request_headers": {},
                                        "request_body": None,
                                        "response_code": response.status_code,
                                        "response_body": (response.text or "")[:500],
                                        "matched_pattern": "Modified UUID still accessible",
                                    },
                                    parameter="id",
                                    payload_used=replacement,
                                    confidence=0.6,
                                    is_confirmed=False,
                                    mitre_id=self.mitre_id,
                                    owasp_category=self.owasp_category,
                                )
                            )
                    except Exception:
                        pass

                body_names = {str(p.get("name", "")).lower() for p in endpoint.body_params or []}
                if endpoint.method.upper() in {"POST", "PUT", "PATCH"} and body_names.intersection({"id", "user_id", "account_id", "order_id"}):
                    findings.append(
                        FindingData(
                            scan_id=self.scan_id,
                            endpoint_url=url,
                            endpoint_id=None,
                            vuln_type=self.vuln_type,
                            severity="medium",
                            title=f"Potential direct object reference in request body at {url}",
                            description=(
                                "Body parameters include direct object identifiers for a state-changing endpoint. "
                                "Manual authorization checks are recommended to validate object ownership enforcement."
                            ),
                            evidence={
                                "request_method": endpoint.method,
                                "request_url": url,
                                "request_headers": {},
                                "request_body": str(endpoint.body_params),
                                "response_code": endpoint.status_code,
                                "response_body": "",
                                "matched_pattern": "Body includes object identifier field",
                            },
                            parameter="id",
                            payload_used=None,
                            confidence=0.5,
                            is_confirmed=False,
                            mitre_id=self.mitre_id,
                            owasp_category=self.owasp_category,
                        )
                    )

        return findings
