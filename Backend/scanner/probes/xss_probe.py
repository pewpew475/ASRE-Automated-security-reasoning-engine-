import re
from typing import List, TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from scanner.crawler import EndpointData

if TYPE_CHECKING:
    from scanner.rule_engine import FindingData


class XSSProbe:
    vuln_type = "xss"
    owasp_category = "A03:2021-Injection"
    mitre_id = "T1059.007"

    SAFE_PAYLOADS = [
        "<img src=x onerror=console.log('ASRE-XSS')>",
        "<svg/onload=console.log('ASRE-XSS')>",
        "javascript:console.log('ASRE-XSS')",
        "\"><img src=x onerror=console.log('ASRE-XSS')>",
        "';console.log('ASRE-XSS')//",
        "<script>console.log('ASRE-XSS')</script>",
        "{{7*7}}",
        "${7*7}",
    ]
    DETECTION_MARKER = "ASRE-XSS"

    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    async def run(self, endpoints: List[EndpointData], rules: dict) -> List["FindingData"]:
        from scanner.rule_engine import RuleEngine

        findings: List["FindingData"] = []
        payloads = rules.get("payloads", self.SAFE_PAYLOADS)
        dom_sinks = rules.get("dom_sinks", ["document.write(", "innerHTML =", "eval(", "setTimeout(", "location.hash", "location.search"])

        async with RuleEngine._build_httpx_client() as client:
            for endpoint in endpoints:
                method = endpoint.method.upper()
                if endpoint.url.lower().endswith((".css", ".js", ".png", ".jpg", ".gif", ".ico")):
                    continue

                params = [str(p.get("name")) for p in (endpoint.params or []) if p.get("name")]
                body_params = [str(p.get("name")) for p in (endpoint.body_params or []) if p.get("name")]
                if not params and not body_params:
                    if any(sink in ("" if endpoint.content_type is None else endpoint.content_type) for sink in []):
                        pass
                    continue

                for param_name in params + body_params:
                    for payload in payloads:
                        req_url = endpoint.url
                        req_body = None

                        if param_name in params:
                            req_url = self._inject_query(req_url, param_name, payload)
                        else:
                            req_body = {param_name: payload}

                        try:
                            if method == "POST":
                                response = await client.post(req_url, data=req_body or {})
                            else:
                                response = await client.get(req_url)
                        except Exception:
                            continue

                        body = response.text or ""
                        reflected = self.DETECTION_MARKER in body
                        unencoded = payload in body and "&lt;" not in body
                        if reflected or unencoded:
                            findings.append(
                                self._finding(
                                    endpoint=endpoint,
                                    parameter=param_name,
                                    payload=payload,
                                    matched_pattern=payload if payload in body else self.DETECTION_MARKER,
                                    response_code=response.status_code,
                                    response_body=body[:500],
                                    request_url=req_url,
                                )
                            )
                            break

                    if method == "GET":
                        try:
                            baseline = await client.get(endpoint.url)
                        except Exception:
                            continue
                        lower_html = baseline.text.lower()
                        if any(sink.lower() in lower_html for sink in dom_sinks):
                            findings.append(
                                self._finding(
                                    endpoint=endpoint,
                                    parameter=param_name,
                                    payload=None,
                                    matched_pattern="Potential DOM XSS sink detected",
                                    response_code=baseline.status_code,
                                    response_body=baseline.text[:500],
                                    request_url=endpoint.url,
                                    severity="info",
                                    title="Potential DOM XSS sink detected",
                                    confirmed=False,
                                    confidence=0.5,
                                )
                            )

        return findings

    def _inject_query(self, url: str, name: str, value: str) -> str:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        params[name] = value
        query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=query))

    def _finding(
        self,
        endpoint: EndpointData,
        parameter: str,
        payload: str | None,
        matched_pattern: str,
        response_code: int,
        response_body: str,
        request_url: str,
        severity: str = "high",
        title: str | None = None,
        confirmed: bool = True,
        confidence: float = 0.9,
    ):
        from scanner.rule_engine import FindingData

        return FindingData(
            scan_id=self.scan_id,
            endpoint_url=endpoint.url,
            endpoint_id=None,
            vuln_type=self.vuln_type,
            severity=severity,
            title=title or f"Reflected XSS in {parameter} at {endpoint.url}",
            description=(
                "User-controlled input appears to be reflected in the response without robust encoding. "
                "This may enable script execution in a victim browser under certain conditions. "
                "Validate and contextually encode all untrusted data before rendering."
            ),
            evidence={
                "request_method": endpoint.method.upper(),
                "request_url": request_url,
                "request_headers": {},
                "request_body": None,
                "response_code": response_code,
                "response_body": response_body[:500],
                "matched_pattern": matched_pattern,
            },
            parameter=parameter,
            payload_used=payload,
            confidence=confidence,
            is_confirmed=confirmed,
            mitre_id=self.mitre_id,
            owasp_category=self.owasp_category,
        )
