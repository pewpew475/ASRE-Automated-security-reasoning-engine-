import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse
from uuid import UUID

from sqlalchemy import update

from config import settings
from core.database import get_db_context
from models.finding import Finding
from scanner.rule_engine import FindingData


@dataclass
class PoCResult:
    finding_id: str
    vuln_type: str
    poc_curl: str
    poc_fetch: str
    poc_notes: str
    severity: str
    safe: bool = True


class PoCGenerator:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.logger = logging.getLogger(__name__)

    async def generate(
        self,
        finding: FindingData,
        finding_db_id: Optional[str] = None,
    ) -> PoCResult:
        dispatch_map = {
            "xss": self._poc_xss,
            "idor": self._poc_idor,
            "csrf": self._poc_csrf,
            "sqli": self._poc_sqli,
            "auth": self._poc_auth,
            "cors": self._poc_cors,
            "header": self._poc_header,
            "business_logic": self._poc_business_logic,
            "rate_limit": self._poc_rate_limit,
            "user_enum": self._poc_user_enum,
            "jwt": self._poc_jwt,
            "cve": self._poc_cve,
        }

        try:
            builder = dispatch_map.get(finding.vuln_type, self._poc_generic)
            poc_curl, poc_fetch, poc_notes = await builder(finding)
        except Exception as exc:
            self.logger.error("PoC build failed for %s: %s", finding.vuln_type, exc)
            poc_curl, poc_fetch, poc_notes = await self._poc_generic(finding)

        result = PoCResult(
            finding_id=finding_db_id or "",
            vuln_type=finding.vuln_type,
            poc_curl=poc_curl,
            poc_fetch=poc_fetch,
            poc_notes=poc_notes,
            severity=finding.severity,
        )

        if finding_db_id:
            await self._save_to_db(finding_db_id, poc_curl)

        return result

    async def _save_to_db(self, finding_db_id: str, poc_curl: str) -> None:
        async with get_db_context() as db:
            await db.execute(
                update(Finding)
                .where(Finding.id == UUID(finding_db_id))
                .values(poc_curl=poc_curl)
            )

    async def _poc_xss(self, finding: FindingData) -> Tuple[str, str, str]:
        url = str(finding.evidence.get("request_url", finding.endpoint_url))
        method = str(finding.evidence.get("request_method", "GET")).upper()
        param = finding.parameter or "input"
        payload = finding.payload_used or "<img src=x onerror=console.log('ASRE-XSS')>"
        encoded_payload = quote(payload, safe="")

        if method == "POST":
            poc_curl = (
                "# XSS PoC - POST form injection\n"
                f"curl -sk -X POST \"{url}\" \\\n"
                "  -H \"Content-Type: application/x-www-form-urlencoded\" \\\n"
                f"  -H \"User-Agent: {getattr(settings, 'APP_NAME', 'ASRE-Scanner')}/1.0\" \\\n"
                f"  --data-urlencode \"{param}={payload}\" \\\n"
                "  | grep -o \"ASRE-XSS\" \\\n"
                "  && echo \"VULNERABLE\" || echo \"NOT VULNERABLE\""
            )
            poc_fetch = (
                "// XSS PoC - POST injection\n"
                "const body = new URLSearchParams();\n"
                f"body.append(\"{param}\", `{payload}`);\n"
                f"fetch(\"{url}\", {{\n"
                "  method: \"POST\",\n"
                "  body: body,\n"
                "  headers: {\"Content-Type\": \"application/x-www-form-urlencoded\"}\n"
                "})\n"
                "  .then(r => r.text())\n"
                "  .then(html => console.log(html.includes(\"ASRE-XSS\") ? \"VULNERABLE\" : \"Not reflected\"));"
            )
        else:
            poc_curl = (
                "# XSS PoC - check if ASRE-XSS appears unencoded in response\n"
                f"curl -sk \"{url}?{param}={encoded_payload}\" \\\n"
                "  -H \"User-Agent: ASRE-Scanner/1.0\" \\\n"
                "  | grep -o \"ASRE-XSS\" \\\n"
                "  && echo \"VULNERABLE: payload reflected unencoded\" \\\n"
                "  || echo \"NOT VULNERABLE or encoded\""
            )
            poc_fetch = (
                "// XSS PoC - run in browser console on same origin\n"
                f"const url = `{url}?{param}={encoded_payload}`;\n"
                "fetch(url)\n"
                "  .then(r => r.text())\n"
                "  .then(html => {\n"
                "    if (html.includes(\"ASRE-XSS\")) {\n"
                "      console.warn(\"VULNERABLE: XSS payload reflected in response\");\n"
                "    } else {\n"
                "      console.log(\"Not reflected or encoded\");\n"
                "    }\n"
                "  });"
            )

        poc_notes = (
            "Look for the literal string \"ASRE-XSS\" unencoded in the response. "
            "If it appears as &lt;img...&gt; (HTML-encoded), output is safe. "
            f"If it appears as <img...>, the parameter {param} is vulnerable to XSS."
        )
        return poc_curl, poc_fetch, poc_notes

    def _modified_idor_url(self, url: str) -> str:
        parsed = urlparse(url)
        path_parts = parsed.path.strip("/").split("/") if parsed.path else []
        modified = False

        for i in range(len(path_parts) - 1, -1, -1):
            segment = path_parts[i]
            if segment.isdigit():
                value = int(segment)
                path_parts[i] = str(value + 1)
                modified = True
                break
            if len(segment) >= 8 and "-" in segment:
                path_parts[i] = segment[:-1] + ("0" if segment[-1] != "0" else "1")
                modified = True
                break

        query = parse_qs(parsed.query)
        if not modified:
            for key, values in query.items():
                if not values:
                    continue
                current = values[0]
                if current.isdigit():
                    query[key] = [str(int(current) + 1)]
                    modified = True
                    break

        if not modified and path_parts:
            path_parts[-1] = path_parts[-1] + "-alt"

        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                "/" + "/".join(path_parts),
                parsed.params,
                urlencode(query, doseq=True),
                parsed.fragment,
            )
        )

    async def _poc_idor(self, finding: FindingData) -> Tuple[str, str, str]:
        url = finding.endpoint_url
        modified_url = self._modified_idor_url(url)
        poc_curl = (
            "# IDOR PoC - request a different user/resource ID\n"
            "# Step 1: Get YOUR resource (should return 200)\n"
            f"curl -sk \"{url}\" \\\n"
            "  -H \"Authorization: Bearer YOUR_JWT_TOKEN\" \\\n"
            "  -H \"Cookie: YOUR_SESSION_COOKIE\"\n\n"
            "# Step 2: Get ANOTHER user's resource (should return 403, but if 200 -> IDOR confirmed)\n"
            f"curl -sk \"{modified_url}\" \\\n"
            "  -H \"Authorization: Bearer YOUR_JWT_TOKEN\" \\\n"
            "  -H \"Cookie: YOUR_SESSION_COOKIE\""
        )
        poc_fetch = (
            "// IDOR PoC - run from authenticated browser session\n"
            "// Step 1: Your own resource\n"
            f"const yours = await fetch(\"{url}\", {{ credentials: \"include\" }});\n"
            "console.log(\"Your resource:\", yours.status);\n\n"
            "// Step 2: Another user's resource (should be 403)\n"
            f"const other = await fetch(\"{modified_url}\", {{ credentials: \"include\" }});\n"
            "console.log(\"Other resource:\", other.status);\n"
            "if (other.status === 200) console.warn(\"IDOR CONFIRMED\");"
        )
        poc_notes = (
            "Replace YOUR_JWT_TOKEN and YOUR_SESSION_COOKIE with valid credentials. "
            "If Step 2 returns HTTP 200, IDOR is confirmed and access control is broken."
        )
        return poc_curl, poc_fetch, poc_notes

    async def _poc_csrf(self, finding: FindingData) -> Tuple[str, str, str]:
        url = finding.endpoint_url
        body_params = finding.evidence.get("body_params", [])
        fields = []
        if isinstance(body_params, list):
            for p in body_params:
                if isinstance(p, dict) and p.get("name"):
                    fields.append(f'  <input type="hidden" name="{p["name"]}" value="ASRE-TEST">')
        form_fields = "\n".join(fields) or '  <input type="hidden" name="test_field" value="ASRE-TEST">'

        poc_curl = (
            "# CSRF PoC - send cross-origin POST without CSRF token\n"
            "# If this succeeds (200/302 not 403), CSRF protection is absent\n"
            f"curl -sk -X POST \"{url}\" \\\n"
            "  -H \"Origin: https://evil-attacker.com\" \\\n"
            "  -H \"Referer: https://evil-attacker.com/attack.html\" \\\n"
            "  -H \"Content-Type: application/x-www-form-urlencoded\" \\\n"
            "  --data \"test_field=ASRE-TEST\"\n\n"
            "# A 200 or 302 response = CSRF protection absent\n"
            "# A 403 with CSRF error = protected"
        )
        poc_fetch = (
            "<!-- Save as csrf_poc.html and open in a browser with an active session -->\n"
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<body>\n"
            "  <h1>CSRF PoC - ASRE Scanner</h1>\n"
            f"  <form id=\"csrf-form\" action=\"{url}\" method=\"POST\">\n"
            f"{form_fields}\n"
            "  </form>\n"
            "  <script>document.getElementById('csrf-form').submit();</script>\n"
            "</body>\n"
            "</html>"
        )
        poc_notes = (
            "Open csrf_poc.html in a browser where you are logged in to the target app. "
            "If the action succeeds without a CSRF token, CSRF is confirmed."
        )
        return poc_curl, poc_fetch, poc_notes

    async def _poc_sqli(self, finding: FindingData) -> Tuple[str, str, str]:
        url = finding.endpoint_url
        param = finding.parameter or "id"
        payload = finding.payload_used or "'"
        safe_payload = quote(payload)

        poc_curl = (
            "# SQLi Indicator PoC - safe boolean/error detection only\n"
            "# This does NOT extract data.\n\n"
            "# Request A - normal response\n"
            f"curl -sk \"{url}?{param}=1\" -o /tmp/sqli_normal.txt\n\n"
            "# Request B - single quote payload\n"
            f"curl -sk \"{url}?{param}={safe_payload}\" -o /tmp/sqli_payload.txt\n\n"
            "# Compare responses\n"
            "diff /tmp/sqli_normal.txt /tmp/sqli_payload.txt\n"
            "grep -Ei \"sql|syntax|ORA-|mysql|SQLSTATE\" /tmp/sqli_payload.txt\n"
            "echo \"If SQL keywords appear, SQLi indicator confirmed\""
        )
        poc_fetch = (
            "// SQLi indicator PoC - safe comparison\n"
            f"const normal = await fetch(\"{url}?{param}=1\");\n"
            f"const payload = await fetch(\"{url}?{param}={safe_payload}\");\n"
            "const [normalText, payloadText] = await Promise.all([normal.text(), payload.text()]);\n"
            "const keywords = [\"SQL syntax\", \"ORA-\", \"mysql_fetch\", \"SQLSTATE\", \"syntax error\"];\n"
            "const hasError = keywords.some(k => payloadText.includes(k));\n"
            "console.log(hasError ? \"SQLi INDICATOR detected\" : \"No obvious indicator\");\n"
            "console.log(\"Status diff:\", normal.status, \"vs\", payload.status);"
        )
        poc_notes = (
            "This PoC only checks safe SQLi indicators and does not extract or modify data. "
            "If SQL engine errors appear, validate with Hardcore mode tooling in approved scope."
        )
        return poc_curl, poc_fetch, poc_notes

    async def _poc_auth(self, finding: FindingData) -> Tuple[str, str, str]:
        url = finding.endpoint_url
        poc_curl = (
            "# Broken Auth PoC - protected endpoint without credentials\n"
            "# Expected: 401/403. If 200 -> broken auth.\n\n"
            "# Without auth:\n"
            f"curl -sk \"{url}\" -w \"\\nHTTP Status: %{{http_code}}\\n\"\n\n"
            "# With fake token:\n"
            f"curl -sk \"{url}\" -H \"Authorization: Bearer fake.token.here\" -w \"\\nHTTP Status: %{{http_code}}\\n\""
        )
        poc_fetch = (
            "// Broken Auth PoC\n"
            f"const noAuth = await fetch(\"{url}\");\n"
            "console.log(\"No auth status:\", noAuth.status);\n"
            f"const fake = await fetch(\"{url}\", {{ headers: {{ Authorization: \"Bearer fake.token.here\" }} }});\n"
            "console.log(\"Fake token status:\", fake.status);\n"
            "if (noAuth.status === 200 || fake.status === 200) console.warn(\"BROKEN AUTH\");"
        )
        poc_notes = "Any 200 response without valid credentials confirms broken authentication."
        return poc_curl, poc_fetch, poc_notes

    async def _poc_cors(self, finding: FindingData) -> Tuple[str, str, str]:
        url = finding.endpoint_url
        poc_curl = (
            "# CORS PoC - test origin reflection\n"
            f"curl -sk \"{url}\" -H \"Origin: https://evil-attacker.com\" -I | grep -i \"access-control\"\n\n"
            "# Also test null origin\n"
            f"curl -sk \"{url}\" -H \"Origin: null\" -I | grep -i \"access-control\""
        )
        poc_fetch = (
            "// CORS PoC\n"
            "try {\n"
            f"  const response = await fetch(\"{url}\", {{ credentials: \"include\" }});\n"
            "  console.warn(\"If this succeeds from attacker origin, CORS is vulnerable\");\n"
            "  console.log(await response.text());\n"
            "} catch (e) {\n"
            "  console.log(\"CORS blocked by browser:\", e.message);\n"
            "}"
        )
        poc_notes = (
            "If Access-Control-Allow-Origin reflects attacker origin and credentials are allowed, "
            "cross-origin data theft is possible."
        )
        return poc_curl, poc_fetch, poc_notes

    async def _poc_header(self, finding: FindingData) -> Tuple[str, str, str]:
        url = finding.endpoint_url
        header_name = finding.parameter or "X-Frame-Options"
        poc_curl = (
            "# Missing Security Header PoC\n"
            f"curl -sk \"{url}\" -I | grep -i \"{header_name.lower()}\" \\\n"
            "  && echo \"Header present (OK)\" || echo \"MISSING\""
        )
        poc_fetch = (
            "// Missing Header PoC\n"
            f"const response = await fetch(\"{url}\");\n"
            f"const v = response.headers.get(\"{header_name}\");\n"
            f"if (!v) console.warn(\"MISSING: {header_name}\"); else console.log(v);"
        )
        poc_notes = "Confirm the missing header and add it in server or middleware configuration."
        return poc_curl, poc_fetch, poc_notes

    async def _poc_business_logic(self, finding: FindingData) -> Tuple[str, str, str]:
        url = finding.endpoint_url
        param = finding.parameter or "amount"
        poc_curl = (
            "# Business Logic PoC - parameter tampering\n"
            f"curl -sk -X POST \"{url}\" \\\n"
            "  -H \"Content-Type: application/json\" \\\n"
            "  -H \"Authorization: Bearer YOUR_JWT_TOKEN\" \\\n"
            f"  -d '{{\"{param}\": -1}}' \\\n"
            "  -w \"\\nHTTP Status: %{http_code}\\n\""
        )
        poc_fetch = (
            "// Business Logic PoC\n"
            f"const r = await fetch(\"{url}\", {{\n"
            "  method: \"POST\",\n"
            "  credentials: \"include\",\n"
            "  headers: { \"Content-Type\": \"application/json\" },\n"
            f"  body: JSON.stringify({{ \"{param}\": -1 }})\n"
            "});\n"
            "console.log(r.status, await r.text());\n"
            "if (r.status === 200) console.warn(\"BUSINESS LOGIC FLAW: negative accepted\");"
        )
        poc_notes = f"If {param} accepts <= 0 with success status, server-side business validation is weak."
        return poc_curl, poc_fetch, poc_notes

    async def _poc_rate_limit(self, finding: FindingData) -> Tuple[str, str, str]:
        url = finding.endpoint_url
        poc_curl = (
            "# Rate Limit PoC - burst 10 rapid requests\n"
            "for i in $(seq 1 10); do\n"
            f"  curl -sk -o /dev/null -w \"$i -> %{{http_code}}\\n\" \"{url}\";\n"
            "done"
        )
        poc_fetch = (
            "// Rate Limit PoC\n"
            f"const url = \"{url}\";\n"
            "const reqs = Array.from({ length: 10 }, () => fetch(url));\n"
            "const results = await Promise.all(reqs);\n"
            "console.table(results.map((r, i) => ({ i: i + 1, status: r.status })));"
        )
        poc_notes = "Expected behavior is throttling (429) after burst; all 200 responses indicate weak rate limiting."
        return poc_curl, poc_fetch, poc_notes

    async def _poc_user_enum(self, finding: FindingData) -> Tuple[str, str, str]:
        url = str(finding.evidence.get("request_url", finding.endpoint_url))
        poc_curl = (
            "# User Enumeration PoC\n"
            "# Compare known vs unknown account responses\n"
            f"curl -sk -X POST \"{url}\" -H \"Content-Type: application/json\" -d '{{\"email\":\"known@example.com\",\"password\":\"bad\"}}' -w \"\\nStatus=%{{http_code}} Time=%{{time_total}}\\n\"\n"
            f"curl -sk -X POST \"{url}\" -H \"Content-Type: application/json\" -d '{{\"email\":\"unknown@example.com\",\"password\":\"bad\"}}' -w \"\\nStatus=%{{http_code}} Time=%{{time_total}}\\n\""
        )
        poc_fetch = (
            "// User Enumeration PoC\n"
            "const attempt = async (email) => {\n"
            "  const t0 = performance.now();\n"
            f"  const r = await fetch(\"{url}\", {{ method: \"POST\", headers: {{\"Content-Type\":\"application/json\"}}, body: JSON.stringify({{ email, password: \"bad\" }}) }});\n"
            "  return { email, status: r.status, ms: performance.now() - t0, body: await r.text() };\n"
            "};\n"
            "console.log(await attempt(\"known@example.com\"));\n"
            "console.log(await attempt(\"unknown@example.com\"));"
        )
        poc_notes = "Different response content, status, or timing for known vs unknown accounts indicates enumeration risk."
        return poc_curl, poc_fetch, poc_notes

    async def _poc_jwt(self, finding: FindingData) -> Tuple[str, str, str]:
        token = str(finding.evidence.get("jwt_sample", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature"))
        poc_curl = (
            "# JWT analysis PoC - passive only, no token forgery\n"
            f"TOKEN=\"{token}\"\n"
            "HEADER=$(echo $TOKEN | cut -d'.' -f1 | tr '_-' '/+' | base64 -d 2>/dev/null || true)\n"
            "echo \"Decoded header: $HEADER\"\n"
            "echo \"If alg is none or weak alg accepted, JWT validation is vulnerable\""
        )
        poc_fetch = (
            "// JWT analysis PoC - passive decode only\n"
            f"const token = \"{token}\";\n"
            "const headerB64 = token.split('.')[0].replace(/-/g, '+').replace(/_/g, '/');\n"
            "const header = JSON.parse(atob(headerB64));\n"
            "console.log('JWT header:', header);\n"
            "if ((header.alg || '').toLowerCase() === 'none') console.warn('Potential JWT none-alg acceptance risk');"
        )
        poc_notes = "This PoC only inspects token metadata. It does not forge or replay tokens."
        return poc_curl, poc_fetch, poc_notes

    async def _poc_cve(self, finding: FindingData) -> Tuple[str, str, str]:
        evidence = finding.evidence or {}
        template_id = str(evidence.get("template_id", "unknown-template"))
        cve = str(evidence.get("cve", finding.mitre_id or "CVE-UNKNOWN"))
        replay = str(evidence.get("curl", f'curl -sk "{finding.endpoint_url}" -I'))
        poc_curl = (
            "# CVE PoC - replay the matching probe\n"
            f"# Template: {template_id}\n"
            f"# CVE: {cve}\n"
            f"{replay}"
        )
        poc_fetch = (
            "// CVE PoC notes\n"
            f"console.log('Matched template: {template_id}');\n"
            f"console.log('Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}');"
        )
        poc_notes = "Re-run the same non-destructive probe and confirm the service version matches the vulnerable range."
        return poc_curl, poc_fetch, poc_notes

    async def _poc_generic(self, finding: FindingData) -> Tuple[str, str, str]:
        method = str(finding.evidence.get("request_method", "GET")).upper()
        request_url = str(finding.evidence.get("request_url", finding.endpoint_url))
        headers = finding.evidence.get("request_headers", {})
        if not isinstance(headers, dict):
            headers = {}

        header_flags = " \\\n".join([f'  -H "{k}: {v}"' for k, v in headers.items()][:6])
        body = finding.evidence.get("request_body")
        body_line = f'  --data \'{body}\'' if body else ""

        poc_curl = (
            f"# Generic PoC replay ({finding.vuln_type})\n"
            f"curl -sk -X {method} \"{request_url}\""
        )
        if header_flags:
            poc_curl += " \\\n" + header_flags
        if body_line:
            poc_curl += " \\\n" + body_line

        poc_fetch = (
            "// Generic PoC fetch replay\n"
            f"fetch(\"{request_url}\", {{\n"
            f"  method: \"{method}\",\n"
            f"  headers: {json.dumps(headers)},\n"
            f"  body: {json.dumps(str(body) if body else '')} || undefined\n"
            "}).then(r => r.text()).then(console.log);"
        )
        poc_notes = "Generic safe replay PoC generated from captured request evidence."
        return poc_curl, poc_fetch, poc_notes

    async def generate_all(
        self,
        findings: List[FindingData],
        finding_db_ids: List[str],
    ) -> List[PoCResult]:
        results: List[PoCResult] = []
        batch_size = 10

        for i in range(0, len(findings), batch_size):
            batch = findings[i : i + batch_size]
            batch_ids = finding_db_ids[i : i + batch_size]
            tasks = [self.generate(f, fid if idx < len(batch_ids) else None) for idx, (f, fid) in enumerate(zip(batch, batch_ids))]

            if len(batch_ids) < len(batch):
                for f in batch[len(batch_ids) :]:
                    tasks.append(self.generate(f, None))

            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for j, item in enumerate(batch_results):
                if isinstance(item, Exception):
                    self.logger.error("PoC generation failed for finding index %s: %s", i + j, item)
                    fallback = PoCResult(
                        finding_id=batch_ids[j] if j < len(batch_ids) else "",
                        vuln_type=batch[j].vuln_type if j < len(batch) else "unknown",
                        poc_curl="# PoC unavailable due to generator error",
                        poc_fetch="// PoC unavailable due to generator error",
                        poc_notes="PoC generation failed; review scanner logs for details.",
                        severity=batch[j].severity if j < len(batch) else "info",
                        safe=True,
                    )
                    results.append(fallback)
                else:
                    if isinstance(item, PoCResult):
                        results.append(item)
                    else:
                        fallback = PoCResult(
                            finding_id=batch_ids[j] if j < len(batch_ids) else "",
                            vuln_type=batch[j].vuln_type if j < len(batch) else "unknown",
                            poc_curl="# PoC unavailable due to generator error",
                            poc_fetch="// PoC unavailable due to generator error",
                            poc_notes="PoC generation returned invalid result type.",
                            severity=batch[j].severity if j < len(batch) else "info",
                            safe=True,
                        )
                        results.append(fallback)

        return results
