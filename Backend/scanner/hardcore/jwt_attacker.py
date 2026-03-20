import base64
import hashlib
import hmac
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import httpx

from api.routes.websocket import publish_scan_event
from scanner.crawler import EndpointData
from scanner.rule_engine import FindingData
from tasks.scan_tasks import log_audit_entry

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


class JWTAttacker:
    WEAK_SECRETS = [
        "secret",
        "password",
        "123456",
        "jwt_secret",
        "your-256-bit-secret",
        "supersecret",
        "changeme",
        "mysecretkey",
        "secretkey",
        "token_secret",
        "asre_test",
        "",
    ]

    def __init__(self, scan_id: str, endpoints: List[EndpointData], cookies: Dict[str, str]):
        self.scan_id = scan_id
        self.endpoints = endpoints[:20]
        self.cookies = cookies or {}
        self.logger = logging.getLogger(__name__)

    async def run(self) -> List[FindingData]:
        tokens = await self._collect_jwts()
        findings: List[FindingData] = []

        for token_data in tokens:
            token = token_data["token"]
            source_url = token_data["source_url"]

            none_finding = self._check_none_algorithm(token, source_url)
            if none_finding:
                findings.append(none_finding)

            weak_secret = self._check_weak_secret(token, source_url)
            if weak_secret:
                findings.append(weak_secret)

            expiry_finding = self._check_expiry(token, source_url)
            if expiry_finding:
                findings.append(expiry_finding)

        for finding in findings:
            await publish_scan_event(
                self.scan_id,
                "scan.finding",
                {
                    "vuln_type": finding.vuln_type,
                    "severity": finding.severity,
                    "title": finding.title,
                    "url": finding.endpoint_url,
                    "source": "jwt_attacker",
                },
            )

        return findings

    async def _collect_jwts(self) -> List[Dict[str, str]]:
        found: List[Dict[str, str]] = []
        seen: set[str] = set()

        async with httpx.AsyncClient(verify=False, timeout=15, cookies=self.cookies) as client:
            for ep in self.endpoints:
                method = ep.method.upper()
                if method not in {"GET", "POST"}:
                    continue
                try:
                    if method == "POST":
                        response = await client.post(ep.url, json={})
                    else:
                        response = await client.get(ep.url)

                    await log_audit_entry(
                        scan_id=self.scan_id,
                        module="jwt_attacker",
                        request_method=method,
                        request_url=ep.url,
                        response_code=response.status_code,
                        notes="JWT collection probe",
                    )

                    candidates: List[str] = []
                    candidates.extend(JWT_PATTERN.findall(response.text))

                    auth_header = response.headers.get("Authorization", "")
                    candidates.extend(JWT_PATTERN.findall(auth_header))

                    for set_cookie in response.headers.get_list("set-cookie"):
                        candidates.extend(JWT_PATTERN.findall(set_cookie))

                    for token in candidates:
                        if token in seen:
                            continue
                        seen.add(token)
                        found.append({"token": token, "source_url": ep.url, "location": "response"})
                except Exception as exc:
                    await log_audit_entry(
                        scan_id=self.scan_id,
                        module="jwt_attacker",
                        request_method=method,
                        request_url=ep.url,
                        response_code=None,
                        notes=f"JWT collection error: {exc}",
                    )
        return found

    @staticmethod
    def _b64url_decode(segment: str) -> bytes:
        padding = "=" * ((4 - len(segment) % 4) % 4)
        return base64.urlsafe_b64decode(segment + padding)

    @staticmethod
    def _b64url_encode(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    def _decode_header_payload(self, token: str) -> Optional[tuple[dict, dict, List[str]]]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            header = json.loads(self._b64url_decode(parts[0]).decode("utf-8", errors="ignore"))
            payload = json.loads(self._b64url_decode(parts[1]).decode("utf-8", errors="ignore"))
            return header, payload, parts
        except Exception:
            return None

    def _check_none_algorithm(self, token: str, source_url: str) -> Optional[FindingData]:
        decoded = self._decode_header_payload(token)
        if not decoded:
            return None

        header, _, parts = decoded
        alg = str(header.get("alg", "")).lower()
        none_header = self._b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8"))
        forged = f"{none_header}.{parts[1]}."

        if alg == "none" or alg in {"hs256", "rs256"}:
            confirmed = alg == "none"
            return FindingData(
                scan_id=self.scan_id,
                endpoint_url=source_url,
                endpoint_id=None,
                vuln_type="jwt",
                severity="critical" if confirmed else "high",
                title="JWT none-algorithm vulnerability",
                description=(
                    "A JWT token was found using alg:none or appears susceptible to none-algorithm abuse. "
                    "Attackers may forge unsigned tokens if verification is weak."
                ),
                evidence={
                    "original_alg": alg,
                    "token_source": source_url,
                    "forged_example": forged[:100] + "...",
                },
                parameter=None,
                payload_used="alg:none",
                confidence=1.0 if confirmed else 0.7,
                is_confirmed=confirmed,
                mitre_id="T1550.001",
                owasp_category="A02:2021-Cryptographic Failures",
            )

        return None

    def _check_weak_secret(self, token: str, source_url: str) -> Optional[FindingData]:
        decoded = self._decode_header_payload(token)
        if not decoded:
            return None

        header, _, parts = decoded
        alg = str(header.get("alg", "")).upper()
        if alg != "HS256":
            return None

        signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
        signature = parts[2]

        for secret in self.WEAK_SECRETS:
            digest = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
            candidate_sig = self._b64url_encode(digest)
            if hmac.compare_digest(candidate_sig, signature):
                masked = secret[:2] + "*" * max(0, len(secret) - 2)
                return FindingData(
                    scan_id=self.scan_id,
                    endpoint_url=source_url,
                    endpoint_id=None,
                    vuln_type="jwt",
                    severity="critical",
                    title="JWT signed with weak/guessable secret",
                    description=(
                        "The JWT secret appears in a common weak-secret list, allowing token forgery."
                    ),
                    evidence={
                        "weak_secret_found": True,
                        "secret_hint": masked,
                        "token_source": source_url,
                    },
                    parameter=None,
                    payload_used="weak-secret-check",
                    confidence=1.0,
                    is_confirmed=True,
                    mitre_id="T1550.001",
                    owasp_category="A02:2021-Cryptographic Failures",
                )
        return None

    def _check_expiry(self, token: str, source_url: str) -> Optional[FindingData]:
        decoded = self._decode_header_payload(token)
        if not decoded:
            return None

        _, payload, _ = decoded
        exp = payload.get("exp")
        now = int(datetime.now(timezone.utc).timestamp())

        if exp is None:
            return FindingData(
                scan_id=self.scan_id,
                endpoint_url=source_url,
                endpoint_id=None,
                vuln_type="jwt",
                severity="high",
                title="JWT token has no expiration claim",
                description="A non-expiring JWT increases replay window and token abuse risk.",
                evidence={"token_source": source_url, "exp_present": False},
                parameter="exp",
                payload_used="no-exp-claim",
                confidence=0.9,
                is_confirmed=True,
                mitre_id="T1550.001",
                owasp_category="A07:2021-Identification and Authentication Failures",
            )

        try:
            exp_value = int(exp)
        except Exception:
            return None

        if exp_value > now + 365 * 24 * 3600:
            return FindingData(
                scan_id=self.scan_id,
                endpoint_url=source_url,
                endpoint_id=None,
                vuln_type="jwt",
                severity="medium",
                title="JWT token expiration is excessively long",
                description="JWT expiration exceeds one year, increasing risk from stolen token replay.",
                evidence={"token_source": source_url, "exp": exp_value},
                parameter="exp",
                payload_used="far-future-exp",
                confidence=0.8,
                is_confirmed=False,
                mitre_id="T1550.001",
                owasp_category="A07:2021-Identification and Authentication Failures",
            )

        return None
