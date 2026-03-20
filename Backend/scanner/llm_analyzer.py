import asyncio
import json
import logging
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from uuid import UUID

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import JsonOutputParser, StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from sqlalchemy import update

from config import settings
from core.database import get_db_context
from core.llm_registry import LLMRegistry
from models.finding import Finding
from models.scan import Scan
from scanner.chain_builder import ChainData
from scanner.rule_engine import FindingData

SYSTEM_PROMPT_SECURITY_ANALYST = """
You are a senior application security analyst.
Your job is to explain security vulnerabilities in plain developer language.
Be precise, technical, and concise. Avoid vague statements.
Always link vulnerabilities to real business impact.
Format your responses as valid JSON only - no markdown, no prose outside JSON.
""".strip()

FINDING_ANALYSIS_PROMPT = """
Analyze this security finding and return a JSON object.

Finding:
  Type:        {vuln_type}
  Severity:    {severity}
  URL:         {endpoint_url}
  Parameter:   {parameter}
  Payload:     {payload_used}
  Evidence:    {evidence_summary}

Return EXACTLY this JSON structure (no other text):
{{
  "llm_impact": "2-3 sentences: what an attacker could do if this is exploited. Be specific to the endpoint and parameter.",
  "fix_suggestion": "3-5 bullet points: concrete developer steps to fix this specific issue.",
  "owasp_category": "OWASP Top 10 category (e.g. A03:2021-Injection)",
  "mitre_id": "MITRE ATT&CK technique ID (e.g. T1190)",
  "cvss_score": <float between 0.0 and 10.0>,
  "developer_note": "One sentence: context or caveat a developer needs to know."
}}
""".strip()

CHAIN_ANALYSIS_PROMPT = """
Analyze this attack chain and return a JSON object.

Attack Chain:
  Entry Point:  {entry_point}
  Final Impact: {final_impact}
  Chain Length: {chain_length} hops
  Vulnerabilities involved: {vuln_types}
  Severity Score: {severity_score}/10

Return EXACTLY this JSON structure:
{{
  "narrative": "3-4 sentences: tell the story of how an attacker would chain these vulnerabilities step-by-step. Be specific.",
  "business_impact": "2-3 sentences: what business damage results from this chain (data breach, financial loss, reputation, compliance).",
  "urgency": "immediate | high | medium | low",
  "affected_users": "description of who is at risk (e.g. all authenticated users, admin only, anonymous users)",
  "remediation_priority": "Fix {vuln_type_1} first because..."
}}
""".strip()

EXECUTIVE_SUMMARY_PROMPT = """
Generate an executive summary for a security scan report.

Scan Results:
  Target:         {target_url}
  Total Findings: {total_findings}
  Critical:       {critical_count}
  High:           {high_count}
  Medium:         {medium_count}
  Low:            {low_count}
  Attack Chains:  {chain_count}
  Top Chains:     {top_chains_summary}

Return EXACTLY this JSON structure:
{{
  "headline": "One sentence: the most important security risk in plain English.",
  "summary": "3-4 sentences: overall security posture, key risks, and urgency.",
  "top_risks": ["Risk 1 in plain English", "Risk 2", "Risk 3"],
  "immediate_actions": ["Action 1 that should be done TODAY", "Action 2", "Action 3"],
  "overall_risk_rating": "critical | high | medium | low",
  "compliance_flags": ["Possible GDPR Article 32 violation", "PCI DSS 6.5.1 concern"]
}}
""".strip()


@dataclass
class LLMFallback:
    llm_impact: str = "LLM analysis unavailable."
    fix_suggestion: List[str] = None
    owasp_category: str = ""
    mitre_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "llm_impact": self.llm_impact,
            "fix_suggestion": self.fix_suggestion or [],
            "owasp_category": self.owasp_category,
            "mitre_id": self.mitre_id,
        }


class LLMAnalyzer:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.logger = logging.getLogger(__name__)
        self._llm: Optional[BaseChatModel] = None
        self._parser = JsonOutputParser()
        self._str_parser = StrOutputParser()

    def _get_llm(self) -> BaseChatModel:
        if self._llm is None:
            if not settings.llm_configured:
                raise ValueError(
                    "No LLM configured. Set LLM_PROVIDER + LLM_API_KEY "
                    "(or LLM_PROVIDER=ollama) in your .env file. "
                    "See .env.example for all supported providers."
                )
            self._llm = LLMRegistry.get_client()
        return self._llm

    async def analyze_finding(
        self,
        finding: FindingData,
        finding_db_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        evidence_summary = {
            "request_url": finding.evidence.get("request_url", ""),
            "response_code": finding.evidence.get("response_code", ""),
            "matched_pattern": str(finding.evidence.get("matched_pattern", ""))[:100],
        }

        prompt = FINDING_ANALYSIS_PROMPT.format(
            vuln_type=finding.vuln_type,
            severity=finding.severity,
            endpoint_url=finding.endpoint_url,
            parameter=finding.parameter or "N/A",
            payload_used=finding.payload_used or "N/A",
            evidence_summary=json.dumps(evidence_summary),
        )

        result = await self._invoke_with_retry(
            system=SYSTEM_PROMPT_SECURITY_ANALYST,
            human=prompt,
        )
        analysis = self._parse_json_response(result)

        if finding_db_id:
            async with get_db_context() as db:
                await db.execute(
                    update(Finding)
                    .where(Finding.id == UUID(finding_db_id))
                    .values(
                        llm_impact=analysis.get("llm_impact"),
                        fix_suggestion=json.dumps(analysis.get("fix_suggestion", [])),
                        owasp_category=analysis.get("owasp_category"),
                        mitre_id=analysis.get("mitre_id"),
                    )
                )

        return analysis

    async def analyze_chain(
        self,
        chain: ChainData,
    ) -> Dict[str, Any]:
        prompt = CHAIN_ANALYSIS_PROMPT.format(
            entry_point=chain.entry_point,
            final_impact=chain.final_impact,
            chain_length=chain.length,
            vuln_types=", ".join(chain.nodes),
            severity_score=chain.severity_score,
            vuln_type_1=chain.nodes[0] if chain.nodes else "the first vulnerable step",
        )

        result = await self._invoke_with_retry(
            system=SYSTEM_PROMPT_SECURITY_ANALYST,
            human=prompt,
        )
        analysis = self._parse_json_response(result)
        chain.llm_analysis = str(analysis.get("narrative", ""))
        return analysis

    async def generate_executive_summary(
        self,
        scan_id: str,
        findings: List[FindingData],
        chains: List[ChainData],
    ) -> Dict[str, Any]:
        counts = Counter(f.severity for f in findings)
        top_3 = sorted(chains, key=lambda c: c.severity_score, reverse=True)[:3]
        top_chains_summary = [
            f"{c.entry_point} -> {c.final_impact} (score: {c.severity_score})"
            for c in top_3
        ]

        async with get_db_context() as db:
            scan = await db.get(Scan, UUID(scan_id))
            target_url = str(scan.target_url) if scan is not None else "unknown"

        prompt = EXECUTIVE_SUMMARY_PROMPT.format(
            target_url=target_url,
            total_findings=len(findings),
            critical_count=counts.get("critical", 0),
            high_count=counts.get("high", 0),
            medium_count=counts.get("medium", 0),
            low_count=counts.get("low", 0),
            chain_count=len(chains),
            top_chains_summary=json.dumps(top_chains_summary),
        )

        result = await self._invoke_with_retry(
            system=SYSTEM_PROMPT_SECURITY_ANALYST,
            human=prompt,
        )
        return self._parse_json_response(result)

    async def run_concurrent_analysis(
        self,
        findings: List[FindingData],
        finding_db_ids: List[str],
        batch_size: int = 5,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        for i in range(0, len(findings), batch_size):
            batch = findings[i : i + batch_size]
            batch_ids = finding_db_ids[i : i + batch_size]
            tasks = [self.analyze_finding(f, fid) for f, fid in zip(batch, batch_ids)]

            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for j, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    self.logger.error(
                        "LLM analysis failed for finding %s: %s",
                        batch_ids[j],
                        result,
                    )
                    fallback = LLMFallback(
                        owasp_category=findings[i + j].owasp_category or "",
                        mitre_id=findings[i + j].mitre_id or "",
                    )
                    results.append(fallback.to_dict())
                else:
                    results.append(result)

            if i + batch_size < len(findings):
                await asyncio.sleep(1.0)

        return results

    async def _invoke_with_retry(
        self,
        system: str,
        human: str,
        max_retries: int = 3,
        base_delay: float = 2.0,
    ) -> str:
        llm = self._get_llm()

        for attempt in range(max_retries):
            try:
                prompt = ChatPromptTemplate.from_messages(
                    [
                        ("system", "{system}"),
                        ("human", "{human}"),
                    ]
                )
                messages = prompt.format_messages(system=system, human=human)
                response = await llm.ainvoke(messages)
                return self._str_parser.parse(str(response.content))
            except Exception as exc:
                error_str = str(exc).lower()
                is_rate_limit = any(
                    token in error_str
                    for token in [
                        "rate limit",
                        "rate_limit",
                        "429",
                        "too many requests",
                        "quota exceeded",
                        "context_length_exceeded",
                    ]
                )

                if "context_length_exceeded" in error_str and attempt < max_retries - 1:
                    human = human[: int(len(human) * 0.7)]
                    continue

                if is_rate_limit and attempt < max_retries - 1:
                    delay = base_delay * (2**attempt)
                    self.logger.warning(
                        "LLM rate limit hit (attempt %s). Retrying in %ss...",
                        attempt + 1,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue

                self.logger.error("LLM invocation failed: %s", exc)
                raise

        raise RuntimeError(f"LLM invocation failed after {max_retries} retries.")

    def _parse_json_response(self, raw: str) -> Dict[str, Any]:
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            cleaned = "\n".join(line for line in lines if not line.startswith("```"))
            cleaned = cleaned.strip()

        try:
            parsed = self._parser.parse(cleaned)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass

        self.logger.warning("Could not parse LLM JSON response. Raw: %s", raw[:200])
        return LLMFallback(llm_impact="Could not parse LLM response.").to_dict()
