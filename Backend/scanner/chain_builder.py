import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from uuid import UUID, uuid4

from sqlalchemy import select, update

from api.routes.websocket import publish_scan_event
from core.database import get_db_context
from core.neo4j_client import neo4j_client
from models.finding import Endpoint, Finding
from models.scan import Scan
from scanner.crawler import EndpointData
from scanner.rule_engine import FindingData


@dataclass
class GraphNode:
    node_id: str
    node_type: str
    label: str
    data: Dict
    severity: Optional[str] = None
    color: str = "#6B7280"


@dataclass
class GraphEdge:
    edge_id: str
    source: str
    target: str
    label: str
    data: Dict = field(default_factory=dict)


@dataclass
class ChainData:
    path_id: str
    nodes: List[str]
    entry_point: str
    final_impact: str
    severity_score: float
    length: int
    llm_analysis: Optional[str] = None


@dataclass
class GraphData:
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    chains: List[ChainData]


NODE_COLORS = {
    "Endpoint": "#3B82F6",
    "Vulnerability": "#F97316",
    "Asset": "#22C55E",
    "Impact": "#EF4444",
    "ScanSession": "#8B5CF6",
}

SEVERITY_COLORS = {
    "critical": "#7F1D1D",
    "high": "#EF4444",
    "medium": "#F97316",
    "low": "#EAB308",
    "info": "#6B7280",
}

VULN_TO_ASSET = {
    "xss": "UserSession",
    "idor": "UserData",
    "csrf": "UserAccount",
    "sqli": "DatabaseAccess",
    "auth": "AdminPanel",
    "cors": "APICredentials",
    "header": "BrowserSecurity",
    "business_logic": "ApplicationLogic",
    "rate_limit": "ApplicationAvailability",
    "user_enum": "UserAccountList",
    "jwt": "AuthenticationToken",
    "session": "UserSession",
    "cve": "SystemAccess",
}

ASSET_TO_IMPACT = {
    "UserSession": "Account Takeover",
    "UserData": "Data Breach",
    "UserAccount": "Unauthorized Action",
    "DatabaseAccess": "Full Database Compromise",
    "AdminPanel": "Privilege Escalation",
    "APICredentials": "API Abuse",
    "BrowserSecurity": "Malware Distribution",
    "ApplicationLogic": "Financial Fraud",
    "ApplicationAvailability": "Denial of Service",
    "UserAccountList": "Mass Account Enumeration",
    "AuthenticationToken": "Session Hijacking",
    "SystemAccess": "Remote Code Execution",
}


class ChainBuilder:
    def __init__(self, scan_id: str, endpoints: List[EndpointData], findings: List[FindingData]):
        self.scan_id = scan_id
        self.endpoints = endpoints
        self.findings = findings
        self.logger = logging.getLogger(__name__)

        self._endpoint_rows: List[Dict] = []
        self._finding_rows: List[Dict] = []

    async def build(self) -> List[ChainData]:
        await self._create_scan_session_node()
        await self._ingest_endpoints()
        await self._ingest_findings()
        await self._connect_scan_to_endpoints()
        await self._connect_endpoints_to_vulns()
        await self._create_asset_nodes()
        await self._create_impact_nodes()
        await self._build_lateral_chains()

        chains = await self._query_attack_chains()

        async with get_db_context() as db:
            await db.execute(
                update(Scan)
                .where(Scan.id == UUID(self.scan_id))
                .values(chains_found=len(chains))
            )

        self.logger.info(
            "Chain builder: %s attack chains built for scan %s",
            len(chains),
            self.scan_id,
        )
        return chains

    async def _create_scan_session_node(self) -> None:
        await neo4j_client.execute_write(
            """
            MERGE (s:ScanSession {scan_id: $scan_id})
            SET s.created_at = $created_at,
                s.scan_id = $scan_id
            """,
            {
                "scan_id": self.scan_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    async def _ingest_endpoints(self) -> None:
        rows = []
        for index, endpoint in enumerate(self.endpoints):
            rows.append(
                {
                    "endpoint_id": f"ep_{self.scan_id}_{index}",
                    "url": endpoint.url,
                    "method": endpoint.method.upper(),
                    "auth_required": bool(endpoint.auth_required),
                    "scan_id": self.scan_id,
                    "status_code": endpoint.status_code,
                }
            )
        self._endpoint_rows = rows

        if not rows:
            return

        await neo4j_client.execute_write(
            """
            UNWIND $rows AS row
            MERGE (e:Endpoint {endpoint_id: row.endpoint_id})
            SET e.url = row.url,
                e.method = row.method,
                e.auth_required = row.auth_required,
                e.scan_id = row.scan_id,
                e.status_code = row.status_code
            """,
            {"rows": rows},
        )

    async def _ingest_findings(self) -> None:
        rows = []
        for index, finding in enumerate(self.findings):
            rows.append(
                {
                    "finding_id": f"vuln_{self.scan_id}_{finding.vuln_type}_{index}",
                    "vuln_type": finding.vuln_type,
                    "severity": finding.severity,
                    "title": finding.title,
                    "parameter": finding.parameter,
                    "confidence": float(finding.confidence),
                    "scan_id": self.scan_id,
                    "endpoint_url": finding.endpoint_url,
                }
            )
        self._finding_rows = rows

        if not rows:
            return

        await neo4j_client.execute_write(
            """
            UNWIND $rows AS row
            MERGE (v:Vulnerability {finding_id: row.finding_id})
            SET v.type = row.vuln_type,
                v.severity = row.severity,
                v.title = row.title,
                v.parameter = row.parameter,
                v.confidence = row.confidence,
                v.scan_id = row.scan_id
            """,
            {"rows": rows},
        )

    async def _connect_scan_to_endpoints(self) -> None:
        if not self._endpoint_rows:
            return

        await neo4j_client.execute_write(
            """
            MATCH (s:ScanSession {scan_id: $scan_id})
            UNWIND $rows AS row
            MATCH (e:Endpoint {endpoint_id: row.endpoint_id})
            MERGE (s)-[:DISCOVERED {scan_id: $scan_id}]->(e)
            """,
            {
                "scan_id": self.scan_id,
                "rows": [{"endpoint_id": row["endpoint_id"]} for row in self._endpoint_rows],
            },
        )

    async def _connect_endpoints_to_vulns(self) -> None:
        if not self._finding_rows:
            return

        await neo4j_client.execute_write(
            """
            UNWIND $rows AS row
            MATCH (e:Endpoint {scan_id: $scan_id})
            WHERE e.url = row.endpoint_url
            MATCH (v:Vulnerability {finding_id: row.finding_id, scan_id: $scan_id})
            MERGE (e)-[:LEADS_TO {scan_id: $scan_id}]->(v)
            """,
            {
                "scan_id": self.scan_id,
                "rows": [
                    {
                        "endpoint_url": row["endpoint_url"],
                        "finding_id": row["finding_id"],
                    }
                    for row in self._finding_rows
                ],
            },
        )

    async def _create_asset_nodes(self) -> None:
        if not self._finding_rows:
            return

        rows = []
        for finding in self._finding_rows:
            asset_type = VULN_TO_ASSET.get(str(finding["vuln_type"]), "UnknownAsset")
            rows.append(
                {
                    "finding_id": finding["finding_id"],
                    "asset_id": f"asset_{self.scan_id}_{asset_type}",
                    "asset_type": asset_type,
                    "scan_id": self.scan_id,
                }
            )

        await neo4j_client.execute_write(
            """
            UNWIND $rows AS row
            MERGE (a:Asset {asset_id: row.asset_id})
            SET a.type = row.asset_type,
                a.scan_id = row.scan_id
            WITH row, a
            MATCH (v:Vulnerability {finding_id: row.finding_id})
            MERGE (v)-[:EXPOSES {scan_id: row.scan_id}]->(a)
            """,
            {"rows": rows},
        )

    async def _create_impact_nodes(self) -> None:
        if not self._finding_rows:
            return

        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        asset_max_severity: Dict[str, str] = {}

        for finding in self._finding_rows:
            asset_type = VULN_TO_ASSET.get(str(finding["vuln_type"]), "UnknownAsset")
            current = asset_max_severity.get(asset_type)
            next_sev = str(finding.get("severity", "info"))
            if current is None or severity_rank.get(next_sev, 0) > severity_rank.get(current, 0):
                asset_max_severity[asset_type] = next_sev

        rows = []
        for asset_type, severity in asset_max_severity.items():
            impact_description = ASSET_TO_IMPACT.get(asset_type, "Unknown Impact")
            rows.append(
                {
                    "asset_id": f"asset_{self.scan_id}_{asset_type}",
                    "impact_id": f"impact_{self.scan_id}_{asset_type}",
                    "impact_description": impact_description,
                    "severity": severity,
                    "scan_id": self.scan_id,
                }
            )

        await neo4j_client.execute_write(
            """
            UNWIND $rows AS row
            MERGE (i:Impact {impact_id: row.impact_id})
            SET i.description = row.impact_description,
                i.severity = row.severity,
                i.scan_id = row.scan_id
            WITH row, i
            MATCH (a:Asset {asset_id: row.asset_id})
            MERGE (a)-[:ESCALATES_TO {scan_id: row.scan_id}]->(i)
            """,
            {"rows": rows},
        )

    async def _build_lateral_chains(self) -> None:
        rules = [
            """
            MATCH (xss:Vulnerability {type: 'xss', scan_id: $scan_id})
            MATCH (auth:Vulnerability {type: 'auth', scan_id: $scan_id})
            MERGE (xss)-[:CHAINS_WITH {scan_id: $scan_id, reason: 'XSS enables cookie theft'}]->(auth)
            """,
            """
            MATCH (idor:Vulnerability {type: 'idor', scan_id: $scan_id})
            MATCH (auth:Vulnerability {type: 'auth', scan_id: $scan_id})
            MERGE (idor)-[:CHAINS_WITH {scan_id: $scan_id, reason: 'IDOR exposes admin endpoints'}]->(auth)
            """,
            """
            MATCH (sqli:Vulnerability {type: 'sqli', scan_id: $scan_id})
            MATCH (auth:Vulnerability {type: 'auth', scan_id: $scan_id})
            MERGE (sqli)-[:CHAINS_WITH {scan_id: $scan_id, reason: 'SQLi can extract credentials'}]->(auth)
            """,
            """
            MATCH (cors:Vulnerability {type: 'cors', scan_id: $scan_id})
            MATCH (xss:Vulnerability {type: 'xss', scan_id: $scan_id})
            MERGE (cors)-[:CHAINS_WITH {scan_id: $scan_id, reason: 'CORS + XSS enables cross-origin data theft'}]->(xss)
            """,
            """
            MATCH (bl:Vulnerability {type: 'business_logic', scan_id: $scan_id})
            MATCH (auth:Vulnerability {type: 'auth', scan_id: $scan_id})
            MERGE (bl)-[:CHAINS_WITH {scan_id: $scan_id, reason: 'Auth bypass amplifies business logic flaws'}]->(auth)
            """,
        ]

        for rule in rules:
            try:
                await neo4j_client.execute_write(rule, {"scan_id": self.scan_id})
            except Exception as exc:
                self.logger.warning("Lateral chain rule failed for scan %s: %s", self.scan_id, exc)

    async def _query_attack_chains(self) -> List[ChainData]:
        primary_rows = await neo4j_client.execute_query(
            """
            MATCH path = (e:Endpoint {scan_id: $scan_id})
                         -[:LEADS_TO]->
                         (v:Vulnerability)
                         -[:EXPOSES]->
                         (a:Asset)
                         -[:ESCALATES_TO]->
                         (i:Impact)
            RETURN
              e.url          AS entry_point,
              v.type         AS vuln_type,
              v.severity     AS severity,
              v.finding_id   AS finding_id,
              a.type         AS asset_type,
              i.description  AS impact,
              i.severity     AS impact_severity,
              length(path)   AS chain_length
            ORDER BY
              CASE i.severity
                WHEN 'critical' THEN 0
                WHEN 'high'     THEN 1
                WHEN 'medium'   THEN 2
                WHEN 'low'      THEN 3
                ELSE 4
              END ASC
            LIMIT 50
            """,
            {"scan_id": self.scan_id},
        )

        _ = await neo4j_client.execute_query(
            """
            MATCH path = (v1:Vulnerability {scan_id: $scan_id})
                         -[:CHAINS_WITH*1..3]->
                         (v2:Vulnerability)
            RETURN
              v1.type AS start_vuln,
              v2.type AS end_vuln,
              length(path) AS chain_length,
              [r IN relationships(path) | r.reason] AS chain_reasons
            ORDER BY chain_length DESC
            LIMIT 20
            """,
            {"scan_id": self.scan_id},
        )

        dedup: Dict[Tuple[str, str], ChainData] = {}

        for row in primary_rows:
            entry_point = str(row.get("entry_point", ""))
            vuln_type = str(row.get("vuln_type", "unknown"))
            asset_type = str(row.get("asset_type", "UnknownAsset"))
            impact = str(row.get("impact", "Unknown Impact"))
            severity = str(row.get("severity", "info"))
            chain_length = int(row.get("chain_length", 1))

            chain = ChainData(
                path_id=str(uuid4()),
                nodes=[entry_point, vuln_type, asset_type, impact],
                entry_point=entry_point,
                final_impact=impact,
                severity_score=self._calculate_severity_score(severity, chain_length),
                length=chain_length,
            )

            key = (entry_point, impact)
            existing = dedup.get(key)
            if existing is None or chain.severity_score > existing.severity_score:
                dedup[key] = chain

        chains = list(dedup.values())
        for chain in chains:
            await publish_scan_event(
                self.scan_id,
                "chain.built",
                {
                    "chain_id": chain.path_id,
                    "entry_point": chain.entry_point,
                    "final_impact": chain.final_impact,
                    "severity": chain.severity_score,
                    "length": chain.length,
                },
            )

        return chains

    def _calculate_severity_score(self, severity: str, chain_length: int) -> float:
        base_scores = {
            "critical": 9.0,
            "high": 7.0,
            "medium": 5.0,
            "low": 3.0,
            "info": 1.0,
        }
        base = base_scores.get(severity.lower(), 1.0)

        if chain_length <= 1:
            multiplier = 1.0
        elif chain_length == 2:
            multiplier = 1.2
        elif chain_length == 3:
            multiplier = 1.4
        else:
            multiplier = 1.5

        return min(10.0, round(base * multiplier, 2))

    @staticmethod
    async def get_graph_for_frontend(scan_id: str) -> GraphData:
        node_rows = await neo4j_client.execute_query(
            """
            MATCH (n {scan_id: $scan_id})
            RETURN labels(n)[0] AS node_type, n AS props
            ORDER BY labels(n)[0]
            """,
            {"scan_id": scan_id},
        )

        edge_rows = await neo4j_client.execute_query(
            """
            MATCH (a {scan_id: $scan_id})-[r]->(b {scan_id: $scan_id})
            RETURN type(r) AS rel_type, a AS source_props, b AS target_props, r AS rel_props
            """,
            {"scan_id": scan_id},
        )

        nodes: List[GraphNode] = []
        for row in node_rows:
            node_type = str(row.get("node_type", "Unknown"))
            props_raw = row.get("props", {})
            props = dict(props_raw) if props_raw else {}

            node_id = (
                props.get("endpoint_id")
                or props.get("finding_id")
                or props.get("asset_id")
                or props.get("impact_id")
                or props.get("scan_id")
                or str(uuid4())
            )

            nodes.append(
                GraphNode(
                    node_id=str(node_id),
                    node_type=node_type,
                    label=ChainBuilder._get_node_label(node_type, props),
                    data=props,
                    severity=props.get("severity"),
                    color=NODE_COLORS.get(node_type, "#6B7280"),
                )
            )

        edges: List[GraphEdge] = []
        for row in edge_rows:
            rel_type = str(row.get("rel_type", "RELATED"))
            source_props_raw = row.get("source_props", {})
            target_props_raw = row.get("target_props", {})
            rel_props_raw = row.get("rel_props", {})

            source_props = dict(source_props_raw) if source_props_raw else {}
            target_props = dict(target_props_raw) if target_props_raw else {}
            rel_props = dict(rel_props_raw) if rel_props_raw else {}

            source_id = (
                source_props.get("endpoint_id")
                or source_props.get("finding_id")
                or source_props.get("asset_id")
                or source_props.get("impact_id")
                or source_props.get("scan_id")
            )
            target_id = (
                target_props.get("endpoint_id")
                or target_props.get("finding_id")
                or target_props.get("asset_id")
                or target_props.get("impact_id")
                or target_props.get("scan_id")
            )

            if not source_id or not target_id:
                continue

            edges.append(
                GraphEdge(
                    edge_id=f"{source_id}__{rel_type}__{target_id}",
                    source=str(source_id),
                    target=str(target_id),
                    label=rel_type,
                    data={"rel_props": json.dumps(rel_props)},
                )
            )

        ranked = await ChainBuilder.get_ranked_chains(scan_id)
        chains = [
            ChainData(
                path_id=str(item.get("path_id", str(uuid4()))),
                nodes=[],
                entry_point=str(item.get("entry_point", "")),
                final_impact=str(item.get("final_impact", "")),
                severity_score=float(item.get("severity_score", 0.0)),
                length=int(item.get("length", 0)),
                llm_analysis=item.get("llm_analysis"),
            )
            for item in ranked
        ]

        return GraphData(nodes=nodes, edges=edges, chains=chains)

    @staticmethod
    def _get_node_label(node_type: str, props: dict) -> str:
        if node_type == "Endpoint":
            url = str(props.get("url", "Endpoint"))
            return url[-40:] if len(url) <= 40 else f"...{url[-40:]}"
        if node_type == "Vulnerability":
            vuln = str(props.get("type", "VULN")).upper()
            parameter = str(props.get("parameter", ""))
            return f"{vuln} - {parameter}".rstrip(" -")
        if node_type == "Asset":
            return str(props.get("type", "Asset"))
        if node_type == "Impact":
            return str(props.get("description", "Impact"))
        if node_type == "ScanSession":
            return "Scan Root"

        values = list(props.values())
        return str(values[0])[:40] if values else "Node"

    @staticmethod
    async def get_ranked_chains(scan_id: str) -> List[Dict]:
        rows = await neo4j_client.execute_query(
            """
            MATCH path = (e:Endpoint {scan_id: $scan_id})
                         -[:LEADS_TO]->
                         (v:Vulnerability)
                         -[:EXPOSES]->
                         (a:Asset)
                         -[:ESCALATES_TO]->
                         (i:Impact)
            RETURN
              e.url          AS entry_point,
              v.severity     AS severity,
              a.type         AS asset_type,
              i.description  AS impact,
              length(path)   AS chain_length
            LIMIT 50
            """,
            {"scan_id": scan_id},
        )

        dedup: Dict[Tuple[str, str], Dict] = {}
        builder = ChainBuilder(scan_id=scan_id, endpoints=[], findings=[])

        for row in rows:
            entry = str(row.get("entry_point", ""))
            impact = str(row.get("impact", "Unknown Impact"))
            length = int(row.get("chain_length", 1))
            severity = str(row.get("severity", "info"))
            score = builder._calculate_severity_score(severity, length)

            key = (entry, impact)
            payload = {
                "path_id": str(uuid4()),
                "length": length,
                "entry_point": entry,
                "final_impact": impact,
                "severity_score": score,
                "llm_analysis": None,
            }
            existing = dedup.get(key)
            if existing is None or score > float(existing.get("severity_score", 0.0)):
                dedup[key] = payload

        ranked = sorted(dedup.values(), key=lambda item: float(item["severity_score"]), reverse=True)
        return ranked
