import json
import logging
from typing import Any, Dict
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from api.deps import get_current_user
from core.database import get_db_context
from models.scan import Scan
from scanner.chain_builder import ChainBuilder, GraphData

router = APIRouter(prefix="/scans", tags=["Graph"])
logger = logging.getLogger(__name__)

_GRAPH_READY_STATUSES = {
    "completed",
    "analyzing",
    "chaining",
    "generating_poc",
    "reporting",
}


async def _verify_scan_ownership(scan_id: str, current_user: Any) -> Scan:
    try:
        scan_uuid = UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid scan ID") from exc

    async with get_db_context() as db:
        scan = await db.get(Scan, scan_uuid)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if str(scan.user_id) != str(current_user.id):
            raise HTTPException(status_code=403, detail="Access denied")
        if scan.status not in _GRAPH_READY_STATUSES:
            raise HTTPException(
                status_code=400,
                detail="Graph not yet available - scan in progress",
            )

    return scan


@router.get("/{scan_id}/graph")
async def get_attack_graph(
    scan_id: str,
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    await _verify_scan_ownership(scan_id=scan_id, current_user=current_user)

    meta = {
        "scan_id": scan_id,
        "node_count": 0,
        "edge_count": 0,
        "chain_count": 0,
    }

    try:
        graph_data: GraphData = await ChainBuilder.get_graph_for_frontend(scan_id=scan_id)
        payload = {
            "nodes": [
                {
                    "id": node.node_id,
                    "type": node.node_type.lower(),
                    "data": {
                        "label": node.label,
                        "severity": node.severity,
                        "color": node.color,
                        **node.data,
                    },
                    "position": {"x": 0, "y": 0},
                }
                for node in graph_data.nodes
            ],
            "edges": [
                {
                    "id": edge.edge_id,
                    "source": edge.source,
                    "target": edge.target,
                    "label": edge.label,
                    "animated": True,
                    "data": edge.data,
                }
                for edge in graph_data.edges
            ],
            "meta": {
                "scan_id": scan_id,
                "node_count": len(graph_data.nodes),
                "edge_count": len(graph_data.edges),
                "chain_count": len(graph_data.chains),
            },
        }
        return payload
    except Exception:
        logger.exception("Failed to fetch graph from Neo4j for scan %s", scan_id)
        return {
            "nodes": [],
            "edges": [],
            "meta": meta,
        }


@router.get("/{scan_id}/graph/chains")
async def get_attack_chains(
    scan_id: str,
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    await _verify_scan_ownership(scan_id=scan_id, current_user=current_user)

    chains = await ChainBuilder.get_ranked_chains(scan_id=scan_id)
    return {
        "chains": chains,
        "total": len(chains),
        "scan_id": scan_id,
    }


@router.get("/{scan_id}/graph/export")
async def export_graph_json(
    scan_id: str,
    current_user=Depends(get_current_user),
) -> Response:
    payload = await get_attack_graph(scan_id=scan_id, current_user=current_user)
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="asre-graph-{scan_id}.json"',
        },
    )
