import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Optional, Set
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from fastapi.websockets import WebSocketState
from redis.asyncio import Redis
from sqlalchemy import select

from config import settings
from core.database import get_db_context
from core.security import TokenExpiredError, TokenInvalidError, verify_access_token
from models.scan import Scan
from models.user import User

router = APIRouter()
logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        if websocket.client_state == WebSocketState.CONNECTING:
            await websocket.accept()

        sockets = self._connections.setdefault(scan_id, set())
        sockets.add(websocket)
        logger.info("WS connected: scan=%s | total=%s", scan_id, len(sockets))

    async def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        sockets = self._connections.get(scan_id)
        if not sockets:
            return

        sockets.discard(websocket)
        if not sockets:
            self._connections.pop(scan_id, None)
        logger.info("WS disconnected: scan=%s", scan_id)

    async def broadcast(self, scan_id: str, event: dict) -> None:
        sockets = self._connections.get(scan_id)
        if not sockets:
            return

        for websocket in list(sockets):
            try:
                await websocket.send_json(event)
            except Exception:
                await self.disconnect(scan_id, websocket)
                logger.warning("WS send failed, removed dead connection")

    async def send_to_one(self, websocket: WebSocket, event: dict) -> None:
        try:
            # Check if connection is still open before sending
            if websocket.client_state != WebSocketState.CONNECTED:
                return
            await websocket.send_json(event)
        except Exception:
            logger.warning("WS send_to_one failed", exc_info=True)

    def active_connection_count(self, scan_id: str) -> int:
        return len(self._connections.get(scan_id, set()))

    @staticmethod
    def build_event(event: str, scan_id: str, data: dict) -> dict:
        return {
            "event": event,
            "scan_id": scan_id,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


manager = ConnectionManager()


async def listen_for_scan_events(scan_id: str, websocket: WebSocket) -> None:
    channel = f"scan:{scan_id}:events"
    redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = redis.pubsub()

    try:
        await pubsub.subscribe(channel)

        async for message in pubsub.listen():
            if message.get("type") != "message":
                continue

            try:
                event_data = json.loads(message.get("data", ""))
                await manager.send_to_one(websocket, event_data)

                if event_data.get("event") in {
                    "scan.completed",
                    "scan.failed",
                    "scan.cancelled",
                }:
                    break
            except json.JSONDecodeError:
                raw_data = str(message.get("data", ""))
                logger.warning("Invalid JSON from Redis channel: %s", raw_data[:100])
                continue
    finally:
        await pubsub.unsubscribe(channel)
        await redis.aclose()


async def send_heartbeat(scan_id: str, websocket: WebSocket) -> None:
    while True:
        await asyncio.sleep(25)
        if websocket.client_state == WebSocketState.CONNECTED:
            await manager.send_to_one(
                websocket,
                manager.build_event("ping", scan_id, {"status": "alive"}),
            )
        else:
            break


async def consume_client_messages(scan_id: str, websocket: WebSocket) -> None:
    while websocket.client_state == WebSocketState.CONNECTED:
        try:
            message = await websocket.receive_json()
        except WebSocketDisconnect:
            break
        except Exception:
            # Ignore malformed/non-JSON frames and keep the connection alive.
            continue
        if not isinstance(message, dict):
            continue

        event_type = str(message.get("event") or message.get("type") or "").lower()
        if event_type in {"ping", "client.ping"}:
            await manager.send_to_one(
                websocket,
                manager.build_event("pong", scan_id, {"status": "alive"}),
            )
        elif event_type in {"pong", "client.pong"}:
            # Client acknowledged heartbeat.
            continue


@router.websocket("/scan/{scan_id}")
async def websocket_scan_endpoint(websocket: WebSocket, scan_id: UUID) -> None:
    scan_id_str = str(scan_id)
    await websocket.accept()

    try:
        try:
            auth_message = await asyncio.wait_for(websocket.receive_json(), timeout=10.0)
        except asyncio.TimeoutError:
            await manager.send_to_one(
                websocket,
                manager.build_event("error", scan_id_str, {"message": "Authentication timeout"}),
            )
            await websocket.close(code=4001)
            return

        token = auth_message.get("token") if isinstance(auth_message, dict) else None
        if not token:
            await manager.send_to_one(
                websocket,
                manager.build_event(
                    "error",
                    scan_id_str,
                    {"message": "Missing authentication token"},
                ),
            )
            await websocket.close(code=4001)
            return

        try:
            payload = verify_access_token(token)
            user_id = payload["sub"]
        except (TokenExpiredError, TokenInvalidError) as exc:
            await manager.send_to_one(
                websocket,
                manager.build_event("error", scan_id_str, {"message": str(exc)}),
            )
            await websocket.close(code=4001)
            return

        async with get_db_context() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()

            _ = User

            if scan is None:
                await manager.send_to_one(
                    websocket,
                    manager.build_event("error", scan_id_str, {"message": "Scan not found"}),
                )
                await websocket.close(code=4004)
                return

            if str(scan.user_id) != str(user_id):
                await manager.send_to_one(
                    websocket,
                    manager.build_event(
                        "error",
                        scan_id_str,
                        {"message": "You do not have access to this scan"},
                    ),
                )
                await websocket.close(code=4003)
                return

            await manager.send_to_one(
                websocket,
                manager.build_event(
                    "scan.progress",
                    scan_id_str,
                    {
                        "status": scan.status,
                        "endpoints_found": scan.endpoints_found,
                        "vulns_found": scan.vulns_found,
                        "chains_found": scan.chains_found,
                    },
                ),
            )

            if scan.status in {"completed", "failed", "cancelled"}:
                status_key = str(scan.status)
                final_event = {
                    "completed": "scan.completed",
                    "failed": "scan.failed",
                    "cancelled": "scan.cancelled",
                }[status_key]
                await manager.send_to_one(
                    websocket,
                    manager.build_event(
                        final_event,
                        scan_id_str,
                        {
                            "status": status_key,
                            "error_message": scan.error_message,
                        },
                    ),
                )

        await manager.connect(scan_id_str, websocket)

        results = await asyncio.gather(
            listen_for_scan_events(scan_id_str, websocket),
            send_heartbeat(scan_id_str, websocket),
            consume_client_messages(scan_id_str, websocket),
            return_exceptions=True,
        )

        for result in results:
            if isinstance(result, Exception) and not isinstance(result, WebSocketDisconnect):
                logger.warning("WS background task error for scan=%s: %s", scan_id_str, result)
    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(scan_id_str, websocket)
        if (
            websocket.client_state == WebSocketState.CONNECTED
            and websocket.application_state == WebSocketState.CONNECTED
        ):
            try:
                await websocket.close(code=status.WS_1000_NORMAL_CLOSURE)
            except RuntimeError:
                # Another task may have already sent the close frame.
                pass
        logger.info("WS session ended: scan=%s", scan_id_str)


async def publish_scan_event(scan_id: str, event: str, data: dict) -> None:
    channel = f"scan:{scan_id}:events"
    redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)

    try:
        payload = json.dumps(manager.build_event(event, scan_id, data))
        await redis.publish(channel, payload)
    except ConnectionError:
        logger.warning("Redis publish failed for scan=%s event=%s", scan_id, event, exc_info=True)
    finally:
        await redis.aclose()
