import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, List, Optional

from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncSession
from neo4j.exceptions import AuthError, ServiceUnavailable

from config import settings

logger = logging.getLogger(__name__)


class Neo4jClient:
    def __init__(self) -> None:
        self._driver: Optional[AsyncDriver] = None

    async def connect(self) -> None:
        try:
            driver = AsyncGraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USERNAME, settings.NEO4J_PASSWORD),
                database=settings.NEO4J_DATABASE,
            )
            await driver.verify_connectivity()
            self._driver = driver
            logger.info("Neo4j connected ✓")
        except ServiceUnavailable as exc:
            logger.error("Neo4j service unavailable: %s", exc)
            raise ServiceUnavailable(
                f"Neo4j is not reachable at {settings.NEO4J_URI}"
            ) from exc
        except AuthError as exc:
            logger.error("Neo4j authentication failed: %s", exc)
            raise AuthError(
                "Neo4j authentication failed — check NEO4J_USERNAME / NEO4J_PASSWORD"
            ) from exc

    async def disconnect(self) -> None:
        if self._driver is not None:
            await self._driver.close()
            logger.info("Neo4j driver closed.")
            self._driver = None

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        if self._driver is None:
            raise RuntimeError("Neo4j driver is not connected.")

        session = self._driver.session(database=settings.NEO4J_DATABASE)
        try:
            yield session
        finally:
            await session.close()

    async def execute_query(
        self,
        cypher: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        try:
            logger.debug("Executing Cypher query: %s", cypher[:200])
            async with self.session() as session:
                result = await session.run(cypher, parameters or {})
                records = await result.data()
                return records
        except Exception as exc:
            logger.exception("Neo4j query execution failed: %s", exc)
            raise

    async def execute_write(
        self,
        cypher: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> None:
        async def _write_transaction(tx: Any) -> None:
            await tx.run(cypher, parameters or {})

        try:
            logger.debug("Executing Cypher write: %s", cypher[:200])
            async with self.session() as session:
                await session.execute_write(_write_transaction)
        except Exception as exc:
            logger.exception("Neo4j write execution failed: %s", exc)
            raise

    async def init_constraints(self) -> None:
        statements = [
            "CREATE CONSTRAINT scan_session_id IF NOT EXISTS FOR (s:ScanSession) REQUIRE s.scan_id IS UNIQUE",
            "CREATE CONSTRAINT endpoint_id IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.endpoint_id IS UNIQUE",
            "CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.finding_id IS UNIQUE",
            "CREATE INDEX vuln_type IF NOT EXISTS FOR (v:Vulnerability) ON (v.type)",
            "CREATE INDEX asset_type IF NOT EXISTS FOR (a:Asset) ON (a.type)",
            "CREATE INDEX impact_severity IF NOT EXISTS FOR (i:Impact) ON (i.severity)",
        ]

        for statement in statements:
            await self.execute_write(statement)

        logger.info("Neo4j constraints and indexes initialized ✓")


neo4j_client = Neo4jClient()
