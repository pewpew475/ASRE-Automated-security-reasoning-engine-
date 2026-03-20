import logging
from typing import Any, Dict, List, Optional

from neo4j import AsyncDriver, AsyncGraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable

from config import settings


class Neo4jClient:
    def __init__(self) -> None:
        self._driver: Optional[AsyncDriver] = None
        self.logger = logging.getLogger(__name__)

    async def connect(self) -> None:
        if self._driver is not None:
            return

        try:
            self._driver = AsyncGraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USERNAME, settings.NEO4J_PASSWORD),
                max_connection_pool_size=10,
                connection_timeout=30.0,
                max_transaction_retry_time=15.0,
            )
            await self._driver.verify_connectivity()
            self.logger.info("Neo4j connected: %s", settings.NEO4J_URI)
        except ServiceUnavailable:
            self.logger.error(
                "Neo4j unavailable. Is the Neo4j container running? "
                "Run: docker compose up neo4j"
            )
            self._driver = None
            raise
        except AuthError:
            self.logger.error(
                "Neo4j authentication failed. "
                "Check NEO4J_PASSWORD in your .env file."
            )
            self._driver = None
            raise

    async def close(self) -> None:
        if self._driver is not None:
            await self._driver.close()
            self.logger.info("Neo4j connection closed")
            self._driver = None

    async def disconnect(self) -> None:
        await self.close()

    def _require_driver(self) -> AsyncDriver:
        if self._driver is None:
            raise RuntimeError("Neo4j driver is not connected.")
        return self._driver

    async def init_constraints(self) -> None:
        statements = [
            """
            CREATE CONSTRAINT asre_endpoint_unique IF NOT EXISTS
            FOR (e:Endpoint)
            REQUIRE (e.endpoint_id) IS UNIQUE
            """,
            """
            CREATE CONSTRAINT asre_vuln_unique IF NOT EXISTS
            FOR (v:Vulnerability)
            REQUIRE (v.finding_id) IS UNIQUE
            """,
            """
            CREATE CONSTRAINT asre_asset_unique IF NOT EXISTS
            FOR (a:Asset)
            REQUIRE (a.asset_id) IS UNIQUE
            """,
            """
            CREATE CONSTRAINT asre_impact_unique IF NOT EXISTS
            FOR (i:Impact)
            REQUIRE (i.impact_id) IS UNIQUE
            """,
            """
            CREATE CONSTRAINT asre_scan_session_unique IF NOT EXISTS
            FOR (s:ScanSession)
            REQUIRE (s.scan_id) IS UNIQUE
            """,
            """
            CREATE INDEX asre_endpoint_scan_idx IF NOT EXISTS
            FOR (e:Endpoint) ON (e.scan_id)
            """,
            """
            CREATE INDEX asre_vuln_scan_idx IF NOT EXISTS
            FOR (v:Vulnerability) ON (v.scan_id)
            """,
            """
            CREATE INDEX asre_vuln_type_idx IF NOT EXISTS
            FOR (v:Vulnerability) ON (v.type)
            """,
            """
            CREATE INDEX asre_asset_scan_idx IF NOT EXISTS
            FOR (a:Asset) ON (a.scan_id)
            """,
            """
            CREATE INDEX asre_impact_scan_idx IF NOT EXISTS
            FOR (i:Impact) ON (i.scan_id)
            """,
        ]

        driver = self._require_driver()
        for statement in statements:
            try:
                async with driver.session(database=settings.NEO4J_DATABASE) as session:
                    await session.run(statement)
            except Exception as exc:
                self.logger.warning("Neo4j schema statement failed: %s", exc)

        self.logger.info("Neo4j constraints + indexes initialized")

    async def execute_query(
        self,
        query: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        driver = self._require_driver()
        try:
            async with driver.session(database=settings.NEO4J_DATABASE) as session:
                result = await session.run(query, parameters or {})
                records = await result.data()
                return records
        except Exception as exc:
            self.logger.exception("Neo4j query execution failed: %s", exc)
            raise

    async def execute_write(
        self,
        query: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> None:
        driver = self._require_driver()

        try:
            async with driver.session(database=settings.NEO4J_DATABASE) as session:
                async def _write_tx(tx: Any) -> None:
                    await tx.run(query, parameters or {})

                await session.execute_write(_write_tx)
        except Exception as exc:
            self.logger.exception("Neo4j write execution failed: %s", exc)
            raise

    async def execute_write_many(self, queries: List[Dict[str, Any]]) -> None:
        if not queries:
            return

        driver = self._require_driver()

        async def _batch_tx(tx: Any) -> None:
            for item in queries:
                await tx.run(item["query"], item.get("params", {}))

        async with driver.session(database=settings.NEO4J_DATABASE) as session:
            await session.execute_write(_batch_tx)

    async def health_check(self) -> bool:
        try:
            result = await self.execute_query("RETURN 1 AS n")
            return bool(result and result[0].get("n") == 1)
        except Exception:
            return False

    async def purge_scan_graph(self, scan_id: str) -> None:
        await self.execute_write(
            """
            MATCH (n {scan_id: $scan_id})
            DETACH DELETE n
            """,
            {"scan_id": scan_id},
        )
        self.logger.info("Purged Neo4j graph for scan %s", scan_id)


neo4j_client = Neo4jClient()
