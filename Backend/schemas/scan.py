import ipaddress
import logging
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

logger = logging.getLogger(__name__)


class ScanCredentials(BaseModel):
    username: Optional[str] = Field(
        default=None,
        description="Target application login username.",
        json_schema_extra={"example": "admin@example.com"},
    )
    password: Optional[str] = Field(
        default=None,
        description="Target application login password in plaintext before service-layer encryption.",
        json_schema_extra={"example": "TargetPassword123"},
    )
    login_url: Optional[str] = Field(
        default=None,
        description="Authentication endpoint URL used to establish a session before scanning.",
        json_schema_extra={"example": "https://example.com/login"},
    )
    cookie: Optional[str] = Field(
        default=None,
        description="Optional pre-authenticated cookie string.",
        json_schema_extra={"example": "sessionid=abc123; csrftoken=xyz789"},
    )


class ScanConfig(BaseModel):
    max_depth: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Maximum crawler link depth.",
        json_schema_extra={"example": 5},
    )
    max_pages: int = Field(
        default=100,
        ge=1,
        le=500,
        description="Maximum number of pages/endpoints the crawler can collect.",
        json_schema_extra={"example": 100},
    )
    excluded_paths: List[str] = Field(
        default_factory=list,
        description="URL paths excluded from crawling and scanning.",
        json_schema_extra={"example": ["/logout", "/admin/delete"]},
    )
    follow_redirects: bool = Field(
        default=True,
        description="Whether scanner HTTP clients should follow redirects.",
        json_schema_extra={"example": True},
    )
    scan_rate_limit: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum scanner request throughput per second.",
        json_schema_extra={"example": 10},
    )


class StartScanRequest(BaseModel):
    target_url: str = Field(
        ...,
        description="Public target URL to scan. Must be HTTP/HTTPS and cannot point to localhost or private networks.",
        json_schema_extra={"example": "https://example.com"},
    )
    mode: Literal["normal", "hardcore"] = Field(
        ...,
        description="Scan mode. Hardcore enables active exploitation modules.",
        json_schema_extra={"example": "normal"},
    )
    credentials: Optional[ScanCredentials] = Field(
        default=None,
        description="Optional target-app credentials for authenticated crawling/scanning.",
        json_schema_extra={"example": None},
    )
    config: ScanConfig = Field(
        default_factory=ScanConfig,
        description="Scanner runtime configuration.",
        json_schema_extra={"example": {"max_depth": 5, "max_pages": 100, "scan_rate_limit": 10}},
    )

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, value: str) -> str:
        lowered = value.lower()
        if not (lowered.startswith("http://") or lowered.startswith("https://")):
            raise ValueError("target_url must be a valid public HTTP/HTTPS URL")

        parsed = urlparse(value)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("target_url must be a valid public HTTP/HTTPS URL")

        blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0"}
        if hostname.lower() in blocked_hosts:
            raise ValueError("target_url must be a valid public HTTP/HTTPS URL")

        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
                raise ValueError("target_url must be a valid public HTTP/HTTPS URL")
        except ValueError:
            if hostname.startswith("10."):
                raise ValueError("target_url must be a valid public HTTP/HTTPS URL")
            if hostname.startswith("192.168."):
                raise ValueError("target_url must be a valid public HTTP/HTTPS URL")
            if hostname.startswith("172."):
                parts = hostname.split(".")
                if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
                    raise ValueError("target_url must be a valid public HTTP/HTTPS URL")

        return value

    @model_validator(mode="after")
    def warn_hardcore_without_credentials(self) -> "StartScanRequest":
        if self.mode == "hardcore" and self.credentials is None:
            logger.warning(
                "Hardcore mode requested without credentials; proceeding with unauthenticated scan."
            )
        return self


class ScanStatusResponse(BaseModel):
    scan_id: UUID = Field(
        ...,
        description="Unique scan identifier.",
        json_schema_extra={"example": "1086de2a-6d96-468b-84e8-4768c7f04979"},
    )
    status: str = Field(
        ...,
        description="Current high-level scan status.",
        json_schema_extra={"example": "scanning"},
    )
    mode: str = Field(
        ...,
        description="Mode in which the scan is running.",
        json_schema_extra={"example": "normal"},
    )
    target_url: str = Field(
        ...,
        description="Target URL being assessed.",
        json_schema_extra={"example": "https://example.com"},
    )
    phase: Optional[str] = Field(
        default=None,
        description="Current pipeline phase.",
        json_schema_extra={"example": "phase-3-active-scanning"},
    )
    progress: Dict[str, int] = Field(
        default_factory=lambda: {
            "endpoints_found": 0,
            "vulns_found": 0,
            "chains_found": 0,
        },
        description="Progress counters for discovered endpoints, findings, and attack chains.",
        json_schema_extra={"example": {"endpoints_found": 12, "vulns_found": 3, "chains_found": 1}},
    )
    started_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp when scanning started.",
        json_schema_extra={"example": "2026-03-20T10:00:00Z"},
    )
    completed_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp when scanning completed.",
        json_schema_extra={"example": "2026-03-20T10:05:22Z"},
    )
    elapsed_seconds: Optional[float] = Field(
        default=None,
        description="Elapsed scan duration in seconds.",
        json_schema_extra={"example": 322.4},
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Failure reason when scan status is failed.",
        json_schema_extra={"example": "Crawler timed out"},
    )

    model_config = ConfigDict(from_attributes=True)


class ScanListItem(BaseModel):
    scan_id: UUID = Field(
        ...,
        alias="id",
        description="Unique scan identifier mapped from ORM id.",
        json_schema_extra={"example": "1086de2a-6d96-468b-84e8-4768c7f04979"},
    )
    target_url: str = Field(
        ...,
        description="Target URL for the scan.",
        json_schema_extra={"example": "https://example.com"},
    )
    mode: str = Field(
        ...,
        description="Scan mode.",
        json_schema_extra={"example": "hardcore"},
    )
    status: str = Field(
        ...,
        description="Current or terminal scan status.",
        json_schema_extra={"example": "completed"},
    )
    created_at: datetime = Field(
        ...,
        description="Timestamp when scan record was created.",
        json_schema_extra={"example": "2026-03-20T10:00:00Z"},
    )
    vulns_found: int = Field(
        ...,
        description="Total vulnerabilities detected for the scan.",
        json_schema_extra={"example": 5},
    )
    chains_found: int = Field(
        ...,
        description="Total attack chains generated for the scan.",
        json_schema_extra={"example": 2},
    )

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class ScanListResponse(BaseModel):
    scans: List[ScanListItem] = Field(
        ...,
        description="Paginated list of scan summaries.",
        json_schema_extra={"example": []},
    )
    total: int = Field(
        ...,
        description="Total number of scans available for the query.",
        json_schema_extra={"example": 42},
    )
    page: int = Field(
        ...,
        description="Current page number.",
        json_schema_extra={"example": 1},
    )
    limit: int = Field(
        ...,
        description="Maximum scans returned per page.",
        json_schema_extra={"example": 20},
    )


class ScanCreateResponse(BaseModel):
    scan_id: UUID = Field(
        ...,
        description="Newly created scan identifier.",
        json_schema_extra={"example": "1086de2a-6d96-468b-84e8-4768c7f04979"},
    )
    status: str = Field(
        default="pending",
        description="Initial scan status after queueing.",
        json_schema_extra={"example": "pending"},
    )
    message: str = Field(
        default="Scan queued successfully",
        description="Human-readable queue acknowledgement.",
        json_schema_extra={"example": "Scan queued successfully"},
    )
