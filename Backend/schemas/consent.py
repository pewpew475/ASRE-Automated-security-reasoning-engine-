from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from config import settings


class ConsentInitiateRequest(BaseModel):
    target_domain: str = Field(
        ...,
        description="Bare target domain name without protocol or path.",
        json_schema_extra={"example": ["example.com"]},
    )

    @field_validator("target_domain")
    @classmethod
    def validate_target_domain(cls, value: str) -> str:
        normalized = value.strip().lower()
        if "://" in normalized or "/" in normalized or "." not in normalized:
            raise ValueError("target_domain must be a bare domain, e.g. 'example.com'")
        return normalized


class DNSVerificationInstructions(BaseModel):
    target_domain: str = Field(
        ...,
        description="Target domain to verify for hardcore scan authorization.",
        json_schema_extra={"example": ["example.com"]},
    )
    dns_txt_record: str = Field(
        ...,
        description="Exact TXT record value that must be added.",
        json_schema_extra={"example": ["pentest-verify=abc123uuid"]},
    )
    instructions: str = Field(
        ...,
        description="Human-readable DNS verification instructions.",
        json_schema_extra={
            "example": "Add a DNS TXT record to example.com with value: pentest-verify=abc123uuid Then call POST /api/consent/verify-domain to confirm."
        },
    )
    expires_in_hours: int = Field(
        default=24,
        description="Hours until this DNS verification challenge expires.",
        json_schema_extra={"example": [24]},
    )


class ScopeConfigSchema(BaseModel):
    allowed_paths: List[str] = Field(
        default_factory=lambda: ["/"],
        description="Allowed URL paths within scope.",
        json_schema_extra={"example": [["/", "/api/"]]},
    )
    excluded_paths: List[str] = Field(
        default_factory=list,
        description="Explicit URL paths excluded from scanning.",
        json_schema_extra={"example": [["/admin/delete", "/payments/"]]},
    )
    max_depth: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Maximum crawler depth permitted by consent.",
        json_schema_extra={"example": [5]},
    )
    subdomain_scope: bool = Field(
        default=False,
        description="Whether subdomains are included in allowed scope.",
        json_schema_extra={"example": [False]},
    )


class ConsentAcceptRequest(BaseModel):
    target_domain: str = Field(
        ...,
        description="Domain for which consent is being accepted.",
        json_schema_extra={"example": ["example.com"]},
    )
    tc_version: str = Field(
        ...,
        description="Terms and Conditions version acknowledged by the user.",
        json_schema_extra={"example": ["1.0.0"]},
    )
    scope_config: ScopeConfigSchema = Field(
        ...,
        description="Authorized scanner scope constraints.",
        json_schema_extra={"example": [{"allowed_paths": ["/"], "excluded_paths": [], "max_depth": 5, "subdomain_scope": False}]},
    )

    @field_validator("target_domain")
    @classmethod
    def validate_target_domain(cls, value: str) -> str:
        normalized = value.strip().lower()
        if "://" in normalized or "/" in normalized or "." not in normalized:
            raise ValueError("target_domain must be a bare domain, e.g. 'example.com'")
        return normalized

    @field_validator("tc_version")
    @classmethod
    def validate_tc_version(cls, value: str) -> str:
        if value != settings.TC_CURRENT_VERSION:
            raise ValueError(
                f"tc_version must match current version {settings.TC_CURRENT_VERSION}"
            )
        return value


class ConsentStatusResponse(BaseModel):
    id: UUID = Field(
        ...,
        description="Unique consent record identifier.",
        json_schema_extra={"example": ["d6b584f3-835e-4dd3-8fd2-e57e397d2e70"]},
    )
    target_domain: str = Field(
        ...,
        description="Domain covered by consent.",
        json_schema_extra={"example": ["example.com"]},
    )
    domain_verified: bool = Field(
        ...,
        description="Whether DNS ownership verification is completed.",
        json_schema_extra={"example": [True]},
    )
    verified_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp when DNS ownership was verified.",
        json_schema_extra={"example": ["2026-03-20T09:30:00Z"]},
    )
    tc_version: str = Field(
        ...,
        description="Accepted Terms and Conditions version.",
        json_schema_extra={"example": ["1.0.0"]},
    )
    tc_accepted_at: datetime = Field(
        ...,
        description="Timestamp when terms were accepted.",
        json_schema_extra={"example": ["2026-03-20T09:31:00Z"]},
    )
    scope_config: Dict[str, Any] = Field(
        ...,
        description="Stored consent scope configuration.",
        json_schema_extra={"example": [{"allowed_paths": ["/"], "excluded_paths": [], "max_depth": 5}]},
    )
    expires_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp when consent expires.",
        json_schema_extra={"example": ["2026-04-19T09:31:00Z"]},
    )
    created_at: datetime = Field(
        ...,
        description="Timestamp when consent record was created.",
        json_schema_extra={"example": ["2026-03-20T09:25:00Z"]},
    )

    model_config = ConfigDict(from_attributes=True)
