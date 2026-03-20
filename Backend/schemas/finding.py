from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator


class EvidenceSchema(BaseModel):
    request_method: Optional[str] = Field(
        default=None,
        description="HTTP method used for the probe request.",
        json_schema_extra={"example": ["GET"]},
    )
    request_url: Optional[str] = Field(
        default=None,
        description="Full request URL used during detection.",
        json_schema_extra={"example": ["https://example.com/search?q=test"]},
    )
    request_headers: Optional[Dict[str, str]] = Field(
        default=None,
        description="Request headers sent for the probe.",
        json_schema_extra={"example": [{"User-Agent": "ASRE-Scanner/1.0"}]},
    )
    request_body: Optional[str] = Field(
        default=None,
        description="Request body payload if applicable.",
        json_schema_extra={"example": ["username=alice&password=test"]},
    )
    response_code: Optional[int] = Field(
        default=None,
        description="HTTP response status code.",
        json_schema_extra={"example": [200]},
    )
    response_body: Optional[str] = Field(
        default=None,
        description="Response body excerpt truncated to 500 characters at service layer.",
        json_schema_extra={"example": ["<html>...</html>"]},
    )
    matched_pattern: Optional[str] = Field(
        default=None,
        description="Signature or pattern that triggered detection.",
        json_schema_extra={"example": ["SQL syntax error near 'UNION SELECT'"]},
    )


class FindingResponse(BaseModel):
    id: UUID = Field(
        ...,
        description="Unique finding identifier.",
        json_schema_extra={"example": ["f868a209-f01d-4548-a98b-e4596f9f5df2"]},
    )
    scan_id: UUID = Field(
        ...,
        description="Associated scan identifier.",
        json_schema_extra={"example": ["1086de2a-6d96-468b-84e8-4768c7f04979"]},
    )
    endpoint_id: Optional[UUID] = Field(
        default=None,
        description="Related endpoint identifier when available.",
        json_schema_extra={"example": ["f650a6dc-790a-4d06-95c8-f0f9a1ce7472"]},
    )
    vuln_type: str = Field(
        ...,
        description="Normalized vulnerability type.",
        json_schema_extra={"example": ["sqli"]},
    )
    severity: str = Field(
        ...,
        description="Severity rating for prioritization.",
        json_schema_extra={"example": ["high"]},
    )
    title: str = Field(
        ...,
        description="Short human-readable finding title.",
        json_schema_extra={"example": ["SQL Injection in search endpoint"]},
    )
    description: Optional[str] = Field(
        default=None,
        description="Detailed vulnerability narrative.",
        json_schema_extra={"example": ["Unsanitized query parameter enables SQL injection."]},
    )
    evidence: Optional[EvidenceSchema] = Field(
        default=None,
        description="Structured proof of detection.",
        json_schema_extra={"example": [None]},
    )
    parameter: Optional[str] = Field(
        default=None,
        description="Parameter name associated with the issue.",
        json_schema_extra={"example": ["q"]},
    )
    payload_used: Optional[str] = Field(
        default=None,
        description="Attack payload used during probing.",
        json_schema_extra={"example": ["' OR 1=1 --"]},
    )
    confidence: float = Field(
        ...,
        description="Confidence score in range 0.0 to 1.0.",
        json_schema_extra={"example": [0.93]},
    )
    is_confirmed: bool = Field(
        ...,
        description="Whether the finding was actively confirmed.",
        json_schema_extra={"example": [True]},
    )
    poc_curl: Optional[str] = Field(
        default=None,
        description="PoC curl command for reproducibility.",
        json_schema_extra={"example": ["curl -X GET 'https://example.com/search?q=%27%20OR%201%3D1--'"]},
    )
    llm_impact: Optional[str] = Field(
        default=None,
        description="LLM-generated impact analysis.",
        json_schema_extra={"example": ["An attacker can exfiltrate user records."]},
    )
    fix_suggestion: Optional[str] = Field(
        default=None,
        description="LLM-generated remediation guidance.",
        json_schema_extra={"example": ["Use parameterized queries and strict input validation."]},
    )
    mitre_id: Optional[str] = Field(
        default=None,
        description="Mapped MITRE ATT&CK technique identifier.",
        json_schema_extra={"example": ["T1190"]},
    )
    owasp_category: Optional[str] = Field(
        default=None,
        description="Mapped OWASP category.",
        json_schema_extra={"example": ["A03:2021-Injection"]},
    )
    detected_at: datetime = Field(
        ...,
        description="Timestamp when the finding was detected.",
        json_schema_extra={"example": ["2026-03-20T10:03:00Z"]},
    )

    model_config = ConfigDict(from_attributes=True)


class FindingsListResponse(BaseModel):
    findings: List[FindingResponse] = Field(
        ...,
        description="List of findings for the given filter scope.",
        json_schema_extra={"example": [[]]},
    )
    total: int = Field(
        ...,
        description="Total number of findings in the result set.",
        json_schema_extra={"example": [11]},
    )
    by_severity: Dict[str, int] = Field(
        ...,
        description="Severity distribution map.",
        json_schema_extra={"example": [{"critical": 2, "high": 5, "medium": 3, "low": 1, "info": 0}]},
    )


class EndpointResponse(BaseModel):
    id: UUID = Field(
        ...,
        description="Unique endpoint identifier.",
        json_schema_extra={"example": ["f650a6dc-790a-4d06-95c8-f0f9a1ce7472"]},
    )
    url: str = Field(
        ...,
        description="Endpoint URL path or absolute URL.",
        json_schema_extra={"example": ["https://example.com/api/users"]},
    )
    method: str = Field(
        ...,
        description="HTTP method used by the endpoint.",
        json_schema_extra={"example": ["POST"]},
    )
    params: List[Any] = Field(
        default_factory=list,
        description="Captured query parameter names or structures.",
        json_schema_extra={"example": [["q", "page"]]},
    )
    body_params: List[Any] = Field(
        default_factory=list,
        description="Captured form/body parameter names or structures.",
        json_schema_extra={"example": [["username", "password"]]},
    )
    auth_required: bool = Field(
        ...,
        description="Whether authentication is required to access the endpoint.",
        json_schema_extra={"example": [False]},
    )
    status_code: Optional[int] = Field(
        default=None,
        description="Observed HTTP status code.",
        json_schema_extra={"example": [200]},
    )
    discovered_at: datetime = Field(
        ...,
        description="Timestamp when endpoint was discovered.",
        json_schema_extra={"example": ["2026-03-20T10:01:00Z"]},
    )

    model_config = ConfigDict(from_attributes=True)
