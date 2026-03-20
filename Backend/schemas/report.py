from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator


class GenerateReportRequest(BaseModel):
    format: Literal["pdf"] = Field(
        default="pdf",
        description="Output report format. Currently only PDF is supported.",
        json_schema_extra={"example": ["pdf"]},
    )
    include_poc: bool = Field(
        default=True,
        description="Whether proof-of-concept payload details are included.",
        json_schema_extra={"example": [True]},
    )
    include_graph: bool = Field(
        default=True,
        description="Whether attack-chain graph sections are included.",
        json_schema_extra={"example": [True]},
    )


class ReportResponse(BaseModel):
    id: UUID = Field(
        ...,
        description="Unique report identifier.",
        json_schema_extra={"example": ["209564eb-2352-4688-ba4a-47c1f7ea7932"]},
    )
    scan_id: UUID = Field(
        ...,
        description="Related scan identifier.",
        json_schema_extra={"example": ["1086de2a-6d96-468b-84e8-4768c7f04979"]},
    )
    format: str = Field(
        ...,
        description="Generated report format.",
        json_schema_extra={"example": ["pdf"]},
    )
    file_path: Optional[str] = Field(
        default=None,
        description="Filesystem path or object storage key for the generated report.",
        json_schema_extra={"example": ["./reports/scan-1086de2a.pdf"]},
    )
    generated_at: datetime = Field(
        ...,
        description="Timestamp when the report was generated.",
        json_schema_extra={"example": ["2026-03-20T10:10:00Z"]},
    )
    total_findings: int = Field(
        ...,
        description="Total finding count included in the report.",
        json_schema_extra={"example": [12]},
    )
    critical_count: int = Field(
        ...,
        description="Count of critical findings.",
        json_schema_extra={"example": [1]},
    )
    high_count: int = Field(
        ...,
        description="Count of high findings.",
        json_schema_extra={"example": [4]},
    )
    medium_count: int = Field(
        ...,
        description="Count of medium findings.",
        json_schema_extra={"example": [3]},
    )
    low_count: int = Field(
        ...,
        description="Count of low findings.",
        json_schema_extra={"example": [2]},
    )
    info_count: int = Field(
        ...,
        description="Count of informational findings.",
        json_schema_extra={"example": [2]},
    )
    executive_summary: Optional[str] = Field(
        default=None,
        description="LLM-generated executive summary text.",
        json_schema_extra={"example": ["The application presents moderate risk with one critical injection path."]},
    )

    model_config = ConfigDict(from_attributes=True)


class ReportGenerateResponse(BaseModel):
    report_id: UUID = Field(
        ...,
        description="Identifier of the report job/output record.",
        json_schema_extra={"example": ["209564eb-2352-4688-ba4a-47c1f7ea7932"]},
    )
    status: str = Field(
        default="generating",
        description="Current generation job status.",
        json_schema_extra={"example": ["generating"]},
    )
    message: str = Field(
        default="Report generation queued",
        description="Human-readable response message.",
        json_schema_extra={"example": ["Report generation queued"]},
    )
