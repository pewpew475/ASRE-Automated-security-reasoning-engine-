from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator


class RegisterRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        description="Email address used for account registration.",
        json_schema_extra={"example": "user@example.com"},
    )
    password: str = Field(
        ...,
        min_length=8,
        description="Account password with complexity requirements.",
        json_schema_extra={"example": "Securepass123"},
    )
    full_name: Optional[str] = Field(
        default=None,
        description="Optional display name for the user profile.",
        json_schema_extra={"example": "Alice Dev"},
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(char.isdigit() for char in value):
            raise ValueError("Password must contain at least one digit")
        if not any(char.isupper() for char in value):
            raise ValueError("Password must contain at least one uppercase letter")
        return value


class LoginRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        description="Email address for user login.",
        json_schema_extra={"example": "user@example.com"},
    )
    password: str = Field(
        ...,
        description="Plaintext password submitted during login.",
        json_schema_extra={"example": "Securepass123"},
    )


class TokenResponse(BaseModel):
    access_token: str = Field(
        ...,
        description="Signed JWT access token.",
        json_schema_extra={"example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.access"},
    )
    refresh_token: str = Field(
        ...,
        description="Signed JWT refresh token.",
        json_schema_extra={"example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.refresh"},
    )
    token_type: str = Field(
        default="bearer",
        description="OAuth2 token type.",
        json_schema_extra={"example": "bearer"},
    )
    expires_in: int = Field(
        ...,
        description="Access token lifetime in seconds.",
        json_schema_extra={"example": 3600},
    )


class RefreshRequest(BaseModel):
    refresh_token: str = Field(
        ...,
        description="Refresh token used to obtain a new access token.",
        json_schema_extra={"example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.refresh"},
    )


class UserResponse(BaseModel):
    id: UUID = Field(
        ...,
        description="Unique user identifier.",
        json_schema_extra={"example": "1c4f34ba-3934-4ff8-86bd-c5a57888529e"},
    )
    email: EmailStr = Field(
        ...,
        description="User email address.",
        json_schema_extra={"example": "user@example.com"},
    )
    full_name: Optional[str] = Field(
        default=None,
        description="Optional user full name.",
        json_schema_extra={"example": "Alice Dev"},
    )
    created_at: datetime = Field(
        ...,
        description="Timestamp when the user account was created.",
        json_schema_extra={"example": "2026-03-20T10:00:00Z"},
    )

    model_config = ConfigDict(from_attributes=True)
