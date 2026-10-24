import re
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

Role = Literal["platform_admin", "security_analyst", "incident_responder", "auditor"]
AssetType = Literal["postgresql", "application", "api", "cloud_environment", "server", "identity_provider"]
Environment = Literal["production", "staging", "development", "test"]

_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]{0,253}[A-Za-z0-9])?$")
_DBNAME = re.compile(r"^[A-Za-z0-9_\-.]{1,120}$")
_SECRET_REF = re.compile(r"^[A-Za-z0-9/_.\-:]{1,200}$")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginIn(Strict):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    totp_code: str | None = Field(default=None, max_length=10)


class ChangePasswordIn(Strict):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class MfaConfirmIn(Strict):
    code: str = Field(max_length=10)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    email: str
    display_name: str
    role: str
    is_active: bool
    mfa_enabled: bool
    must_change_password: bool
    last_login_at: datetime | None
    created_at: datetime


class UserCreateIn(Strict):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=200)
    role: Role
    initial_password: str = Field(min_length=1, max_length=256)


class UserUpdateIn(Strict):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    role: Role | None = None
    is_active: bool | None = None


class PasswordResetIn(Strict):
    new_password: str = Field(min_length=1, max_length=256)


class AssetIn(Strict):
    name: str = Field(min_length=1, max_length=120)
    asset_type: AssetType
    environment: Environment
    description: str = Field(default="", max_length=1000)
    host: str | None = Field(default=None, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    database_name: str | None = Field(default=None, max_length=120)
    secret_ref: str | None = Field(default=None, max_length=200)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name is required")
        return v

    @field_validator("host")
    @classmethod
    def _host(cls, v: str | None) -> str | None:
        if v in (None, ""):
            return None
        if not _HOST.match(v):
            raise ValueError("host must be a hostname or IP address only")
        return v

    @field_validator("database_name")
    @classmethod
    def _db(cls, v: str | None) -> str | None:
        if v in (None, ""):
            return None
        if not _DBNAME.match(v):
            raise ValueError("database_name contains invalid characters")
        return v

    @field_validator("secret_ref")
    @classmethod
    def _ref(cls, v: str | None) -> str | None:
        if v in (None, ""):
            return None
        if not _SECRET_REF.match(v):
            raise ValueError("secret_ref must be the name of a secret in your secrets manager, never the secret itself")
        return v


class AssetUpdateIn(AssetIn):
    pass


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    asset_type: str
    environment: str
    description: str
    host: str | None
    port: int | None
    database_name: str | None
    secret_ref: str | None
    created_at: datetime
    updated_at: datetime
    # No telemetry exists in Milestone 1, and the API says so rather than implying coverage.
    monitoring_status: str = "not_configured"
    last_event_at: datetime | None = None


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    seq: int
    ts: datetime
    actor_user_id: uuid.UUID | None
    actor_label: str | None
    action: str
    outcome: str
    target_type: str | None
    target_id: str | None
    ip: str | None
    details: dict
    hash: str
