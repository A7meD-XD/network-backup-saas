import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class DeviceCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    ip_address: str = Field(min_length=1, max_length=45)
    device_type: str = Field(min_length=1, max_length=100, examples=["cisco_ios"])
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1)
    ssh_port: int = Field(default=22, ge=1, le=65535)


class DeviceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    ip_address: str
    device_type: str
    username: str
    ssh_port: int


class RestoreRequest(BaseModel):
    backup_id: int | None = Field(default=None, gt=0)


class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    role: Literal["Admin", "Viewer"] = "Viewer"

    @field_validator("password")
    @classmethod
    def limit_bcrypt_password_bytes(cls, password: str) -> str:
        if len(password.encode("utf-8")) > 72:
            raise ValueError("Password must be no longer than 72 UTF-8 bytes for bcrypt.")
        return password


class UserRead(BaseModel):
    id: int
    email: EmailStr
    role: Literal["Admin", "Viewer"]


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: Literal["Admin", "Viewer"]


class BulkCommandRequest(BaseModel):
    device_ids: list[int] = Field(min_length=1, max_length=50)
    commands: list[str] = Field(min_length=1, max_length=20)

    @field_validator("device_ids")
    @classmethod
    def validate_unique_device_ids(cls, device_ids: list[int]) -> list[int]:
        if any(device_id <= 0 for device_id in device_ids):
            raise ValueError("Device IDs must be positive integers.")
        if len(device_ids) != len(set(device_ids)):
            raise ValueError("Device IDs must not contain duplicates.")
        return device_ids

    @field_validator("commands")
    @classmethod
    def validate_commands(cls, commands: list[str]) -> list[str]:
        cleaned = [command.strip() for command in commands]
        if any(not command or len(command) > 300 for command in cleaned):
            raise ValueError("Commands must contain 1-300 non-whitespace characters.")
        if any("\n" in command or "\r" in command for command in cleaned):
            raise ValueError("Each list item must contain exactly one CLI command.")
        return cleaned


class ComplianceRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=1000)
    pattern: str = Field(min_length=1, max_length=1000)
    remediation: str = Field(min_length=1, max_length=1000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, pattern: str) -> str:
        try:
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as exc:
            raise ValueError("Compliance pattern must be a valid Python regular expression.") from exc
        return pattern


class ComplianceRuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    pattern: str
    remediation: str
    severity: str
    enabled: bool
