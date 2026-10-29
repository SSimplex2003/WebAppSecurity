import re
from datetime import datetime, timezone
from typing import Annotated

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    StringConstraints,
    field_serializer,
    field_validator,
)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL_RE = re.compile(r"^https?://\S+$", re.IGNORECASE)

MIN_MASTER_PASSWORD_LENGTH = 12
MAX_MASTER_PASSWORD_LENGTH = 128


def _check_email(value: str) -> str:
    if not _EMAIL_RE.match(value):
        raise ValueError("Enter a valid email address")
    return value


def _check_new_master_password(value: str) -> str:
    if len(value) < MIN_MASTER_PASSWORD_LENGTH:
        raise ValueError(f"must be at least {MIN_MASTER_PASSWORD_LENGTH} characters")
    return value


Email = Annotated[
    str,
    StringConstraints(strip_whitespace=True, to_lower=True, max_length=254),
    AfterValidator(_check_email),
]
NewMasterPassword = Annotated[
    str,
    StringConstraints(max_length=MAX_MASTER_PASSWORD_LENGTH),
    AfterValidator(_check_new_master_password),
]
LoginPassword = Annotated[
    str, StringConstraints(min_length=1, max_length=MAX_MASTER_PASSWORD_LENGTH)
]


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: Email
    master_password: NewMasterPassword


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: Email
    master_password: LoginPassword


class ItemIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
    username: Annotated[str, StringConstraints(max_length=200)] = ""
    password: Annotated[str, StringConstraints(max_length=1000)] = ""
    url: Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000)] = ""
    notes: Annotated[str, StringConstraints(max_length=5000)] = ""

    @field_validator("url")
    @classmethod
    def _http_url_only(cls, value: str) -> str:
        if value and not _URL_RE.match(value):
            raise ValueError("must start with http:// or https://")
        return value


class ItemOut(BaseModel):
    id: int
    title: str
    username: str
    password: str
    url: str
    notes: str
    created_at: datetime
    updated_at: datetime

    @field_serializer("created_at", "updated_at")
    def _as_utc_iso(self, value: datetime) -> str:
        return value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
