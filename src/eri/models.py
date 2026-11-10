"""Wire format for result submissions.

Validation is strict on purpose: no type coercion ("5" is not 5), no unknown
fields. Anything ambiguous is rejected instead of being "fixed" silently.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"
NONCE_PATTERN = r"^[0-9a-f]{32}$"


class ResultPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    version: Literal[1]
    election_id: str = Field(pattern=ID_PATTERN)
    station_id: str = Field(pattern=ID_PATTERN)
    device_id: str = Field(pattern=ID_PATTERN)
    sequence: int = Field(ge=1)
    issued_at: str = Field(max_length=40)
    nonce: str = Field(pattern=NONCE_PATTERN)
    ballots_cast: int = Field(ge=0)
    invalid_ballots: int = Field(ge=0)
    votes: dict[str, int] = Field(max_length=100)

    @field_validator("issued_at")
    @classmethod
    def _timezone_aware_iso(cls, value: str) -> str:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            raise ValueError("issued_at must include a timezone offset")
        return value

    @field_validator("votes")
    @classmethod
    def _non_negative_votes(cls, value: dict[str, int]) -> dict[str, int]:
        if any(n < 0 for n in value.values()):
            raise ValueError("vote counts must be non-negative")
        return value

    def issued_at_dt(self) -> datetime:
        return datetime.fromisoformat(self.issued_at)


class Envelope(BaseModel):
    """What a scanner POSTs: the payload exactly as signed, plus the signature.

    `payload` is kept as a raw dict so the signature is checked over exactly
    what the device sent, before any parsing or normalisation.
    """

    model_config = ConfigDict(extra="forbid")

    payload: dict[str, Any]
    signature: str = Field(max_length=200)
