from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

EventType = Literal[
    "login_success",
    "login_failure",
    "mfa_denied",
    "mfa_approved",
]
Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    event_type: EventType
    user: str
    src_ip: str
    country: str
    role: str
    app: str

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        object.__setattr__(self, "timestamp", self.timestamp.astimezone(UTC))


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    technique_id: str
    technique_name: str
    tactic: str
    user: str | None
    src_ip: str | None
    first_seen: datetime
    last_seen: datetime
    event_count: int
    evidence: list[Event]
    description: str
    recommended_actions: list[str]
    false_positive_notes: str

    def __post_init__(self) -> None:
        if self.severity not in {"low", "medium", "high", "critical"}:
            raise ValueError(f"unsupported severity: {self.severity}")
