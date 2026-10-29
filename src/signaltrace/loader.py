import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from signaltrace.models import Event

_EVENT_TYPES = {
    "login_success",
    "login_failure",
    "mfa_denied",
    "mfa_approved",
}
_EVENT_FIELDS = ("user", "src_ip", "country", "role", "app")


@dataclass(frozen=True)
class LoadResult:
    events: list[Event]
    skipped_lines: int


def _parse_event(value: Any) -> Event | None:
    if not isinstance(value, dict):
        return None

    timestamp_value = value.get("timestamp")
    event_type = value.get("event_type")
    if (
        not isinstance(timestamp_value, str)
        or not isinstance(event_type, str)
        or event_type not in _EVENT_TYPES
    ):
        return None

    if any(not isinstance(value.get(field), str) for field in _EVENT_FIELDS):
        return None

    try:
        timestamp = datetime.fromisoformat(timestamp_value)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            return None
        timestamp = timestamp.astimezone(UTC)
    except (OverflowError, ValueError):
        return None

    return Event(
        timestamp=timestamp,
        event_type=event_type,
        user=value["user"],
        src_ip=value["src_ip"],
        country=value["country"],
        role=value["role"],
        app=value["app"],
    )


def load_events(path: str | Path) -> LoadResult:
    events: list[Event] = []
    skipped_lines = 0

    with Path(path).open(encoding="utf-8") as event_file:
        for line in event_file:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                skipped_lines += 1
                continue

            event = _parse_event(value)
            if event is None:
                skipped_lines += 1
                continue
            events.append(event)

    events.sort(key=lambda event: event.timestamp)
    return LoadResult(events=events, skipped_lines=skipped_lines)
