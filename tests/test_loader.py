import json
from datetime import UTC, datetime

from signaltrace.loader import load_events


def _event(
    timestamp: str = "2026-10-29T12:00:00Z",
    event_type: str = "login_success",
) -> dict[str, str]:
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "user": "alice",
        "src_ip": "192.0.2.1",
        "country": "GB",
        "role": "analyst",
        "app": "portal",
    }


def test_loads_valid_event(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps(_event()) + "\n", encoding="utf-8")

    result = load_events(path)

    assert result.skipped_lines == 0
    assert len(result.events) == 1
    assert result.events[0].timestamp == datetime(
        2026, 10, 29, 12, 0, tzinfo=UTC
    )
    assert result.events[0].event_type == "login_success"
    assert result.events[0].user == "alice"


def test_skips_malformed_lines_and_counts_them(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    valid = json.dumps(_event())
    missing_field = _event()
    del missing_field["app"]
    bad_timestamp = _event(timestamp="not-a-timestamp")
    naive_timestamp = _event(timestamp="2026-10-29T12:00:00")
    overflow_timestamp = _event(timestamp="9999-12-31T23:59:59-23:59")
    unknown_type = _event(event_type="password_reset")
    path.write_text(
        "\n".join(
            [
                valid,
                "{not valid json",
                json.dumps(missing_field),
                json.dumps(bad_timestamp),
                json.dumps(naive_timestamp),
                json.dumps(overflow_timestamp),
                json.dumps(unknown_type),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = load_events(path)

    assert len(result.events) == 1
    assert result.skipped_lines == 6


def test_sorts_events_by_timestamp(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps(_event("2026-10-29T14:00:00Z")),
                json.dumps(_event("2026-10-29T11:00:00Z", "login_failure")),
                json.dumps(_event("2026-10-29T13:00:00Z", "mfa_approved")),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = load_events(path)

    assert [event.timestamp.hour for event in result.events] == [11, 13, 14]
