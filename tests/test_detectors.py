from datetime import UTC, datetime, timedelta
from pathlib import Path

from signaltrace.detectors import (
    distinct_threshold,
    impossible_travel,
    mfa_fatigue,
    success_after_failures,
    threshold,
)
from signaltrace.engine import load_rules
from signaltrace.models import Event

RULES_DIRECTORY = Path(__file__).parents[1] / "rules"
RULES = {rule["id"]: rule for rule in load_rules(RULES_DIRECTORY)}
START = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def _event(
    seconds: int,
    event_type: str,
    *,
    user: str = "alice",
    src_ip: str = "192.0.2.10",
    country: str = "GB",
) -> Event:
    return Event(
        timestamp=START + timedelta(seconds=seconds),
        event_type=event_type,
        user=user,
        src_ip=src_ip,
        country=country,
        role="employee",
        app="Example Portal",
    )


def test_threshold_above_below_and_at_window_edge() -> None:
    detect = threshold.detect
    rule = RULES["ST-001"]
    above = [_event(second, "login_failure") for second in range(11)]
    below = [_event(second, "login_failure") for second in range(9)]
    at_edge = [
        _event(second, "login_failure")
        for second in (0, 30, 60, 90, 120, 150, 180, 210, 240, 300)
    ]

    assert len(detect(above, rule)) == 1
    assert detect(below, rule) == []
    boundary_findings = detect(at_edge, rule)
    assert len(boundary_findings) == 1
    assert boundary_findings[0].event_count == 10
    assert boundary_findings[0].last_seen - boundary_findings[
        0
    ].first_seen == timedelta(minutes=5)


def test_distinct_threshold_above_below_and_at_window_edge() -> None:
    detect = distinct_threshold.detect
    rule = RULES["ST-002"]
    above = [_event(index, "login_failure", user=f"user{index}") for index in range(6)]
    below = [_event(index, "login_failure", user=f"user{index}") for index in range(4)]
    at_edge = [
        _event(
            second,
            "login_failure",
            user=f"user{index}",
        )
        for index, second in enumerate((0, 120, 240, 360, 600))
    ]

    assert len(detect(above, rule)) == 1
    assert detect(below, rule) == []
    boundary_findings = detect(at_edge, rule)
    assert len(boundary_findings) == 1
    assert boundary_findings[0].last_seen - boundary_findings[
        0
    ].first_seen == timedelta(minutes=10)


def test_success_after_failures_above_below_and_at_window_edge() -> None:
    detect = success_after_failures.detect
    rule = RULES["ST-003"]
    above = [
        *[_event(second, "login_failure") for second in range(6)],
        _event(60, "login_success"),
    ]
    below = [
        *[_event(second, "login_failure") for second in range(4)],
        _event(60, "login_success"),
    ]
    at_edge = [
        *[_event(second, "login_failure") for second in (0, 60, 120, 180, 300)],
        _event(600, "login_success"),
    ]

    assert len(detect(above, rule)) == 1
    assert detect(below, rule) == []
    boundary_findings = detect(at_edge, rule)
    assert len(boundary_findings) == 1
    assert boundary_findings[0].last_seen - boundary_findings[
        0
    ].first_seen == timedelta(minutes=10)


def test_impossible_travel_above_below_and_at_window_edge() -> None:
    detect = impossible_travel.detect
    rule = RULES["ST-004"]
    above = [
        _event(0, "login_success", country="GB"),
        _event(60, "login_success", country="FR"),
        _event(120, "login_success", country="BR"),
    ]
    below = [
        _event(0, "login_success", country="GB"),
        _event(60, "login_success", country="GB"),
    ]
    at_edge = [
        _event(0, "login_success", country="GB"),
        _event(3600, "login_success", country="BR"),
    ]

    assert len(detect(above, rule)) == 1
    assert detect(below, rule) == []
    boundary_findings = detect(at_edge, rule)
    assert len(boundary_findings) == 1
    assert boundary_findings[0].last_seen - boundary_findings[
        0
    ].first_seen == timedelta(minutes=60)


def test_mfa_fatigue_above_below_and_at_window_edge() -> None:
    detect = mfa_fatigue.detect
    rule = RULES["ST-005"]
    above = [
        *[_event(second, "mfa_denied") for second in range(6)],
        _event(60, "mfa_approved"),
    ]
    below = [
        *[_event(second, "mfa_denied") for second in range(4)],
        _event(60, "mfa_approved"),
    ]
    at_edge = [
        *[_event(second, "mfa_denied") for second in (0, 60, 120, 180, 300)],
        _event(600, "mfa_approved"),
    ]

    assert len(detect(above, rule)) == 1
    assert detect(below, rule) == []
    boundary_findings = detect(at_edge, rule)
    assert len(boundary_findings) == 1
    assert boundary_findings[0].last_seen - boundary_findings[
        0
    ].first_seen == timedelta(minutes=10)
