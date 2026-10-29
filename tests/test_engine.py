import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from signaltrace.engine import load_rules, run
from signaltrace.generator import generate_dataset
from signaltrace.loader import load_events
from signaltrace.models import Event

RULES_DIRECTORY = Path(__file__).parents[1] / "rules"


def _event(
    minute: int,
    event_type: str,
    user: str = "alice",
    src_ip: str = "192.0.2.1",
    country: str = "GB",
) -> Event:
    return Event(
        timestamp=datetime(2026, 10, 29, 12, minute, tzinfo=UTC),
        event_type=event_type,
        user=user,
        src_ip=src_ip,
        country=country,
        role="employee",
        app="Example Portal",
    )


def test_loads_all_default_rules() -> None:
    rules = load_rules(RULES_DIRECTORY)

    assert [rule["id"] for rule in rules] == [
        "ST-001",
        "ST-002",
        "ST-003",
        "ST-004",
        "ST-005",
    ]


def test_run_detects_all_default_rules_in_generated_sample(tmp_path) -> None:
    output = tmp_path / "events.jsonl"
    truth_path = generate_dataset(output, seed=42)
    events = load_events(output).events
    expected_ids = {
        entry["expected_rule_id"]
        for entry in json.loads(truth_path.read_text(encoding="utf-8"))
    }

    findings = run(events, load_rules(RULES_DIRECTORY))

    assert len(findings) == len(expected_ids)
    assert {finding.rule_id for finding in findings} == expected_ids


def test_threshold_merges_overlapping_windows_into_one_finding() -> None:
    events = [
        _event(minute=minute // 2, event_type="login_failure") for minute in range(24)
    ]
    rule = next(rule for rule in load_rules(RULES_DIRECTORY) if rule["id"] == "ST-001")

    findings = run(events, [rule])

    assert len(findings) == 1
    assert findings[0].event_count == 24
    assert findings[0].user == "alice"
    assert findings[0].src_ip == "192.0.2.1"


def test_run_orders_findings_by_severity_then_time() -> None:
    rules = load_rules(RULES_DIRECTORY)
    events = [
        *[_event(minute=minute, event_type="login_failure") for minute in range(5)],
        _event(7, "login_success"),
        *[
            _event(minute=minute, event_type="login_failure", user="bob")
            for minute in range(10, 15)
            for _ in range(2)
        ],
    ]
    findings = run(events, rules)

    assert [finding.severity for finding in findings] == ["critical", "medium"]
    assert findings[0].first_seen < findings[1].first_seen


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (
            (
                "id: bad\ntitle: Bad\ndescription: bad\nseverity: medium\ntype: unknown\n"
                "params: {}\nattack: {technique_id: T1, technique_name: Bad, tactic: Test}\n"
                "recommended_actions: []\nfalse_positive_notes: none\n"
            ),
            "unknown rule type",
        ),
        (
            (
                "id: bad\ntitle: Bad\ndescription: bad\nseverity: medium\n"
                "type: threshold\nparams: {event_type: login_failure}\n"
                "attack: {technique_id: T1, technique_name: Bad, tactic: Test}\n"
                "recommended_actions: []\nfalse_positive_notes: none\n"
            ),
            "missing params",
        ),
    ],
)
def test_load_rules_rejects_invalid_rule_params(tmp_path, content, message) -> None:
    (tmp_path / "bad.yaml").write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        load_rules(tmp_path)
