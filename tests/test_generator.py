import json
from collections import Counter
from datetime import datetime

from signaltrace.generator import generate_dataset


def test_same_seed_generates_identical_files(tmp_path) -> None:
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"

    first_truth = generate_dataset(first, seed=42)
    second_truth = generate_dataset(second, seed=42)

    assert first.read_bytes() == second.read_bytes()
    assert first_truth.read_bytes() == second_truth.read_bytes()


def test_different_seeds_generate_different_files(tmp_path) -> None:
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"

    generate_dataset(first, seed=42)
    generate_dataset(second, seed=43)

    assert first.read_bytes() != second.read_bytes()


def test_generator_injects_five_truth_scenarios(tmp_path) -> None:
    output = tmp_path / "sample.jsonl"
    truth_path = generate_dataset(output, seed=42)

    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    events = [
        json.loads(line)
        for line in output.read_text(encoding="utf-8").splitlines()
    ]
    assert len(truth) == 5
    assert {scenario["scenario_name"] for scenario in truth} == {
        "brute_force",
        "password_spraying",
        "compromise_after_failures",
        "impossible_travel",
        "mfa_fatigue",
    }
    assert all(
        set(scenario) == {"scenario_name", "user", "src_ip", "expected_rule_id"}
        for scenario in truth
    )

    scenarios = {scenario["scenario_name"]: scenario for scenario in truth}
    brute = scenarios["brute_force"]
    brute_events = [
        event
        for event in events
        if event["user"] == brute["user"]
        and event["src_ip"] == brute["src_ip"]
        and event["event_type"] == "login_failure"
    ]
    assert len(brute_events) == 12
    assert (
        datetime.fromisoformat(brute_events[-1]["timestamp"])
        - datetime.fromisoformat(brute_events[0]["timestamp"])
    ).total_seconds() <= 180

    spray = scenarios["password_spraying"]
    spray_counts = Counter(
        event["user"]
        for event in events
        if event["src_ip"] == spray["src_ip"]
        and event["event_type"] == "login_failure"
    )
    assert len(spray_counts) == 8
    assert all(count in {1, 2} for count in spray_counts.values())

    compromise = scenarios["compromise_after_failures"]
    compromise_events = [
        event
        for event in events
        if event["user"] == compromise["user"]
        and event["src_ip"] == compromise["src_ip"]
    ]
    assert [event["event_type"] for event in compromise_events].count(
        "login_failure"
    ) == 7
    assert [event["event_type"] for event in compromise_events].count(
        "login_success"
    ) == 1

    travel = scenarios["impossible_travel"]
    br_event = next(
        event
        for event in events
        if event["user"] == travel["user"] and event["src_ip"] == travel["src_ip"]
    )
    gb_event = next(
        event
        for event in events
        if event["user"] == travel["user"]
        and event["country"] == "GB"
        and (
            datetime.fromisoformat(br_event["timestamp"])
            - datetime.fromisoformat(event["timestamp"])
        ).total_seconds()
        == 1200
    )
    assert br_event["country"] == "BR"
    assert gb_event["country"] == "GB"

    mfa = scenarios["mfa_fatigue"]
    mfa_events = [
        event
        for event in events
        if event["user"] == mfa["user"] and event["src_ip"] == mfa["src_ip"]
    ]
    assert [event["event_type"] for event in mfa_events].count("mfa_denied") == 7
    assert [event["event_type"] for event in mfa_events].count("mfa_approved") == 1
