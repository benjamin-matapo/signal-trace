import json
from pathlib import Path

from signaltrace.engine import load_rules, run
from signaltrace.generator import generate_dataset
from signaltrace.loader import load_events

ROOT = Path(__file__).parents[1]


def test_seed_42_sample_matches_every_truth_scenario(tmp_path) -> None:
    generated_path = tmp_path / "sample.jsonl"
    generate_dataset(generated_path, seed=42)
    events = load_events(generated_path).events
    truth = json.loads((ROOT / "data/sample.truth.json").read_text(encoding="utf-8"))
    findings = run(events, load_rules(ROOT / "rules"))

    truth_rules = {
        (scenario["expected_rule_id"], scenario["user"], scenario["src_ip"])
        for scenario in truth
    }
    truth_users = {scenario["user"] for scenario in truth}
    truth_ips = {scenario["src_ip"] for scenario in truth}
    missing = [
        (rule_id, user, src_ip)
        for rule_id, user, src_ip in sorted(truth_rules)
        if not any(
            finding.rule_id == rule_id
            and user in {event.user for event in finding.evidence}
            and src_ip in {event.src_ip for event in finding.evidence}
            for finding in findings
        )
    ]
    false_positives = [
        finding
        for finding in findings
        if (finding.user is not None and finding.user not in truth_users)
        or (finding.src_ip is not None and finding.src_ip not in truth_ips)
    ]
    false_positive_names = [
        (
            f"{finding.rule_id} user={finding.user or '<multiple>'} "
            f"src_ip={finding.src_ip or '<multiple>'}"
        )
        for finding in false_positives
    ]
    assert not missing and not false_positives, (
        f"Missing scenarios: {missing}; false positives: "
        f"{'; '.join(false_positive_names) or 'none'}"
    )
