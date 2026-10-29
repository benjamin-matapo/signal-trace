from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from signaltrace.detectors import DETECTORS
from signaltrace.models import Event, Finding

_REQUIRED_FIELDS = {
    "id",
    "title",
    "description",
    "severity",
    "type",
    "params",
    "attack",
    "recommended_actions",
    "false_positive_notes",
}
_ATTACK_FIELDS = {"technique_id", "technique_name", "tactic"}
_SEVERITIES = {"low", "medium", "high", "critical"}
_EVENT_FIELDS = {"timestamp", "event_type", "user", "src_ip", "country", "role", "app"}
_EVENT_TYPES = {"login_success", "login_failure", "mfa_denied", "mfa_approved"}
_PARAM_FIELDS = {
    "threshold": {"event_type", "count", "group_by", "window_minutes"},
    "distinct_threshold": {"count", "window_minutes"},
    "success_after_failures": {"count", "window_minutes"},
    "impossible_travel": {"window_minutes"},
    "mfa_fatigue": {"count", "window_minutes"},
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _validate_rule(rule: Any, source: str) -> dict[str, Any]:
    if not isinstance(rule, dict):
        raise TypeError(f"{source}: rule must be a YAML mapping")

    missing = _REQUIRED_FIELDS - rule.keys()
    if missing:
        raise ValueError(
            f"{source}: missing required fields: {', '.join(sorted(missing))}"
        )

    for field in ("id", "title", "description", "false_positive_notes"):
        if not isinstance(rule[field], str) or not rule[field].strip():
            raise ValueError(f"{source}: {field} must be a non-empty string")
    if not isinstance(rule["severity"], str) or rule["severity"] not in _SEVERITIES:
        raise ValueError(
            f"{source}: severity must be one of {', '.join(sorted(_SEVERITIES))}"
        )

    rule_type = rule["type"]
    if not isinstance(rule_type, str) or rule_type not in DETECTORS:
        raise ValueError(
            f"{source}: unknown rule type {rule_type!r}; "
            f"expected one of {', '.join(sorted(DETECTORS))}"
        )

    params = rule["params"]
    if not isinstance(params, dict):
        raise TypeError(f"{source}: params must be a mapping")
    expected_params = _PARAM_FIELDS[rule_type]
    missing_params = expected_params - params.keys()
    if missing_params:
        raise ValueError(
            f"{source}: type {rule_type!r} missing params: "
            f"{', '.join(sorted(missing_params))}"
        )
    unexpected_params = params.keys() - expected_params
    if unexpected_params:
        raise ValueError(
            f"{source}: type {rule_type!r} has unknown params: "
            f"{', '.join(sorted(unexpected_params))}"
        )

    if "count" in expected_params and (
        type(params["count"]) is not int or params["count"] < 1
    ):
        raise ValueError(f"{source}: params.count must be a positive integer")
    if type(params["window_minutes"]) is not int or params["window_minutes"] < 1:
        raise ValueError(f"{source}: params.window_minutes must be a positive integer")
    if "event_type" in expected_params and (
        not isinstance(params["event_type"], str)
        or params["event_type"] not in _EVENT_TYPES
    ):
        raise ValueError(
            f"{source}: params.event_type must be one of "
            f"{', '.join(sorted(_EVENT_TYPES))}"
        )
    if "group_by" in expected_params:
        fields = params["group_by"]
        if (
            not isinstance(fields, list)
            or not fields
            or any(
                not isinstance(field, str) or field not in _EVENT_FIELDS
                for field in fields
            )
        ):
            raise ValueError(
                f"{source}: params.group_by must be a non-empty list of event fields"
            )
        if len(set(fields)) != len(fields):
            raise ValueError(f"{source}: params.group_by fields must be unique")

    attack = rule["attack"]
    if not isinstance(attack, dict):
        raise TypeError(f"{source}: attack must be a mapping")
    missing_attack = _ATTACK_FIELDS - attack.keys()
    if missing_attack:
        raise ValueError(
            f"{source}: attack missing fields: {', '.join(sorted(missing_attack))}"
        )
    for field in _ATTACK_FIELDS:
        if not isinstance(attack[field], str) or not attack[field].strip():
            raise ValueError(f"{source}: attack.{field} must be a non-empty string")

    actions = rule["recommended_actions"]
    if not isinstance(actions, list) or any(
        not isinstance(action, str) or not action.strip() for action in actions
    ):
        raise ValueError(f"{source}: recommended_actions must be a list of strings")

    return rule


def load_rules(directory: str | Path) -> list[dict[str, Any]]:
    rule_directory = Path(directory)
    if not rule_directory.is_dir():
        raise FileNotFoundError(f"rule directory does not exist: {rule_directory}")

    rules: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for path in sorted((*rule_directory.glob("*.yaml"), *rule_directory.glob("*.yml"))):
        try:
            with path.open(encoding="utf-8") as rule_file:
                data = yaml.safe_load(rule_file)
        except yaml.YAMLError as error:
            raise ValueError(f"{path}: invalid YAML: {error}") from error

        rule = _validate_rule(data, str(path))
        if rule["id"] in seen_ids:
            raise ValueError(f"{path}: duplicate rule id {rule['id']!r}")
        seen_ids.add(rule["id"])
        rules.append(rule)
    return rules


def run(
    events: Sequence[Event],
    rules: Sequence[Mapping[str, Any]],
) -> list[Finding]:
    findings: list[Finding] = []
    for index, input_rule in enumerate(rules):
        rule = _validate_rule(dict(input_rule), f"rule #{index + 1}")
        findings.extend(DETECTORS[rule["type"]](events, rule))
    return sorted(
        findings,
        key=lambda finding: (
            _SEVERITY_ORDER[finding.severity],
            finding.first_seen,
            finding.rule_id,
        ),
    )
