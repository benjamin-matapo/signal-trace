from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from signaltrace.models import Event, Finding


def _rule_metadata(rule: Mapping[str, Any]) -> dict[str, Any]:
    attack = rule["attack"]
    return {
        "rule_id": rule["id"],
        "title": rule["title"],
        "severity": rule["severity"],
        "technique_id": attack["technique_id"],
        "technique_name": attack["technique_name"],
        "tactic": attack["tactic"],
        "description": rule["description"],
        "recommended_actions": rule["recommended_actions"],
        "false_positive_notes": rule["false_positive_notes"],
    }


def _episodes(
    events: Sequence[Event],
    rule: Mapping[str, Any],
    candidates: list[list[int]],
) -> list[Finding]:
    ordered = sorted(
        (
            (
                min(events[index].timestamp for index in candidate),
                max(events[index].timestamp for index in candidate),
                candidate,
            )
            for candidate in candidates
            if candidate
        ),
        key=lambda item: (item[0], item[1]),
    )
    merged: list[tuple[list[int], datetime]] = []
    current_indices: list[int] = []
    current_end: datetime | None = None

    for start, end, indices in ordered:
        if current_end is None or start > current_end:
            if current_indices:
                merged.append((current_indices, current_end))
            current_indices = list(indices)
            current_end = end
        else:
            current_indices.extend(indices)
            current_end = max(current_end, end)
    if current_indices:
        merged.append((current_indices, current_end))

    findings: list[Finding] = []
    metadata = _rule_metadata(rule)
    for indices, _ in merged:
        unique_indices = sorted(
            set(indices),
            key=lambda index: (events[index].timestamp, index),
        )
        evidence = [events[index] for index in unique_indices]
        users = {event.user for event in evidence}
        source_ips = {event.src_ip for event in evidence}
        findings.append(
            Finding(
                **metadata,
                user=next(iter(users)) if len(users) == 1 else None,
                src_ip=next(iter(source_ips)) if len(source_ips) == 1 else None,
                first_seen=evidence[0].timestamp,
                last_seen=evidence[-1].timestamp,
                event_count=len(evidence),
                evidence=evidence,
            )
        )
    return findings


def window(rule: Mapping[str, Any]) -> timedelta:
    return timedelta(minutes=rule["params"]["window_minutes"])
