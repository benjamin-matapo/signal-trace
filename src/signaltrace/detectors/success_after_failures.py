from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from signaltrace.detectors._common import _episodes, window
from signaltrace.models import Event, Finding


def detect(events: Sequence[Event], rule: Mapping[str, Any]) -> list[Finding]:
    failures_by_ip: dict[str, list[int]] = defaultdict(list)
    successes_by_ip: dict[str, list[int]] = defaultdict(list)
    for index, event in enumerate(events):
        if event.event_type == "login_failure":
            failures_by_ip[event.src_ip].append(index)
        elif event.event_type == "login_success":
            successes_by_ip[event.src_ip].append(index)

    findings: list[Finding] = []
    duration = window(rule)
    threshold = rule["params"]["count"]
    for src_ip, successes in successes_by_ip.items():
        failures = failures_by_ip.get(src_ip, [])
        failures.sort(key=lambda index: events[index].timestamp)
        candidates: list[list[int]] = []
        for success_index in successes:
            success_time = events[success_index].timestamp
            preceding = [
                index
                for index in failures
                if events[index].timestamp < success_time
                and success_time - events[index].timestamp <= duration
            ]
            if len(preceding) >= threshold:
                candidates.append([*preceding, success_index])
        findings.extend(_episodes(events, rule, candidates))
    return findings
