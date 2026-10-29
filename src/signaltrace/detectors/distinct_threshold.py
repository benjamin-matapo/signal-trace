from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from signaltrace.detectors._common import _episodes, window
from signaltrace.models import Event, Finding


def detect(events: Sequence[Event], rule: Mapping[str, Any]) -> list[Finding]:
    by_ip: dict[str, list[int]] = defaultdict(list)
    for index, event in enumerate(events):
        if event.event_type == "login_failure":
            by_ip[event.src_ip].append(index)

    findings: list[Finding] = []
    duration = window(rule)
    for indices in by_ip.values():
        indices.sort(key=lambda index: events[index].timestamp)
        candidates: list[list[int]] = []
        end = 0
        for start in range(len(indices)):
            end = max(end, start)
            while (
                end < len(indices)
                and events[indices[end]].timestamp - events[indices[start]].timestamp
                <= duration
            ):
                end += 1
            window_indices = indices[start:end]
            if (
                len({events[index].user for index in window_indices})
                >= rule["params"]["count"]
            ):
                candidates.append(window_indices)
        findings.extend(_episodes(events, rule, candidates))
    return findings
