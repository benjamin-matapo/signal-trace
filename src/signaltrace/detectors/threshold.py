from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from signaltrace.detectors._common import _episodes, window
from signaltrace.models import Event, Finding


def detect(events: Sequence[Event], rule: Mapping[str, Any]) -> list[Finding]:
    params = rule["params"]
    fields = params["group_by"]
    groups: dict[tuple[object, ...], list[int]] = defaultdict(list)
    for index, event in enumerate(events):
        if event.event_type == params["event_type"]:
            groups[tuple(getattr(event, field) for field in fields)].append(index)

    findings: list[Finding] = []
    duration = window(rule)
    for indices in groups.values():
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
            if end - start >= params["count"]:
                candidates.append(indices[start:end])
        findings.extend(_episodes(events, rule, candidates))
    return findings
