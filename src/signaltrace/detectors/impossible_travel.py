from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from signaltrace.detectors._common import _episodes, window
from signaltrace.models import Event, Finding


def detect(events: Sequence[Event], rule: Mapping[str, Any]) -> list[Finding]:
    successes_by_user: dict[str, list[int]] = defaultdict(list)
    for index, event in enumerate(events):
        if event.event_type == "login_success":
            successes_by_user[event.user].append(index)

    findings: list[Finding] = []
    duration = window(rule)
    for indices in successes_by_user.values():
        indices.sort(key=lambda index: events[index].timestamp)
        candidates: list[list[int]] = []
        for later_position, later_index in enumerate(indices):
            later = events[later_index]
            for earlier_index in indices[:later_position]:
                earlier = events[earlier_index]
                if (
                    earlier.country != later.country
                    and later.timestamp - earlier.timestamp <= duration
                ):
                    candidates.append([earlier_index, later_index])
        findings.extend(_episodes(events, rule, candidates))
    return findings
