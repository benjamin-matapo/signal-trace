from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from signaltrace.detectors._common import _episodes, window
from signaltrace.models import Event, Finding


def detect(events: Sequence[Event], rule: Mapping[str, Any]) -> list[Finding]:
    denied_by_user: dict[str, list[int]] = defaultdict(list)
    approvals_by_user: dict[str, list[int]] = defaultdict(list)
    for index, event in enumerate(events):
        if event.event_type == "mfa_denied":
            denied_by_user[event.user].append(index)
        elif event.event_type == "mfa_approved":
            approvals_by_user[event.user].append(index)

    findings: list[Finding] = []
    duration = window(rule)
    threshold = rule["params"]["count"]
    for user, approvals in approvals_by_user.items():
        denied = denied_by_user.get(user, [])
        denied.sort(key=lambda index: events[index].timestamp)
        candidates: list[list[int]] = []
        for approval_index in approvals:
            approval_time = events[approval_index].timestamp
            preceding = [
                index
                for index in denied
                if events[index].timestamp < approval_time
                and approval_time - events[index].timestamp <= duration
            ]
            if len(preceding) >= threshold:
                candidates.append([*preceding, approval_index])
        findings.extend(_episodes(events, rule, candidates))
    return findings
