from collections.abc import Callable, Mapping, Sequence
from typing import Any

from signaltrace.detectors import (
    distinct_threshold,
    impossible_travel,
    mfa_fatigue,
    success_after_failures,
    threshold,
)
from signaltrace.models import Event, Finding

Detector = Callable[[Sequence[Event], Mapping[str, Any]], list[Finding]]

DETECTORS: dict[str, Detector] = {
    "threshold": threshold.detect,
    "distinct_threshold": distinct_threshold.detect,
    "success_after_failures": success_after_failures.detect,
    "impossible_travel": impossible_travel.detect,
    "mfa_fatigue": mfa_fatigue.detect,
}
