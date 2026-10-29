import json
import random
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path

from signaltrace.models import Event, EventType

COMPANY_NAME = "Example Retail Ltd"
_USERS = tuple(f"retail.user{number:02d}" for number in range(1, 21))
_ADMIN_USERS = {"retail.user01", "retail.user07", "retail.user14"}
_APPS = (
    f"{COMPANY_NAME} Portal",
    f"{COMPANY_NAME} POS",
    f"{COMPANY_NAME} Stock",
)
_BASE_DATE = date(2026, 10, 28)
_IP_NETWORKS = ("192.0.2", "198.51.100", "203.0.113")


def _timestamp(hour: int, minute: int, second: int = 0) -> datetime:
    return datetime.combine(_BASE_DATE, time(hour, minute, second), tzinfo=UTC)


def _random_timestamp(
    rng: random.Random,
    start_hour: int,
    end_hour: int,
) -> datetime:
    seconds_after_start = rng.randrange((end_hour - start_hour) * 60 * 60)
    return _timestamp(start_hour, 0) + timedelta(seconds=seconds_after_start)


def _random_ip(
    rng: random.Random,
    network: str | None = None,
    excluded: set[str] | None = None,
) -> str:
    while True:
        selected_network = network or rng.choice(_IP_NETWORKS)
        candidate = f"{selected_network}.{rng.randrange(1, 255)}"
        if excluded is None or candidate not in excluded:
            return candidate


def _event(
    timestamp: datetime,
    event_type: EventType,
    user: str,
    src_ip: str,
    country: str = "GB",
    app: str = _APPS[0],
) -> Event:
    return Event(
        timestamp=timestamp,
        event_type=event_type,
        user=user,
        src_ip=src_ip,
        country=country,
        role="admin" if user in _ADMIN_USERS else "employee",
        app=app,
    )


def generate_dataset(
    out_path: str | Path,
    seed: int,
) -> Path:
    """Write a deterministic 24-hour authentication log and its truth file."""
    rng = random.Random(seed)
    events: list[Event] = []
    scenario_users = _USERS[:5]
    reserved_ips: set[str] = set()

    brute_ip = _random_ip(rng, "192.0.2", reserved_ips)
    reserved_ips.add(brute_ip)
    spray_ip = _random_ip(rng, "198.51.100", reserved_ips)
    reserved_ips.add(spray_ip)
    compromise_ip = _random_ip(rng, "203.0.113", reserved_ips)
    reserved_ips.add(compromise_ip)
    gb_ip = _random_ip(rng, "192.0.2", reserved_ips)
    reserved_ips.add(gb_ip)
    br_ip = _random_ip(rng, "203.0.113", reserved_ips)
    reserved_ips.add(br_ip)
    mfa_ip = _random_ip(rng, "198.51.100", reserved_ips)
    reserved_ips.add(mfa_ip)

    for user in _USERS:
        for _ in range(rng.randint(2, 4)):
            events.append(
                _event(
                    timestamp=_random_timestamp(rng, 8, 18),
                    event_type="login_success",
                    user=user,
                    src_ip=_random_ip(rng, excluded=reserved_ips),
                    app=rng.choice(_APPS),
                )
            )

    for _ in range(rng.randint(5, 8)):
        events.append(
            _event(
                timestamp=_random_timestamp(rng, 8, 18),
                event_type="login_failure",
                user=rng.choice(_USERS[5:]),
                src_ip=_random_ip(rng, excluded=reserved_ips),
                app=rng.choice(_APPS),
            )
        )

    truth: list[dict[str, str]] = []

    brute_user = scenario_users[0]
    brute_start = _timestamp(9, 0) + timedelta(seconds=rng.randrange(60))
    for attempt in range(12):
        events.append(
            _event(
                brute_start + timedelta(seconds=attempt * 12),
                "login_failure",
                brute_user,
                brute_ip,
            )
        )
    truth.append(
        {
            "scenario_name": "brute_force",
            "user": brute_user,
            "src_ip": brute_ip,
            "expected_rule_id": "ST-001",
        }
    )

    spray_user = _USERS[5]
    spray_start = _timestamp(10, 0) + timedelta(seconds=rng.randrange(60))
    for index, user in enumerate(_USERS[5:13]):
        events.append(
            _event(
                spray_start + timedelta(seconds=index * 35),
                "login_failure",
                user,
                spray_ip,
            )
        )
        if rng.choice((False, True)):
            events.append(
                _event(
                    spray_start + timedelta(seconds=index * 35 + 8),
                    "login_failure",
                    user,
                    spray_ip,
                )
            )
    truth.append(
        {
            "scenario_name": "password_spraying",
            "user": spray_user,
            "src_ip": spray_ip,
            "expected_rule_id": "ST-002",
        }
    )

    compromise_user = scenario_users[2]
    compromise_start = _timestamp(11, 0) + timedelta(seconds=rng.randrange(60))
    for attempt in range(7):
        events.append(
            _event(
                compromise_start + timedelta(seconds=attempt * 15),
                "login_failure",
                compromise_user,
                compromise_ip,
            )
        )
    events.append(
        _event(
            compromise_start + timedelta(minutes=2),
            "login_success",
            compromise_user,
            compromise_ip,
        )
    )
    truth.append(
        {
            "scenario_name": "compromise_after_failures",
            "user": compromise_user,
            "src_ip": compromise_ip,
            "expected_rule_id": "ST-003",
        }
    )

    travel_user = scenario_users[3]
    travel_start = _timestamp(13, 0) + timedelta(seconds=rng.randrange(60))
    events.append(_event(travel_start, "login_success", travel_user, gb_ip, "GB"))
    events.append(
        _event(
            travel_start + timedelta(minutes=20),
            "login_success",
            travel_user,
            br_ip,
            "BR",
        )
    )
    truth.append(
        {
            "scenario_name": "impossible_travel",
            "user": travel_user,
            "src_ip": br_ip,
            "expected_rule_id": "ST-004",
        }
    )
    mfa_user = scenario_users[4]
    mfa_user = scenario_users[4]
    mfa_start = _timestamp(15, 0) + timedelta(seconds=rng.randrange(60))
    for attempt in range(7):
        events.append(
            _event(
                mfa_start + timedelta(seconds=attempt * 30),
                "mfa_denied",
                mfa_user,
                mfa_ip,
            )
        )
    events.append(
        _event(
            mfa_start + timedelta(minutes=4),
            "mfa_approved",
            mfa_user,
            mfa_ip,
        )
    )
    truth.append(
        {
            "scenario_name": "mfa_fatigue",
            "user": mfa_user,
            "src_ip": mfa_ip,
            "expected_rule_id": "ST-005",
        }
    )

    events.sort(key=lambda event: event.timestamp)
    output_path = Path(out_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as event_file:
        for event in events:
            row = {
                "timestamp": event.timestamp.isoformat().replace("+00:00", "Z"),
                "event_type": event.event_type,
                "user": event.user,
                "src_ip": event.src_ip,
                "country": event.country,
                "role": event.role,
                "app": event.app,
            }
            event_file.write(json.dumps(row, separators=(",", ":")) + "\n")

    truth_path = output_path.with_suffix(".truth.json")
    with truth_path.open("w", encoding="utf-8", newline="\n") as truth_file:
        json.dump(truth, truth_file, indent=2)
        truth_file.write("\n")

    return truth_path
