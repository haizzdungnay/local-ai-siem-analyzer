"""UTC timestamp helpers shared by reader and dashboard."""
from datetime import datetime, timezone


def parse_utc(value: str | datetime, field_name: str = "timestamp") -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"{field_name} phải là RFC 3339 có timezone") from exc
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field_name} phải là datetime có timezone")
    return value.astimezone(timezone.utc)


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def utc_now() -> str:
    return format_utc(datetime.now(timezone.utc))
