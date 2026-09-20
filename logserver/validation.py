from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import LogInput, SEVERITIES_BY_URGENCY


class ValidationError(ValueError):
    pass


SEVERITIES = set(SEVERITIES_BY_URGENCY)


def parse_timestamp(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValidationError("timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("timestamp must be ISO 8601 formatted") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def log_input_from_json(payload: Any, fallback_source: str) -> LogInput:
    if not isinstance(payload, dict):
        raise ValidationError("each log must be a JSON object")

    message = payload.get("message")
    if not isinstance(message, str) or not message.strip():
        raise ValidationError("message must be a non-empty string")
    if len(message) > 65_536:
        raise ValidationError("message is too long (maximum 65536 characters)")

    source = payload.get("source", fallback_source)
    if not isinstance(source, str) or not source.strip() or len(source) > 255:
        raise ValidationError("source must be a non-empty string of at most 255 characters")

    severity = payload.get("severity", payload.get("level", "info"))
    if not isinstance(severity, str) or severity.lower() not in SEVERITIES:
        raise ValidationError(f"severity must be one of: {', '.join(sorted(SEVERITIES))}")

    facility = payload.get("facility")
    if facility is not None and (not isinstance(facility, str) or len(facility) > 64):
        raise ValidationError("facility must be a string of at most 64 characters")

    topics_value = payload.get("topics", payload.get("topic", []))
    if isinstance(topics_value, str):
        topics = [part.strip() for part in topics_value.split(",") if part.strip()]
    elif isinstance(topics_value, list) and all(isinstance(part, str) for part in topics_value):
        topics = [part.strip() for part in topics_value if part.strip()]
    else:
        raise ValidationError("topics must be a string or an array of strings")
    if len(topics) > 64 or any(len(topic) > 64 for topic in topics):
        raise ValidationError("too many topics or topic is too long")

    metadata = payload.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValidationError("metadata must be a JSON object")

    raw = payload.get("raw")
    if raw is not None and not isinstance(raw, str):
        raise ValidationError("raw must be a string")

    return LogInput(
        message=message.strip(),
        source=source.strip(),
        severity=severity.lower(),
        facility=facility,
        topics=topics,
        event_at=parse_timestamp(payload.get("timestamp", payload.get("event_at"))),
        raw=raw,
        transport="http",
        metadata=metadata,
    )
