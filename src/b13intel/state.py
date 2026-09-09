"""State persistence and change detection for B13 Threat Intel."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


STATE_SCHEMA_VERSION = 1


class StateError(ValueError):
    """Raised when intelligence state cannot be processed."""


def fingerprint_record(record: dict[str, Any]) -> str:
    """Return a stable SHA-256 fingerprint for a normalized record."""

    serialized = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def build_state(
    records: list[dict[str, Any]],
    *,
    source: str,
    catalog_version: str | None = None,
) -> dict[str, Any]:
    """Build compact state from normalized intelligence records."""

    fingerprints: dict[str, str] = {}

    for record in records:
        record_id = record.get("id")

        if not isinstance(record_id, str) or not record_id.strip():
            raise StateError(
                "Normalized record is missing a valid id"
            )

        record_id = record_id.strip()

        if record_id in fingerprints:
            raise StateError(
                f"Duplicate normalized record id: {record_id}"
            )

        fingerprints[record_id] = fingerprint_record(record)

    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "source": source,
        "catalog_version": catalog_version,
        "record_count": len(fingerprints),
        "fingerprints": dict(sorted(fingerprints.items())),
    }


def compare_states(
    previous: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    """Compare two intelligence states."""

    previous_fingerprints = previous.get("fingerprints")
    current_fingerprints = current.get("fingerprints")

    if not isinstance(previous_fingerprints, dict):
        raise StateError(
            "Previous state is missing fingerprints"
        )

    if not isinstance(current_fingerprints, dict):
        raise StateError(
            "Current state is missing fingerprints"
        )

    previous_ids = set(previous_fingerprints)
    current_ids = set(current_fingerprints)

    new_ids = sorted(current_ids - previous_ids)
    removed_ids = sorted(previous_ids - current_ids)

    common_ids = previous_ids & current_ids

    changed_ids = sorted(
        record_id
        for record_id in common_ids
        if previous_fingerprints[record_id]
        != current_fingerprints[record_id]
    )

    unchanged_ids = sorted(
        record_id
        for record_id in common_ids
        if previous_fingerprints[record_id]
        == current_fingerprints[record_id]
    )

    return {
        "new": new_ids,
        "changed": changed_ids,
        "removed": removed_ids,
        "unchanged": unchanged_ids,
        "counts": {
            "new": len(new_ids),
            "changed": len(changed_ids),
            "removed": len(removed_ids),
            "unchanged": len(unchanged_ids),
        },
    }


def save_state(
    path: Path,
    state: dict[str, Any],
) -> None:
    """Write intelligence state to disk."""

    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(
            state,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def load_state(path: Path) -> dict[str, Any]:
    """Load intelligence state from disk."""

    if not path.exists():
        raise StateError(
            f"State file does not exist: {path}"
        )

    try:
        state = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise StateError(
            f"Failed to load state: {exc}"
        ) from exc

    if not isinstance(state, dict):
        raise StateError(
            "State must be a JSON object"
        )

    if state.get("schema_version") != STATE_SCHEMA_VERSION:
        raise StateError(
            "Unsupported state schema version"
        )

    if not isinstance(state.get("fingerprints"), dict):
        raise StateError(
            "State is missing fingerprints"
        )

    return state
