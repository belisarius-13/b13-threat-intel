"""Historical trend retention for BELISARIUS13 threat intelligence."""

from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from b13intel.prioritize.engine import (
    PRIORITY_MODEL,
    PRIORITY_ORDER,
)


HISTORY_SCHEMA_VERSION = 1

PRIORITY_KEYS = (
    "critical",
    "high",
    "medium",
    "low",
)

CHANGE_KEYS = (
    "new",
    "changed",
    "removed",
    "unchanged",
)


class HistoryError(ValueError):
    """Raised when intelligence history cannot be processed safely."""


def empty_history() -> dict[str, Any]:
    """Return a new empty B13 trend-history document."""

    return {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "priority_model": PRIORITY_MODEL,
        "points": [],
    }


def _utc_date(
    generated_at: str,
) -> str:
    """Return the UTC calendar date for an ISO timestamp."""

    if not isinstance(generated_at, str) or not generated_at:
        raise HistoryError(
            "generated_at must be a non-empty ISO timestamp"
        )

    try:
        parsed = datetime.fromisoformat(
            generated_at.replace(
                "Z",
                "+00:00",
            )
        )
    except ValueError as exc:
        raise HistoryError(
            "generated_at is not a valid ISO timestamp"
        ) from exc

    if parsed.tzinfo is None:
        raise HistoryError(
            "generated_at must include timezone information"
        )

    return (
        parsed.astimezone(timezone.utc)
        .date()
        .isoformat()
    )


def _validate_change_counts(
    change_counts: Any,
) -> dict[str, int]:
    """Validate source-change counters."""

    if not isinstance(change_counts, dict):
        raise HistoryError(
            "change_counts must be a dictionary"
        )

    if set(change_counts) != set(CHANGE_KEYS):
        raise HistoryError(
            "change_counts contains invalid fields"
        )

    for name in CHANGE_KEYS:
        value = change_counts[name]

        if not isinstance(value, int) or value < 0:
            raise HistoryError(
                f"change_counts.{name} must be a non-negative integer"
            )

    return change_counts


def build_history_point(
    records: list[dict[str, Any]],
    *,
    generated_at: str,
    catalog_version: str | None,
    change_counts: dict[str, int],
) -> dict[str, Any]:
    """Build one compact daily intelligence observation."""

    observation_date = _utc_date(
        generated_at
    )

    validated_changes = _validate_change_counts(
        change_counts
    )

    priorities: Counter[str] = Counter()

    ransomware_known = 0
    epss_matched = 0
    epss_ge_090 = 0
    epss_ge_095 = 0

    for record in records:
        if not isinstance(record, dict):
            raise HistoryError(
                "history records must be dictionaries"
            )

        priority = record.get("priority")

        if priority not in PRIORITY_ORDER:
            raise HistoryError(
                f"unsupported history priority: {priority}"
            )

        priorities[priority] += 1

        ransomware_use = str(
            record.get(
                "ransomware_use",
                "",
            )
        ).lower()

        if ransomware_use == "known":
            ransomware_known += 1

        epss = record.get("epss")

        if isinstance(epss, (int, float)):
            epss_matched += 1

            if epss >= 0.90:
                epss_ge_090 += 1

            if epss >= 0.95:
                epss_ge_095 += 1

    total = len(records)

    return {
        "date": observation_date,
        "generated_at": generated_at,
        "catalog_version": catalog_version,
        "total": total,
        "priorities": {
            "critical": priorities["CRITICAL"],
            "high": priorities["HIGH"],
            "medium": priorities["MEDIUM"],
            "low": priorities["LOW"],
        },
        "signals": {
            "ransomware_known": ransomware_known,
            "epss_ge_090": epss_ge_090,
            "epss_ge_095": epss_ge_095,
        },
        "coverage": {
            "epss_matched": epss_matched,
            "epss_missing": total - epss_matched,
        },
        "changes": dict(
            validated_changes
        ),
    }


def _validate_history(
    history: Any,
) -> dict[str, Any]:
    """Validate the history document envelope."""

    if not isinstance(history, dict):
        raise HistoryError(
            "history must be a JSON object"
        )

    if (
        history.get("schema_version")
        != HISTORY_SCHEMA_VERSION
    ):
        raise HistoryError(
            "unsupported history schema version"
        )

    if (
        history.get("priority_model")
        != PRIORITY_MODEL
    ):
        raise HistoryError(
            "unsupported history priority model"
        )

    points = history.get("points")

    if not isinstance(points, list):
        raise HistoryError(
            "history points must be a list"
        )

    dates: set[str] = set()

    for point in points:
        if not isinstance(point, dict):
            raise HistoryError(
                "history point must be a dictionary"
            )

        point_date = point.get("date")

        if not isinstance(point_date, str):
            raise HistoryError(
                "history point is missing date"
            )

        if point_date in dates:
            raise HistoryError(
                f"duplicate history date: {point_date}"
            )

        dates.add(point_date)

    return history


def upsert_history_point(
    history: dict[str, Any],
    point: dict[str, Any],
) -> dict[str, Any]:
    """Insert or replace the observation for one UTC date."""

    _validate_history(
        history
    )

    if not isinstance(point, dict):
        raise HistoryError(
            "history point must be a dictionary"
        )

    point_date = point.get("date")

    if not isinstance(point_date, str) or not point_date:
        raise HistoryError(
            "history point is missing date"
        )

    result = deepcopy(
        history
    )

    result["points"] = [
        existing
        for existing in result["points"]
        if existing.get("date") != point_date
    ]

    result["points"].append(
        deepcopy(point)
    )

    result["points"].sort(
        key=lambda item: item["date"]
    )

    return result


def load_history(
    path: Path,
) -> dict[str, Any]:
    """Load history, or return an empty history when none exists."""

    if not path.exists():
        return empty_history()

    try:
        history = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
        raise HistoryError(
            f"failed to load history: {exc}"
        ) from exc

    _validate_history(
        history
    )

    return history


def save_history(
    path: Path,
    history: dict[str, Any],
) -> None:
    """Persist validated intelligence history."""

    _validate_history(
        history
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            history,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )