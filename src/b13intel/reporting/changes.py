"""Change-aware reporting for B13 threat intelligence."""

from __future__ import annotations

from collections import Counter
from typing import Any

from b13intel.prioritize.engine import PRIORITY_ORDER


DEFAULT_MAX_CHANGE_RECORDS = 20

CHANGE_CATEGORIES = (
    "new",
    "changed",
    "removed",
    "unchanged",
)


class ChangeReportError(ValueError):
    """Raised when source changes cannot be reported safely."""


def _priority_counts(
    records: list[dict[str, Any]],
) -> dict[str, int]:
    """Count B13 priority levels for a record collection."""

    counts = Counter(
        record.get("priority")
        for record in records
    )

    return {
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
    }


def _validate_changes(
    changes: dict[str, Any],
) -> None:
    """Validate the state comparison structure."""

    if not isinstance(changes, dict):
        raise ChangeReportError(
            "changes must be a dictionary"
        )

    counts = changes.get("counts")

    if not isinstance(counts, dict):
        raise ChangeReportError(
            "changes is missing counts"
        )

    for category in CHANGE_CATEGORIES:
        values = changes.get(category)

        if not isinstance(values, list):
            raise ChangeReportError(
                f"changes is missing {category} records"
            )

        expected_count = counts.get(category)

        if expected_count != len(values):
            raise ChangeReportError(
                f"{category} count does not match records"
            )


def build_change_report(
    records: list[dict[str, Any]],
    changes: dict[str, Any],
    *,
    max_records: int = DEFAULT_MAX_CHANGE_RECORDS,
) -> dict[str, Any]:
    """Build a publication-ready source change report."""

    if max_records <= 0:
        raise ChangeReportError(
            "max_records must be greater than zero"
        )

    _validate_changes(changes)

    records_by_id: dict[str, dict[str, Any]] = {}

    for record in records:
        record_id = record.get("id")

        if not isinstance(record_id, str) or not record_id.strip():
            raise ChangeReportError(
                "Prioritized record is missing a valid id"
            )

        priority = record.get("priority")

        if priority not in PRIORITY_ORDER:
            raise ChangeReportError(
                f"Unsupported or missing priority: {priority}"
            )

        records_by_id[record_id] = record

    new_ids = set(changes["new"])
    changed_ids = set(changes["changed"])

    expected_current_ids = (
        new_ids
        | changed_ids
    )

    missing_ids = sorted(
        expected_current_ids
        - set(records_by_id)
    )

    if missing_ids:
        raise ChangeReportError(
            "Source changes reference records "
            "missing from the current catalog: "
            + ", ".join(missing_ids)
        )

    # The records input is already ranked by B13 priority,
    # so filtering it preserves operational ranking.
    all_new_records = [
        dict(record)
        for record in records
        if record["id"] in new_ids
    ]

    all_changed_records = [
        dict(record)
        for record in records
        if record["id"] in changed_ids
    ]

    removed_ids = list(
        changes["removed"]
    )

    displayed_new = all_new_records[
        :max_records
    ]

    displayed_changed = all_changed_records[
        :max_records
    ]

    displayed_removed = removed_ids[
        :max_records
    ]

    return {
        "counts": dict(
            changes["counts"]
        ),
        "new_priority_counts": _priority_counts(
            all_new_records
        ),
        "changed_priority_counts": _priority_counts(
            all_changed_records
        ),
        "displayed": {
            "new": len(displayed_new),
            "changed": len(displayed_changed),
            "removed": len(displayed_removed),
        },
        "new_records": displayed_new,
        "changed_records": displayed_changed,
        "removed_ids": displayed_removed,
    }
