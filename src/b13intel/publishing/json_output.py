"""JSON publishing for B13 threat intelligence."""

from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any

from b13intel.prioritize.engine import (
    PRIORITY_MODEL,
    PRIORITY_ORDER,
)


OUTPUT_SCHEMA_VERSION = 2
DEFAULT_MAX_RECORDS = 100


class PublishingError(ValueError):
    """Raised when intelligence output cannot be published safely."""


def _validate_priorities(
    records: list[dict[str, Any]],
) -> None:
    """Ensure every record has a supported B13 priority."""

    for record in records:
        priority = record.get("priority")

        if priority not in PRIORITY_ORDER:
            raise PublishingError(
                f"Unsupported or missing priority: {priority}"
            )


def build_json_document(
    records: list[dict[str, Any]],
    *,
    generated_at: str,
    change_report: dict[str, Any],
    catalog_version: str | None = None,
    max_records: int = DEFAULT_MAX_RECORDS,
) -> dict[str, Any]:
    """Build the public B13 intelligence JSON document."""

    if max_records <= 0:
        raise PublishingError(
            "max_records must be greater than zero"
        )

    _validate_priorities(records)

    if not isinstance(change_report, dict):
        raise PublishingError(
            "change_report must be a dictionary"
        )

    required_change_fields = {
        "counts",
        "new_priority_counts",
        "changed_priority_counts",
        "displayed",
        "new_records",
        "changed_records",
        "removed_ids",
    }

    missing_change_fields = (
        required_change_fields
        - set(change_report)
    )

    if missing_change_fields:
        raise PublishingError(
            "change_report is missing required fields"
        )

    counts = Counter(
        record["priority"]
        for record in records
    )

    selected = [
        dict(record)
        for record in records[:max_records]
    ]

    return {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "generated_at": generated_at,
        "source_catalog_version": catalog_version,
        "priority_model": PRIORITY_MODEL,
        "sources": [
            "CISA KEV",
            "FIRST EPSS",
        ],
        "summary": {
            "total": len(records),
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "published_records": len(selected),
        },
        "changes": deepcopy(change_report),
        "records": selected,
    }


def write_json_document(
    path: Path,
    document: dict[str, Any],
) -> None:
    """Write a B13 JSON intelligence document."""

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            document,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
