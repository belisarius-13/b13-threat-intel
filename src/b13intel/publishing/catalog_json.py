"""Compact full-catalog publishing for B13 threat intelligence."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from b13intel.prioritize.engine import (
    PRIORITY_MODEL,
    PRIORITY_ORDER,
)


CATALOG_SCHEMA_VERSION = 1

CATALOG_FIELDS = (
    "id",
    "priority",
    "vendor",
    "product",
    "title",
    "epss",
    "epss_percentile",
    "ransomware_use",
    "date_added",
    "due_date",
)


class CatalogPublishingError(ValueError):
    """Raised when the analyst catalog cannot be published safely."""


def _validate_records(
    records: list[dict[str, Any]],
) -> None:
    """Validate records before building the public catalog."""

    if not isinstance(records, list):
        raise CatalogPublishingError(
            "records must be a list"
        )

    for record in records:
        if not isinstance(record, dict):
            raise CatalogPublishingError(
                "catalog records must be dictionaries"
            )

        record_id = record.get("id")

        if (
            not isinstance(record_id, str)
            or not record_id.strip()
        ):
            raise CatalogPublishingError(
                "catalog record is missing a valid id"
            )

        priority = record.get("priority")

        if priority not in PRIORITY_ORDER:
            raise CatalogPublishingError(
                f"Unsupported or missing priority: {priority}"
            )


def _compact_record(
    record: dict[str, Any],
) -> dict[str, Any]:
    """Return the analyst-facing compact representation."""

    return {
        field: record.get(field)
        for field in CATALOG_FIELDS
    }


def build_catalog_document(
    records: list[dict[str, Any]],
    *,
    generated_at: str,
    catalog_version: str | None = None,
) -> dict[str, Any]:
    """Build the complete compact analyst catalog."""

    _validate_records(
        records
    )

    counts = Counter(
        record["priority"]
        for record in records
    )

    compact_records = [
        _compact_record(record)
        for record in records
    ]

    return {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "generated_at": generated_at,
        "source_catalog_version": catalog_version,
        "priority_model": PRIORITY_MODEL,
        "sources": [
            "CISA KEV",
            "FIRST EPSS",
        ],
        "summary": {
            "total": len(compact_records),
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
        },
        "records": compact_records,
    }


def write_catalog_document(
    path: Path,
    document: dict[str, Any],
) -> None:
    """Write the compact analyst catalog."""

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