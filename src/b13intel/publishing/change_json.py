"""Compact JSON change-feed publishing for B13 threat intelligence."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from b13intel.prioritize.engine import PRIORITY_MODEL


CHANGE_SCHEMA_VERSION = 1


class ChangePublishingError(ValueError):
    """Raised when a change feed cannot be published safely."""


def build_change_document(
    change_report: dict[str, Any],
    *,
    generated_at: str,
    catalog_version: str | None = None,
) -> dict[str, Any]:
    """Build the lightweight B13 intelligence change document."""

    if not isinstance(change_report, dict):
        raise ChangePublishingError(
            "change_report must be a dictionary"
        )

    required_fields = {
        "counts",
        "new_priority_counts",
        "changed_priority_counts",
        "displayed",
        "new_records",
        "changed_records",
        "removed_ids",
    }

    missing_fields = (
        required_fields
        - set(change_report)
    )

    if missing_fields:
        raise ChangePublishingError(
            "change_report is missing required fields"
        )

    counts = change_report["counts"]

    if not isinstance(counts, dict):
        raise ChangePublishingError(
            "change_report counts must be a dictionary"
        )

    expected_count_fields = {
        "new",
        "changed",
        "removed",
        "unchanged",
    }

    if set(counts) != expected_count_fields:
        raise ChangePublishingError(
            "change_report counts are invalid"
        )

    return {
        "schema_version": CHANGE_SCHEMA_VERSION,
        "generated_at": generated_at,
        "source_catalog_version": catalog_version,
        "priority_model": PRIORITY_MODEL,
        "source": "CISA KEV",
        "enrichment": "FIRST EPSS",
        "changes": deepcopy(change_report),
    }


def write_change_document(
    path: Path,
    document: dict[str, Any],
) -> None:
    """Write the compact B13 change feed to disk."""

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
