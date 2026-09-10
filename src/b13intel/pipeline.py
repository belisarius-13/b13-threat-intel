"""End-to-end orchestration for the B13 Threat Intel pipeline."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from b13intel.collectors.cisa_kev import fetch_kev
from b13intel.enrich.epss import (
    enrich_with_epss,
    fetch_epss_scores,
)
from b13intel.normalize.cisa_kev import normalize_kev_catalog
from b13intel.prioritize.engine import prioritize_records
from b13intel.publishing.atom import (
    build_atom_feed,
    write_atom_feed,
)
from b13intel.publishing.change_json import (
    build_change_document,
    write_change_document,
)
from b13intel.publishing.json_output import (
    build_json_document,
    write_json_document,
)
from b13intel.publishing.markdown import (
    render_markdown_brief,
    write_markdown_brief,
)
from b13intel.reporting.changes import build_change_report
from b13intel.state import (
    build_state,
    compare_states,
    load_state,
    save_state,
)


DEFAULT_STATE_PATH = Path("data/state/cisa_kev.json")
DEFAULT_JSON_PATH = Path("data/generated/latest.json")
DEFAULT_CHANGE_JSON_PATH = Path("data/generated/changes.json")
DEFAULT_ATOM_PATH = Path("feeds/changes.atom")
DEFAULT_MARKDOWN_PATH = Path("reports/latest.md")


def _utc_timestamp() -> str:
    """Return a publication timestamp in UTC."""

    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _initial_changes(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    """Treat all records as new when no previous state exists."""

    record_ids = sorted(
        str(record["id"])
        for record in records
    )

    return {
        "new": record_ids,
        "changed": [],
        "removed": [],
        "unchanged": [],
        "counts": {
            "new": len(record_ids),
            "changed": 0,
            "removed": 0,
            "unchanged": 0,
        },
    }


def run_pipeline(
    *,
    root: Path = Path("."),
    generated_at: str | None = None,
    write_outputs: bool = True,
) -> dict[str, Any]:
    """Execute the complete B13 intelligence pipeline."""

    timestamp = generated_at or _utc_timestamp()

    state_path = root / DEFAULT_STATE_PATH
    json_path = root / DEFAULT_JSON_PATH
    change_json_path = root / DEFAULT_CHANGE_JSON_PATH
    atom_path = root / DEFAULT_ATOM_PATH
    markdown_path = root / DEFAULT_MARKDOWN_PATH

    # 1. Collect.
    raw_catalog = fetch_kev()

    # 2. Normalize.
    normalized = normalize_kev_catalog(
        raw_catalog
    )

    catalog_version = raw_catalog.get(
        "catalogVersion"
    )

    # 3. Build current source state before enrichment.
    current_state = build_state(
        normalized,
        source="CISA KEV",
        catalog_version=catalog_version,
    )

    # 4. Compare with the previous source state.
    if state_path.exists():
        previous_state = load_state(
            state_path
        )

        changes = compare_states(
            previous_state,
            current_state,
        )
    else:
        changes = _initial_changes(
            normalized
        )

    # 5. Enrich with FIRST EPSS.
    cve_ids = [
        record["id"]
        for record in normalized
    ]

    epss_scores = fetch_epss_scores(
        cve_ids
    )

    enriched = enrich_with_epss(
        normalized,
        epss_scores,
    )

    # 6. Apply the explainable B13 priority model.
    prioritized = prioritize_records(
        enriched
    )

    priority_counts = Counter(
        record["priority"]
        for record in prioritized
    )

    epss_matched = sum(
        record.get("epss") is not None
        for record in enriched
    )

    # 7. Build the change-aware intelligence report.
    change_report = build_change_report(
        prioritized,
        changes,
        max_records=20,
    )

    # 8. Build publication artifacts.
    json_document = build_json_document(
        prioritized,
        generated_at=timestamp,
        change_report=change_report,
        catalog_version=catalog_version,
        max_records=100,
    )

    change_document = build_change_document(
        change_report,
        generated_at=timestamp,
        catalog_version=catalog_version,
    )

    atom_content = build_atom_feed(
        change_report,
        generated_at=timestamp,
        catalog_version=catalog_version,
    )

    markdown_content = render_markdown_brief(
        prioritized,
        generated_at=timestamp,
        change_report=change_report,
        catalog_version=catalog_version,
        top_n=20,
    )

    # 9. Persist outputs only after all processing succeeds.
    if write_outputs:
        write_json_document(
            json_path,
            json_document,
        )

        write_change_document(
            change_json_path,
            change_document,
        )

        write_atom_feed(
            atom_path,
            atom_content,
        )

        write_markdown_brief(
            markdown_path,
            markdown_content,
        )

        # State is deliberately written last.
        save_state(
            state_path,
            current_state,
        )

    return {
        "generated_at": timestamp,
        "catalog_version": catalog_version,
        "records": len(prioritized),
        "epss_matched": epss_matched,
        "epss_missing": (
            len(prioritized) - epss_matched
        ),
        "priorities": {
            "critical": priority_counts["CRITICAL"],
            "high": priority_counts["HIGH"],
            "medium": priority_counts["MEDIUM"],
            "low": priority_counts["LOW"],
        },
        "changes": changes["counts"],
        "change_report": change_report,
        "write_outputs": write_outputs,
        "paths": {
            "state": str(state_path),
            "json": str(json_path),
            "change_json": str(change_json_path),
            "atom": str(atom_path),
            "markdown": str(markdown_path),
        },
    }
