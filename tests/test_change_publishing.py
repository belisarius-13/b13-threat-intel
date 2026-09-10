import json

import pytest

from b13intel.publishing.change_json import (
    ChangePublishingError,
    build_change_document,
    write_change_document,
)


def sample_change_report():
    return {
        "counts": {
            "new": 1,
            "changed": 1,
            "removed": 1,
            "unchanged": 10,
        },
        "new_priority_counts": {
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "changed_priority_counts": {
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
        },
        "displayed": {
            "new": 1,
            "changed": 1,
            "removed": 1,
        },
        "new_records": [
            {
                "id": "CVE-2026-0001",
                "priority": "CRITICAL",
                "epss": 0.95,
            }
        ],
        "changed_records": [
            {
                "id": "CVE-2026-0002",
                "priority": "HIGH",
                "epss": 0.91,
            }
        ],
        "removed_ids": [
            "CVE-2025-9999"
        ],
    }


def test_build_change_document():
    document = build_change_document(
        sample_change_report(),
        generated_at="2026-09-10T00:00:00Z",
        catalog_version="2026.09.10",
    )

    assert document["schema_version"] == 1
    assert document["priority_model"] == "B13-KEV-v1"
    assert document["source"] == "CISA KEV"
    assert document["enrichment"] == "FIRST EPSS"

    assert document["changes"]["counts"] == {
        "new": 1,
        "changed": 1,
        "removed": 1,
        "unchanged": 10,
    }


def test_change_document_rejects_missing_fields():
    with pytest.raises(
        ChangePublishingError,
        match="missing required fields",
    ):
        build_change_document(
            {
                "counts": {
                    "new": 1,
                    "changed": 0,
                    "removed": 0,
                    "unchanged": 10,
                }
            },
            generated_at="2026-09-10T00:00:00Z",
        )


def test_change_document_does_not_mutate_report():
    report = sample_change_report()

    document = build_change_document(
        report,
        generated_at="2026-09-10T00:00:00Z",
    )

    document["changes"]["counts"]["new"] = 999

    assert report["counts"]["new"] == 1


def test_change_document_round_trip(tmp_path):
    document = build_change_document(
        sample_change_report(),
        generated_at="2026-09-10T00:00:00Z",
    )

    path = tmp_path / "changes.json"

    write_change_document(
        path,
        document,
    )

    loaded = json.loads(
        path.read_text(
            encoding="utf-8",
        )
    )

    assert loaded == document
