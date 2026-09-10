import pytest

from b13intel.reporting.changes import (
    ChangeReportError,
    build_change_report,
)


def sample_records():
    return [
        {
            "id": "CVE-2026-0001",
            "priority": "CRITICAL",
            "epss": 0.95,
        },
        {
            "id": "CVE-2026-0002",
            "priority": "HIGH",
            "epss": 0.91,
        },
        {
            "id": "CVE-2026-0003",
            "priority": "MEDIUM",
            "epss": 0.30,
        },
    ]


def sample_changes():
    return {
        "new": [
            "CVE-2026-0001",
            "CVE-2026-0003",
        ],
        "changed": [
            "CVE-2026-0002",
        ],
        "removed": [
            "CVE-2025-9999",
        ],
        "unchanged": [],
        "counts": {
            "new": 2,
            "changed": 1,
            "removed": 1,
            "unchanged": 0,
        },
    }


def test_build_change_report():
    report = build_change_report(
        sample_records(),
        sample_changes(),
    )

    assert report["counts"] == {
        "new": 2,
        "changed": 1,
        "removed": 1,
        "unchanged": 0,
    }

    assert report["new_priority_counts"] == {
        "critical": 1,
        "high": 0,
        "medium": 1,
        "low": 0,
    }

    assert report["changed_priority_counts"] == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
    }

    assert [
        record["id"]
        for record in report["new_records"]
    ] == [
        "CVE-2026-0001",
        "CVE-2026-0003",
    ]

    assert report["removed_ids"] == [
        "CVE-2025-9999"
    ]


def test_change_report_preserves_priority_order():
    records = [
        {
            "id": "CVE-2026-0002",
            "priority": "CRITICAL",
        },
        {
            "id": "CVE-2026-0001",
            "priority": "HIGH",
        },
    ]

    changes = {
        "new": [
            "CVE-2026-0001",
            "CVE-2026-0002",
        ],
        "changed": [],
        "removed": [],
        "unchanged": [],
        "counts": {
            "new": 2,
            "changed": 0,
            "removed": 0,
            "unchanged": 0,
        },
    }

    report = build_change_report(
        records,
        changes,
    )

    assert [
        record["id"]
        for record in report["new_records"]
    ] == [
        "CVE-2026-0002",
        "CVE-2026-0001",
    ]


def test_change_report_limits_displayed_records():
    report = build_change_report(
        sample_records(),
        sample_changes(),
        max_records=1,
    )

    assert report["counts"]["new"] == 2

    assert report["displayed"] == {
        "new": 1,
        "changed": 1,
        "removed": 1,
    }

    assert len(
        report["new_records"]
    ) == 1


def test_change_report_rejects_missing_current_record():
    changes = {
        "new": [
            "CVE-2099-9999",
        ],
        "changed": [],
        "removed": [],
        "unchanged": [],
        "counts": {
            "new": 1,
            "changed": 0,
            "removed": 0,
            "unchanged": 0,
        },
    }

    with pytest.raises(
        ChangeReportError,
        match="missing from the current catalog",
    ):
        build_change_report(
            sample_records(),
            changes,
        )
