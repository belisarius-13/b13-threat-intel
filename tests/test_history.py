import json

import pytest

from b13intel.history import (
    HistoryError,
    build_history_point,
    empty_history,
    load_history,
    save_history,
    upsert_history_point,
)


def sample_records():
    return [
        {
            "id": "CVE-2026-0001",
            "priority": "CRITICAL",
            "epss": 0.97,
            "ransomware_use": "known",
        },
        {
            "id": "CVE-2026-0002",
            "priority": "HIGH",
            "epss": 0.91,
            "ransomware_use": "unknown",
        },
        {
            "id": "CVE-2026-0003",
            "priority": "MEDIUM",
            "epss": None,
            "ransomware_use": "unknown",
        },
    ]


def sample_changes():
    return {
        "new": 1,
        "changed": 1,
        "removed": 0,
        "unchanged": 1,
    }


def build_point(
    timestamp="2026-09-10T12:00:00Z",
):
    return build_history_point(
        sample_records(),
        generated_at=timestamp,
        catalog_version="2026.09.10",
        change_counts=sample_changes(),
    )


def test_build_history_point():
    point = build_point()

    assert point["date"] == "2026-09-10"
    assert point["total"] == 3

    assert point["priorities"] == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 0,
    }

    assert point["signals"] == {
        "ransomware_known": 1,
        "epss_ge_090": 2,
        "epss_ge_095": 1,
    }

    assert point["coverage"] == {
        "epss_matched": 2,
        "epss_missing": 1,
    }

    assert point["changes"] == sample_changes()


def test_history_rejects_timestamp_without_timezone():
    with pytest.raises(
        HistoryError,
        match="timezone",
    ):
        build_history_point(
            sample_records(),
            generated_at="2026-09-10T12:00:00",
            catalog_version="2026.09.10",
            change_counts=sample_changes(),
        )


def test_history_rejects_invalid_priority():
    records = sample_records()

    records[0]["priority"] = "URGENT"

    with pytest.raises(
        HistoryError,
        match="unsupported history priority",
    ):
        build_history_point(
            records,
            generated_at="2026-09-10T12:00:00Z",
            catalog_version="2026.09.10",
            change_counts=sample_changes(),
        )


def test_upsert_adds_history_point():
    history = upsert_history_point(
        empty_history(),
        build_point(),
    )

    assert len(history["points"]) == 1
    assert history["points"][0]["date"] == "2026-09-10"


def test_upsert_replaces_same_day():
    history = upsert_history_point(
        empty_history(),
        build_point(
            "2026-09-10T10:00:00Z"
        ),
    )

    replacement = build_point(
        "2026-09-10T20:00:00Z"
    )

    history = upsert_history_point(
        history,
        replacement,
    )

    assert len(history["points"]) == 1

    assert (
        history["points"][0]["generated_at"]
        == "2026-09-10T20:00:00Z"
    )


def test_history_points_are_sorted_by_date():
    history = empty_history()

    history = upsert_history_point(
        history,
        build_point(
            "2026-09-11T12:00:00Z"
        ),
    )

    history = upsert_history_point(
        history,
        build_point(
            "2026-09-10T12:00:00Z"
        ),
    )

    assert [
        point["date"]
        for point in history["points"]
    ] == [
        "2026-09-10",
        "2026-09-11",
    ]


def test_history_round_trip(tmp_path):
    path = tmp_path / "trends.json"

    history = upsert_history_point(
        empty_history(),
        build_point(),
    )

    save_history(
        path,
        history,
    )

    assert load_history(path) == history


def test_missing_history_returns_empty_document(tmp_path):
    history = load_history(
        tmp_path / "missing.json"
    )

    assert history == empty_history()


def test_invalid_history_file_is_rejected(tmp_path):
    path = tmp_path / "trends.json"

    path.write_text(
        json.dumps(
            {
                "schema_version": 999,
                "priority_model": "B13-KEV-v1",
                "points": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        HistoryError,
        match="unsupported history schema",
    ):
        load_history(path)
