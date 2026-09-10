import json

import pytest

from b13intel.publishing.catalog_json import (
    CATALOG_FIELDS,
    CatalogPublishingError,
    build_catalog_document,
    write_catalog_document,
)


def sample_records():
    return [
        {
            "id": "CVE-2026-0001",
            "priority": "CRITICAL",
            "vendor": "Vendor A",
            "product": "Product A",
            "title": "Critical vulnerability",
            "description": "Large description not needed by explorer.",
            "epss": 0.97,
            "epss_percentile": 0.999,
            "ransomware_use": "known",
            "date_added": "2026-09-01",
            "due_date": "2026-09-22",
            "priority_reasons": [
                "Reason A",
                "Reason B",
            ],
            "cwes": [
                "CWE-79",
            ],
        },
        {
            "id": "CVE-2026-0002",
            "priority": "HIGH",
            "vendor": "Vendor B",
            "product": "Product B",
            "title": "High vulnerability",
            "description": "Another description.",
            "epss": 0.81,
            "epss_percentile": 0.97,
            "ransomware_use": "unknown",
            "date_added": "2026-09-02",
            "due_date": "2026-09-23",
            "priority_reasons": [
                "Reason C",
            ],
            "cwes": [
                "CWE-20",
            ],
        },
        {
            "id": "CVE-2026-0003",
            "priority": "MEDIUM",
            "vendor": "Vendor C",
            "product": "Product C",
            "title": "Medium vulnerability",
            "description": "Another description.",
            "epss": 0.20,
            "epss_percentile": 0.70,
            "ransomware_use": "unknown",
            "date_added": "2026-09-03",
            "due_date": "2026-09-24",
            "priority_reasons": [
                "Reason D",
            ],
            "cwes": [
                "CWE-200",
            ],
        },
    ]


def test_build_catalog_document_contains_all_records():
    document = build_catalog_document(
        sample_records(),
        generated_at="2026-09-11T00:00:00Z",
        catalog_version="2026.09.11",
    )

    assert document["schema_version"] == 1
    assert document["priority_model"] == "B13-KEV-v1"

    assert document["summary"] == {
        "total": 3,
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 0,
    }

    assert len(document["records"]) == 3


def test_catalog_records_use_compact_shape():
    document = build_catalog_document(
        sample_records(),
        generated_at="2026-09-11T00:00:00Z",
    )

    record = document["records"][0]

    assert tuple(record) == CATALOG_FIELDS

    assert "description" not in record
    assert "priority_reasons" not in record
    assert "cwes" not in record


def test_catalog_preserves_ranked_record_order():
    records = sample_records()

    document = build_catalog_document(
        records,
        generated_at="2026-09-11T00:00:00Z",
    )

    assert [
        record["id"]
        for record in document["records"]
    ] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
        "CVE-2026-0003",
    ]


def test_catalog_rejects_invalid_priority():
    records = sample_records()

    records[0]["priority"] = "URGENT"

    with pytest.raises(
        CatalogPublishingError,
        match="Unsupported or missing priority",
    ):
        build_catalog_document(
            records,
            generated_at="2026-09-11T00:00:00Z",
        )


def test_catalog_rejects_missing_id():
    records = sample_records()

    records[0]["id"] = ""

    with pytest.raises(
        CatalogPublishingError,
        match="missing a valid id",
    ):
        build_catalog_document(
            records,
            generated_at="2026-09-11T00:00:00Z",
        )


def test_catalog_round_trip(tmp_path):
    document = build_catalog_document(
        sample_records(),
        generated_at="2026-09-11T00:00:00Z",
        catalog_version="2026.09.11",
    )

    path = (
        tmp_path
        / "catalog.json"
    )

    write_catalog_document(
        path,
        document,
    )

    loaded = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    assert loaded == document