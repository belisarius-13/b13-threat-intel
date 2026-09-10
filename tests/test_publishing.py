import json

import pytest

from b13intel.publishing.json_output import (
    PublishingError,
    build_json_document,
    write_json_document,
)
from b13intel.publishing.markdown import (
    MarkdownPublishingError,
    render_markdown_brief,
    write_markdown_brief,
)


def sample_records():
    return [
        {
            "id": "CVE-2026-0001",
            "vendor": "Vendor A",
            "product": "Product A",
            "title": "Critical vulnerability",
            "required_action": "Apply update.",
            "ransomware_use": "known",
            "epss": 0.95,
            "epss_percentile": 0.999,
            "priority": "CRITICAL",
            "priority_reasons": [
                "CISA KEV confirms exploitation in the wild",
                "CISA KEV reports known ransomware campaign use",
            ],
        },
        {
            "id": "CVE-2026-0002",
            "vendor": "Vendor B",
            "product": "Product B",
            "title": "High vulnerability",
            "required_action": "Apply mitigation.",
            "ransomware_use": "unknown",
            "epss": 0.91,
            "epss_percentile": 0.998,
            "priority": "HIGH",
            "priority_reasons": [
                "CISA KEV confirms exploitation in the wild",
            ],
        },
        {
            "id": "CVE-2026-0003",
            "vendor": "Vendor C",
            "product": "Product C",
            "title": "Medium vulnerability",
            "required_action": "Review exposure.",
            "ransomware_use": "unknown",
            "epss": 0.30,
            "epss_percentile": 0.85,
            "priority": "MEDIUM",
            "priority_reasons": [
                "CISA KEV confirms exploitation in the wild",
            ],
        },
    ]


def sample_change_report():
    return {
        "counts": {
            "new": 2,
            "changed": 1,
            "removed": 1,
            "unchanged": 0,
        },
        "new_priority_counts": {
            "critical": 1,
            "high": 0,
            "medium": 1,
            "low": 0,
        },
        "changed_priority_counts": {
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
        },
        "displayed": {
            "new": 2,
            "changed": 1,
            "removed": 1,
        },
        "new_records": [
            sample_records()[0],
            sample_records()[2],
        ],
        "changed_records": [
            sample_records()[1],
        ],
        "removed_ids": [
            "CVE-2025-9999",
        ],
    }


def test_build_json_document():
    document = build_json_document(
        sample_records(),
        generated_at="2026-09-10T00:00:00Z",
        change_report=sample_change_report(),
        catalog_version="2026.09.10",
        max_records=2,
    )

    assert document["schema_version"] == 2
    assert document["priority_model"] == "B13-KEV-v1"
    assert document["changes"]["counts"] == {
        "new": 2,
        "changed": 1,
        "removed": 1,
        "unchanged": 0,
    }
    assert (
        document["changes"]["new_priority_counts"]["critical"]
        == 1
    )

    assert document["summary"] == {
        "total": 3,
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 0,
        "published_records": 2,
    }

    assert len(document["records"]) == 2


def test_json_document_rejects_invalid_priority():
    records = sample_records()

    records[0]["priority"] = "URGENT"

    with pytest.raises(
        PublishingError,
        match="Unsupported or missing priority",
    ):
        build_json_document(
            records,
            generated_at="2026-09-10T00:00:00Z",
            change_report=sample_change_report(),
        )


def test_json_document_round_trip(tmp_path):
    document = build_json_document(
        sample_records(),
        generated_at="2026-09-10T00:00:00Z",
        change_report=sample_change_report(),
    )

    path = tmp_path / "latest.json"

    write_json_document(
        path,
        document,
    )

    loaded = json.loads(
        path.read_text(
            encoding="utf-8",
        )
    )

    assert loaded == document


def test_json_document_copies_change_report():
    change_report = sample_change_report()

    document = build_json_document(
        sample_records(),
        generated_at="2026-09-10T00:00:00Z",
        change_report=change_report,
    )

    document["changes"]["counts"]["new"] = 999

    assert change_report["counts"]["new"] == 2


def test_render_markdown_brief():
    content = render_markdown_brief(
        sample_records(),
        generated_at="2026-09-10T00:00:00Z",
        change_report=sample_change_report(),
        catalog_version="2026.09.10",
        top_n=2,
    )

    assert "# B13 Threat Intelligence Brief" in content
    assert "| CRITICAL | 1 |" in content
    assert "| HIGH | 1 |" in content

    assert "CVE-2026-0001" in content
    assert "CVE-2026-0002" in content
    assert "CVE-2026-0003" in content


def test_markdown_rejects_invalid_top_n():
    with pytest.raises(
        MarkdownPublishingError,
        match="top_n must be greater than zero",
    ):
        render_markdown_brief(
            sample_records(),
            generated_at="2026-09-10T00:00:00Z",
            change_report=sample_change_report(),
            top_n=0,
        )


def test_markdown_round_trip(tmp_path):
    content = render_markdown_brief(
        sample_records(),
        generated_at="2026-09-10T00:00:00Z",
        change_report=sample_change_report(),
    )

    path = tmp_path / "latest.md"

    write_markdown_brief(
        path,
        content,
    )

    assert path.read_text(
        encoding="utf-8",
    ) == content


def test_markdown_includes_change_report():
    content = render_markdown_brief(
        sample_records(),
        generated_at="2026-09-10T00:00:00Z",
        change_report=sample_change_report(),
    )

    assert "## What Changed" in content
    assert "| NEW | 2 |" in content
    assert "| CHANGED | 1 |" in content
    assert "| REMOVED | 1 |" in content

    assert "### New Intelligence" in content
    assert "### Updated Intelligence" in content
    assert "### Removed From CISA KEV" in content

    assert "CVE-2025-9999" in content


def test_markdown_rejects_invalid_change_report():
    with pytest.raises(
        MarkdownPublishingError,
        match="change_report is missing required fields",
    ):
        render_markdown_brief(
            sample_records(),
            generated_at="2026-09-10T00:00:00Z",
            change_report={
                "counts": {},
            },
        )
