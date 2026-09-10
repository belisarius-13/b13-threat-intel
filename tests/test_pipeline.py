import json
from pathlib import Path

import pytest

from b13intel.pipeline import run_pipeline
from b13intel.normalize.cisa_kev import normalize_kev_catalog
from b13intel.state import (
    build_state,
    load_state,
    save_state,
)


def fake_catalog():
    return {
        "catalogVersion": "2026.09.10",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Vendor A",
                "product": "Product A",
                "vulnerabilityName": "Example One",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2026-0002",
                "vendorProject": "Vendor B",
                "product": "Product B",
                "vulnerabilityName": "Example Two",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ],
    }


def fake_epss_scores():
    return {
        "CVE-2026-0001": {
            "epss": 0.80,
            "epss_percentile": 0.99,
            "epss_date": "2026-09-10",
            "epss_source": "FIRST EPSS",
        },
        "CVE-2026-0002": {
            "epss": 0.30,
            "epss_percentile": 0.85,
            "epss_date": "2026-09-10",
            "epss_source": "FIRST EPSS",
        },
    }


def test_pipeline_creates_outputs(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        "b13intel.pipeline.fetch_kev",
        fake_catalog,
    )

    monkeypatch.setattr(
        "b13intel.pipeline.fetch_epss_scores",
        lambda cve_ids: fake_epss_scores(),
    )

    result = run_pipeline(
        root=tmp_path,
        generated_at="2026-09-10T00:00:00Z",
    )

    assert result["records"] == 2
    assert result["epss_matched"] == 2

    assert result["priorities"] == {
        "critical": 1,
        "high": 0,
        "medium": 1,
        "low": 0,
    }

    assert result["change_report"]["new_priority_counts"] == {
        "critical": 1,
        "high": 0,
        "medium": 1,
        "low": 0,
    }

    assert result["changes"] == {
        "new": 2,
        "changed": 0,
        "removed": 0,
        "unchanged": 0,
    }

    assert (
        tmp_path
        / "data/generated/latest.json"
    ).exists()

    json_path = (
        tmp_path
        / "data/generated/latest.json"
    )

    document = json.loads(
        json_path.read_text(
            encoding="utf-8",
        )
    )

    assert document["schema_version"] == 2

    assert document["changes"]["counts"] == {
        "new": 2,
        "changed": 0,
        "removed": 0,
        "unchanged": 0,
    }

    markdown_path = (
        tmp_path
        / "reports/latest.md"
    )

    markdown_content = markdown_path.read_text(
        encoding="utf-8",
    )

    assert "## What Changed" in markdown_content
    assert "| NEW | 2 |" in markdown_content

    assert (
        tmp_path
        / "reports/latest.md"
    ).exists()

    assert (
        tmp_path
        / "data/state/cisa_kev.json"
    ).exists()


def test_pipeline_detects_unchanged_state(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        "b13intel.pipeline.fetch_kev",
        fake_catalog,
    )

    monkeypatch.setattr(
        "b13intel.pipeline.fetch_epss_scores",
        lambda cve_ids: fake_epss_scores(),
    )

    first = run_pipeline(
        root=tmp_path,
        generated_at="2026-09-10T00:00:00Z",
    )

    second = run_pipeline(
        root=tmp_path,
        generated_at="2026-09-10T01:00:00Z",
    )

    assert first["changes"]["new"] == 2

    assert second["changes"] == {
        "new": 0,
        "changed": 0,
        "removed": 0,
        "unchanged": 2,
    }


def test_dry_run_does_not_write_files(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        "b13intel.pipeline.fetch_kev",
        fake_catalog,
    )

    monkeypatch.setattr(
        "b13intel.pipeline.fetch_epss_scores",
        lambda cve_ids: fake_epss_scores(),
    )

    result = run_pipeline(
        root=tmp_path,
        generated_at="2026-09-10T00:00:00Z",
        write_outputs=False,
    )

    assert result["write_outputs"] is False

    assert not (
        tmp_path
        / "data/generated/latest.json"
    ).exists()

    assert not (
        tmp_path
        / "reports/latest.md"
    ).exists()

    assert not (
        tmp_path
        / "data/state/cisa_kev.json"
    ).exists()


def test_pipeline_does_not_replace_state_on_failure(
    monkeypatch,
    tmp_path,
):
    state_path = (
        tmp_path
        / "data/state/cisa_kev.json"
    )

    original_state = build_state(
        [
            {
                "id": "CVE-2026-9999",
                "vendor": "Existing Vendor",
            }
        ],
        source="CISA KEV",
        catalog_version="previous",
    )

    save_state(
        state_path,
        original_state,
    )

    monkeypatch.setattr(
        "b13intel.pipeline.fetch_kev",
        fake_catalog,
    )

    def fail_epss(cve_ids):
        raise RuntimeError(
            "simulated EPSS failure"
        )

    monkeypatch.setattr(
        "b13intel.pipeline.fetch_epss_scores",
        fail_epss,
    )

    with pytest.raises(
        RuntimeError,
        match="simulated EPSS failure",
    ):
        run_pipeline(
            root=tmp_path,
            generated_at="2026-09-10T00:00:00Z",
        )

    assert load_state(
        state_path
    ) == original_state


def test_pipeline_reports_change_delta_consistently(
    monkeypatch,
    tmp_path,
):
    previous_catalog = {
        "catalogVersion": "2026.09.09",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Vendor A",
                "product": "Product A",
                "vulnerabilityName": "Previous title",
                "knownRansomwareCampaignUse": "Unknown",
            },
            {
                "cveID": "CVE-2026-0002",
                "vendorProject": "Vendor B",
                "product": "Product B",
                "vulnerabilityName": "Removed vulnerability",
                "knownRansomwareCampaignUse": "Unknown",
            },
            {
                "cveID": "CVE-2026-0003",
                "vendorProject": "Vendor C",
                "product": "Product C",
                "vulnerabilityName": "Unchanged vulnerability",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ],
    }

    current_catalog = {
        "catalogVersion": "2026.09.10",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Vendor A",
                "product": "Product A",
                "vulnerabilityName": "Updated title",
                "knownRansomwareCampaignUse": "Unknown",
            },
            {
                "cveID": "CVE-2026-0003",
                "vendorProject": "Vendor C",
                "product": "Product C",
                "vulnerabilityName": "Unchanged vulnerability",
                "knownRansomwareCampaignUse": "Unknown",
            },
            {
                "cveID": "CVE-2026-0004",
                "vendorProject": "Vendor D",
                "product": "Product D",
                "vulnerabilityName": "New vulnerability",
                "knownRansomwareCampaignUse": "Known",
            },
        ],
    }

    previous_records = normalize_kev_catalog(
        previous_catalog
    )

    previous_state = build_state(
        previous_records,
        source="CISA KEV",
        catalog_version="2026.09.09",
    )

    state_path = (
        tmp_path
        / "data/state/cisa_kev.json"
    )

    save_state(
        state_path,
        previous_state,
    )

    monkeypatch.setattr(
        "b13intel.pipeline.fetch_kev",
        lambda: current_catalog,
    )

    monkeypatch.setattr(
        "b13intel.pipeline.fetch_epss_scores",
        lambda cve_ids: {
            "CVE-2026-0001": {
                "epss": 0.95,
                "epss_percentile": 0.999,
                "epss_date": "2026-09-10",
                "epss_source": "FIRST EPSS",
            },
            "CVE-2026-0003": {
                "epss": 0.30,
                "epss_percentile": 0.85,
                "epss_date": "2026-09-10",
                "epss_source": "FIRST EPSS",
            },
            "CVE-2026-0004": {
                "epss": 0.80,
                "epss_percentile": 0.99,
                "epss_date": "2026-09-10",
                "epss_source": "FIRST EPSS",
            },
        },
    )

    result = run_pipeline(
        root=tmp_path,
        generated_at="2026-09-10T00:00:00Z",
    )

    expected_counts = {
        "new": 1,
        "changed": 1,
        "removed": 1,
        "unchanged": 1,
    }

    assert result["changes"] == expected_counts

    assert (
        result["change_report"]["counts"]
        == expected_counts
    )

    assert (
        result["change_report"]["new_priority_counts"]
        == {
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
    )

    assert (
        result["change_report"]["changed_priority_counts"]
        == {
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
        }
    )

    assert [
        record["id"]
        for record in result["change_report"]["new_records"]
    ] == [
        "CVE-2026-0004"
    ]

    assert [
        record["id"]
        for record in result["change_report"]["changed_records"]
    ] == [
        "CVE-2026-0001"
    ]

    assert result["change_report"]["removed_ids"] == [
        "CVE-2026-0002"
    ]

    json_path = (
        tmp_path
        / "data/generated/latest.json"
    )

    document = json.loads(
        json_path.read_text(
            encoding="utf-8",
        )
    )

    assert document["schema_version"] == 2
    assert document["changes"]["counts"] == expected_counts

    assert (
        document["changes"]["new_records"][0]["id"]
        == "CVE-2026-0004"
    )

    assert (
        document["changes"]["changed_records"][0]["id"]
        == "CVE-2026-0001"
    )

    assert document["changes"]["removed_ids"] == [
        "CVE-2026-0002"
    ]

    markdown_path = (
        tmp_path
        / "reports/latest.md"
    )

    markdown = markdown_path.read_text(
        encoding="utf-8"
    )

    assert "| NEW | 1 |" in markdown
    assert "| CHANGED | 1 |" in markdown
    assert "| REMOVED | 1 |" in markdown
    assert "| UNCHANGED | 1 |" in markdown

    assert "CVE-2026-0004" in markdown
    assert "CVE-2026-0001" in markdown
    assert "CVE-2026-0002" in markdown
