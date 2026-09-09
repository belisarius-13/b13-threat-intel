from pathlib import Path

import pytest

from b13intel.pipeline import run_pipeline
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
