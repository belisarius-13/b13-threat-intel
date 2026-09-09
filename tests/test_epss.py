import pytest
import requests

from b13intel.enrich.epss import (
    EPSS_URL,
    EpssEnrichmentError,
    batch_cve_ids,
    enrich_with_epss,
    fetch_epss_scores,
)


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_batch_cve_ids_respects_query_limit():
    cve_ids = [
        "CVE-2026-0001",
        "CVE-2026-0002",
        "CVE-2026-0003",
    ]

    batches = batch_cve_ids(
        cve_ids,
        max_query_length=27,
    )

    assert batches == [
        ["CVE-2026-0001", "CVE-2026-0002"],
        ["CVE-2026-0003"],
    ]


def test_fetch_epss_scores(monkeypatch):
    payload = {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2026-0001",
                "epss": "0.812340000",
                "percentile": "0.991230000",
                "date": "2026-09-09",
            }
        ],
        "total": 1,
        "limit": 1,
    }

    def fake_get(url, params, timeout, headers):
        assert url == EPSS_URL
        assert params == {
            "cve": "CVE-2026-0001",
            "limit": 1,
        }
        return FakeResponse(payload)

    monkeypatch.setattr(
        "b13intel.enrich.epss.requests.get",
        fake_get,
    )

    result = fetch_epss_scores(
        ["CVE-2026-0001"]
    )

    assert result["CVE-2026-0001"]["epss"] == 0.81234
    assert (
        result["CVE-2026-0001"]["epss_percentile"]
        == 0.99123
    )
    assert (
        result["CVE-2026-0001"]["epss_source"]
        == "FIRST EPSS"
    )



def test_fetch_epss_detects_truncated_response(monkeypatch):
    payload = {
        "status": "OK",
        "total": 2,
        "limit": 1,
        "data": [
            {
                "cve": "CVE-2026-0001",
                "epss": "0.5",
                "percentile": "0.9",
                "date": "2026-09-09",
            }
        ],
    }

    def fake_get(url, params, timeout, headers):
        return FakeResponse(payload)

    monkeypatch.setattr(
        "b13intel.enrich.epss.requests.get",
        fake_get,
    )

    with pytest.raises(
        EpssEnrichmentError,
        match="response was truncated",
    ):
        fetch_epss_scores(
            [
                "CVE-2026-0001",
                "CVE-2026-0002",
            ]
        )

def test_fetch_epss_handles_network_failure(monkeypatch):
    def fake_get(url, params, timeout, headers):
        raise requests.Timeout("request timed out")

    monkeypatch.setattr(
        "b13intel.enrich.epss.requests.get",
        fake_get,
    )

    with pytest.raises(
        EpssEnrichmentError,
        match="Failed to fetch FIRST EPSS data",
    ):
        fetch_epss_scores(
            ["CVE-2026-0001"]
        )


def test_enrich_with_epss():
    records = [
        {
            "id": "CVE-2026-0001",
            "type": "vulnerability",
        },
        {
            "id": "CVE-2026-0002",
            "type": "vulnerability",
        },
    ]

    scores = {
        "CVE-2026-0001": {
            "epss": 0.75,
            "epss_percentile": 0.98,
            "epss_date": "2026-09-09",
            "epss_source": "FIRST EPSS",
        }
    }

    result = enrich_with_epss(records, scores)

    assert result[0]["epss"] == 0.75
    assert result[0]["epss_percentile"] == 0.98
    assert result[0]["epss_source"] == "FIRST EPSS"

    assert result[1]["epss"] is None
    assert result[1]["epss_percentile"] is None


def test_enrich_with_epss_does_not_mutate_source_records():
    records = [
        {
            "id": "CVE-2026-0001",
            "type": "vulnerability",
            "vendor": "Example Vendor",
        }
    ]

    original = records[0].copy()

    scores = {
        "CVE-2026-0001": {
            "epss": 0.75,
            "epss_percentile": 0.98,
            "epss_date": "2026-09-09",
            "epss_source": "FIRST EPSS",
        }
    }

    enriched = enrich_with_epss(records, scores)

    assert records[0] == original
    assert "epss" not in records[0]

    assert enriched[0]["epss"] == 0.75
    assert enriched[0]["epss_percentile"] == 0.98
