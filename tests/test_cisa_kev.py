import pytest
import requests

from b13intel.collectors.cisa_kev import (
    CISA_KEV_URL,
    KevCollectorError,
    fetch_kev,
)


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_fetch_kev_returns_catalog(monkeypatch):
    payload = {
        "catalogVersion": "2026.09.09",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Example",
                "product": "Example Product",
            }
        ],
    }

    def fake_get(url, timeout, headers):
        assert url == CISA_KEV_URL
        return FakeResponse(payload)

    monkeypatch.setattr(
        "b13intel.collectors.cisa_kev.requests.get",
        fake_get,
    )

    result = fetch_kev()

    assert result["count"] == 1
    assert len(result["vulnerabilities"]) == 1


def test_fetch_kev_rejects_missing_vulnerability_list(monkeypatch):
    def fake_get(url, timeout, headers):
        return FakeResponse({"count": 0})

    monkeypatch.setattr(
        "b13intel.collectors.cisa_kev.requests.get",
        fake_get,
    )

    with pytest.raises(
        KevCollectorError,
        match="missing the vulnerabilities list",
    ):
        fetch_kev()


def test_fetch_kev_handles_network_failure(monkeypatch):
    def fake_get(url, timeout, headers):
        raise requests.Timeout("request timed out")

    monkeypatch.setattr(
        "b13intel.collectors.cisa_kev.requests.get",
        fake_get,
    )

    with pytest.raises(
        KevCollectorError,
        match="Failed to fetch CISA KEV",
    ):
        fetch_kev()
