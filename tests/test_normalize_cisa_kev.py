import pytest

from b13intel.normalize.cisa_kev import (
    KevNormalizationError,
    normalize_kev_catalog,
    normalize_kev_record,
)


def test_normalize_kev_record():
    record = {
        "cveID": "CVE-2026-0001",
        "vendorProject": "Example Vendor",
        "product": "Example Product",
        "vulnerabilityName": "Example Vulnerability",
        "dateAdded": "2026-09-01",
        "shortDescription": "Example description.",
        "requiredAction": "Apply mitigations.",
        "dueDate": "2026-09-20",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Example notes.",
        "cwes": ["CWE-79"],
    }

    result = normalize_kev_record(record)

    assert result["id"] == "CVE-2026-0001"
    assert result["type"] == "vulnerability"
    assert result["source"] == "CISA KEV"
    assert result["vendor"] == "Example Vendor"
    assert result["product"] == "Example Product"
    assert result["ransomware_use"] == "known"
    assert result["cwes"] == ["CWE-79"]


def test_normalize_kev_record_rejects_missing_cve():
    with pytest.raises(
        KevNormalizationError,
        match="missing a valid cveID",
    ):
        normalize_kev_record(
            {
                "vendorProject": "Example Vendor",
            }
        )


def test_normalize_kev_catalog():
    catalog = {
        "catalogVersion": "2026.09.09",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Vendor A",
                "knownRansomwareCampaignUse": "Unknown",
            },
            {
                "cveID": "CVE-2026-0002",
                "vendorProject": "Vendor B",
                "knownRansomwareCampaignUse": "Known",
            },
        ],
    }

    result = normalize_kev_catalog(catalog)

    assert len(result) == 2
    assert result[0]["id"] == "CVE-2026-0001"
    assert result[0]["ransomware_use"] == "unknown"
    assert result[1]["id"] == "CVE-2026-0002"
    assert result[1]["ransomware_use"] == "known"
