import pytest

from b13intel.prioritize.engine import (
    PRIORITY_MODEL,
    PrioritizationError,
    prioritize_record,
    prioritize_records,
)


def test_critical_for_ransomware_and_high_epss():
    record = {
        "id": "CVE-2026-0001",
        "source": "CISA KEV",
        "ransomware_use": "known",
        "epss": 0.80,
        "epss_percentile": 0.98,
    }

    result = prioritize_record(record)

    assert result["priority"] == "CRITICAL"
    assert result["priority_model"] == PRIORITY_MODEL
    assert len(result["priority_reasons"]) == 3


def test_high_for_known_ransomware_without_high_epss():
    record = {
        "id": "CVE-2026-0002",
        "source": "CISA KEV",
        "ransomware_use": "known",
        "epss": 0.40,
        "epss_percentile": 0.90,
    }

    result = prioritize_record(record)

    assert result["priority"] == "HIGH"


def test_high_for_very_high_epss_probability():
    record = {
        "id": "CVE-2026-0003",
        "source": "CISA KEV",
        "ransomware_use": "unknown",
        "epss": 0.95,
        "epss_percentile": 0.999,
    }

    result = prioritize_record(record)

    assert result["priority"] == "HIGH"


def test_medium_for_remaining_kev():
    record = {
        "id": "CVE-2026-0004",
        "source": "CISA KEV",
        "ransomware_use": "unknown",
        "epss": 0.40,
        "epss_percentile": 0.90,
    }

    result = prioritize_record(record)

    assert result["priority"] == "MEDIUM"


def test_low_without_elevated_signals():
    record = {
        "id": "CVE-2026-0005",
        "source": "OTHER",
        "ransomware_use": "unknown",
        "epss": 0.25,
        "epss_percentile": 0.80,
    }

    result = prioritize_record(record)

    assert result["priority"] == "LOW"


def test_invalid_epss_probability_is_rejected():
    record = {
        "id": "CVE-2026-0006",
        "source": "CISA KEV",
        "epss": 1.25,
    }

    with pytest.raises(
        PrioritizationError,
        match="EPSS probability must be between 0 and 1",
    ):
        prioritize_record(record)


def test_prioritization_does_not_mutate_source_record():
    record = {
        "id": "CVE-2026-0007",
        "source": "CISA KEV",
        "ransomware_use": "known",
        "epss": 0.99,
        "epss_percentile": 0.999,
    }

    original = record.copy()

    result = prioritize_record(record)

    assert record == original
    assert "priority" not in record
    assert result["priority"] == "CRITICAL"


def test_prioritize_records_orders_by_priority():
    records = [
        {
            "id": "CVE-2026-0001",
            "source": "CISA KEV",
            "ransomware_use": "unknown",
            "epss": 0.30,
            "epss_percentile": 0.95,
        },
        {
            "id": "CVE-2026-0002",
            "source": "CISA KEV",
            "ransomware_use": "known",
            "epss": 0.99,
            "epss_percentile": 0.99,
        },
        {
            "id": "CVE-2026-0003",
            "source": "CISA KEV",
            "ransomware_use": "unknown",
            "epss": 0.97,
            "epss_percentile": 0.999,
        },
    ]

    result = prioritize_records(records)

    assert [
        record["priority"]
        for record in result
    ] == [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
    ]
