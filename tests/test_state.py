from b13intel.state import (
    build_state,
    compare_states,
    fingerprint_record,
    load_state,
    save_state,
)
from b13intel.normalize.cisa_kev import normalize_kev_catalog


def test_fingerprint_is_stable_across_key_order():
    first = {
        "id": "CVE-2026-0001",
        "vendor": "Example",
    }

    second = {
        "vendor": "Example",
        "id": "CVE-2026-0001",
    }

    assert fingerprint_record(first) == fingerprint_record(second)


def test_build_state():
    records = [
        {
            "id": "CVE-2026-0001",
            "vendor": "Vendor A",
        },
        {
            "id": "CVE-2026-0002",
            "vendor": "Vendor B",
        },
    ]

    state = build_state(
        records,
        source="CISA KEV",
        catalog_version="2026.09.09",
    )

    assert state["schema_version"] == 1
    assert state["source"] == "CISA KEV"
    assert state["record_count"] == 2
    assert len(state["fingerprints"]) == 2


def test_compare_states_detects_changes():
    previous_records = [
        {
            "id": "CVE-2026-0001",
            "vendor": "Vendor A",
        },
        {
            "id": "CVE-2026-0002",
            "vendor": "Vendor B",
        },
        {
            "id": "CVE-2026-0003",
            "vendor": "Vendor C",
        },
    ]

    current_records = [
        {
            "id": "CVE-2026-0001",
            "vendor": "Vendor A",
        },
        {
            "id": "CVE-2026-0002",
            "vendor": "Vendor B Updated",
        },
        {
            "id": "CVE-2026-0004",
            "vendor": "Vendor D",
        },
    ]

    previous = build_state(
        previous_records,
        source="CISA KEV",
    )

    current = build_state(
        current_records,
        source="CISA KEV",
    )

    result = compare_states(previous, current)

    assert result["new"] == ["CVE-2026-0004"]
    assert result["changed"] == ["CVE-2026-0002"]
    assert result["removed"] == ["CVE-2026-0003"]
    assert result["unchanged"] == ["CVE-2026-0001"]

    assert result["counts"] == {
        "new": 1,
        "changed": 1,
        "removed": 1,
        "unchanged": 1,
    }


def test_state_round_trip(tmp_path):
    records = [
        {
            "id": "CVE-2026-0001",
            "vendor": "Example",
        }
    ]

    state = build_state(
        records,
        source="CISA KEV",
        catalog_version="2026.09.09",
    )

    path = tmp_path / "state.json"

    save_state(path, state)

    loaded = load_state(path)

    assert loaded == state


def test_catalog_version_change_does_not_change_records():
    vulnerability = {
        "cveID": "CVE-2026-0001",
        "vendorProject": "Example Vendor",
        "product": "Example Product",
        "knownRansomwareCampaignUse": "Unknown",
    }

    first_catalog = {
        "catalogVersion": "2026.09.08",
        "vulnerabilities": [vulnerability],
    }

    second_catalog = {
        "catalogVersion": "2026.09.09",
        "vulnerabilities": [vulnerability],
    }

    first_records = normalize_kev_catalog(first_catalog)
    second_records = normalize_kev_catalog(second_catalog)

    first_state = build_state(
        first_records,
        source="CISA KEV",
        catalog_version="2026.09.08",
    )

    second_state = build_state(
        second_records,
        source="CISA KEV",
        catalog_version="2026.09.09",
    )

    result = compare_states(first_state, second_state)

    assert result["counts"] == {
        "new": 0,
        "changed": 0,
        "removed": 0,
        "unchanged": 1,
    }
