from xml.etree import ElementTree as ET

import pytest

from b13intel.publishing.atom import (
    ATOM_NAMESPACE,
    FEED_ID,
    AtomPublishingError,
    build_atom_feed,
)


NS = {
    "atom": ATOM_NAMESPACE,
}


def sample_change_report():
    return {
        "new_records": [
            {
                "id": "CVE-2026-0001",
                "priority": "CRITICAL",
                "vendor": "Vendor A",
                "product": "Product A",
                "epss": 0.95,
                "ransomware_use": "known",
                "priority_reasons": [
                    "CISA KEV confirms exploitation in the wild",
                ],
                "notes": (
                    "https://nvd.nist.gov/vuln/"
                    "detail/CVE-2026-0001"
                ),
            }
        ],
        "changed_records": [
            {
                "id": "CVE-2026-0002",
                "priority": "HIGH",
                "vendor": "Vendor B",
                "product": "Product B",
                "epss": 0.91,
                "ransomware_use": "unknown",
                "priority_reasons": [
                    "EPSS probability is at or above 0.90",
                ],
            }
        ],
        "removed_ids": [
            "CVE-2025-9999"
        ],
    }


def test_build_atom_feed():
    xml = build_atom_feed(
        sample_change_report(),
        generated_at="2026-09-10T00:00:00Z",
        catalog_version="2026.09.10",
    )

    root = ET.fromstring(xml)

    assert root.tag == (
        f"{{{ATOM_NAMESPACE}}}feed"
    )

    assert (
        root.find("atom:id", NS).text
        == FEED_ID
    )

    entries = root.findall(
        "atom:entry",
        NS,
    )

    assert len(entries) == 3


def test_atom_feed_contains_change_entries():
    xml = build_atom_feed(
        sample_change_report(),
        generated_at="2026-09-10T00:00:00Z",
        catalog_version="2026.09.10",
    )

    root = ET.fromstring(xml)

    titles = [
        entry.find(
            "atom:title",
            NS,
        ).text
        for entry in root.findall(
            "atom:entry",
            NS,
        )
    ]

    assert any(
        "[NEW] [CRITICAL] CVE-2026-0001"
        in title
        for title in titles
    )

    assert any(
        "[CHANGED] [HIGH] CVE-2026-0002"
        in title
        for title in titles
    )

    assert any(
        "[REMOVED] CVE-2025-9999"
        in title
        for title in titles
    )


def test_atom_entry_ids_include_catalog_version():
    xml = build_atom_feed(
        sample_change_report(),
        generated_at="2026-09-10T00:00:00Z",
        catalog_version="2026.09.10",
    )

    root = ET.fromstring(xml)

    ids = [
        entry.find(
            "atom:id",
            NS,
        ).text
        for entry in root.findall(
            "atom:entry",
            NS,
        )
    ]

    assert (
        "urn:belisarius13:threat-intel:"
        "2026.09.10:new:CVE-2026-0001"
        in ids
    )


def test_atom_feed_is_valid_when_no_changes_exist():
    xml = build_atom_feed(
        {
            "new_records": [],
            "changed_records": [],
            "removed_ids": [],
        },
        generated_at="2026-09-10T00:00:00Z",
        catalog_version="2026.09.10",
    )

    root = ET.fromstring(xml)

    assert root.findall(
        "atom:entry",
        NS,
    ) == []


def test_atom_feed_rejects_missing_fields():
    with pytest.raises(
        AtomPublishingError,
        match="missing required fields",
    ):
        build_atom_feed(
            {
                "new_records": [],
            },
            generated_at="2026-09-10T00:00:00Z",
        )
