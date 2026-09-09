"""Normalize CISA KEV records into the B13 intelligence schema."""

from typing import Any


class KevNormalizationError(ValueError):
    """Raised when a CISA KEV record cannot be normalized."""


def normalize_kev_record(
    record: dict[str, Any],
) -> dict[str, Any]:
    """Convert one CISA KEV record into the B13 vulnerability schema."""

    cve_id = record.get("cveID")

    if not isinstance(cve_id, str) or not cve_id.strip():
        raise KevNormalizationError(
            "CISA KEV record is missing a valid cveID"
        )

    ransomware_value = record.get("knownRansomwareCampaignUse")

    if isinstance(ransomware_value, str):
        ransomware_use = ransomware_value.strip().lower()
    else:
        ransomware_use = "unknown"

    return {
        "id": cve_id.strip(),
        "type": "vulnerability",
        "source": "CISA KEV",
        "vendor": record.get("vendorProject"),
        "product": record.get("product"),
        "title": record.get("vulnerabilityName"),
        "description": record.get("shortDescription"),
        "date_added": record.get("dateAdded"),
        "due_date": record.get("dueDate"),
        "required_action": record.get("requiredAction"),
        "ransomware_use": ransomware_use,
        "notes": record.get("notes"),
        "cwes": record.get("cwes", []),
    }


def normalize_kev_catalog(
    catalog: dict[str, Any],
) -> list[dict[str, Any]]:
    """Normalize all vulnerabilities contained in a CISA KEV catalog."""

    vulnerabilities = catalog.get("vulnerabilities")

    if not isinstance(vulnerabilities, list):
        raise KevNormalizationError(
            "CISA KEV catalog is missing the vulnerabilities list"
        )

    normalized = [
        normalize_kev_record(record)
        for record in vulnerabilities
    ]

    return normalized