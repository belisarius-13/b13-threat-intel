"""Atom syndication publishing for B13 threat intelligence."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET


ATOM_NAMESPACE = "http://www.w3.org/2005/Atom"
FEED_ID = "urn:belisarius13:threat-intel:changes"
FEED_TITLE = "BELISARIUS13 Threat Intelligence Changes"

ET.register_namespace("", ATOM_NAMESPACE)


class AtomPublishingError(ValueError):
    """Raised when an Atom feed cannot be generated safely."""


def _atom_tag(name: str) -> str:
    """Return a namespaced Atom XML tag."""

    return f"{{{ATOM_NAMESPACE}}}{name}"


def _safe_text(value: Any) -> str:
    """Return compact human-readable text."""

    if value is None:
        return "N/A"

    return " ".join(str(value).split())


def _entry_id(
    *,
    catalog_version: str | None,
    change_type: str,
    cve_id: str,
) -> str:
    """Return a stable Atom entry ID for one change event."""

    version = catalog_version or "unknown"

    return (
        "urn:belisarius13:threat-intel:"
        f"{version}:{change_type.lower()}:{cve_id}"
    )


def _record_summary(
    record: dict[str, Any],
    *,
    change_type: str,
) -> str:
    """Build an analyst-readable summary for one vulnerability."""

    reasons = record.get(
        "priority_reasons",
        [],
    )

    if not isinstance(reasons, list):
        reasons = []

    reason_text = "; ".join(
        _safe_text(reason)
        for reason in reasons
    )

    parts = [
        f"Change: {change_type}",
        f"Priority: {_safe_text(record.get('priority'))}",
        f"Vendor: {_safe_text(record.get('vendor'))}",
        f"Product: {_safe_text(record.get('product'))}",
        f"EPSS: {_safe_text(record.get('epss'))}",
        (
            "Known ransomware use: "
            f"{_safe_text(record.get('ransomware_use'))}"
        ),
    ]

    if reason_text:
        parts.append(
            f"Reasons: {reason_text}"
        )

    return " | ".join(parts)


def _add_record_entry(
    feed: ET.Element,
    record: dict[str, Any],
    *,
    change_type: str,
    generated_at: str,
    catalog_version: str | None,
) -> None:
    """Add a NEW or CHANGED vulnerability entry."""

    cve_id = record.get("id")

    if not isinstance(cve_id, str) or not cve_id.strip():
        raise AtomPublishingError(
            "Change record is missing a valid id"
        )

    cve_id = cve_id.strip()

    entry = ET.SubElement(
        feed,
        _atom_tag("entry"),
    )

    ET.SubElement(
        entry,
        _atom_tag("id"),
    ).text = _entry_id(
        catalog_version=catalog_version,
        change_type=change_type,
        cve_id=cve_id,
    )

    priority = _safe_text(
        record.get("priority")
    )

    vendor = _safe_text(
        record.get("vendor")
    )

    product = _safe_text(
        record.get("product")
    )

    ET.SubElement(
        entry,
        _atom_tag("title"),
    ).text = (
        f"[{change_type}] [{priority}] "
        f"{cve_id} — {vendor} {product}"
    )

    ET.SubElement(
        entry,
        _atom_tag("updated"),
    ).text = generated_at

    ET.SubElement(
        entry,
        _atom_tag("category"),
        {
            "term": change_type.lower(),
            "label": change_type,
        },
    )

    ET.SubElement(
        entry,
        _atom_tag("category"),
        {
            "term": priority.lower(),
            "label": priority,
        },
    )

    ET.SubElement(
        entry,
        _atom_tag("summary"),
        {
            "type": "text",
        },
    ).text = _record_summary(
        record,
        change_type=change_type,
    )

    notes = record.get("notes")

    if (
        isinstance(notes, str)
        and notes.startswith(
            ("https://", "http://")
        )
    ):
        ET.SubElement(
            entry,
            _atom_tag("link"),
            {
                "href": notes,
                "rel": "alternate",
            },
        )


def _add_removed_entry(
    feed: ET.Element,
    cve_id: str,
    *,
    generated_at: str,
    catalog_version: str | None,
) -> None:
    """Add a removed CISA KEV entry."""

    if not isinstance(cve_id, str) or not cve_id.strip():
        raise AtomPublishingError(
            "Removed record is missing a valid id"
        )

    cve_id = cve_id.strip()

    entry = ET.SubElement(
        feed,
        _atom_tag("entry"),
    )

    ET.SubElement(
        entry,
        _atom_tag("id"),
    ).text = _entry_id(
        catalog_version=catalog_version,
        change_type="REMOVED",
        cve_id=cve_id,
    )

    ET.SubElement(
        entry,
        _atom_tag("title"),
    ).text = (
        f"[REMOVED] {cve_id} removed from CISA KEV"
    )

    ET.SubElement(
        entry,
        _atom_tag("updated"),
    ).text = generated_at

    ET.SubElement(
        entry,
        _atom_tag("category"),
        {
            "term": "removed",
            "label": "REMOVED",
        },
    )

    ET.SubElement(
        entry,
        _atom_tag("summary"),
        {
            "type": "text",
        },
    ).text = (
        f"{cve_id} is no longer present "
        "in the current CISA KEV catalog."
    )


def build_atom_feed(
    change_report: dict[str, Any],
    *,
    generated_at: str,
    catalog_version: str | None = None,
) -> str:
    """Build an Atom feed from the current B13 change report."""

    if not isinstance(change_report, dict):
        raise AtomPublishingError(
            "change_report must be a dictionary"
        )

    required_fields = {
        "new_records",
        "changed_records",
        "removed_ids",
    }

    missing_fields = (
        required_fields
        - set(change_report)
    )

    if missing_fields:
        raise AtomPublishingError(
            "change_report is missing required fields"
        )

    if not generated_at:
        raise AtomPublishingError(
            "generated_at is required"
        )

    feed = ET.Element(
        _atom_tag("feed")
    )

    ET.SubElement(
        feed,
        _atom_tag("id"),
    ).text = FEED_ID

    ET.SubElement(
        feed,
        _atom_tag("title"),
    ).text = FEED_TITLE

    ET.SubElement(
        feed,
        _atom_tag("updated"),
    ).text = generated_at

    ET.SubElement(
        feed,
        _atom_tag("subtitle"),
    ).text = (
        "Change-aware defensive vulnerability intelligence "
        "from BELISARIUS13."
    )

    for record in change_report["new_records"]:
        _add_record_entry(
            feed,
            record,
            change_type="NEW",
            generated_at=generated_at,
            catalog_version=catalog_version,
        )

    for record in change_report["changed_records"]:
        _add_record_entry(
            feed,
            record,
            change_type="CHANGED",
            generated_at=generated_at,
            catalog_version=catalog_version,
        )

    for cve_id in change_report["removed_ids"]:
        _add_removed_entry(
            feed,
            cve_id,
            generated_at=generated_at,
            catalog_version=catalog_version,
        )

    ET.indent(
        feed,
        space="  ",
    )

    xml_body = ET.tostring(
        feed,
        encoding="unicode",
        xml_declaration=False,
    )

    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        + xml_body
        + "\n"
    )


def write_atom_feed(
    path: Path,
    content: str,
) -> None:
    """Write the B13 Atom feed to disk."""

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        content,
        encoding="utf-8",
    )
