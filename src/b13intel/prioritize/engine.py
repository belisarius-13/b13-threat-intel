"""Explainable prioritization for B13 threat intelligence."""

from __future__ import annotations

from typing import Any


PRIORITY_MODEL = "B13-KEV-v1"

PRIORITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}


class PrioritizationError(ValueError):
    """Raised when a record cannot be prioritized safely."""


def _parse_probability(record: dict[str, Any]) -> float | None:
    """Return a validated EPSS probability."""

    value = record.get("epss")

    if value is None:
        return None

    try:
        probability = float(value)
    except (TypeError, ValueError) as exc:
        raise PrioritizationError(
            "EPSS probability must be numeric"
        ) from exc

    if not 0 <= probability <= 1:
        raise PrioritizationError(
            "EPSS probability must be between 0 and 1"
        )

    return probability


def prioritize_record(
    record: dict[str, Any],
) -> dict[str, Any]:
    """Assign an explainable B13 priority to one record."""

    enriched = dict(record)

    probability = _parse_probability(record)

    ransomware_use = record.get("ransomware_use")

    if isinstance(ransomware_use, str):
        ransomware_use = ransomware_use.strip().lower()
    else:
        ransomware_use = "unknown"

    is_kev = record.get("source") == "CISA KEV"

    reasons: list[str] = []

    if is_kev:
        reasons.append(
            "CISA KEV confirms exploitation in the wild"
        )

    if ransomware_use == "known":
        reasons.append(
            "CISA KEV reports known ransomware campaign use"
        )

    if probability is not None and probability >= 0.90:
        reasons.append(
            "EPSS probability is at or above 0.90"
        )
    elif probability is not None and probability >= 0.70:
        reasons.append(
            "EPSS probability is at or above 0.70"
        )

    if (
        is_kev
        and ransomware_use == "known"
        and probability is not None
        and probability >= 0.70
    ):
        priority = "CRITICAL"

    elif (
        is_kev
        and (
            ransomware_use == "known"
            or (
                probability is not None
                and probability >= 0.90
            )
        )
    ):
        priority = "HIGH"

    elif is_kev:
        priority = "MEDIUM"

    else:
        priority = "LOW"

    if not reasons:
        reasons.append(
            "No current elevated B13 prioritization signals"
        )

    enriched.update(
        {
            "priority": priority,
            "priority_reasons": reasons,
            "priority_model": PRIORITY_MODEL,
        }
    )

    return enriched


def prioritize_records(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Prioritize and rank vulnerability intelligence records."""

    prioritized = [
        prioritize_record(record)
        for record in records
    ]

    return sorted(
        prioritized,
        key=lambda record: (
            PRIORITY_ORDER[record["priority"]],
            -(
                record.get("epss")
                if record.get("epss") is not None
                else -1
            ),
            record.get("id", ""),
        ),
    )
