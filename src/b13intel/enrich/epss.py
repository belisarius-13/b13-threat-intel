"""FIRST EPSS enrichment for B13 vulnerability intelligence."""

from __future__ import annotations

from typing import Any

import requests


EPSS_URL = "https://api.first.org/data/v1/epss"
DEFAULT_TIMEOUT = 30
MAX_CVE_QUERY_LENGTH = 2000


class EpssEnrichmentError(RuntimeError):
    """Raised when EPSS enrichment cannot be completed."""


def batch_cve_ids(
    cve_ids: list[str],
    *,
    max_query_length: int = MAX_CVE_QUERY_LENGTH,
) -> list[list[str]]:
    """Split CVE IDs into API-safe batches."""

    batches: list[list[str]] = []
    current_batch: list[str] = []
    current_length = 0

    for raw_cve in cve_ids:
        if not isinstance(raw_cve, str) or not raw_cve.strip():
            raise EpssEnrichmentError(
                "EPSS enrichment received an invalid CVE ID"
            )

        cve_id = raw_cve.strip()

        if len(cve_id) > max_query_length:
            raise EpssEnrichmentError(
                f"CVE ID exceeds EPSS query limit: {cve_id}"
            )

        added_length = len(cve_id)

        if current_batch:
            added_length += 1  # comma separator

        if (
            current_batch
            and current_length + added_length > max_query_length
        ):
            batches.append(current_batch)
            current_batch = [cve_id]
            current_length = len(cve_id)
        else:
            current_batch.append(cve_id)
            current_length += added_length

    if current_batch:
        batches.append(current_batch)

    return batches


def fetch_epss_scores(
    cve_ids: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, dict[str, Any]]:
    """Fetch EPSS scores for CVE IDs and return them keyed by CVE."""

    if not cve_ids:
        return {}

    results: dict[str, dict[str, Any]] = {}

    for batch in batch_cve_ids(cve_ids):
        try:
            response = requests.get(
                EPSS_URL,
                params={
                    "cve": ",".join(batch),
                    "limit": len(batch),
                },
                timeout=timeout,
                headers={
                    "User-Agent": "B13-Threat-Intel/0.1",
                    "Accept": "application/json",
                },
            )
            response.raise_for_status()
            payload = response.json()

        except requests.RequestException as exc:
            raise EpssEnrichmentError(
                f"Failed to fetch FIRST EPSS data: {exc}"
            ) from exc

        except ValueError as exc:
            raise EpssEnrichmentError(
                "FIRST EPSS response was not valid JSON"
            ) from exc

        if not isinstance(payload, dict):
            raise EpssEnrichmentError(
                "FIRST EPSS response must be a JSON object"
            )

        data = payload.get("data")

        if not isinstance(data, list):
            raise EpssEnrichmentError(
                "FIRST EPSS response is missing the data list"
            )

        total = payload.get("total")

        if isinstance(total, int) and len(data) < total:
            raise EpssEnrichmentError(
                "FIRST EPSS response was truncated"
            )

        for item in data:
            if not isinstance(item, dict):
                continue

            cve_id = item.get("cve")

            if not isinstance(cve_id, str) or not cve_id:
                continue

            try:
                epss = float(item["epss"])
                percentile = float(item["percentile"])
            except (KeyError, TypeError, ValueError) as exc:
                raise EpssEnrichmentError(
                    f"Invalid EPSS score for {cve_id}"
                ) from exc

            results[cve_id] = {
                "epss": epss,
                "epss_percentile": percentile,
                "epss_date": item.get("date") or item.get("created"),
                "epss_source": "FIRST EPSS",
            }

    return results


def enrich_with_epss(
    records: list[dict[str, Any]],
    epss_scores: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Add EPSS information to normalized vulnerability records."""

    enriched_records: list[dict[str, Any]] = []

    for record in records:
        enriched = dict(record)

        cve_id = record.get("id")
        score = epss_scores.get(cve_id)

        if score:
            enriched.update(score)
        else:
            enriched.update(
                {
                    "epss": None,
                    "epss_percentile": None,
                    "epss_date": None,
                    "epss_source": None,
                }
            )

        enriched_records.append(enriched)

    return enriched_records
