"""Collector for CISA Known Exploited Vulnerabilities."""

from typing import Any

import requests


CISA_KEV_URL = (
    "https://api.github.com/repos/"
    "cisagov/kev-data/contents/"
    "known_exploited_vulnerabilities.json"
    "?ref=develop"
)

DEFAULT_TIMEOUT = 30


class KevCollectorError(RuntimeError):
    """Raised when the CISA KEV feed cannot be collected or validated."""


def fetch_kev(
    url: str = CISA_KEV_URL,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Fetch and minimally validate the CISA KEV catalog."""

    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={
                "User-Agent": "B13-Threat-Intel/0.1",
                "Accept": "application/vnd.github.raw+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        response.raise_for_status()
        payload = response.json()

    except requests.RequestException as exc:
        raise KevCollectorError(
            f"Failed to fetch CISA KEV: {exc}"
        ) from exc

    except ValueError as exc:
        raise KevCollectorError(
            "CISA KEV response was not valid JSON"
        ) from exc

    if not isinstance(payload, dict):
        raise KevCollectorError(
            "CISA KEV response must be a JSON object"
        )

    vulnerabilities = payload.get("vulnerabilities")

    if not isinstance(vulnerabilities, list):
        raise KevCollectorError(
            "CISA KEV response is missing the vulnerabilities list"
        )

    return payload
