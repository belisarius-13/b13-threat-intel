"""Markdown publishing for B13 threat intelligence."""

from __future__ import annotations

import html
from collections import Counter
from pathlib import Path
from typing import Any

from b13intel.prioritize.engine import PRIORITY_MODEL


DEFAULT_TOP_RECORDS = 20


class MarkdownPublishingError(ValueError):
    """Raised when a Markdown brief cannot be generated."""


def _safe_text(value: Any) -> str:
    """Return safe single-line text for Markdown output."""

    if value is None:
        return "N/A"

    text = " ".join(
        str(value).split()
    )

    text = html.escape(
        text,
        quote=False,
    )

    return text.replace(
        "|",
        "\\|",
    )


def _format_probability(value: Any) -> str:
    """Format an EPSS probability for human-readable output."""

    if value is None:
        return "N/A"

    return f"{float(value):.4f}"


def render_markdown_brief(
    records: list[dict[str, Any]],
    *,
    generated_at: str,
    catalog_version: str | None = None,
    top_n: int = DEFAULT_TOP_RECORDS,
) -> str:
    """Render an analyst-readable B13 threat intelligence brief."""

    if top_n <= 0:
        raise MarkdownPublishingError(
            "top_n must be greater than zero"
        )

    counts = Counter(
        record.get("priority")
        for record in records
    )

    lines = [
        "# B13 Threat Intelligence Brief",
        "",
        f"**Generated:** {_safe_text(generated_at)}",
        "",
        f"**CISA KEV Catalog:** {_safe_text(catalog_version)}",
        "",
        f"**Priority Model:** {PRIORITY_MODEL}",
        "",
        "## Intelligence Summary",
        "",
        "| Priority | Count |",
        "| --- | ---: |",
        f"| CRITICAL | {counts['CRITICAL']} |",
        f"| HIGH | {counts['HIGH']} |",
        f"| MEDIUM | {counts['MEDIUM']} |",
        f"| LOW | {counts['LOW']} |",
        f"| **TOTAL** | **{len(records)}** |",
        "",
        "## Top Priorities",
        "",
    ]

    for index, record in enumerate(
        records[:top_n],
        start=1,
    ):
        cve_id = _safe_text(
            record.get("id")
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

        title = _safe_text(
            record.get("title")
        )

        ransomware = _safe_text(
            record.get("ransomware_use")
        )

        required_action = _safe_text(
            record.get("required_action")
        )

        epss = _format_probability(
            record.get("epss")
        )

        percentile = _format_probability(
            record.get("epss_percentile")
        )

        lines.extend(
            [
                f"### {index}. {cve_id}",
                "",
                f"- **Priority:** {priority}",
                f"- **Vendor:** {vendor}",
                f"- **Product:** {product}",
                f"- **Title:** {title}",
                f"- **EPSS:** {epss}",
                f"- **EPSS Percentile:** {percentile}",
                f"- **Known ransomware use:** {ransomware}",
                "",
                "**Why B13 prioritized this:**",
                "",
            ]
        )

        reasons = record.get(
            "priority_reasons",
            [],
        )

        if isinstance(reasons, list):
            for reason in reasons:
                lines.append(
                    f"- {_safe_text(reason)}"
                )

        lines.extend(
            [
                "",
                "**CISA required action:**",
                "",
                _safe_text(required_action),
                "",
                "---",
                "",
            ]
        )

    lines.extend(
        [
            "## Sources",
            "",
            "- CISA Known Exploited Vulnerabilities",
            "- FIRST Exploit Prediction Scoring System",
            "",
            "This brief is generated for defensive prioritization and threat-intelligence analysis.",
            "",
        ]
    )

    return "\n".join(lines)


def write_markdown_brief(
    path: Path,
    content: str,
) -> None:
    """Write a B13 Markdown intelligence brief."""

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        content,
        encoding="utf-8",
    )
