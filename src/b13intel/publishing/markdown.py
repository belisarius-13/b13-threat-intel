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


def _validate_change_report(
    change_report: dict[str, Any],
) -> None:
    """Validate the change report required for Markdown output."""

    if not isinstance(change_report, dict):
        raise MarkdownPublishingError(
            "change_report must be a dictionary"
        )

    required_fields = {
        "counts",
        "new_priority_counts",
        "changed_priority_counts",
        "displayed",
        "new_records",
        "changed_records",
        "removed_ids",
    }

    missing_fields = (
        required_fields
        - set(change_report)
    )

    if missing_fields:
        raise MarkdownPublishingError(
            "change_report is missing required fields"
        )


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


def _render_change_records(
    title: str,
    records: list[dict[str, Any]],
    *,
    displayed: int,
    total: int,
) -> list[str]:
    """Render ranked new or changed intelligence records."""

    lines = [
        f"### {title}",
        "",
        f"Showing **{displayed}** of **{total}** records.",
        "",
    ]

    if not records:
        lines.extend(
            [
                "No records in this category.",
                "",
            ]
        )

        return lines

    lines.extend(
        [
            "| Priority | CVE | Vendor | Product | EPSS | Ransomware |",
            "| --- | --- | --- | --- | ---: | --- |",
        ]
    )

    for record in records:
        lines.append(
            "| "
            + " | ".join(
                [
                    _safe_text(
                        record.get("priority")
                    ),
                    _safe_text(
                        record.get("id")
                    ),
                    _safe_text(
                        record.get("vendor")
                    ),
                    _safe_text(
                        record.get("product")
                    ),
                    _format_probability(
                        record.get("epss")
                    ),
                    _safe_text(
                        record.get("ransomware_use")
                    ),
                ]
            )
            + " |"
        )

    lines.append("")

    return lines


def render_markdown_brief(
    records: list[dict[str, Any]],
    *,
    generated_at: str,
    change_report: dict[str, Any],
    catalog_version: str | None = None,
    top_n: int = DEFAULT_TOP_RECORDS,
) -> str:
    """Render an analyst-readable B13 threat intelligence brief."""

    if top_n <= 0:
        raise MarkdownPublishingError(
            "top_n must be greater than zero"
        )

    _validate_change_report(
        change_report
    )

    counts = Counter(
        record.get("priority")
        for record in records
    )

    change_counts = change_report["counts"]

    new_priority_counts = (
        change_report["new_priority_counts"]
    )

    changed_priority_counts = (
        change_report["changed_priority_counts"]
    )

    displayed = change_report["displayed"]

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
        "## What Changed",
        "",
        "| Change | Count |",
        "| --- | ---: |",
        f"| NEW | {change_counts['new']} |",
        f"| CHANGED | {change_counts['changed']} |",
        f"| REMOVED | {change_counts['removed']} |",
        f"| UNCHANGED | {change_counts['unchanged']} |",
        "",
        "### Change Priority Breakdown",
        "",
        "| Priority | New | Changed |",
        "| --- | ---: | ---: |",
        (
            f"| CRITICAL | "
            f"{new_priority_counts['critical']} | "
            f"{changed_priority_counts['critical']} |"
        ),
        (
            f"| HIGH | "
            f"{new_priority_counts['high']} | "
            f"{changed_priority_counts['high']} |"
        ),
        (
            f"| MEDIUM | "
            f"{new_priority_counts['medium']} | "
            f"{changed_priority_counts['medium']} |"
        ),
        (
            f"| LOW | "
            f"{new_priority_counts['low']} | "
            f"{changed_priority_counts['low']} |"
        ),
        "",
    ]

    lines.extend(
        _render_change_records(
            "New Intelligence",
            change_report["new_records"],
            displayed=displayed["new"],
            total=change_counts["new"],
        )
    )

    lines.extend(
        _render_change_records(
            "Updated Intelligence",
            change_report["changed_records"],
            displayed=displayed["changed"],
            total=change_counts["changed"],
        )
    )

    lines.extend(
        [
            "### Removed From CISA KEV",
            "",
            (
                f"Showing **{displayed['removed']}** "
                f"of **{change_counts['removed']}** records."
            ),
            "",
        ]
    )

    if change_report["removed_ids"]:
        for cve_id in change_report["removed_ids"]:
            lines.append(
                f"- {_safe_text(cve_id)}"
            )
    else:
        lines.append(
            "No CISA KEV records were removed."
        )

    lines.extend(
        [
            "",
            "## Top Priorities",
            "",
        ]
    )

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
