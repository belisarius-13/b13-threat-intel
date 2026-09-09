"""Command-line entry point for B13 Threat Intel."""

from __future__ import annotations

import argparse

from b13intel.pipeline import run_pipeline


def build_parser() -> argparse.ArgumentParser:
    """Build the B13 command-line parser."""

    parser = argparse.ArgumentParser(
        prog="b13intel",
        description=(
            "Run the BELISARIUS13 defensive "
            "threat-intelligence pipeline."
        ),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Execute collection, enrichment and "
            "prioritization without writing files."
        ),
    )

    return parser


def main() -> None:
    """Run the B13 Threat Intel command."""

    args = build_parser().parse_args()

    result = run_pipeline(
        write_outputs=not args.dry_run
    )

    priorities = result["priorities"]
    changes = result["changes"]

    print("B13 THREAT INTEL")
    print("================")
    print(
        f"Generated: {result['generated_at']}"
    )
    print(
        f"Catalog: {result['catalog_version']}"
    )
    print(
        f"Records: {result['records']}"
    )
    print(
        f"EPSS matched: {result['epss_matched']}"
    )
    print(
        f"EPSS missing: {result['epss_missing']}"
    )
    print()
    print("PRIORITIES")
    print(
        f"CRITICAL: {priorities['critical']}"
    )
    print(
        f"HIGH: {priorities['high']}"
    )
    print(
        f"MEDIUM: {priorities['medium']}"
    )
    print(
        f"LOW: {priorities['low']}"
    )
    print()
    print("SOURCE CHANGES")
    print(
        f"NEW: {changes['new']}"
    )
    print(
        f"CHANGED: {changes['changed']}"
    )
    print(
        f"REMOVED: {changes['removed']}"
    )
    print(
        f"UNCHANGED: {changes['unchanged']}"
    )

    if args.dry_run:
        print()
        print(
            "DRY RUN: no files were written."
        )


if __name__ == "__main__":
    main()
