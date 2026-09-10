"""CLI entrypoint for syncing the native detection corpus into Postgres.

Mirrors ``seed_demo.py`` in style and location. Reads
``detections/<category>/*.yaml`` from the repo root (the API image doesn't ship
``detections/`` — mount ``../../detections:/app/detections:ro`` in the api
container) and upserts one row per rule via
:func:`app.services.detections.native_ruleset.seed_native_ruleset`.

Usage:
    python -m app.scripts.seed_native_detections [--category cloud ...] [--dry-run]

Dry-run prints the computed counts without writing.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from app.db.database import AsyncSessionLocal
from app.services.detections.native_ruleset import seed_native_ruleset


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m app.scripts.seed_native_detections",
        description=(
            "Sync the native repo detection corpus "
            "(detections/<category>/*.yaml) into the detection_rules table so "
            "the rules appear in the /detection console."
        ),
    )
    p.add_argument(
        "--category",
        action="append",
        dest="categories",
        metavar="NAME",
        help=(
            "Restrict the sync to one native category. Repeatable. "
            "One of: cloud, identity, endpoint, network, application, "
            "data-exfil. Omit to sync all six."
        ),
    )
    p.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help=(
            "Directory that contains detections/ (defaults to the repo checkout "
            "resolved from this file's location). Set when running image-only."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute and print counts without writing to the database.",
    )
    return p


async def _run(args: argparse.Namespace) -> None:
    categories = tuple(args.categories) if args.categories else None
    async with AsyncSessionLocal() as session:
        try:
            report = await seed_native_ruleset(
                session,
                repo_root=args.repo_root,
                categories=categories,
                dry_run=args.dry_run,
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise

    print(f"[seed] mode={'dry-run' if args.dry_run else 'write'}")
    print(f"[seed] categories={categories or 'all six native'}")
    print(f"[seed] rows_read:     {report.rows_read}")
    print(f"[seed] rows_inserted: {report.rows_inserted}")
    print(f"[seed] rows_updated:  {report.rows_updated}")
    print(f"[seed] rows_skipped:  {report.rows_skipped}")
    print(f"[seed] errors:        {len(report.errors)}")
    for err in report.errors:
        print(f"[seed]   ! {err.path}: {err.error}")
    verb = "would update" if args.dry_run else "updated"
    print(f"[seed] done — {report.rows_inserted} native rows inserted and {report.rows_updated} {verb}")


def main(argv: list[str] | None = None) -> None:
    args, _unknown = _build_arg_parser().parse_known_args(argv)
    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001 -- CLI surfaces operational errors
        print(f"[seed] failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
