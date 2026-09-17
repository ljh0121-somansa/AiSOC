#!/usr/bin/env python3
"""Keep ``services/api/app/_vendor/detection_matcher.py`` in lockstep with its source.

The ``match_when`` matcher is canonically owned by the fusion service at
``services/fusion/app/services/detection_matcher.py``. The api-service transpiler
``sigma_match_when.compile_sigma_to_match_when`` emits ``match_when`` grammar that
the fusion matcher must consume, so the matcher's exact operator semantics are the
contract the transpiler output is validated against (see
``services/api/tests/test_sigma_match_when.py``). Because the ``aisoc-api`` Docker
image is built with ``services/api`` as its build context, anything under
``services/fusion`` is unavailable at test time, so the api service ships a
byte-faithful vendored copy of the fusion matcher under ``app._vendor``.

Run modes
---------
* ``python scripts/sync_vendored_detection_matcher.py``           — copy source → vendored.
* ``python scripts/sync_vendored_detection_matcher.py --check``   — fail (exit 1) if the
  vendored file is missing or differs from the source. CI uses this mode.

The script is intentionally tiny and dependency-free so it can run in any CI runner.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILE = (
    REPO_ROOT
    / "services"
    / "fusion"
    / "app"
    / "services"
    / "detection_matcher.py"
)
VENDORED_FILE = (
    REPO_ROOT
    / "services"
    / "api"
    / "app"
    / "_vendor"
    / "detection_matcher.py"
)


def _check() -> int:
    if not SOURCE_FILE.is_file():
        print(f"FAIL: source file missing: {SOURCE_FILE}", file=sys.stderr)
        return 1
    if not VENDORED_FILE.is_file():
        print(f"FAIL: vendored file missing: {VENDORED_FILE}", file=sys.stderr)
        return 1
    if not filecmp.cmp(SOURCE_FILE, VENDORED_FILE, shallow=False):
        print(
            "FAIL: vendored detection_matcher.py is out of sync with source.\n"
            f"  Source:   {SOURCE_FILE.relative_to(REPO_ROOT)}\n"
            f"  Vendored: {VENDORED_FILE.relative_to(REPO_ROOT)}\n\n"
            "Re-run: python scripts/sync_vendored_detection_matcher.py",
            file=sys.stderr,
        )
        return 1
    print("OK: vendored detection_matcher.py matches source.")
    return 0


def _sync() -> int:
    if not SOURCE_FILE.is_file():
        print(f"FAIL: source file missing: {SOURCE_FILE}", file=sys.stderr)
        return 1
    VENDORED_FILE.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE_FILE, VENDORED_FILE)
    print(
        f"copied {SOURCE_FILE.relative_to(REPO_ROOT)} → "
        f"{VENDORED_FILE.relative_to(REPO_ROOT)}"
    )
    print("\nDone. Don't forget to commit services/api/app/_vendor/detection_matcher.py.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail with a non-zero exit code if the vendored file is out of sync.",
    )
    args = parser.parse_args()
    return _check() if args.check else _sync()


if __name__ == "__main__":
    raise SystemExit(main())
