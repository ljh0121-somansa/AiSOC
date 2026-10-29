"""Shared AiSOC service-token resolver (plan U16, de-duplication).

The agents service talks to the api service's internal graph routes using a
shared secret passed as the ``X-AiSOC-Service-Token`` header. Six modules
previously each defined their own ``_service_token``; this module is the
single source of truth for that lookup.

The token is read dynamically (never at import time) so a secret injected
after the process starts is picked up — see the incident fix in
docker-compose.yml. ``AISOC_AGENTS_SERVICE_TOKEN`` is primary; the legacy
``AISOC_SERVICE_TOKEN`` is the fallback alias.
"""

from __future__ import annotations

import os

#: Primary + legacy env var names for the shared service token.
PRIMARY_ENV = "AISOC_AGENTS_SERVICE_TOKEN"
LEGACY_ENV = "AISOC_SERVICE_TOKEN"


def service_token() -> str:
    """Return the shared service token, or ``""`` when unset.

    Reads ``AISOC_AGENTS_SERVICE_TOKEN`` first, falling back to the legacy
    ``AISOC_SERVICE_TOKEN``. An empty return means "do not call" the API's
    service path.
    """
    return (
        os.getenv(PRIMARY_ENV, "").strip()
        or os.getenv(LEGACY_ENV, "").strip()
    )
