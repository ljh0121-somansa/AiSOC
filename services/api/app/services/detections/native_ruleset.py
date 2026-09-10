"""Sync the on-disk native detection corpus into the ``detection_rules`` table.

The repo ships ~870 curated rules under ``detections/<category>/*.yaml`` (cloud,
identity, endpoint, network, application, data-exfil). Each is a plain native-
format YAML file with an ``id: det-<category>-NNN`` key. This module walks the
tree and upserts one row per rule so the corpus is visible and manageable from
the web console at ``/detection`` — **without** touching the live fusion
pipeline, which evaluates events against ``detection_ruleset.json`` and is not
reconfigured by this sync.

Key design points (see the plan for the full rationale):

* The ``detection_rules.id`` column is a UUID, but native ids are strings like
  ``det-endpoint-123``. We hash each native id into a deterministic UUIDv5
  (:func:`uuid.uuid5`) so the row lands in the UUID column AND re-runs map to
  the same row (idempotency) instead of colliding.

* The two rows the migration-050 seed inserted by hand never set ``id`` (they
  let Postgres assign a random uuid4 default), so they can't be deleted by id.
  They are retired here **by name** before the native rows are written, and the
  native re-sync recreates the same two rules from YAML as ``rule_type='native'``.

* The sync never clobbers an operator's toggle: when a row already exists we
  refresh only metadata and preserve ``status`` (plus ``total_hits`` /
  ``last_triggered`` / ``confidence``), so turning a rule off survives a re-seed.

Nothing here is a new dependency; PyYAML is already pinned in ``services/api``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection_rule import DetectionRule

# Fixed namespace so the same native id always maps to the same UUIDv5 on any
# machine / any re-run. It's a plain opaque seed — no security meaning.
_NAMESPACE_UUID = uuid.UUID("c15a2c00-1111-4b04-8000-0000000000a1")

# The six native-format categories we treat as built-in platform content. The
# folders that hold sigma/splunk/car imports, playbooks and fixtures are
# deliberately excluded — those are governed by their own pipelines.
_NATIVE_CATEGORIES: tuple[str, ...] = (
    "cloud",
    "identity",
    "endpoint",
    "network",
    "application",
    "data-exfil",
)

# Legacy hardcoded rows (migration-050) keyed by the exact ``name`` they were
# inserted with. Deleting by name is required because their real ``id`` is a
# random uuid4, never the ``det-`` string a naive id-based delete expects.
_LEGACY_ROW_NAMES: tuple[str, ...] = (
    "Authentication Brute-Force Burst",
    "Burst Of File Extension Renames To Common Ransom Markers",
)

# Best-effort MITRE technique → tactic lookup for native rules. Native YAML
# only carries the technique id in a tag (``mitre.attack.t1486``), so we map the
# id to a tactic label for the ``mitre_tactics`` column. Incomplete here is
# harmless: a rule simply won't list a tactic it can't resolve. This is a small,
# stable table covering the techniques the corpus actually uses.
_TECHNIQUE_TO_TACTIC: dict[str, str] = {
    "t1003": "Credential Access",
    "t1005": "Credential Access",
    "t1014": "Persistence",
    "t1021": "Lateral Movement",
    "t1027": "Defense Evasion",
    "t1030": "Data Transfer",
    "t1036": "Defense Evasion",
    "t1037": "Persistence",
    "t1040": "Credential Access",
    "t1041": "Exfiltration",
    "t1046": "Discovery",
    "t1047": "Discovery",
    "t1052": "Discovery",
    "t1053": "Execution",
    "t1055": "Defense Evasion",
    "t1056": "Collection",
    "t1059": "Execution",
    "t1068": "Privilege Escalation",
    "t1069": "Privilege Escalation",
    "t1070": "Impact",
    "t1071": "Command and Control",
    "t1074": "Collection",
    "t1078": "Persistence",
    "t1083": "Discovery",
    "t1087": "Discovery",
    "t1090": "Command and Control",
    "t1095": "Command and Control",
    "t1098": "Persistence",
    "t1105": "Command and Control",
    "t1110": "Credential Access",
    "t1112": "Defense Evasion",
    "t1113": "Collection",
    "t1114": "Collection",
    "t1127": "Defense Evasion",
    "t1133": "Persistence",
    "t1135": "Persistence",
    "t1136": "Persistence",
    "t1140": "Defense Evasion",
    "t1176": "Persistence",
    "t1185": "Persistence",
    "t1190": "Initial Access",
    "t1195": "Initial Access",
    "t1199": "Initial Access",
    "t1204": "Execution",
    "t1212": "Privilege Escalation",
    "t1213": "Discovery",
    "t1218": "Execution",
    "t1219": "Persistence",
    "t1222": "Defense Evasion",
    "t1404": "Persistence",
    "t1482": "Discovery",
    "t1484": "Privilege Escalation",
    "t1485": "Impact",
    "t1486": "Impact",
    "t1489": "Impact",
    "t1490": "Impact",
    "t1496": "Discovery",
    "t1498": "Network Service Discovery",
    "t1499": "Impact",
    "t1505": "Persistence",
    "t1525": "Implant",
    "t1528": "Credential Access",
    "t1530": "Collection",
    "t1531": "Impact",
    "t1537": "Transfer Data to Cloud Account",
    "t1539": "Steal Web Credentials",
    "t1542": "Persistence",
    "t1543": "Persistence",
    "t1546": "Privilege Escalation",
    "t1547": "Privilege Escalation",
    "t1548": "Privilege Escalation",
    "t1550": "Use Alternate Authentication Material",
    "t1552": "Credential Access",
    "t1553": "Defense Evasion",
    "t1554": "Persistence",
    "t1555": "Credential Access",
    "t1556": "Credential Access",
    "t1557": "Credential Access",
    "t1558": "Credential Access",
    "t1560": "Collect Data",
    "t1561": "Collect Data",
    "t1562": "Defense Evasion",
    "t1564": "Privilege Escalation",
    "t1565": "Data Manipulation",
    "t1566": "Initial Access",
    "t1567": "Exfiltration",
    "t1568": "Command and Control",
    "t1570": "Command and Control",
    "t1572": "Command and Control",
    "t1573": "Exfiltration",
    "t1574": "Privilege Escalation",
    "t1578": "Command and Control",
    "t1583": "Resource Development",
    "t1592": "Discovery",
    "t1595": "Active Scanning",
    "t1600": "Resource Development",
    "t1606": "Initial Access",
    "t1609": "Command and Control",
    "t1610": "Execution",
    "t1611": "Privilege Escalation",
    "t1612": "Command and Control",
    "t1620": "Implant",
    "t1621": "Command and Control",
    "t1647": "Command and Control",
    "t1659": "Command and Control",
}


@dataclass(frozen=True, slots=True)
class NativeRuleError:
    """A per-file problem recorded (never raised) so one bad file can't abort."""

    path: str
    error: str


@dataclass(slots=True)
class NativeRulesetReport:
    """Aggregate outcome of one :func:`seed_native_ruleset` run."""

    rows_read: int = 0
    rows_inserted: int = 0
    rows_updated: int = 0
    rows_skipped: int = 0
    errors: list[NativeRuleError] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rows_read": self.rows_read,
            "rows_inserted": self.rows_inserted,
            "rows_updated": self.rows_updated,
            "rows_skipped": self.rows_skipped,
            "errors": [dict(e) for e in self.errors],
        }


_NATIVE_CATEGORY_DIRS: frozenset[str] = frozenset(_NATIVE_CATEGORIES)


def _is_native_corpus(candidate: Path) -> bool:
    """True if ``candidate`` is a repo root whose ``detections/`` holds the
    native-format corpus (the six category folders). This is used to
    disambiguate the repo checkout from the coincidentally named Python package
    directory ``services/api/app/services/detections/`` that merely contains
    this module — walking for "any ``detections/``" would resolve to that.
    """
    return (candidate / "detections").is_dir() and _NATIVE_CATEGORY_DIRS.issubset(
        {d.name for d in (candidate / "detections").iterdir() if d.is_dir()}
    )


def _repo_root(default: Path | None) -> Path:
    """Resolve where ``detections/`` lives.
    Walks up from this file looking for the deepest ancestor whose
    ``detections/`` child actually holds the native-format corpus (the six
    category folders: cloud, identity, endpoint, network, application,
    data-exfil). Walking stops at the first package-named ``detections/`` that
    does NOT — the module itself lives under
    ``services/api/app/services/detections/``, so a naive "deepest match" would
    otherwise resolve to that empty package directory.
    Returns the repo checkout root. ``--repo-root`` overrides the search
    entirely (used when running image-only without the checkout mounted).
    """
    if default is not None:
        return default
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        if _is_native_corpus(ancestor):
            return ancestor
    return here.parents[-1]


def _extract_mitre_techniques(tags: list[Any] | None) -> list[str]:
    """Pull ``mitre.attack.tXXXX[.yyy]`` ids out of a native YAML ``tags`` list."""
    out: list[str] = []
    if not tags:
        return out
    for tag in tags:
        text = str(tag)
        if not text.startswith("mitre.attack.t"):
            continue
        # Keep the leading technique id (drop any subtechnique suffix).
        parts = text.split(".", 3)  # [mitre, attack, t1486, ...]
        if len(parts) >= 3 and parts[2].upper().startswith("T"):
            base = parts[2][1:]  # strip the leading 't'
            out.append(base)
    return out


def _extract_mitre_tactics(techniques: list[str]) -> list[str]:
    """Best-effort tactic names from the resolved technique ids."""
    out: list[str] = []
    for tech in techniques:
        tactic = _TECHNIQUE_TO_TACTIC.get(f"t{tech.lower()}")
        if tactic and tactic not in out:
            out.append(tactic)
    return out


def _coerce_severity(value: Any) -> str:
    """Coerce a native ``severity`` to the five-tier ladder, never NULL."""
    text = str(value).strip().lower() if value is not None else ""
    if text in {"critical", "high", "medium", "low", "info"}:
        return text
    return "medium"


def _read_native_rules(repo_root: Path, categories: tuple[str, ...] | None) -> list[dict[str, Path]]:
    """Yield ``(raw_dict, rel_path)`` for every native rule file under ``repo_root``.

    Files are read verbatim (the exact bytes become ``rule_body``) and parsed with
    ``safe_load``. Parse failures are surfaced by raising ``ValueError`` for the
    caller to record — per-file isolation lives in the caller, not here.
    """
    root = _repo_root(repo_root)
    cats = _NATIVE_CATEGORIES if categories is None else tuple(categories)
    results: list[dict[str, Path]] = []
    for cat in cats:
        cat_dir = root / "detections" / cat
        if not cat_dir.is_dir():
            continue
        for yaml_file in sorted(cat_dir.glob("*.yaml")):
            raw_text = yaml_file.read_text(encoding="utf-8")
            results.append({"raw": raw_text, "path": yaml_file})
    return results


async def seed_native_ruleset(
    session: AsyncSession,
    *,
    repo_root: Path | None = None,
    categories: tuple[str, ...] | None = None,
    dry_run: bool = False,
    exclude_ids: tuple[str, ...] = (),
) -> NativeRulesetReport:
    """Upsert the native YAML corpus into ``detection_rules``.

    Idempotent and keyed on the deterministic UUIDv5 of each native id: re-running
    updates metadata while preserving whatever an operator set for ``status``,
    ``total_hits`` and ``confidence``.

    Args:
        session: open async SQLAlchemy session. Caller owns the commit.
        repo_root: where ``detections/`` lives. Defaults to the deepest available
            ancestor of this file (the local repo checkout).
        categories: restrict to a subset of the native categories; ``None`` (the
            default) syncs all six.
        dry_run: compute and report without writing.
        exclude_ids: native ids (the ``det-...`` strings) to skip entirely; used
            to drop a rule the operator decided to retire from the corpus.

    Returns:
        :class:`NativeRulesetReport` with the per-run counts.
    """
    report = NativeRulesetReport()
    repo = _repo_root(repo_root)
    if not (repo / "detections").is_dir():
        raise FileNotFoundError(
            f"detections/ not found at {repo}. Pass --repo-root, mount the "
            f"detections/ volume, or run from the repo checkout."
        )

    # ── Legacy cleanup ──────────────────────────────────────────────────────────
    # Remove the hardcoded migration-050 rows by name before the native re-sync
    # recreates them as proper native rows. Scoped to rule_type <> 'native' so a
    # native row that merely shares a legacy name (e.g. the brute-force / ransom
    # rules, which are rule_language='sigma') is never deleted here — the native
    # re-sync below re-inserts/updates it. Without this guard every re-seed would
    # churn those rows and destroy any operator toggle-off state.
    if not dry_run:
        try:
            from sqlalchemy import text as _text

            await session.execute(
                _text(
                    "DELETE FROM detection_rules "
                    "WHERE rule_type <> 'native' "
                    "AND rule_language = 'sigma' "
                    f"AND name IN ({','.join(chr(39) + n + chr(39) for n in _LEGACY_ROW_NAMES)})"
                )
            )
        except Exception:  # noqa: BLE001 -- best-effort, never fatal
            # If this fails (e.g. legacy rows already gone), the native rows will
            # simply upsert over anything sharing the same name-derived id.
            pass

    # ─── Walk + upsert ──────────────────────────────────────────────────────────

    for entry in _read_native_rules(repo, categories):
        raw = entry["raw"]
        yaml_file = entry["path"]
        rel = str(yaml_file.relative_to(repo))
        report.rows_read += 1

        try:
            data = yaml.safe_load(raw)
            if not isinstance(data, dict):
                raise ValueError("document is not a mapping")
            native_id = str(data.get("id") or "").strip()
            if not native_id or not native_id.startswith("det-"):
                raise ValueError(f"missing or non-native id (got {native_id!r})")
            name = str(data.get("name") or "").strip()
            if not name:
                raise ValueError("missing 'name'")
        except Exception as exc:  # noqa: BLE001 -- per-file failure isolation
            report.errors.append(NativeRuleError(path=rel, error=str(exc)))
            report.rows_skipped += 1
            continue

        if native_id in exclude_ids:
            report.rows_skipped += 1
            continue

        raw_id = uuid.uuid5(_NAMESPACE_UUID, native_id)
        # ── Fetch any existing row by the deterministic id ────────────────
        existing = None
        if not dry_run:
            existing = (await session.execute(select(DetectionRule).where(DetectionRule.id == raw_id))).scalar_one_or_none()

        new_rule = DetectionRule(
            id=raw_id,
            name=name,
            tenant_id=None,  # platform-wide built-in
            rule_language="sigma",  # frontend LANG_LABEL knows 'sigma'
            rule_body=raw,  # verbatim bytes — editor shows the exact shipped rule
            category=(yaml_file.parent.name),
            provenance={
                "source": "native",
                "origin": rel,
                "tier": "native",
            },
            is_builtin=True,
            version=data.get("version", 1) if isinstance(data.get("version"), int) else 1,
            confidence=85,
            status="active",  # insert default; the update path leaves status untouched
            created_by_id=None,
        )

        if existing is not None:
            # Metadata refresh ONLY. Preserve operator state (status, hits,
            # last_triggered, confidence) so a toggle-off survives a re-seed.
            existing.name = name
            existing.description = data.get("description")
            existing.category = new_rule.category
            existing.severity = _coerce_severity(data.get("severity"))
            existing.mitre_tactics = _extract_mitre_tactics(_extract_mitre_techniques(data.get("tags")))
            existing.mitre_techniques = _extract_mitre_techniques(data.get("tags"))
            existing.tags = list(data.get("tags") or [])
            existing.file_path = rel
            existing.version = new_rule.version
            existing.provenance = dict(new_rule.provenance)
            existing.rule_type = "native"
            # ``status`` intentionally preserved.
            report.rows_updated += 1
        else:
            new_rule.severity = _coerce_severity(data.get("severity"))
            new_rule.mitre_tactics = _extract_mitre_tactics(_extract_mitre_techniques(data.get("tags")))
            new_rule.mitre_techniques = _extract_mitre_techniques(data.get("tags"))
            new_rule.tags = list(data.get("tags") or [])
            new_rule.file_path = rel
            new_rule.rule_type = "native"
            if not dry_run:
                session.add(new_rule)
            report.rows_inserted += 1

    if not dry_run:
        await session.flush()

    return report
