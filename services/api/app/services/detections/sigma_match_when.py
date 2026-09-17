"""Compile Sigma ``selection``/``filter`` blocks into the live detection DSL.

The fusion live-detection pipeline evaluates an ingested event against a rule's
``match_when`` spec using the vendored matcher
(:mod:`app.services.detection_matcher`). This module is the *only* thing that
produces ``match_when`` for rules authored in Sigma, so it must emit tokens the
matcher actually understands and target the flat ``raw_data`` field schema the
matcher reads (connector-normalised, e.g. ``command_line``, ``image_basename``).

The matcher's evaluation core (``_eval_clause``) runs every top-level key through
``_split_op`` and compares the *value* directly, so ``match_when`` is a *flat*
``field_op -> value`` grammar with ``any_of`` / ``all_of`` as the only nested
combinators. (The plan's illustrative ``{"image_basename": {"in": [...]}}`` shape
is therefore unreachable; we emit the flat grammar that truly evaluates.)

Field alignment: Sigma
keys map to corpus fields via :data:`FIELD_MAP`; the matcher's ``_split_op`` then
recognises the ``_in`` / ``_contains`` / ``_not_in`` / ``_not_startswith``
suffixes this module emits.
"""

from __future__ import annotations

from typing import Any, NamedTuple

import structlog
import yaml

logger = structlog.get_logger()

# Sigma ``selection`` key -> flat connector raw_data field. Keys with no mapping
# are skipped (soft-fail); a missing raw_data field only short-circuits a clause.
# Both the plain Sigma name and its ``process.`` / ``destination.`` dotted forms
# are accepted so real community rules transpile without rewriting.
FIELD_MAP: dict[str, str] = {
    "commandline": "command_line",
    "process.commandline": "command_line",
    "image": "file_path",
    "image.path": "file_path",
    "process.path": "file_path",
    "image.name": "image_basename",
    "process.name": "image_basename",
    "sourceimage": "source_image",
    "process.source_image": "source_image",
    "process.parentimage": "source_image",
    "user": "user",
    "user.name": "user",
    "targetobject": "registry_path",
    "registry.key": "registry_path",
    "destinationip": "dst_ip",
    "destination.ip": "dst_ip",
    "destinationport": "dst_port",
    "destination.port": "dst_port",
    "sourceip": "src_ip",
    "source.ip": "src_ip",
    "eventcategory": "event_type",
    "event.category": "event_type",
}

# Sigma keys that already name a corpus flat field verbatim — pass straight through.
# ``image_basename`` lives here (a Sigma ``image: [a, b]`` list becomes
# ``image_basename_in`` and ``image: "*foo*`` becomes ``image_basename_contains``).
_PASSTHROUGH_FIELDS = frozenset(
    {
        "command_line",
        "file_path",
        "source_image",
        "user",
        "registry_path",
        "dst_ip",
        "src_ip",
        "dst_port",
        "event_type",
        "image_basename",
        "process_path",
    }
)

# Top-level ``detection.*`` keys that unambiguously make a rule windowed/stateful.
# Checked as *keys* (never as values) so Windows path strings inside selections
# never trip this — ``C:\\Windows\\...`` is data, not a window declaration.
_STATEFUL_TOP_KEYS = frozenset({"windows", "timeframe", "detection_actions"})
_STATEFUL_CONDITION_MARKERS = ("count(", "windows:", "timeframe:")


class CompileResult(NamedTuple):
    """Outcome of compiling one rule body.

    ``status``: ``compiled`` (``match_when`` populated), ``unsupported_stateful``
    (windowed / stateful — not broadcast to fusion) or ``error`` (parse problem).
    """

    status: str
    match_when: dict[str, Any] | None
    error: str | None


def _resolve_field(key: str) -> str | None:
    """Map a Sigma selection key to a flat field, or None if unrecognised."""
    lowered = key.lower()
    if lowered in FIELD_MAP:
        return FIELD_MAP[lowered]
    if key in _PASSTHROUGH_FIELDS:
        return key
    return None


def _coerce_value(value: Any) -> Any:
    """Coerce a Sigma scalar/list into the matcher's operand shape.

    A wildcard string (``*powershell*``) has its ``*`` stripped so ``contains``
    becomes a plain substring test; an empty/whitespace-only string returns None
    so the caller can drop the clause.
    """
    if isinstance(value, list):
        items = [str(v) for v in value if v is not None]
        return items or None
    if not isinstance(value, str):
        return value
    stripped = value.replace("*", "").strip()
    if not stripped:
        return None
    return stripped


def _build_clause(key: str, value: Any) -> tuple[str, Any] | None:
    """Build one ``field_op -> value`` clause for a ``selection`` entry.

    ``None`` means "skip" (unmapped field or empty operand) — a soft fail.
    """
    field = _resolve_field(key)
    if field is None:
        return None  # unmapped key -> skip (soft-fail)
    operand = _coerce_value(value)
    if operand is None:
        return None
    if isinstance(operand, list):
        return f"{field}_in", operand
    if "*" in str(value):
        return f"{field}_contains", operand
    return field, operand


def _clause_from_filter(key: str, value: Any) -> tuple[str, Any] | None:
    """Build one negated ``field_op -> value`` clause for a ``filter`` entry.

    Only the matcher's negation operators are emitted: ``not_in`` /
    ``not_contains_any`` for lists, ``not_startswith`` for a plain string.
    ``None`` means the value can't be negated (empty) -> caller drops it.
    """
    field = _resolve_field(key)
    if field is None:
        return None  # unmapped filter field -> drop (unsupported negation)
    if isinstance(value, list):
        items = [str(v) for v in value if v is not None]
        if not items:
            return None
        return f"{field}_not_in", items
    if not isinstance(value, str):
        return None
    stripped = value.replace("*", "").strip()
    if not stripped:
        return None
    if "*" in value:
        return f"{field}_not_contains_any", [stripped]
    return f"{field}_not_startswith", stripped


def _flatten_selection(selection_block: dict[str, Any]) -> dict[str, Any]:
    """Merge a selection's entries into a single flat AND dict (top-level).

    Unmappable keys and empty operands are dropped (soft-fail).
    """
    merged: dict[str, Any] = {}
    for key, value in selection_block.items():
        clause = _build_clause(key, value)
        if clause is None:
            continue
        merged[clause[0]] = clause[1]
    return merged


def _flatten_filter(filter_block: dict[str, Any]) -> dict[str, Any] | None:
    """Merge a ``filter`` block into negated clauses; None if it can't."""
    merged: dict[str, Any] = {}
    for key, value in filter_block.items():
        clause = _clause_from_filter(key, value)
        if clause is None:
            # A non-empty filter whose value can't be negated -> stateful so the
            # operator sees the rule is not live (guardrail A-5).
            if value not in (None, "", []):
                return None
            continue
        merged[clause[0]] = clause[1]
    return merged


def _is_stateful(detection: dict[str, Any]) -> bool:
    """True if the rule is windowed/stateful and must not be single-event matched."""
    if any(k in detection for k in _STATEFUL_TOP_KEYS):
        return True
    cond = detection.get("condition")
    if isinstance(cond, str) and any(m in cond for m in _STATEFUL_CONDITION_MARKERS):
        return True
    return False


def compile_sigma_to_match_when(rule_body: str) -> CompileResult:
    """Compile a Sigma YAML rule body into the fusion ``match_when`` DSL.

    See :class:`CompileResult` for the three status codes. Stateful rules return
    ``unsupported_stateful`` (and are *not* broadcast to fusion).
    """
    try:
        data = yaml.safe_load(rule_body)
    except yaml.YAMLError as exc:
        return CompileResult("error", None, f"YAML parse error: {exc}")

    if not isinstance(data, dict):
        return CompileResult("error", None, "rule body is not a mapping")

    detection = data.get("detection")
    if not isinstance(detection, dict):
        return CompileResult("error", None, "no 'detection' block found")

    if _is_stateful(detection):
        return CompileResult("unsupported_stateful", None, "Requires stateful window")

    # Guardrail [0-1]: emit only operators the vendored matcher recognises.
    # Iterate every dict-valued ``detection.*`` block (selection/filter/any named
    # selection groups); ``condition``/``windows``/``timeframe`` are strings and
    # are skipped.
    clause_dots: list[dict[str, Any]] = []
    for name, block in detection.items():
        if not isinstance(block, dict):
            continue
        if name == "filter":
            filter_clauses = _flatten_filter(block)
            if filter_clauses is None:
                return CompileResult("unsupported_stateful", None, "Unsupported filter negation")
            clause_dots.append(filter_clauses)
        else:
            flat = _flatten_selection(block)
            if flat:
                clause_dots.append(flat)

    if not clause_dots:
        return CompileResult("error", None, "selection produced no clauses")

    # Single selection/filter group -> flat dict; multiple groups -> all_of (AND),
    # which is the matcher's sole nested combinator. (OR-of-groups is not emitted;
    # Sigma ``1 of selection*`` is rare and out of single-event scope.)
    if len(clause_dots) == 1:
        return CompileResult("compiled", clause_dots[0], None)

    return CompileResult("compiled", {"all_of": clause_dots}, None)
