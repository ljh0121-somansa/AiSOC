"""Compile native infix ``detection.condition`` into the fusion ``match_when`` DSL.

Native-format rules under ``detections/`` do not use Sigma ``selection`` /
``filter`` blocks (see :mod:`sigma_match_when`). Their ``detection.condition`` is a
human-readable infix string, e.g.:

    event_type == "user.session.start"
    AND outcome == "FAILURE"
    AND distinct_ports_per_src > 50
    AND (source_ports CONTAINS_ANY ["22", "3389"] OR source_ports IN ["445"])

This module turns that infix grammar into the nested ``match_when`` dict the vendored
fusion matcher (:mod:`app.services.detection_matcher`) evaluates. It mirrors
``sigma_match_when.compile_sigma_to_match_when`` so the two compilers share one
:class:`CompileResult` contract and are wired symmetrically into both the seed path
(``native_ruleset._record_compile``) and the console-write path
(``compiler.compile_rule``).

Grammar (inverse of the matcher contract in ``detection_matcher.OPERATORS``):

* ``field == val`` (string / bool / number) -> ``{field: val}``
* ``field IS NULL``                           -> ``{field: None}``
* ``field IN [...]`` / ``NOT IN [...]``       -> ``{field}_in`` / ``{field}_not_in``
* ``CONTAINS`` / ``CONTAINS_ANY`` / ``CONTAINS_ALL`` -> ``_contains`` / ``_contains_any`` / ``_contains_all``
* ``STARTSWITH(ANY)`` / ``ENDSWITH(ANY)``     -> ``_startswith(_any)`` / ``_endswith(_any)``
* ``NOT STARTSWITH`` / ``NOT CONTAINS_ANY`` / ``NOT ENDSWITH_ANY`` -> negation clause
* ``MATCH(MATCHES)(ANY)``                     -> ``_match(_any)``
* ``PATTERN_MATCH_ANY``                       -> ``_pattern_match_any``
* ``HAS_ANY``                                 -> ``_has_any``
* comparators ``> >= < <=``                   -> ``gt`` / ``gte`` / ``lt`` / ``lte``

OR flattens to nested ``any_of``; AND merges flat dicts (or nests ``all_of`` when a
member is itself a group). Parenthesised sub-expressions are parsed recursively.
"""

from __future__ import annotations

import re
from typing import Any

from app.services.detections.sigma_match_when import CompileResult

# Aggregate / window telemetry fields no connector can emit as a single event. A
# rule whose condition references any of these can never fire as a single-event
# match, so it is quarantined as ``unsupported_stateful`` (never evaluated by
# fusion) rather than erroring. This is the plan's canonical 11-field set.
_AGGREGATE_FIELDS: frozenset[str] = frozenset(
    {
        "time_window_minutes",
        "connection_count",
        "interval_consistency",
        "distinct_ports_per_src",
        "distinct_dst_per_src",
        "distinct_hosts_per_src",
        "distinct_users_per_ip",
        "event_count",
        "failed_attempts",
        "request_rate",
        "bytes_transferred_total",
    }
)

# Multi-word / long operator keywords that must match before shorter prefixes
# (e.g. ``CONTAINS`` before ``CONTAINS_ANY`` is unsafe; list longest-first).
# ``IS NULL`` is matched as a two-word unit.
_OP_ALTS = "|".join(
    [
        "IS NULL",
        "NOT CONTAINS_ANY",
        "NOT ENDSWITH_ANY",
        "NOT STARTSWITH",
        "NOT IN",
        "CONTAINS_ALL",
        "CONTAINS_ANY",
        "CONTAINS",
        "STARTSWITH_ANY",
        "STARTS_WITH_ANY",
        "ENDS_WITH_ANY",
        "ENDSWITH_ANY",
        "STARTSWITH",
        "ENDSWITH",
        "MATCHES",
        "MATCH_ANY",
        "PATTERN_MATCH_ANY",
        "MATCH",
        "HAS_ANY",
        ">=",
        "<=",
        "==",
        "!=",
        ">",
        "<",
        "IN",
    ]
)

_FIELD_RE = re.compile(r"[A-Za-z_][\w.]*")

# Operator keyword -> matcher key suffix. ``==`` and ``IS NULL`` are special (see
# below) and map to a bare field key, so they are absent here.
_OP_SUFFIX: dict[str, str] = {
    "IN": "in",
    "NOT IN": "not_in",
    "CONTAINS": "contains",
    "CONTAINS_ANY": "contains_any",
    "CONTAINS_ALL": "contains_all",
    "STARTSWITH": "startswith",
    "STARTSWITH_ANY": "startswith_any",
    "STARTS_WITH_ANY": "startswith_any",
    "ENDSWITH": "endswith",
    "ENDSWITH_ANY": "endswith_any",
    "ENDS_WITH_ANY": "endswith_any",
    "HAS_ANY": "has_any",
    "MATCH": "match",
    "MATCHES": "match",
    "MATCH_ANY": "match_any",
    "PATTERN_MATCH_ANY": "pattern_match_any",
    "NOT STARTSWITH": "not_startswith",
    "NOT ENDSWITH_ANY": "not_endswith_any",
    "NOT CONTAINS_ANY": "not_contains_any",
    ">=": "gte",
    "<=": "lte",
    ">": "gt",
    "<": "lt",
    "!=": "not_in",
}

# Operators whose operand is a ``[ ... ]`` list.
_LIST_OPS: frozenset[str] = frozenset(
    [
        "IN",
        "NOT IN",
        "CONTAINS_ANY",
        "CONTAINS_ALL",
        "STARTSWITH_ANY",
        "STARTS_WITH_ANY",
        "ENDSWITH_ANY",
        "ENDS_WITH_ANY",
        "HAS_ANY",
        "MATCH_ANY",
        "PATTERN_MATCH_ANY",
        "NOT ENDSWITH_ANY",
        "NOT CONTAINS_ANY",
    ]
)
# ``IS NULL`` carries no operand.
_NULL_OPS: frozenset[str] = frozenset({"IS NULL"})


class _Tok:
    __slots__ = ("kind", "val")

    def __init__(self, kind: str, val: str) -> None:
        self.kind = kind
        self.val = val


def _tokenize(condition: str) -> list[_Tok]:
    """Split an infix condition into a flat token stream.

    Field identifiers keep their original case; operator and logical keywords are
    matched case-insensitively. ``IS NULL`` is a single ``op`` token.
    """
    collapsed = re.sub(r"\s+", " ", condition).strip()
    tokens: list[_Tok] = []
    i = 0
    n = len(collapsed)
    while i < n:
        c = collapsed[i]
        if c.isspace():
            i += 1
            continue
        if c in "(),[]":
            tokens.append(_Tok("paren", c))
            i += 1
            continue
        if c == ",":
            tokens.append(_Tok("comma", ","))
            i += 1
            continue
        if c in "\"'":
            quote = c
            j = i + 1
            buf: list[str] = []
            while j < n and collapsed[j] != quote:
                buf.append(collapsed[j])
                j += 1
            tokens.append(_Tok("str", "".join(buf)))
            i = j + 1
            continue
        m = _FIELD_RE.match(collapsed, i)
        if m and collapsed[i : m.end()].lower() in ("and", "or"):
            tokens.append(_Tok("logical", collapsed[i : m.end()].upper()))
            i = m.end()
            continue
        bm = re.match(r"(?:any|all)\b", collapsed[i:], re.IGNORECASE)
        if bm:
            tokens.append(_Tok("block", collapsed[i : i + bm.end()].upper()))
            i += bm.end()
            continue
        if collapsed[i] == "-" and (i + 1 >= n or not collapsed[i + 1].isdigit()):
            tokens.append(_Tok("dash", "-"))
            i += 1
            continue
        opm = re.match(
            r"(?:" + _OP_ALTS + r")", collapsed[i:], re.IGNORECASE
        )
        if opm:
            tokens.append(_Tok("op", collapsed[i : i + opm.end()].strip()))
            i += opm.end()
            continue
        num = re.match(r"-?\d+(?:\.\d+)?", collapsed[i:])
        if num and num.group(0) != "-":
            tokens.append(_Tok("num", num.group(0)))
            i += num.end()
            continue
        fm = _FIELD_RE.match(collapsed, i)
        if fm:
            tokens.append(_Tok("field", collapsed[i : fm.end()]))
            i = fm.end()
            continue
        # Unparseable character: skip it so one bad byte never aborts the rule.
        i += 1
    return tokens


def _literals(tokens: list[_Tok], i: int) -> tuple[Any, int]:
    """Parse one scalar literal (str / num / bool / null) starting at ``i``."""
    if i >= len(tokens):
        return None, i
    tok = tokens[i]
    if tok.kind in ("str", "num", "field"):
        return _parse_literal(tok.val), i + 1
    return None, i


def _parse_literal(v: str) -> Any:
    if "." in v and all(ch.isdigit() or ch == "." for ch in v):
        return float(v)
    try:
        return int(v)
    except ValueError:
        pass
    low = v.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low == "null":
        return None
    return v


def _parse_list(tokens: list[_Tok], i: int) -> tuple[list[Any], int]:
    """Parse a ``[ ... ]`` value list starting at ``tokens[i] == '['``."""
    i += 1  # consume '['
    items: list[Any] = []
    while i < len(tokens) and tokens[i].val != "]":
        tok = tokens[i]
        if tok.kind == "comma":
            i += 1
            continue
        if tok.kind == "paren" and tok.val == ")":
            return items, i  # unbalanced; stop defensively
        if tok.kind in ("str", "num", "field"):
            items.append(_parse_literal(tok.val))
        i += 1
    if i < len(tokens) and tokens[i].val == "]":
        i += 1  # consume ']'
    return items, i


def _build_clause(field: str, op: str, value: Any) -> dict[str, Any]:
    """Build one ``field_op -> operand`` clause from a parsed ``field OP value``."""
    if op == "==":
        return {field: value}
    if op == "IS NULL":
        return {field: None}
    suffix = _OP_SUFFIX[op]
    if op == "!=":
        # ``!=`` is a single-element blacklist negation.
        return {f"{field}_not_in": [value]}
    if op in _LIST_OPS:
        return {f"{field}_{suffix}": value}
    return {f"{field}_{suffix}": value}


def _combine_or(left: Any, right: Any) -> dict[str, list[Any]]:
    return {"any_of": [_flatten(left), _flatten(right)]}


def _combine_and(left: Any, right: Any) -> Any:
    left_flat = _flatten(left)
    right_flat = _flatten(right)
    if isinstance(left_flat, dict) and isinstance(right_flat, dict):
        if any(k in left_flat for k in ("all_of", "any_of")) or any(
            k in right_flat for k in ("all_of", "any_of")
        ):
            return {"all_of": [left_flat, right_flat]}
        merged: dict[str, Any] = {}
        merged.update(left_flat)
        merged.update(right_flat)
        return merged
    return {"all_of": [left_flat, right_flat]}


def _flatten(node: Any) -> Any:
    """Coerce a single-member ``any_of`` back to a flat dict when safe."""
    if isinstance(node, dict) and set(node.keys()) == {"any_of"}:
        members = node["any_of"]
        if len(members) == 1:
            return members[0]
    return node


def _parse_block(tokens: list[_Tok], i: int) -> tuple[Any, int]:

    """Parse an ``ANY OF:`` / ``ALL OF:`` block-keyword grammar.

    Native YAML rules write list-style disjunctions/conjunctions::

       ANY OF:
         - a == 1 AND b == 2
         - c == 3

    Each ``-``-prefixed member is itself an AND-chain, so it is parsed with
    :func:`_parse_and`. ``ANY OF`` maps to ``any_of`` (matches when *any*
    member holds) and ``ALL OF`` maps to ``all_of`` (matches when *all* do).
    """
    kind = tokens[i].val  # ANY or ALL
    i += 1
    if i < len(tokens) and tokens[i].val.upper() == "OF":
        i += 1
    members: list[Any] = []
    while i < len(tokens):
        t = tokens[i]
        if t.kind == "dash":
            i += 1
            continue
        # Block terminates here; the token is left for the caller to handle.
        if t.kind == "logical" or t.kind == "block":
            break
        if t.kind == "paren" and t.val == ")":
            break
        member, j = _parse_and(tokens, i)
        members.append(member)
        if j <= i:
            i += 1
        else:
            i = j
    if not members:
        return None, i
    if len(members) == 1:
        return members[0], i
    key = "any_of" if kind == "ANY" else "all_of"
    return {key: members}, i


def _parse_or(tokens: list[_Tok], i: int) -> tuple[Any, int]:
    node, i = _parse_and(tokens, i)
    while i < len(tokens) and tokens[i].kind == "logical" and tokens[i].val == "OR":
        right, i = _parse_and(tokens, i + 1)
        node = _combine_or(node, right)
    return node, i


def _parse_and(tokens: list[_Tok], i: int) -> tuple[Any, int]:
    node, i = _parse_term(tokens, i)
    while i < len(tokens) and tokens[i].kind == "logical" and tokens[i].val == "AND":
        right, i = _parse_term(tokens, i + 1)
        node = _combine_and(node, right)
    return node, i


def _parse_term(tokens: list[_Tok], i: int) -> tuple[Any, int]:
    t = tokens[i]
    if t.kind == "block":
        return _parse_block(tokens, i)
    if t.kind == "paren" and t.val == "(":
        node, i = _parse_or(tokens, i + 1)
        if i < len(tokens) and tokens[i].kind == "paren" and tokens[i].val == ")":
            i += 1
        return _flatten(node), i
    return _parse_predicate(tokens, i)


def _parse_predicate(tokens: list[_Tok], i: int) -> tuple[dict[str, Any], int]:
    field = tokens[i].val
    i += 1
    if i >= len(tokens):
        return {field: None}, i
    nt = tokens[i]
    if nt.kind == "logical":
        # Bare keyword predicate (no operator follows).
        return {field: None}, i
    if nt.kind == "paren" and nt.val == ")":
        return {field: None}, i
    if nt.kind != "op":
        # Unexpected operand where an operator was expected; bail gracefully.
        return {field: None}, i
    op = nt.val
    if op in _NULL_OPS:
        return {field: None}, i + 1
    if op in _LIST_OPS:
        if i + 1 < len(tokens) and tokens[i + 1].kind == "paren" and tokens[i + 1].val == "[":
            items, j = _parse_list(tokens, i + 1)
            return {f"{field}_{_OP_SUFFIX[op]}": items}, j
        value, j = _literals(tokens, i + 1)
        return {f"{field}_{_OP_SUFFIX[op]}": [value] if value is not None else []}, j
    value, i = _literals(tokens, i + 1)
    return _build_clause(field, op, value), i


def _is_agg(condition: str) -> bool:
    """True if the condition references any aggregate/window field."""
    for tok in _tokenize(condition):
        if tok.kind == "field" and tok.val in _AGGREGATE_FIELDS:
            return True
    return False


def compile_native_to_match_when(rule_body: str) -> CompileResult:
    """Compile a native infix condition into the fusion ``match_when`` DSL.

    Follows the :class:`CompileResult` contract exactly like
    ``compile_sigma_to_match_when``: ``compiled`` / ``unsupported_stateful`` /
    ``error``.
    """
    condition = _extract_condition(rule_body)
    if condition is None:
        return CompileResult("error", None, "no condition block found")

    if _is_agg(condition):
        return CompileResult(
            "unsupported_stateful",
            None,
            "Requires stateful aggregate telemetry fields",
        )

    try:
        tokens = _tokenize(condition)
        node, _ = _parse_or(tokens, 0)
    except Exception as exc:  # noqa: BLE001 -- per-call failure isolation
        return CompileResult("error", None, f"parse error: {exc}")

    if not isinstance(node, dict) or not node:
        return CompileResult("error", None, "condition produced no clauses")
    return CompileResult("compiled", node, None)


def _extract_condition(rule_body: str) -> str | None:
    """Pull the infix condition string out of a native YAML rule body.

    Native rules carry the condition under ``detection.condition`` as a literal
    block scalar (``|``). The plain text form may also be a bare infix string.
    """
    import yaml

    try:
        data = yaml.safe_load(rule_body)
    except Exception:  # noqa: BLE001
        data = None
    if isinstance(data, dict):
        det = data.get("detection")
        if isinstance(det, dict):
            cond = det.get("condition")
            if isinstance(cond, str):
                return cond
    if isinstance(rule_body, str) and rule_body.strip().startswith("det-"):
        return rule_body.strip()
    return None
