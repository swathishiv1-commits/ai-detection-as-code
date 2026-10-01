"""
validator/sigma_evaluator.py

Evaluates whether a rule's detection block matches a single log event dict.
This is a lightweight Python implementation -- no pySigma backend required.

Design goals:
  - Handle the field modifiers the generator actually emits:
    exact match, contains, startswith, endswith, all (list AND).
  - Parse simple boolean conditions between named selections (AND / OR / NOT).
  - Clearly flag and skip aggregate conditions (count, sum, etc.)
    since those require a window of events, not a single log.
  - Be easy to read and debug. Detection engineering tooling should be
    transparent -- not a black box.

What this does NOT handle (intentional scope limits for this project):
  - Aggregate / time-window conditions (|count() > N, |sum(...))
  - Regular expression modifiers (|re)
  - Sigma near / temporal correlations
  - Multi-field conditions with nested parentheses beyond basic AND/OR/NOT

For those, use pySigma with an Elasticsearch or Splunk backend.
"""

from __future__ import annotations

import re
from typing import Any

# Tokens we skip when parsing condition strings
_BOOLEAN_KEYWORDS = {"and", "or", "not"}
_AGGREGATE_KEYWORDS = {"count", "sum", "min", "max", "avg", "near"}


class AggregateConditionError(Exception):
    """Raised when the condition uses an aggregate we can't evaluate per-event."""


def _get_field_value(log: dict[str, Any], field_name: str) -> Any:
    """
    Retrieve a field from a log dict.  Supports two conventions:
      - flat keys:  log["CommandLine"]
      - dot-path:   log["process"]["command_line"] via "process.command_line"
    Field lookup is case-insensitive against the actual key names.
    """
    # Direct lookup first (fastest path)
    if field_name in log:
        return log[field_name]

    # Case-insensitive flat lookup
    lower = field_name.lower()
    for k, v in log.items():
        if k.lower() == lower:
            return v

    # Dot-path descent
    parts = field_name.split(".", 1)
    if len(parts) == 2:
        parent, child = parts
        for k, v in log.items():
            if k.lower() == parent.lower() and isinstance(v, dict):
                return _get_field_value(v, child)

    return None


def _match_value(field_val: Any, match_val: Any, modifier: str | None) -> bool:
    """Test a single field value against a single match value with a modifier."""
    if field_val is None:
        return False
    field_str = str(field_val).lower()
    match_str = str(match_val).lower()

    if modifier == "contains":
        return match_str in field_str
    if modifier == "startswith":
        return field_str.startswith(match_str)
    if modifier == "endswith":
        return field_str.endswith(match_str)
    # exact match (no modifier or unknown)
    return field_str == match_str


def _evaluate_selection(selection: dict[str, Any], log: dict[str, Any]) -> bool:
    """
    Returns True if ALL field conditions in a selection match the log.
    Each field must match (selection = implicit AND across fields).
    """
    for raw_key, match_value in selection.items():
        # Parse modifier from key, e.g. "CommandLine|contains" -> ("CommandLine", "contains")
        if "|" in raw_key:
            field_name, modifier_str = raw_key.split("|", 1)
            # Take the last modifier for chained ones (e.g. "contains|all" -> we look at both)
            modifiers = modifier_str.split("|")
        else:
            field_name = raw_key
            modifiers = []

        is_all = "all" in modifiers
        effective_modifier = next((m for m in modifiers if m != "all"), None)

        field_val = _get_field_value(log, field_name)

        if isinstance(match_value, list):
            # list with 'all' modifier: every value must match
            if is_all:
                if not all(_match_value(field_val, v, effective_modifier) for v in match_value):
                    return False
            else:
                # list without 'all': any value can match (OR semantics)
                if not any(_match_value(field_val, v, effective_modifier) for v in match_value):
                    return False
        else:
            if not _match_value(field_val, match_value, effective_modifier):
                return False

    return True


def _parse_condition(condition: str, selections: dict[str, bool]) -> bool:
    """
    Evaluate a simple boolean condition string against pre-computed selection
    results.  Handles:
        selection_name
        sel_a and sel_b
        sel_a or sel_b
        sel_a and not sel_b
        (nested parentheses via recursive call)

    Raises AggregateConditionError if the condition uses count/sum/etc.
    """
    condition = condition.strip()

    # Guard: detect aggregate conditions we can't evaluate here
    for agg in _AGGREGATE_KEYWORDS:
        if re.search(rf"\b{agg}\b", condition, re.IGNORECASE):
            raise AggregateConditionError(
                f"Condition uses aggregate function '{agg}': '{condition}'. "
                "Per-event evaluation is not supported for this condition -- "
                "use a SIEM backend to evaluate aggregate logic."
            )

    # Strip outer parentheses if wrapping the whole expression
    if condition.startswith("(") and condition.endswith(")"):
        inner = condition[1:-1].strip()
        # Make sure the parens actually wrap the whole thing (not two sub-exprs)
        depth = 0
        for ch in inner:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            if depth < 0:
                break
        if depth == 0:
            return _parse_condition(inner, selections)

    # Split on top-level 'or' (lowest precedence)
    parts = _split_on_keyword(condition, "or")
    if len(parts) > 1:
        return any(_parse_condition(p, selections) for p in parts)

    # Split on top-level 'and'
    parts = _split_on_keyword(condition, "and")
    if len(parts) > 1:
        return all(_parse_condition(p, selections) for p in parts)

    # Handle 'not expr'
    not_match = re.match(r"^not\s+(.+)$", condition, re.IGNORECASE)
    if not_match:
        return not _parse_condition(not_match.group(1), selections)

    # Leaf: must be a selection name
    name = condition.strip()
    if name in selections:
        return selections[name]

    # Unknown name -- warn and treat as False
    return False


def _split_on_keyword(expr: str, keyword: str) -> list[str]:
    """
    Split expr on the given keyword (and/or) at the top level only
    (not inside parentheses).  Case-insensitive.
    """
    parts = []
    depth = 0
    current: list[str] = []
    tokens = re.split(r"(\s+)", expr)  # keep whitespace tokens for reassembly
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        depth += tok.count("(") - tok.count(")")
        if depth == 0 and tok.strip().lower() == keyword:
            candidate = "".join(current).strip()
            if candidate:
                parts.append(candidate)
            current = []
        else:
            current.append(tok)
        i += 1
    remainder = "".join(current).strip()
    if remainder:
        parts.append(remainder)
    return parts if len(parts) > 1 else [expr]


def evaluate(rule: dict[str, Any], log: dict[str, Any]) -> bool:
    """
    Evaluate whether a rule's detection block matches a log event.

    Args:
        rule: rule dict (as produced by the generator / validator).
        log:  a single parsed log event dict.

    Returns:
        True if the rule matches the log, False otherwise.

    Raises:
        AggregateConditionError: if the rule uses aggregate logic that
            can't be evaluated against a single log event.
    """
    detection = rule["detection"]
    selections_block = {s["name"]: s["fields"] for s in detection["selections"]}
    condition = detection["condition"]

    # Pre-compute each selection's boolean result against the log
    selection_results = {
        name: _evaluate_selection(fields, log)
        for name, fields in selections_block.items()
    }

    return _parse_condition(condition, selection_results)
