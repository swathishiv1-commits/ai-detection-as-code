"""
validator/sigma_validator.py

Validates a rule dict (from the LLM generator) against the expected schema
before we render it to Sigma YAML or push it through the test runner.

Two-layer approach:
  1. Local structural check  — always runs, no dependencies required.
     Catches missing required fields, bad level/status values,
     malformed detection blocks, etc.
  2. pySigma round-trip check — runs if pySigma is installed.
     Renders the rule to YAML, parses it back through pySigma's schema
     parser, and reports any field-level errors pySigma finds.
     Gracefully skipped with a warning if pySigma isn't installed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

VALID_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
FIELD_MODIFIER_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*"
    r"(\|(contains|startswith|endswith|all|re|cidr|lt|gt|lte|gte|expand))*$"
)
MITRE_TAG_PATTERN = re.compile(r"^attack\.(t\d{4}(\.\d{3})?|[a-z\-]+)$")


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = []
        if self.valid:
            lines.append("✅ Rule is valid")
        else:
            lines.append("❌ Rule has validation errors")
        for e in self.errors:
            lines.append(f"  ERROR:   {e}")
        for w in self.warnings:
            lines.append(f"  WARNING: {w}")
        return "\n".join(lines)


def _check_required_string(obj: dict, key: str, errors: list[str]) -> None:
    v = obj.get(key)
    if not v or not isinstance(v, str) or not v.strip():
        errors.append(f"Missing or empty required field: '{key}'")


def _validate_logsource(logsource: Any, errors: list[str]) -> None:
    if not isinstance(logsource, dict):
        errors.append("'logsource' must be a dict")
        return
    if not any(logsource.get(k) for k in ("category", "product", "service")):
        errors.append("'logsource' must define at least one of: category, product, service")


def _validate_detection(detection: Any, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(detection, dict):
        errors.append("'detection' must be a dict")
        return

    selections = detection.get("selections")
    if not selections or not isinstance(selections, list):
        errors.append("'detection.selections' must be a non-empty list")
        return

    declared_names: set[str] = set()
    for i, sel in enumerate(selections):
        if not isinstance(sel, dict):
            errors.append(f"selection[{i}] must be a dict")
            continue
        name = sel.get("name")
        if not name or not isinstance(name, str):
            errors.append(f"selection[{i}] missing 'name'")
        else:
            declared_names.add(name)
        fields = sel.get("fields")
        if not isinstance(fields, dict):
            errors.append(f"selection '{name}': 'fields' must be a dict")
        else:
            for fk in fields:
                if not FIELD_MODIFIER_PATTERN.match(fk):
                    errors.append(
                        f"selection '{name}': field key '{fk}' contains invalid modifier syntax"
                    )

    condition = detection.get("condition")
    if not condition or not isinstance(condition, str):
        errors.append("'detection.condition' must be a non-empty string")
    else:
        # Warn about count-based conditions we can't evaluate locally
        if "|" in condition and "count" in condition:
            warnings.append(
                "Condition uses aggregate (count/sum/…) — the local test runner "
                "will evaluate per-event logic only. Verify aggregate thresholds manually."
            )
        # Check all names referenced in condition are declared
        referenced = set(re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", condition))
        reserved = {"and", "or", "not", "count", "sum", "min", "max", "avg", "near", "by", "window"}
        for ref in referenced - reserved:
            if not re.match(r"^\d", ref) and ref not in declared_names:
                warnings.append(
                    f"Condition references '{ref}' which is not a declared selection name. "
                    "This is fine if it's part of an aggregate expression — double-check."
                )


def _validate_tags(tags: Any, warnings: list[str]) -> None:
    if not isinstance(tags, list):
        warnings.append("'tags' should be a list")
        return
    for tag in tags:
        if not isinstance(tag, str):
            continue
        if tag.startswith("attack.") and not MITRE_TAG_PATTERN.match(tag):
            warnings.append(
                f"Tag '{tag}' looks like a MITRE tag but doesn't match the expected "
                "pattern 'attack.tNNNN' or 'attack.tactic-name'"
            )


def validate_rule_dict(rule: dict[str, Any]) -> ValidationResult:
    """
    Structural validation of a rule dict. Returns a ValidationResult.
    Does not require pySigma to be installed.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Required string fields
    for key in ("title", "id", "status", "description", "author", "date"):
        _check_required_string(rule, key, errors)

    # Controlled-vocabulary fields
    status = rule.get("status", "")
    if status and status not in VALID_STATUSES:
        errors.append(f"'status' must be one of {sorted(VALID_STATUSES)}, got '{status}'")

    level = rule.get("level", "")
    if level and level not in VALID_LEVELS:
        errors.append(f"'level' must be one of {sorted(VALID_LEVELS)}, got '{level}'")

    # Title length
    title = rule.get("title", "")
    if isinstance(title, str) and len(title) > 80:
        warnings.append(f"'title' is {len(title)} chars; convention is <= 80")

    # Structured fields
    _validate_logsource(rule.get("logsource"), errors)
    _validate_detection(rule.get("detection"), errors, warnings)
    _validate_tags(rule.get("tags"), warnings)

    # falsepositives
    fp = rule.get("falsepositives", [])
    if not isinstance(fp, list) or len(fp) == 0:
        warnings.append("'falsepositives' is empty — add at least one realistic FP scenario")

    return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)


def validate_with_pysigma(sigma_yaml: str) -> ValidationResult:
    """
    Round-trip the rendered Sigma YAML through pySigma's schema parser.
    Returns a ValidationResult. If pySigma is not installed, returns a
    warning-only result so callers can decide whether to treat it as a failure.
    """
    try:
        from sigma.rule import SigmaRule  # type: ignore
        from sigma.exceptions import SigmaError  # type: ignore
    except ImportError:
        return ValidationResult(
            valid=True,
            warnings=["pySigma is not installed — skipping deep schema validation. Run: pip install pysigma"],
        )

    try:
        SigmaRule.from_yaml(sigma_yaml)
        return ValidationResult(valid=True)
    except SigmaError as exc:
        return ValidationResult(valid=False, errors=[str(exc)])
    except Exception as exc:  # noqa: BLE001
        return ValidationResult(valid=False, errors=[f"Unexpected pySigma error: {exc}"])
