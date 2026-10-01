"""
converters/sigma_to_datadog.py

Stretch-goal converter: takes the same rule dict produced by the generator
and renders a best-effort Datadog Cloud SIEM detection rule payload, in the
shape accepted by Datadog's create/validate/test rule APIs:
https://docs.datadoghq.com/api/latest/security-monitoring/

IMPORTANT CAVEATS (read before treating this as production-ready):

1. Sigma's field-based detection logic and Datadog's log search query syntax
   are not 1:1. This module translates simple field-equality / contains /
   startswith / endswith modifiers into Datadog query terms, but it does not
   attempt to handle every Sigma modifier or complex boolean nesting.
2. Field names are passed through as-is with an "@" prefix, which is how
   Datadog references parsed log attributes. Whether `@Image` or `@CommandLine`
   actually resolves to the right attribute depends entirely on how your
   Datadog log pipeline parses that log source -- verify field names against
   your actual parsed log facets before relying on this.
3. Technique tags require the format "technique:T1234-canonical-att&ck-name".
   This converter generates a best-effort slug from the rule title since it
   doesn't have a full ATT&CK technique name lookup table -- replace with the
   exact canonical technique name before deploying.
4. This produces a payload suitable for the validate-a-detection-rule and
   test-a-rule APIs to sanity-check structure. Treat it as a first draft a
   human reviews, the same way the Sigma rule itself is a first draft.

Reference for the schema shape used below: Datadog's "Build, test, and scale
detections as code with Datadog Cloud SIEM" engineering blog post (2025),
which shows full example payloads for rule validation, testing, and creation.
"""

from __future__ import annotations

import re
from typing import Any

# Stable, well-known ATT&CK tactic ID mapping -- ATT&CK tactics rarely change.
TACTIC_IDS = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}

LEVEL_TO_STATUS = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _field_to_query_term(field_key: str, value: Any) -> str:
    """Translate a single Sigma field|modifier: value pair into a Datadog query term."""
    if "|" in field_key:
        field, modifier = field_key.split("|", 1)
    else:
        field, modifier = field_key, None

    def term(v: str) -> str:
        v = str(v)
        if modifier == "contains":
            return f'@{field}:*{v}*'
        if modifier == "startswith":
            return f'@{field}:{v}*'
        if modifier == "endswith":
            return f'@{field}:*{v}'
        # exact match -- quote if it contains whitespace
        return f'@{field}:"{v}"' if " " in v else f"@{field}:{v}"

    if isinstance(value, list):
        if modifier == "all":
            return "(" + " AND ".join(term(v) for v in value) + ")"
        return "(" + " OR ".join(term(v) for v in value) + ")"
    return term(value)


def _selection_to_query(fields: dict[str, Any]) -> str:
    terms = [_field_to_query_term(k, v) for k, v in fields.items() if v != ""]
    return " AND ".join(terms) if terms else "*"


def _condition_to_query(rule: dict[str, Any]) -> str:
    """
    Best-effort: build a query string per named selection, then combine
    according to the condition string. Only handles simple 'and' / 'or' /
    'and not' patterns between named selections -- complex nested boolean
    logic should be reviewed and adjusted by hand.
    """
    selections = {s["name"]: _selection_to_query(s["fields"]) for s in rule["detection"]["selections"]}
    condition = rule["detection"]["condition"]

    # naive token substitution: longest names first to avoid partial overlaps
    for name in sorted(selections, key=len, reverse=True):
        condition = re.sub(rf"\b{re.escape(name)}\b", f"({selections[name]})", condition)

    condition = condition.replace(" and not ", " AND NOT ").replace(" and ", " AND ").replace(" or ", " OR ")
    return condition


def to_datadog_rule(rule: dict[str, Any], rule_name_override: str | None = None) -> dict[str, Any]:
    """Build a Datadog Cloud SIEM detection-rule payload from a generator rule dict."""
    query_str = _condition_to_query(rule)

    tags = ["source:ai-detection-as-code"]
    has_mitre = False
    for tag in rule.get("tags", []):
        if tag.startswith("attack.t"):
            technique_id = tag.split(".", 1)[1].upper()  # e.g. t1059.001 -> T1059.001
            slug = _slugify(rule["title"])
            tags.append(f"technique:{technique_id}-{slug}")
            has_mitre = True
        elif tag.startswith("attack.") and tag.split(".", 1)[1] in TACTIC_IDS:
            tactic_name = tag.split(".", 1)[1]
            tags.append(f"tactic:{TACTIC_IDS[tactic_name]}-{tactic_name}")
            has_mitre = True
    if has_mitre:
        tags.append("security:attack")

    status = LEVEL_TO_STATUS.get(rule["level"], "medium")

    return {
        "name": rule_name_override or rule["title"],
        "isEnabled": False,  # default to disabled -- review before enabling in a live environment
        "queries": [
            {
                "query": query_str,
                "groupByFields": [],
                "hasOptionalGroupByFields": False,
                "distinctFields": [],
                "aggregation": "count",
                "name": "a",
                "dataSource": "logs",
            }
        ],
        "options": {
            "evaluationWindow": 300,
            "detectionMethod": "threshold",
            "maxSignalDuration": 86400,
            "keepAlive": 3600,
        },
        "cases": [
            {
                "name": "Match",
                "status": status,
                "notifications": [],
                "condition": "a > 0",
            }
        ],
        "message": rule["description"] + (f"\n\nNotes: {rule['notes']}" if rule.get("notes") else ""),
        "tags": tags,
        "hasExtendedTitle": True,
        "type": "log_detection",
        "filters": [],
    }
