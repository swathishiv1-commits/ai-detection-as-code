"""
converters/json_to_sigma.py

Renders a validated rule dict (matching generator/prompts/system_prompt.md's
schema) into a proper Sigma YAML file. We template this deterministically
rather than asking the LLM to emit YAML directly -- LLMs are unreliable at
producing syntactically exact Sigma YAML, but reliable at producing JSON that
matches a fixed schema.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class _SigmaDumper(yaml.SafeDumper):
    """Keep block-style lists/dicts readable instead of YAML's flow style."""


def _ordered_rule_dict(rule: dict[str, Any]) -> dict[str, Any]:
    """Lay out fields in the conventional Sigma rule order."""
    detection: dict[str, Any] = {}
    for selection in rule["detection"]["selections"]:
        detection[selection["name"]] = selection["fields"]
    detection["condition"] = rule["detection"]["condition"]

    ordered = {
        "title": rule["title"],
        "id": rule["id"],
        "status": rule["status"],
        "description": rule["description"],
        "references": rule.get("references", []),
        "author": rule["author"],
        "date": rule["date"],
        "tags": rule["tags"],
        "logsource": {k: v for k, v in rule["logsource"].items() if v is not None},
        "detection": detection,
        "falsepositives": rule["falsepositives"],
        "level": rule["level"],
    }
    if rule.get("notes"):
        ordered["notes"] = rule["notes"]
    return ordered


def render_sigma_yaml(rule: dict[str, Any]) -> str:
    """Return a Sigma-formatted YAML string for the given rule dict."""
    ordered = _ordered_rule_dict(rule)
    return yaml.dump(
        ordered,
        Dumper=_SigmaDumper,
        sort_keys=False,
        default_flow_style=False,
        width=100,
        allow_unicode=True,
    )


def _slugify(title: str) -> str:
    return (
        title.lower()
        .replace(" ", "_")
        .replace("/", "_")
        .replace("(", "")
        .replace(")", "")
        .replace(",", "")
        .replace("-", "_")
    )


def write_rule(rule: dict[str, Any], output_dir: str) -> Path:
    """Render and write a rule to disk, returning the path written."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = _slugify(rule["title"]) + ".yml"
    path = out_dir / filename
    path.write_text(render_sigma_yaml(rule), encoding="utf-8")
    return path
