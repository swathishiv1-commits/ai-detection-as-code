"""
generator/llm_rule_generator.py

Calls Claude to draft a structured detection-rule JSON object from CTI text.
The model is constrained to a fixed schema (see prompts/system_prompt.md) so
downstream code never has to parse freeform Sigma YAML out of the model --
we render the YAML ourselves from validated JSON.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

PROMPT_DIR = Path(__file__).parent / "prompts"
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
MAX_RETRIES = 2


class RuleGenerationError(Exception):
    """Raised when the model fails to produce a parseable rule after retries."""


def _load_system_prompt() -> str:
    return (PROMPT_DIR / "system_prompt.md").read_text(encoding="utf-8")


def _load_few_shot_block() -> str:
    """Render the few-shot examples into a single text block for the prompt."""
    examples = yaml.safe_load((PROMPT_DIR / "few_shot_examples.yaml").read_text(encoding="utf-8"))
    parts = []
    for ex in examples:
        parts.append(
            "CTI SNIPPET:\n"
            + ex["cti_snippet"].strip()
            + "\n\nEXPECTED OUTPUT JSON:\n"
            + json.dumps(ex["rule_json"], indent=2)
        )
    return "\n\n---\n\n".join(parts)


def _extract_json(raw_text: str) -> dict[str, Any]:
    """
    Models occasionally wrap JSON in a markdown fence even when told not to.
    Strip that defensively before parsing.
    """
    text = raw_text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    return json.loads(text.strip())


def generate_rule(cti_text: str, logsource_hint: str | None = None, client: Anthropic | None = None) -> dict[str, Any]:
    """
    Generate a structured detection-rule JSON object from CTI text.

    Args:
        cti_text: cleaned threat report / technique description text.
        logsource_hint: optional hint like "aws_cloudtrail" or "windows_sysmon"
            to steer the model toward a log source it has field knowledge of.
        client: optional pre-built Anthropic client (mainly for testing).

    Returns:
        Parsed rule dict matching the schema in prompts/system_prompt.md.

    Raises:
        RuleGenerationError: if the model doesn't return parseable JSON
            after MAX_RETRIES attempts.
    """
    client = client or Anthropic()
    system_prompt = _load_system_prompt()
    few_shot_block = _load_few_shot_block()

    user_content = (
        f"{few_shot_block}\n\n---\n\nNow generate a rule for this CTI text.\n"
    )
    if logsource_hint:
        user_content += f"Log source hint: {logsource_hint}\n"
    user_content += f"\nCTI SNIPPET:\n{cti_text}\n\nEXPECTED OUTPUT JSON:"

    last_error: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 2):
        response = client.messages.create(
            model=MODEL,
            max_tokens=1500,
            system=system_prompt,
            messages=[{"role": "user", "content": user_content}],
        )
        raw_text = "".join(block.text for block in response.content if block.type == "text")

        try:
            return _extract_json(raw_text)
        except (json.JSONDecodeError, ValueError) as exc:
            last_error = exc
            # Ask the model to fix its own output rather than starting over cold.
            user_content = (
                f"Your previous response could not be parsed as JSON: {exc}\n"
                f"Previous response:\n{raw_text}\n\n"
                "Return ONLY the corrected JSON object, no other text."
            )
            continue

    raise RuleGenerationError(
        f"Failed to get parseable rule JSON after {MAX_RETRIES + 1} attempts: {last_error}"
    )
