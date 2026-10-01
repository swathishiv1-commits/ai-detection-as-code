"""
test_corpus/test_runner.py

Runs a compiled rule's detection logic against the matching synthetic log
corpus and outputs precision, recall, TP/FP/FN/TN counts, and per-event
match details.

Usage (standalone):
    python -m test_corpus.test_runner --rule rules/windows/hidden_encoded_powershell.yml
    python -m test_corpus.test_runner --rule-dict <rule_dict>  # programmatic use

Log corpus routing by logsource:
    product=aws / service=cloudtrail  -> aws_cloudtrail_samples.json
    product=windows                   -> windows_sysmon_samples.json

If the logsource doesn't match a known corpus file, the runner exits with a
clear message rather than silently scoring 0%.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from validator.sigma_evaluator import AggregateConditionError, evaluate

CORPUS_DIR = Path(__file__).parent / "synthetic_logs"

# Map logsource attributes to corpus files.
# Add new entries here as you expand the log corpus.
CORPUS_ROUTING: list[tuple[dict[str, str | None], Path]] = [
    ({"product": "aws", "service": "cloudtrail"}, CORPUS_DIR / "aws_cloudtrail_samples.json"),
    ({"product": "aws"}, CORPUS_DIR / "aws_cloudtrail_samples.json"),
    ({"product": "windows"}, CORPUS_DIR / "windows_sysmon_samples.json"),
    ({"category": "process_creation"}, CORPUS_DIR / "windows_sysmon_samples.json"),
    ({"category": "cloud"}, CORPUS_DIR / "aws_cloudtrail_samples.json"),
    ({"category": "authentication"}, CORPUS_DIR / "windows_sysmon_samples.json"),
]


@dataclass
class TestResult:
    rule_title: str
    corpus_file: str
    tp: int = 0   # malicious logs the rule caught
    fp: int = 0   # benign logs the rule incorrectly fired on
    fn: int = 0   # malicious logs the rule missed
    tn: int = 0   # benign logs the rule correctly ignored
    skipped: int = 0  # logs skipped due to aggregate condition
    details: list[dict] = field(default_factory=list)

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else None

    def summary(self) -> str:
        lines = [
            f"\n{'═' * 60}",
            f"Rule:      {self.rule_title}",
            f"Corpus:    {self.corpus_file}",
            f"{'─' * 60}",
            f"  True Positives  (malicious → matched):  {self.tp}",
            f"  False Positives (benign    → matched):  {self.fp}",
            f"  False Negatives (malicious → missed):   {self.fn}",
            f"  True Negatives  (benign    → ignored):  {self.tn}",
        ]
        if self.skipped:
            lines.append(f"  Skipped (aggregate condition):          {self.skipped}")
        prec = f"{self.precision:.0%}" if self.precision is not None else "N/A"
        rec = f"{self.recall:.0%}" if self.recall is not None else "N/A"
        lines += [
            f"{'─' * 60}",
            f"  Precision: {prec}   Recall: {rec}",
            f"{'═' * 60}",
        ]
        return "\n".join(lines)

    def per_event_lines(self) -> str:
        lines = []
        for d in self.details:
            icon = "✅" if d["outcome"] in ("TP", "TN") else "❌"
            lines.append(
                f"  {icon} [{d['outcome']}] {d['label'].upper():8s} | "
                f"matched={str(d['matched']):5s} | {d['comment']}"
            )
        return "\n".join(lines)


def _resolve_corpus(logsource: dict[str, Any]) -> Path | None:
    """Find the best matching corpus file for a logsource dict."""
    for criteria, path in CORPUS_ROUTING:
        if all(
            str(logsource.get(k, "")).lower() == str(v).lower()
            for k, v in criteria.items()
            if v is not None
        ):
            if path.exists():
                return path
    return None


def _load_rule_from_yaml(path: str) -> dict[str, Any]:
    """Load a Sigma YAML file and convert it back to the generator rule dict format."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))

    # Reconstruct the 'selections' list from the Sigma YAML detection block
    detection_raw = raw.get("detection", {})
    condition = detection_raw.get("condition", "")
    selections = []
    for name, fields in detection_raw.items():
        if name == "condition":
            continue
        if isinstance(fields, dict):
            selections.append({"name": name, "fields": fields})

    return {
        "title": raw.get("title", path),
        "detection": {
            "selections": selections,
            "condition": condition,
        },
        "logsource": raw.get("logsource", {}),
    }


def run_test(rule: dict[str, Any], corpus_path: Path | None = None, verbose: bool = True) -> TestResult:
    """
    Evaluate a rule dict against a log corpus and return a scored TestResult.

    Args:
        rule:        rule dict (generator format or loaded from YAML via _load_rule_from_yaml).
        corpus_path: override corpus path (auto-resolved from logsource if None).
        verbose:     print summary and per-event lines to stdout.
    """
    title = rule.get("title", "<unknown>")

    # Resolve corpus
    if corpus_path is None:
        corpus_path = _resolve_corpus(rule.get("logsource", {}))

    if corpus_path is None:
        print(
            f"⚠️  No corpus file found for logsource: {rule.get('logsource', {})}.\n"
            "   Add a matching entry to CORPUS_ROUTING in test_runner.py."
        )
        return TestResult(rule_title=title, corpus_file="<none>")

    logs = json.loads(corpus_path.read_text(encoding="utf-8"))
    result = TestResult(rule_title=title, corpus_file=corpus_path.name)

    for log in logs:
        label = log.get("_label", "unknown")  # "malicious" or "benign"
        comment = log.get("_comment", "")

        try:
            matched = evaluate(rule, log)
        except AggregateConditionError as exc:
            result.skipped += 1
            result.details.append({"label": label, "matched": None, "outcome": "SKIP", "comment": str(exc)[:80]})
            continue

        if label == "malicious":
            if matched:
                result.tp += 1
                outcome = "TP"
            else:
                result.fn += 1
                outcome = "FN"
        else:
            if matched:
                result.fp += 1
                outcome = "FP"
            else:
                result.tn += 1
                outcome = "TN"

        result.details.append({"label": label, "matched": matched, "outcome": outcome, "comment": comment[:90]})

    if verbose:
        print(result.per_event_lines())
        print(result.summary())

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a Sigma rule against the synthetic log corpus")
    parser.add_argument("--rule", required=True, help="Path to a Sigma YAML rule file")
    parser.add_argument("--corpus", help="Override corpus JSON file path")
    parser.add_argument("--quiet", action="store_true", help="Only print summary, no per-event lines")
    args = parser.parse_args()

    rule = _load_rule_from_yaml(args.rule)
    corpus_path = Path(args.corpus) if args.corpus else None
    result = run_test(rule, corpus_path=corpus_path, verbose=not args.quiet)

    if result.tp == 0 and result.fn > 0:
        print("❌ CI FAIL: rule scored zero true positives against its own synthetic corpus.")
        return 1
    if result.fp > result.tp:
        print(
            f"⚠️  WARNING: more false positives ({result.fp}) than true positives ({result.tp}). "
            "Consider narrowing the rule."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
